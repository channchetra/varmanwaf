//! Stream inspection: body tails and WebSocket frames (Phase 8, stream level).
//!
//! The handshake detector (`varman-waf/src/pipeline/semantic/websocket.rs`)
//! covers the upgrade request; this module covers what flows after it. The
//! proxy hands raw bytes to read-only plugin hooks:
//!
//! * `handle_request_body` sees the request-body chunks the early read pass
//!   did not consume - the tail of a large body - and, once upgraded, the
//!   client-to-server tunnel. [`TailWindow`] scans the tail with a sliding
//!   window; [`StreamInspector`] decodes client frames.
//! * `handle_upgraded_body` sees the server-to-client tunnel; the same
//!   [`StreamInspector`] decodes server frames.
//!
//! The frame decoder is defensive: reserved bits, interleaved data frames,
//! continuation frames without a start, oversized control frames and
//! oversized frames/messages all fail the stream instead of being
//! mis-interpreted. Fragmented messages are assembled up to a hard cap and
//! only complete messages are scanned, so a payload split across fragments is
//! still inspected as one unit.

use std::sync::LazyLock;

use varman_waf::canonical::{Canonicalizer, RequestParts};
use varman_waf::pipeline::SecurityPipeline;
use varman_waf::pipeline::fast::{RawPathTraversalDetector, SignatureDetector};
use varman_waf::pipeline::semantic::{
    CommandInjectionDetector, HtmlXssDetector, SqlStructuralDetector,
};

/// Largest single frame payload accepted. Larger frames fail the stream
/// rather than being buffered.
pub const MAX_FRAME_BYTES: usize = 128 * 1024;
/// Largest assembled (fragmented) message accepted.
pub const MAX_MESSAGE_BYTES: usize = 512 * 1024;

/// Focused detector set for tunnel payloads. An HTTP request-shape check
/// would misfire on a message payload, so the scan is limited to the
/// injection families that make sense for message content.
static WS_PIPELINE: LazyLock<SecurityPipeline> = LazyLock::new(|| {
    SecurityPipeline::new(vec![
        Box::new(SignatureDetector::new()),
        Box::new(SqlStructuralDetector::new()),
        Box::new(HtmlXssDetector::new()),
        Box::new(CommandInjectionDetector::new()),
        Box::new(RawPathTraversalDetector::new()),
    ])
});

/// One decoded frame event.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FrameEvent {
    /// A complete data message: `(opcode, payload)` with opcode 1 or 2.
    Message(u8, Vec<u8>),
    /// A complete control frame: `(opcode, payload)`.
    Control(u8, Vec<u8>),
    /// More bytes are needed before the next frame can be decoded.
    NeedMore,
    /// The stream is not valid RFC 6455 (or exceeds the limits).
    Invalid(&'static str),
}

/// Internal decode step: frames that produce no event (non-final fragments)
/// are consumed without stopping the caller's loop.
enum Decode {
    Event(FrameEvent),
    Consumed,
    NeedMore,
    Invalid(&'static str),
}

/// A streaming RFC 6455 frame decoder: feed bytes, pull events.
pub struct FrameDecoder {
    buffer: Vec<u8>,
    /// Partially assembled fragmented message: `(opcode, payload)`.
    fragmented: Option<(u8, Vec<u8>)>,
}

impl Default for FrameDecoder {
    fn default() -> Self {
        Self::new()
    }
}

impl FrameDecoder {
    pub fn new() -> Self {
        Self {
            buffer: Vec::new(),
            fragmented: None,
        }
    }

    /// Append freshly received bytes.
    pub fn feed(&mut self, bytes: &[u8]) {
        self.buffer.extend_from_slice(bytes);
    }

    /// Decode until an event is produced or more bytes are needed.
    pub fn next_event(&mut self) -> FrameEvent {
        loop {
            match self.decode_one() {
                Decode::Event(event) => return event,
                Decode::Consumed => continue,
                Decode::NeedMore => return FrameEvent::NeedMore,
                Decode::Invalid(reason) => return FrameEvent::Invalid(reason),
            }
        }
    }

    fn decode_one(&mut self) -> Decode {
        if self.buffer.len() < 2 {
            return Decode::NeedMore;
        }
        let first = self.buffer[0];
        let second = self.buffer[1];
        let fin = first & 0x80 != 0;
        let opcode = first & 0x0f;
        if first & 0x70 != 0 {
            return Decode::Invalid("reserved bits set");
        }
        let masked = second & 0x80 != 0;
        let short_len = (second & 0x7f) as usize;
        let mut offset = 2;
        let payload_len = match short_len {
            126 => {
                if self.buffer.len() < offset + 2 {
                    return Decode::NeedMore;
                }
                let len = u16::from_be_bytes([
                    self.buffer[offset],
                    self.buffer[offset + 1],
                ]) as usize;
                offset += 2;
                len
            },
            127 => {
                if self.buffer.len() < offset + 8 {
                    return Decode::NeedMore;
                }
                let mut bytes = [0u8; 8];
                bytes.copy_from_slice(&self.buffer[offset..offset + 8]);
                let len = u64::from_be_bytes(bytes);
                offset += 8;
                if len > MAX_FRAME_BYTES as u64 {
                    return Decode::Invalid("frame payload too large");
                }
                len as usize
            },
            len => len,
        };
        if payload_len > MAX_FRAME_BYTES {
            return Decode::Invalid("frame payload too large");
        }
        let mask = if masked {
            if self.buffer.len() < offset + 4 {
                return Decode::NeedMore;
            }
            let mut key = [0u8; 4];
            key.copy_from_slice(&self.buffer[offset..offset + 4]);
            offset += 4;
            Some(key)
        } else {
            None
        };
        if self.buffer.len() < offset + payload_len {
            return Decode::NeedMore;
        }
        let mut payload = self.buffer[offset..offset + payload_len].to_vec();
        if let Some(key) = mask {
            for (index, byte) in payload.iter_mut().enumerate() {
                *byte ^= key[index % 4];
            }
        }
        self.buffer.drain(..offset + payload_len);

        if opcode >= 8 {
            if !fin {
                return Decode::Invalid("fragmented control frame");
            }
            if payload_len > 125 {
                return Decode::Invalid("oversized control frame");
            }
            return Decode::Event(FrameEvent::Control(opcode, payload));
        }
        match opcode {
            0 => {
                let Some((start_opcode, mut assembled)) =
                    self.fragmented.take()
                else {
                    return Decode::Invalid(
                        "continuation without a start frame",
                    );
                };
                if assembled.len() + payload.len() > MAX_MESSAGE_BYTES {
                    return Decode::Invalid("fragmented message too large");
                }
                assembled.extend_from_slice(&payload);
                if fin {
                    Decode::Event(FrameEvent::Message(start_opcode, assembled))
                } else {
                    self.fragmented = Some((start_opcode, assembled));
                    Decode::Consumed
                }
            },
            1 | 2 => {
                if self.fragmented.is_some() {
                    return Decode::Invalid("interleaved data frame");
                }
                if fin {
                    Decode::Event(FrameEvent::Message(opcode, payload))
                } else {
                    if payload.len() > MAX_MESSAGE_BYTES {
                        return Decode::Invalid("fragmented message too large");
                    }
                    self.fragmented = Some((opcode, payload));
                    Decode::Consumed
                }
            },
            _ => Decode::Invalid("unknown opcode"),
        }
    }
}

/// What the inspector found in a stream chunk.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StreamFinding {
    /// The bytes are not valid RFC 6455 frames.
    Protocol(&'static str),
    /// A complete message payload matched the injection detectors.
    Payload { rule_id: String, detail: String },
}

/// Per-connection inspection state: one decoder per direction.
pub struct StreamInspector {
    client: FrameDecoder,
    server: FrameDecoder,
}

impl Default for StreamInspector {
    fn default() -> Self {
        Self::new()
    }
}

impl StreamInspector {
    pub fn new() -> Self {
        Self {
            client: FrameDecoder::new(),
            server: FrameDecoder::new(),
        }
    }

    /// Inspect one chunk of tunnel bytes. `from_client` selects the decoder;
    /// both masked (client) and unmasked (server) frames are handled.
    pub fn inspect(
        &mut self,
        from_client: bool,
        bytes: &[u8],
    ) -> Option<StreamFinding> {
        let decoder = if from_client {
            &mut self.client
        } else {
            &mut self.server
        };
        decoder.feed(bytes);
        loop {
            match decoder.next_event() {
                FrameEvent::NeedMore => return None,
                FrameEvent::Control(_, _) => continue,
                FrameEvent::Invalid(reason) => {
                    return Some(StreamFinding::Protocol(reason));
                },
                FrameEvent::Message(opcode, payload) => {
                    if let Some(finding) = scan_payload(opcode, &payload) {
                        return Some(finding);
                    }
                },
            }
        }
    }
}

/// Scan one content window with the focused detector set. Shared by the frame
/// inspector (complete messages) and the tail window (forwarded body bytes).
/// Returns `(rule_id, detail)` on the first finding.
pub(crate) fn scan_content(payload: &[u8]) -> Option<(String, String)> {
    if payload.is_empty() || payload.len() > MAX_FRAME_BYTES {
        return None;
    }
    let canonical = Canonicalizer::default().canonicalize(
        RequestParts::new("POST", "ws.invalid", "/websocket")
            .with_header("Content-Type", "application/octet-stream")
            .with_body(payload.to_vec()),
    );
    let verdict = WS_PIPELINE.inspect(&canonical);
    let finding = verdict.findings.first()?;
    Some((
        finding.rule_id.to_string(),
        format!(
            "payload matched {} ({:?})",
            finding.rule_id, finding.category
        ),
    ))
}

/// Bytes kept between forwarded chunks when scanning a body tail.
const TAIL_WINDOW_BYTES: usize = 256;

/// A sliding window over forwarded body chunks: keeps the trailing bytes so a
/// pattern split across chunk boundaries is still seen, and bounds memory to
/// one window regardless of body size.
pub(crate) struct TailWindow {
    window: Vec<u8>,
}

impl Default for TailWindow {
    fn default() -> Self {
        Self::new()
    }
}

impl TailWindow {
    pub fn new() -> Self {
        Self { window: Vec::new() }
    }

    /// Feed one chunk; returns a finding when the combined window matches.
    pub fn push(&mut self, bytes: &[u8]) -> Option<(String, String)> {
        let mut combined = std::mem::take(&mut self.window);
        combined.extend_from_slice(bytes);
        let finding = scan_content(&combined);
        if combined.len() > TAIL_WINDOW_BYTES {
            let keep = combined.len() - TAIL_WINDOW_BYTES;
            combined.drain(..keep);
        }
        self.window = combined;
        finding
    }

    /// Bytes currently held for the next chunk.
    #[cfg(test)]
    pub fn len(&self) -> usize {
        self.window.len()
    }
}

/// Scan one complete message payload with the focused detector set.
fn scan_payload(opcode: u8, payload: &[u8]) -> Option<StreamFinding> {
    if !matches!(opcode, 1 | 2) {
        return None;
    }
    let (rule_id, detail) = scan_content(payload)?;
    Some(StreamFinding::Payload { rule_id, detail })
}

#[cfg(test)]
mod tests {
    use super::{
        FrameDecoder, FrameEvent, MAX_FRAME_BYTES, StreamFinding,
        StreamInspector,
    };

    /// Build one frame: `(fin, opcode, masked, payload)`.
    fn frame(
        fin: bool,
        opcode: u8,
        mask: Option<[u8; 4]>,
        payload: &[u8],
    ) -> Vec<u8> {
        let mut out = Vec::new();
        out.push((if fin { 0x80 } else { 0 }) | opcode);
        let masked = mask.is_some();
        let len = payload.len();
        if len < 126 {
            out.push((if masked { 0x80 } else { 0 }) | len as u8);
        } else if len <= u16::MAX as usize {
            out.push((if masked { 0x80 } else { 0 }) | 126);
            out.extend_from_slice(&(len as u16).to_be_bytes());
        } else {
            out.push((if masked { 0x80 } else { 0 }) | 127);
            out.extend_from_slice(&(len as u64).to_be_bytes());
        }
        match mask {
            Some(key) => {
                out.extend_from_slice(&key);
                for (index, byte) in payload.iter().enumerate() {
                    out.push(byte ^ key[index % 4]);
                }
            },
            None => out.extend_from_slice(payload),
        }
        out
    }

    #[test]
    fn decodes_masked_and_unmasked_frames() {
        let mut decoder = FrameDecoder::new();
        decoder.feed(&frame(true, 1, Some([1, 2, 3, 4]), b"hello"));
        assert_eq!(
            decoder.next_event(),
            FrameEvent::Message(1, b"hello".to_vec())
        );
        assert_eq!(decoder.next_event(), FrameEvent::NeedMore);

        decoder.feed(&frame(true, 2, None, b"raw"));
        assert_eq!(
            decoder.next_event(),
            FrameEvent::Message(2, b"raw".to_vec())
        );
    }

    #[test]
    fn partial_feeds_need_more_and_resume() {
        let bytes = frame(true, 1, None, b"abcdef");
        let mut decoder = FrameDecoder::new();
        for byte in &bytes[..3] {
            decoder.feed(&[*byte]);
            assert_eq!(decoder.next_event(), FrameEvent::NeedMore);
        }
        decoder.feed(&bytes[3..]);
        assert_eq!(
            decoder.next_event(),
            FrameEvent::Message(1, b"abcdef".to_vec())
        );
    }

    #[test]
    fn fragmented_messages_assemble_before_scanning() {
        let mut decoder = FrameDecoder::new();
        decoder.feed(&frame(false, 1, None, b"SELECT "));
        assert_eq!(decoder.next_event(), FrameEvent::NeedMore);
        decoder.feed(&frame(true, 0, None, b"* FROM t"));
        assert_eq!(
            decoder.next_event(),
            FrameEvent::Message(1, b"SELECT * FROM t".to_vec())
        );
    }

    #[test]
    fn control_frames_interleave_with_fragments() {
        let mut decoder = FrameDecoder::new();
        decoder.feed(&frame(false, 1, None, b"part"));
        assert_eq!(decoder.next_event(), FrameEvent::NeedMore);
        decoder.feed(&frame(true, 9, None, b"ping"));
        assert_eq!(
            decoder.next_event(),
            FrameEvent::Control(9, b"ping".to_vec())
        );
        decoder.feed(&frame(true, 0, None, b"-two"));
        assert_eq!(
            decoder.next_event(),
            FrameEvent::Message(1, b"part-two".to_vec())
        );
    }

    #[test]
    fn extended_lengths_decode() {
        let payload = vec![b'x'; 300];
        let mut decoder = FrameDecoder::new();
        decoder.feed(&frame(true, 2, None, &payload));
        assert_eq!(decoder.next_event(), FrameEvent::Message(2, payload));
    }

    #[test]
    fn protocol_violations_fail_the_stream() {
        // Reserved bits.
        let mut decoder = FrameDecoder::new();
        decoder.feed(&[0xC1, 0x00]);
        assert_eq!(
            decoder.next_event(),
            FrameEvent::Invalid("reserved bits set")
        );
        // Continuation without a start frame.
        let mut decoder = FrameDecoder::new();
        decoder.feed(&frame(true, 0, None, b"orphan"));
        assert_eq!(
            decoder.next_event(),
            FrameEvent::Invalid("continuation without a start frame")
        );
        // Fragmented control frame.
        let mut decoder = FrameDecoder::new();
        decoder.feed(&frame(false, 9, None, b"ping"));
        assert_eq!(
            decoder.next_event(),
            FrameEvent::Invalid("fragmented control frame")
        );
        // Interleaved data frame while a fragment is pending.
        let mut decoder = FrameDecoder::new();
        decoder.feed(&frame(false, 1, None, b"a"));
        assert_eq!(decoder.next_event(), FrameEvent::NeedMore);
        decoder.feed(&frame(true, 2, None, b"b"));
        assert_eq!(
            decoder.next_event(),
            FrameEvent::Invalid("interleaved data frame")
        );
    }

    #[test]
    fn oversized_frames_fail_the_stream() {
        let mut header = vec![0x82, 127];
        header.extend_from_slice(&((MAX_FRAME_BYTES as u64) + 1).to_be_bytes());
        let mut decoder = FrameDecoder::new();
        decoder.feed(&header);
        assert_eq!(
            decoder.next_event(),
            FrameEvent::Invalid("frame payload too large")
        );
    }

    #[test]
    fn inspector_flags_injection_payloads() {
        let mut inspector = StreamInspector::new();
        assert!(
            inspector
                .inspect(
                    true,
                    &frame(true, 1, Some([9, 9, 9, 9]), b"hello world")
                )
                .is_none()
        );
        let finding = inspector.inspect(
            true,
            &frame(
                true,
                1,
                Some([1, 2, 3, 4]),
                b"1' OR '1'='1 UNION SELECT password FROM users",
            ),
        );
        match finding {
            Some(StreamFinding::Payload { rule_id, .. }) => {
                assert!(!rule_id.is_empty());
            },
            other => panic!("expected a payload finding, got {other:?}"),
        }
    }

    #[test]
    fn inspector_flags_both_directions_and_protocol_errors() {
        let mut inspector = StreamInspector::new();
        // Server-to-client XSS payload.
        assert!(matches!(
            inspector.inspect(
                false,
                &frame(
                    true,
                    1,
                    None,
                    b"<script>alert(document.cookie)</script>"
                ),
            ),
            Some(StreamFinding::Payload { .. })
        ));
        // A malformed frame fails the stream.
        assert_eq!(
            inspector.inspect(true, &[0xC1, 0x00]),
            Some(StreamFinding::Protocol("reserved bits set"))
        );
    }

    #[test]
    fn tail_window_catches_payloads_split_across_chunks() {
        use super::TailWindow;

        let mut window = TailWindow::new();
        // The classic payload split mid-signature across two chunks.
        assert!(window.push(b"prefix text 1' OR '1'=").is_none());
        let finding = window.push(b"'1 suffix");
        assert!(finding.is_some(), "split payload must be caught");
        assert!(window.len() <= super::TAIL_WINDOW_BYTES);
    }

    #[test]
    fn tail_window_is_bounded_and_clean_for_benign_chunks() {
        use super::TailWindow;

        let mut window = TailWindow::new();
        for _ in 0..64 {
            assert!(window.push(&vec![b'a'; 4096]).is_none());
        }
        assert!(
            window.len() <= super::TAIL_WINDOW_BYTES,
            "window must stay bounded, got {}",
            window.len()
        );
    }
}
