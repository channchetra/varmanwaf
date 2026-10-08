//! WebSocket handshake detector (Phase 8, WebSocket inspection first slice).
//!
//! The handshake is an ordinary HTTP request, so it flows through the whole
//! pipeline; this detector reasons about the WebSocket-specific parts:
//!
//! | Evidence | Tier |
//! | --- | --- |
//! | `Origin` that is not the request host (cross-origin handshake) | Monitor (`ws.cross_origin`) |
//! | Handshake carrying a request body | Monitor (`ws.handshake_with_body`) |
//!
//! Cross-origin WebSocket hijacking (CSWSH) works because the browser attaches
//! the victim's cookies to a handshake initiated by any page: a handshake whose
//! `Origin` host differs from the requested host is the attack shape. Ordinary
//! same-origin applications never send one, so Monitor-tier events surface the
//! shape without breaking deliberate cross-origin gateways (a site-level
//! allow-list is future work). Browsers always send `Origin`; clients that do
//! not (CLIs, bots) are not CSWSH vectors and stay clean.

use super::super::{
    Action, AttackCategory, Confidence, Detector, DetectorId, DetectorResult,
    EvidenceSource, Finding, Severity,
};

use crate::canonical::CanonicalRequest;

/// `true` when the request asks for a WebSocket upgrade.
fn is_handshake(request: &CanonicalRequest) -> bool {
    request
        .header("upgrade")
        .is_some_and(|value| value.to_ascii_lowercase().contains("websocket"))
}

/// `(host, explicit non-default port)` for an authority or origin value.
///
/// Default ports (`80` for http/ws, `443` for https/wss) are folded away;
/// a missing port and a default port are equivalent.
fn normalize(
    authority: &str,
    scheme: Option<&str>,
) -> Option<(String, Option<u16>)> {
    // Strip any userinfo and path.
    let authority = authority.rsplit('@').next()?.split('/').next()?;
    let (host, port) = match authority.rsplit_once(':') {
        Some((host, port)) if port.chars().all(|c| c.is_ascii_digit()) => {
            (host, port.parse::<u16>().ok())
        },
        _ => (authority, None),
    };
    let host = host.trim_end_matches('.').to_ascii_lowercase();
    if host.is_empty() {
        return None;
    }
    let default_port = match scheme {
        Some("http") | Some("ws") => Some(80),
        Some("https") | Some("wss") => Some(443),
        _ => None,
    };
    let port = match port {
        Some(port) if default_port != Some(port) => Some(port),
        _ => None,
    };
    Some((host, port))
}

/// Origin values that can never be same-origin.
fn is_opaque_origin(origin: &str) -> bool {
    origin.eq_ignore_ascii_case("null")
}

/// WebSocket handshake detector.
#[derive(Debug, Clone, Copy, Default)]
pub struct WebSocketDetector;

impl WebSocketDetector {
    pub const fn new() -> Self {
        Self
    }
}

impl Detector for WebSocketDetector {
    fn id(&self) -> DetectorId {
        DetectorId("semantic.websocket.handshake")
    }

    fn inspect(
        &self,
        request: &CanonicalRequest,
        _ctx: &mut super::super::DetectionContext,
    ) -> DetectorResult {
        if !is_handshake(request) {
            return DetectorResult {
                findings: Vec::new(),
                degraded: None,
            };
        }
        let mut findings: Vec<Finding> = Vec::new();

        if let Some(origin) = request.header("origin") {
            let request_authority = normalize(request.authority(), None);
            let origin_parts = normalize(
                origin.split_once("://").map_or(origin, |(_, rest)| rest),
                origin
                    .split_once("://")
                    .map(|(scheme, _)| scheme.to_ascii_lowercase())
                    .as_deref(),
            );
            let mismatch = is_opaque_origin(origin)
                || match (&request_authority, &origin_parts) {
                    (Some(mine), Some(theirs)) => {
                        mine.0 != theirs.0 || mine.1 != theirs.1
                    },
                    _ => true,
                };
            if mismatch {
                findings.push(
                    Finding::new(
                        DetectorId("semantic.websocket.handshake"),
                        "ws.cross_origin",
                        AttackCategory::ApiAbuse,
                    )
                    .confidence(Confidence::Medium)
                    .severity(Severity::Medium)
                    .score(20)
                    .action(Action::Monitor)
                    .source(EvidenceSource::Header)
                    .field("origin")
                    .detail(format!(
                        "WebSocket handshake Origin {origin:?} does not match \
                         the requested host"
                    )),
                );
            }
        }

        let declared_body = request
            .header("content-length")
            .and_then(|value| value.trim().parse::<u64>().ok())
            .unwrap_or(0)
            > 0
            || request.header("transfer-encoding").is_some();
        if declared_body {
            findings.push(
                Finding::new(
                    DetectorId("semantic.websocket.handshake"),
                    "ws.handshake_with_body",
                    AttackCategory::ApiAbuse,
                )
                .confidence(Confidence::Medium)
                .severity(Severity::Medium)
                .score(15)
                .action(Action::Monitor)
                .source(EvidenceSource::Header)
                .detail(
                    "WebSocket handshake declares a request body; RFC 6455 \
                     forbids one"
                        .to_string(),
                ),
            );
        }

        DetectorResult {
            findings,
            degraded: None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{normalize, WebSocketDetector};
    use crate::canonical::{Canonicalizer, RequestParts};
    use crate::pipeline::{Action, AttackCategory, DetectionContext, Detector};

    fn handshake(host: &str, origin: Option<&str>) -> RequestParts {
        let mut parts = RequestParts::new("GET", host, "/ws")
            .with_header("Upgrade", "websocket")
            .with_header("Connection", "Upgrade")
            .with_header("Sec-WebSocket-Key", "dGhlIHNhbXBsZSBub25jZQ==")
            .with_header("Sec-WebSocket-Version", "13");
        if let Some(origin) = origin {
            parts = parts.with_header("Origin", origin);
        }
        parts
    }

    fn inspect(parts: RequestParts) -> crate::pipeline::DetectorResult {
        let request = Canonicalizer::default().canonicalize(parts);
        let detector = WebSocketDetector::new();
        let mut ctx = DetectionContext::new();
        detector.inspect(&request, &mut ctx)
    }

    #[test]
    fn normalization_folds_defaults() {
        assert_eq!(
            normalize("example.com", None),
            Some(("example.com".to_string(), None))
        );
        assert_eq!(
            normalize("example.com:443", Some("https")),
            Some(("example.com".to_string(), None))
        );
        assert_eq!(
            normalize("example.com:80", Some("http")),
            Some(("example.com".to_string(), None))
        );
        assert_eq!(
            normalize("example.com:8443", Some("https")),
            Some(("example.com".to_string(), Some(8443)))
        );
        assert_eq!(
            normalize("user:pass@example.com:8080", None),
            Some(("example.com".to_string(), Some(8080)))
        );
        assert_eq!(normalize("", None), None);
    }

    #[test]
    fn same_origin_handshakes_stay_clean() {
        for origin in [
            "https://example.com",
            "https://example.com:443",
            "http://example.com:80",
            "https://EXAMPLE.com",
            "https://example.com/chat",
        ] {
            let result = inspect(handshake("example.com", Some(origin)));
            assert!(
                result.findings.is_empty(),
                "{origin} must stay clean: {:?}",
                result.findings
            );
        }
        // No Origin at all: CLI/bot clients, not CSWSH vectors.
        assert!(inspect(handshake("example.com", None)).findings.is_empty());
    }

    #[test]
    fn cross_origin_handshakes_monitor() {
        for origin in [
            "https://evil.example",
            "https://example.com.evil.example",
            "https://example.com:8443",
            "null",
            "http://127.0.0.1",
        ] {
            let result = inspect(handshake("example.com", Some(origin)));
            assert_eq!(result.findings.len(), 1, "{origin}");
            assert_eq!(result.findings[0].rule_id, "ws.cross_origin");
            assert_eq!(result.findings[0].action_hint, Action::Monitor);
            assert_eq!(result.findings[0].category, AttackCategory::ApiAbuse);
        }
    }

    #[test]
    fn non_websocket_requests_are_untouched() {
        let request = Canonicalizer::default().canonicalize(
            RequestParts::new("GET", "example.com", "/")
                .with_header("Origin", "https://evil.example"),
        );
        let mut ctx = DetectionContext::new();
        assert!(WebSocketDetector::new()
            .inspect(&request, &mut ctx)
            .findings
            .is_empty());
    }

    #[test]
    fn handshake_with_a_body_monitors() {
        let parts = handshake("example.com", Some("https://example.com"))
            .with_header("Content-Length", "12")
            .with_body(b"hello=world!".to_vec());
        let result = inspect(parts);
        assert_eq!(result.findings.len(), 1);
        assert_eq!(result.findings[0].rule_id, "ws.handshake_with_body");
        assert_eq!(result.findings[0].action_hint, Action::Monitor);

        let parts = handshake("example.com", Some("https://example.com"))
            .with_header("Transfer-Encoding", "chunked");
        assert_eq!(
            inspect(parts).findings[0].rule_id,
            "ws.handshake_with_body"
        );
    }
}
