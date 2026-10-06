//! Lane 1 protocol sanity checks (Phase 4).
//!
//! Content signatures are not enough: request smuggling, header injection and
//! malformed framing are protocol-level attacks (mandate §27). This detector
//! inspects what still reaches the plugin after the HTTP parser and reports
//! structured findings; it is defense in depth, not a replacement for the
//! parser's own rejection.
//!
//! Checks:
//! - multiple `Content-Length` headers: identical duplicates are a weak
//!   signal, conflicting values are smuggling material;
//! - `Content-Length` + `Transfer-Encoding` together: smuggling material;
//! - `Transfer-Encoding` with unsupported/unknown encodings: rejected per
//!   RFC 9112 (a server that cannot parse the framing must refuse);
//! - duplicate `Transfer-Encoding` headers: weak signal;
//! - non-numeric or absurdly large `Content-Length`: protocol violation;
//! - CR/LF or NUL bytes in header values (injection material);
//! - NUL bytes in the canonical path or query values;
//! - invalid token bytes in header names / method;
//! - header count above a sane ceiling.

use super::super::{
    Action, AttackCategory, Confidence, Detector, DetectorId, DetectorResult,
    EvidenceSource, Finding, Severity,
};

use crate::canonical::CanonicalRequest;

/// Default header-count ceiling.
pub const DEFAULT_MAX_HEADERS: usize = 100;

/// Reasonable maximum for a numeric `Content-Length`.
const MAX_CONTENT_LENGTH: u64 = 1 << 42;

/// Protocol/ smuggling checks over the canonical request.
#[derive(Debug, Clone, Copy)]
pub struct ProtocolDetector {
    max_headers: usize,
}

impl ProtocolDetector {
    pub const fn new() -> Self {
        Self {
            max_headers: DEFAULT_MAX_HEADERS,
        }
    }

    pub const fn with_max_headers(max_headers: usize) -> Self {
        Self { max_headers }
    }
}

impl Default for ProtocolDetector {
    fn default() -> Self {
        Self::new()
    }
}

/// RFC 9110 token byte (used for header names and methods).
fn is_token_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric()
        || matches!(
            byte,
            b'!' | b'#'
                | b'$'
                | b'%'
                | b'&'
                | b'\''
                | b'*'
                | b'+'
                | b'-'
                | b'.'
                | b'^'
                | b'_'
                | b'`'
                | b'|'
                | b'~'
        )
}

fn push_once(findings: &mut Vec<Finding>, finding: Finding) {
    if !findings.iter().any(|f| f.rule_id == finding.rule_id) {
        findings.push(finding);
    }
}

impl Detector for ProtocolDetector {
    fn id(&self) -> DetectorId {
        DetectorId("fast.protocol")
    }

    fn inspect(
        &self,
        request: &CanonicalRequest,
        _ctx: &mut super::super::DetectionContext,
    ) -> DetectorResult {
        let mut findings: Vec<Finding> = Vec::new();

        let content_lengths: Vec<&str> =
            request.headers_all("content-length").collect();
        let transfer_encodings: Vec<&str> =
            request.headers_all("transfer-encoding").collect();

        // ── Content-Length handling ─────────────────────────────────────
        if content_lengths.len() > 1 {
            let first = content_lengths[0].trim();
            let conflicting =
                content_lengths.iter().any(|value| value.trim() != first);
            if conflicting {
                push_once(
                    &mut findings,
                    Finding::new(
                        self.id(),
                        "proto.cl_duplicate_conflict",
                        AttackCategory::HttpSmuggling,
                    )
                    .confidence(Confidence::High)
                    .severity(Severity::High)
                    .score(30)
                    .action(Action::Block)
                    .source(EvidenceSource::Header)
                    .field("content-length")
                    .detail("conflicting duplicate Content-Length headers"),
                );
            } else {
                push_once(
                    &mut findings,
                    Finding::new(
                        self.id(),
                        "proto.cl_duplicate",
                        AttackCategory::ProtocolViolation,
                    )
                    .confidence(Confidence::High)
                    .severity(Severity::Low)
                    .score(5)
                    .action(Action::Log)
                    .source(EvidenceSource::Header)
                    .field("content-length")
                    .detail("duplicate identical Content-Length headers"),
                );
            }
        }
        if let Some(raw) = content_lengths.first() {
            let parsed = raw.trim().parse::<u64>();
            match parsed {
                Ok(value) if value <= MAX_CONTENT_LENGTH => {},
                _ => {
                    push_once(
                        &mut findings,
                        Finding::new(
                            self.id(),
                            "proto.cl_invalid",
                            AttackCategory::ProtocolViolation,
                        )
                        .confidence(Confidence::High)
                        .severity(Severity::Medium)
                        .score(15)
                        .action(Action::Monitor)
                        .source(EvidenceSource::Header)
                        .field("content-length")
                        .detail(format!(
                            "invalid Content-Length value {raw:?}"
                        )),
                    );
                },
            }
        }

        // ── Transfer-Encoding handling ──────────────────────────────────
        if !transfer_encodings.is_empty() {
            if !content_lengths.is_empty() {
                push_once(
                    &mut findings,
                    Finding::new(
                        self.id(),
                        "proto.cl_te_conflict",
                        AttackCategory::HttpSmuggling,
                    )
                    .confidence(Confidence::High)
                    .severity(Severity::High)
                    .score(30)
                    .action(Action::Block)
                    .source(EvidenceSource::Header)
                    .field("transfer-encoding")
                    .detail(
                        "Content-Length and Transfer-Encoding present together",
                    ),
                );
            }
            if transfer_encodings.len() > 1 {
                push_once(
                    &mut findings,
                    Finding::new(
                        self.id(),
                        "proto.te_multiple",
                        AttackCategory::ProtocolViolation,
                    )
                    .confidence(Confidence::High)
                    .severity(Severity::Low)
                    .score(5)
                    .action(Action::Log)
                    .source(EvidenceSource::Header)
                    .field("transfer-encoding")
                    .detail("multiple Transfer-Encoding headers"),
                );
            }
            let unsupported: Vec<&str> = transfer_encodings
                .iter()
                .flat_map(|value| value.split(','))
                .map(str::trim)
                .filter(|token| {
                    !token.is_empty() && !token.eq_ignore_ascii_case("chunked")
                })
                .collect();
            if !unsupported.is_empty() {
                push_once(
                    &mut findings,
                    Finding::new(
                        self.id(),
                        "proto.te_unsupported",
                        AttackCategory::HttpSmuggling,
                    )
                    .confidence(Confidence::High)
                    .severity(Severity::High)
                    .score(30)
                    .action(Action::Block)
                    .source(EvidenceSource::Header)
                    .field("transfer-encoding")
                    .detail(format!(
                        "unsupported Transfer-Encoding {unsupported:?}"
                    )),
                );
            }
        }

        // ── Header sanity ───────────────────────────────────────────────
        if request.headers().len() > self.max_headers {
            push_once(
                &mut findings,
                Finding::new(
                    self.id(),
                    "proto.header_count",
                    AttackCategory::ProtocolViolation,
                )
                .confidence(Confidence::High)
                .severity(Severity::Low)
                .score(5)
                .action(Action::Log)
                .source(EvidenceSource::Metadata)
                .detail(format!(
                    "{} headers exceeds the {} ceiling",
                    request.headers().len(),
                    self.max_headers
                )),
            );
        }
        for (name, value) in request.headers() {
            if name.is_empty() || !name.bytes().all(is_token_byte) {
                push_once(
                    &mut findings,
                    Finding::new(
                        self.id(),
                        "proto.header_name",
                        AttackCategory::ProtocolViolation,
                    )
                    .confidence(Confidence::High)
                    .severity(Severity::Medium)
                    .score(15)
                    .action(Action::Monitor)
                    .source(EvidenceSource::Header)
                    .detail(format!("invalid header name {name:?}")),
                );
            }
            if value.bytes().any(|b| b == b'\r' || b == b'\n') {
                push_once(
                    &mut findings,
                    Finding::new(
                        self.id(),
                        "proto.header_value_ctrl",
                        AttackCategory::CrlfInjection,
                    )
                    .confidence(Confidence::High)
                    .severity(Severity::High)
                    .score(30)
                    .action(Action::Block)
                    .source(EvidenceSource::Header)
                    .field(name.to_string())
                    .detail("CR/LF in a header value (injection material)"),
                );
            }
            if value.bytes().any(|b| b == 0) {
                push_once(
                    &mut findings,
                    Finding::new(
                        self.id(),
                        "proto.header_value_nul",
                        AttackCategory::ProtocolViolation,
                    )
                    .confidence(Confidence::High)
                    .severity(Severity::Medium)
                    .score(15)
                    .action(Action::Monitor)
                    .source(EvidenceSource::Header)
                    .field(name.to_string())
                    .detail("NUL byte in a header value"),
                );
            }
        }

        // ── Target and method sanity ────────────────────────────────────
        if request.path().contains('\0')
            || request.query().iter().any(|param| {
                param.name.contains('\0') || param.value.contains('\0')
            })
        {
            push_once(
                &mut findings,
                Finding::new(
                    self.id(),
                    "proto.target_nul",
                    AttackCategory::ProtocolViolation,
                )
                .confidence(Confidence::High)
                .severity(Severity::Medium)
                .score(15)
                .action(Action::Monitor)
                .source(EvidenceSource::Path)
                .detail("NUL byte in the request target"),
            );
        }
        let method = request.method();
        if method.is_empty() || !method.bytes().all(is_token_byte) {
            push_once(
                &mut findings,
                Finding::new(
                    self.id(),
                    "proto.method_token",
                    AttackCategory::ProtocolViolation,
                )
                .confidence(Confidence::High)
                .severity(Severity::Low)
                .score(5)
                .action(Action::Log)
                .source(EvidenceSource::Method)
                .detail(format!("invalid request method {method:?}")),
            );
        }

        DetectorResult::with_findings(findings)
    }
}

#[cfg(test)]
mod tests {
    use super::ProtocolDetector;
    use crate::canonical::{Canonicalizer, RequestParts};
    use crate::pipeline::{Action, AttackCategory, DetectionContext, Detector};

    fn inspect(parts: RequestParts) -> crate::pipeline::DetectorResult {
        let request = Canonicalizer::default().canonicalize(parts);
        let detector = ProtocolDetector::new();
        let mut ctx = DetectionContext::new();
        detector.inspect(&request, &mut ctx)
    }

    fn plain() -> RequestParts {
        RequestParts::new("GET", "example.com", "/")
    }

    fn has(result: &crate::pipeline::DetectorResult, rule: &str) -> bool {
        result.findings.iter().any(|f| f.rule_id == rule)
    }

    #[test]
    fn clean_request_has_no_findings() {
        let result = inspect(plain().with_header("host", "example.com"));
        assert!(result.findings.is_empty(), "{:?}", result.findings);
    }

    #[test]
    fn conflicting_content_lengths_block_as_smuggling() {
        let result = inspect(
            plain()
                .with_header("content-length", "13")
                .with_header("content-length", "6"),
        );
        assert!(has(&result, "proto.cl_duplicate_conflict"));
        let finding = result
            .findings
            .iter()
            .find(|f| f.rule_id == "proto.cl_duplicate_conflict")
            .expect("finding present");
        assert_eq!(finding.action_hint, Action::Block);
        assert_eq!(finding.category, AttackCategory::HttpSmuggling);
    }

    #[test]
    fn identical_content_length_duplicates_are_weak() {
        let result = inspect(
            plain()
                .with_header("content-length", "13")
                .with_header("content-length", "13"),
        );
        assert!(has(&result, "proto.cl_duplicate"));
        assert!(!has(&result, "proto.cl_duplicate_conflict"));
    }

    #[test]
    fn content_length_with_transfer_encoding_blocks() {
        let result = inspect(
            plain()
                .with_header("content-length", "6")
                .with_header("transfer-encoding", "chunked"),
        );
        assert!(has(&result, "proto.cl_te_conflict"));
    }

    #[test]
    fn unsupported_transfer_encoding_blocks() {
        let result = inspect(plain().with_header("transfer-encoding", "gzip"));
        assert!(has(&result, "proto.te_unsupported"));
    }

    #[test]
    fn plain_chunked_transfer_encoding_is_fine() {
        let result =
            inspect(plain().with_header("transfer-encoding", "chunked"));
        assert!(result.findings.is_empty(), "{:?}", result.findings);
    }

    #[test]
    fn invalid_content_length_monitors() {
        let result = inspect(plain().with_header("content-length", "banana"));
        assert!(has(&result, "proto.cl_invalid"));
        let finding = result
            .findings
            .iter()
            .find(|f| f.rule_id == "proto.cl_invalid")
            .expect("finding present");
        assert_eq!(finding.action_hint, Action::Monitor);
    }

    #[test]
    fn crlf_in_header_value_blocks() {
        let result =
            inspect(plain().with_header("x-note", "a\r\nset-cookie: b"));
        assert!(has(&result, "proto.header_value_ctrl"));
        let finding = result
            .findings
            .iter()
            .find(|f| f.rule_id == "proto.header_value_ctrl")
            .expect("finding present");
        assert_eq!(finding.action_hint, Action::Block);
        assert_eq!(finding.category, AttackCategory::CrlfInjection);
    }

    #[test]
    fn nul_in_target_monitors() {
        // %00 is decoded into the canonical path.
        let result = inspect(RequestParts::new("GET", "example.com", "/a%00b"));
        assert_eq!(result.findings.len(), 1, "{:?}", result.findings);
        assert!(has(&result, "proto.target_nul"));
    }

    #[test]
    fn invalid_method_is_weak() {
        let result = inspect(RequestParts::new("GE T", "example.com", "/"));
        assert!(has(&result, "proto.method_token"));
        let finding = result
            .findings
            .iter()
            .find(|f| f.rule_id == "proto.method_token")
            .expect("finding present");
        assert_eq!(finding.action_hint, Action::Log);
    }

    #[test]
    fn too_many_headers_is_weak() {
        let mut parts = plain();
        for i in 0..110 {
            parts = parts.with_header(format!("x-h{i}"), "1");
        }
        let result = inspect(parts);
        assert!(has(&result, "proto.header_count"));
    }
}
