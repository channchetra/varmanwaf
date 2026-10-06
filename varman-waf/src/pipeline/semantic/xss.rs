//! HTML/XSS structural detector (Phase 6).
//!
//! Signatures match literal payloads; browsers do not. This detector applies
//! the inspection transformation the canonical model deliberately excludes —
//! **HTML entity decoding** — and then reasons about structure: dangerous
//! tags, event-handler attributes that call something, `javascript:`/
//! `vbscript:` URIs that actually call something, and iframe/URI
//! combinations.
//!
//! Tiering keeps documentation safe: a bare `<script` snippet or the words
//! "javascript: URL scheme" in prose stay at Log; only a tag/handler/URI that
//! *calls* (or an entity-obfuscated dangerous tag) reaches Monitor/Block.

use super::super::{
    Action, AttackCategory, Confidence, Detector, DetectorId, DetectorResult,
    EvidenceSource, Finding, Severity,
};

use crate::canonical::CanonicalRequest;
use crate::normalize::html::decode_entities;

/// Default maximum value length considered by the structural analysis.
pub const DEFAULT_MAX_VALUE_LEN: usize = 8 * 1024;

/// Tags that can execute or embed content.
const DANGEROUS_TAGS: &[&str] = &[
    "<script", "<iframe", "<object", "<embed", "<svg", "<math", "<base",
    "<form", "<meta",
];

/// Tokens that indicate the dangerous construct is being *called*, not just
/// mentioned.
const CALL_TOKENS: &[&str] = &[
    "alert(",
    "prompt(",
    "confirm(",
    "eval(",
    "document.",
    "window.",
    "fetch(",
    "xmlhttprequest",
    "expression(",
];

/// Structural HTML/XSS detector.
#[derive(Debug, Clone, Copy)]
pub struct HtmlXssDetector {
    max_value_len: usize,
}

impl HtmlXssDetector {
    pub const fn new() -> Self {
        Self {
            max_value_len: DEFAULT_MAX_VALUE_LEN,
        }
    }

    pub const fn with_max_value_len(max_value_len: usize) -> Self {
        Self { max_value_len }
    }
}

impl Default for HtmlXssDetector {
    fn default() -> Self {
        Self::new()
    }
}

fn first_dangerous_tag(low: &str) -> Option<&'static str> {
    DANGEROUS_TAGS.iter().copied().find(|tag| low.contains(tag))
}

fn contains_call(window: &str) -> bool {
    CALL_TOKENS.iter().any(|token| window.contains(token))
}

/// `on…=` attribute within `window` distance of a call token.
fn handler_call(low: &str) -> bool {
    let bytes = low.as_bytes();
    let mut i = 0;
    while i + 2 < bytes.len() {
        // Look for "on" followed by word chars and '='.
        if bytes[i] == b'o' && bytes[i + 1] == b'n' {
            let mut j = i + 2;
            while j < bytes.len()
                && (bytes[j].is_ascii_alphanumeric() || bytes[j] == b'_')
            {
                j += 1;
            }
            if j < bytes.len() && bytes[j] == b'=' && j > i + 2 {
                let window_end = low.len().min(j + 40);
                if contains_call(&low[j..window_end]) {
                    return true;
                }
            }
            i = j;
        } else {
            i += 1;
        }
    }
    false
}

/// `javascript:` / `vbscript:` followed by a call token.
fn js_uri_call(low: &str) -> bool {
    for scheme in ["javascript:", "vbscript:"] {
        let mut start = 0;
        while let Some(pos) = low[start..].find(scheme) {
            let after = start + pos + scheme.len();
            let window_end = low.len().min(after + 40);
            if contains_call(&low[after..window_end]) {
                return true;
            }
            start = after;
        }
    }
    false
}

struct Evidence {
    rule: &'static str,
    severity: Severity,
    action: Action,
    score: u32,
    detail: String,
}

fn analyze(value: &str) -> Option<Evidence> {
    let decoded = decode_entities(value);
    let had_entities = decoded != value;
    let low = decoded.to_ascii_lowercase();
    let tag = first_dangerous_tag(&low);

    if had_entities {
        if let Some(tag) = tag {
            return Some(Evidence {
                rule: "sem.xss.entity_encoded_tag",
                severity: Severity::High,
                action: Action::Block,
                score: 30,
                detail: format!("entity-encoded dangerous tag {tag:?}"),
            });
        }
    }
    if low.contains("<iframe")
        && (low.contains("javascript:") || low.contains("data:text/html"))
    {
        return Some(Evidence {
            rule: "sem.xss.iframe_script",
            severity: Severity::High,
            action: Action::Block,
            score: 30,
            detail: "iframe with script URI".to_string(),
        });
    }
    if handler_call(&low) {
        return Some(Evidence {
            rule: "sem.xss.event_handler_call",
            severity: Severity::High,
            action: Action::Block,
            score: 30,
            detail: "event handler attribute calling a function".to_string(),
        });
    }
    if js_uri_call(&low) {
        return Some(Evidence {
            rule: "sem.xss.javascript_uri_call",
            severity: Severity::High,
            action: Action::Block,
            score: 30,
            detail: "javascript:/vbscript: URI calling a function".to_string(),
        });
    }
    if let Some(tag) = tag {
        // A dangerous tag followed by a call token inside the same value
        // (e.g. `<script>alert(1)`).
        let call_after = low
            .find(tag)
            .map(|pos| contains_call(&low[pos..low.len().min(pos + 64)]))
            .unwrap_or(false);
        if call_after {
            return Some(Evidence {
                rule: "sem.xss.tag_call",
                severity: Severity::High,
                action: Action::Block,
                score: 30,
                detail: format!("dangerous tag {tag:?} followed by a call"),
            });
        }
        return Some(Evidence {
            rule: "sem.xss.dangerous_tag",
            severity: Severity::Low,
            action: Action::Log,
            score: 5,
            detail: format!("dangerous tag {tag:?} without a call"),
        });
    }
    if low.contains("javascript:") || low.contains("vbscript:") {
        return Some(Evidence {
            rule: "sem.xss.js_uri",
            severity: Severity::Low,
            action: Action::Log,
            score: 5,
            detail: "script URI without a call".to_string(),
        });
    }
    None
}

impl Detector for HtmlXssDetector {
    fn id(&self) -> DetectorId {
        DetectorId("semantic.xss.html")
    }

    fn inspect(
        &self,
        request: &CanonicalRequest,
        ctx: &mut super::super::DetectionContext,
    ) -> DetectorResult {
        let mut findings: Vec<Finding> = Vec::new();
        let mut degraded = None;

        let scan = |value: &str,
                    source: EvidenceSource,
                    field: Option<&str>,
                    findings: &mut Vec<Finding>,
                    degraded: &mut Option<&'static str>| {
            if value.len() > self.max_value_len {
                if degraded.is_none() {
                    *degraded = Some("value exceeds semantic budget");
                }
                return;
            }
            let Some(evidence) = analyze(value) else {
                return;
            };
            let mut finding = Finding::new(
                DetectorId("semantic.xss.html"),
                evidence.rule,
                AttackCategory::Xss,
            )
            .confidence(match evidence.action {
                Action::Block => Confidence::High,
                Action::Monitor => Confidence::Medium,
                _ => Confidence::Low,
            })
            .severity(evidence.severity)
            .score(evidence.score)
            .action(evidence.action)
            .source(source)
            .detail(evidence.detail);
            if let Some(field) = field {
                finding = finding.field(field.to_string());
            }
            findings.push(finding);
        };

        for param in request.query() {
            scan(
                &param.value,
                EvidenceSource::Query,
                Some(&param.name),
                &mut findings,
                &mut degraded,
            );
        }
        for (name, value) in request.cookies() {
            scan(
                value,
                EvidenceSource::Cookie,
                Some(name),
                &mut findings,
                &mut degraded,
            );
        }
        if let Some(body) = request.body() {
            let limit = ctx.budget().max_body_bytes.min(body.len());
            match std::str::from_utf8(&body[..limit]) {
                Ok(text) => {
                    scan(
                        text,
                        EvidenceSource::Body,
                        None,
                        &mut findings,
                        &mut degraded,
                    );
                    if body.len() > limit && degraded.is_none() {
                        degraded = Some("body scan truncated at budget");
                    }
                },
                Err(_) => {
                    if degraded.is_none() {
                        degraded = Some("body is not valid utf-8");
                    }
                },
            }
        }

        DetectorResult { findings, degraded }
    }
}

#[cfg(test)]
mod tests {
    use super::HtmlXssDetector;
    use crate::canonical::{Canonicalizer, RequestParts};
    use crate::pipeline::{Action, AttackCategory, DetectionContext, Detector};

    fn query(value: &str) -> crate::pipeline::DetectorResult {
        // A client must percent-encode `&` inside a query value; do the same
        // so `&lt;` arrives as `&lt;` rather than splitting the query.
        let encoded = value.replace('%', "%25").replace('&', "%26");
        let target = format!("/?q={encoded}");
        let request = Canonicalizer::default().canonicalize(RequestParts::new(
            "GET",
            "example.com",
            target,
        ));
        let detector = HtmlXssDetector::new();
        let mut ctx = DetectionContext::new();
        detector.inspect(&request, &mut ctx)
    }

    fn tier(value: &str) -> Option<(String, Action)> {
        let result = query(value);
        result
            .findings
            .first()
            .map(|f| (f.rule_id.to_string(), f.action_hint))
    }

    #[test]
    fn entity_encoded_tags_block() {
        let (rule, action) =
            tier("&lt;script&gt;alert(1)&lt;/script&gt;").expect("finding");
        assert_eq!(rule, "sem.xss.entity_encoded_tag");
        assert_eq!(action, Action::Block);
    }

    #[test]
    fn script_tag_with_call_blocks() {
        let (rule, action) =
            tier("<script>alert(1)</script>").expect("finding");
        assert_eq!(rule, "sem.xss.tag_call");
        assert_eq!(action, Action::Block);
    }

    #[test]
    fn event_handler_call_blocks() {
        let (rule, action) =
            tier("<img src=x onerror=alert(1)>").expect("finding");
        assert_eq!(rule, "sem.xss.event_handler_call");
        assert_eq!(action, Action::Block);
    }

    #[test]
    fn iframe_script_uri_blocks() {
        let (rule, action) =
            tier("<iframe src=\"javascript:alert(1)\">").expect("finding");
        assert_eq!(rule, "sem.xss.iframe_script");
        assert_eq!(action, Action::Block);
    }

    #[test]
    fn javascript_uri_with_call_blocks() {
        let (rule, action) = tier("javascript:document.location='http://evil'")
            .expect("finding");
        assert_eq!(rule, "sem.xss.javascript_uri_call");
        assert_eq!(action, Action::Block);
    }

    #[test]
    fn documentation_stays_weak() {
        let cases = [
            "The javascript: URL scheme is legacy; prefer https: links.",
            "<script src=\"/assets/app.js\" defer></script>",
            "<div class=\"card\">Hello world</div>",
            "Use element.addEventListener('click', handler) for events.",
        ];
        for case in cases {
            if let Some((_, action)) = tier(case) {
                assert!(action < Action::Monitor, "{case:?} reached {action}");
            }
        }
    }

    #[test]
    fn category_is_xss() {
        let result = query("<script>alert(1)</script>");
        assert_eq!(result.findings[0].category, AttackCategory::Xss);
    }

    #[test]
    fn oversized_values_degrade() {
        let detector = HtmlXssDetector::with_max_value_len(16);
        let target = format!("/?q={}", "<script>".repeat(6));
        let request = Canonicalizer::default().canonicalize(RequestParts::new(
            "GET",
            "example.com",
            target,
        ));
        let mut ctx = DetectionContext::new();
        let result = detector.inspect(&request, &mut ctx);
        assert!(result.findings.is_empty());
        assert_eq!(result.degraded, Some("value exceeds semantic budget"));
    }
}
