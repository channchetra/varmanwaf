//! Deserialization structural detector (Phase 6).
//!
//! Java serialized markers (`rO0AB`, `aced0005`) and gadget class names are
//! owned by the signature table. This detector adds the *other* formats:
//!
//! | Evidence | Tier |
//! | --- | --- |
//! | PHP serialized object/array shape (`O:8:"…"`, `a:2:{…`) | Block |
//! | .NET ViewState/LosFormatter base64 prefix (`AAEAAAD…`) | Block |
//! | PHP magic-method mentions (`__wakeup`, `__destruct`) | Log |
//!
//! PHP magic-method names appear in framework documentation, so they never
//! block on their own.

use super::super::{
    Action, AttackCategory, Confidence, Detector, DetectorId, DetectorResult,
    EvidenceSource, Finding, Severity,
};

use crate::canonical::CanonicalRequest;

/// Default maximum value length considered by the structural analysis.
pub const DEFAULT_MAX_VALUE_LEN: usize = 8 * 1024;

/// PHP serialized shapes: `o:<len>:"…` or `a:<len>:{…`.
fn has_php_serialized(low: &str) -> bool {
    for marker in ["o:", "a:"] {
        let mut start = 0;
        while let Some(pos) = low[start..].find(marker) {
            let after = start + pos + marker.len();
            let digits: String = low[after..]
                .chars()
                .take_while(|c| c.is_ascii_digit())
                .collect();
            if !digits.is_empty() && digits.len() <= 6 {
                let rest = &low[after + digits.len()..];
                let shaped = if marker == "o:" {
                    rest.starts_with(":\"")
                } else {
                    rest.starts_with(":{")
                };
                if shaped {
                    return true;
                }
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
    let low = value.to_ascii_lowercase();

    if has_php_serialized(&low) {
        return Some(Evidence {
            rule: "sem.deser.php_serialized",
            severity: Severity::High,
            action: Action::Block,
            score: 30,
            detail: "PHP serialized object/array shape".to_string(),
        });
    }
    if low.contains("aaeaaad") {
        return Some(Evidence {
            rule: "sem.deser.dotnet_payload",
            severity: Severity::High,
            action: Action::Block,
            score: 30,
            detail: ".NET serialized payload prefix (ViewState/LosFormatter)"
                .to_string(),
        });
    }
    if low.contains("__wakeup") || low.contains("__destruct") {
        return Some(Evidence {
            rule: "sem.deser.magic_method",
            severity: Severity::Low,
            action: Action::Log,
            score: 5,
            detail: "PHP magic-method name in a user-controlled value"
                .to_string(),
        });
    }
    None
}

/// Deserialization structural detector.
#[derive(Debug, Clone, Copy)]
pub struct DeserializationDetector {
    max_value_len: usize,
}

impl DeserializationDetector {
    pub const fn new() -> Self {
        Self {
            max_value_len: DEFAULT_MAX_VALUE_LEN,
        }
    }

    pub const fn with_max_value_len(max_value_len: usize) -> Self {
        Self { max_value_len }
    }
}

impl Default for DeserializationDetector {
    fn default() -> Self {
        Self::new()
    }
}

impl Detector for DeserializationDetector {
    fn id(&self) -> DetectorId {
        DetectorId("semantic.deser.structural")
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
                DetectorId("semantic.deser.structural"),
                evidence.rule,
                AttackCategory::Deserialization,
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
    use super::DeserializationDetector;
    use crate::canonical::{Canonicalizer, RequestParts};
    use crate::pipeline::{Action, AttackCategory, DetectionContext, Detector};

    fn query(value: &str) -> crate::pipeline::DetectorResult {
        let encoded = value
            .replace('%', "%25")
            .replace('&', "%26")
            .replace('#', "%23");
        let target = format!("/?q={encoded}");
        let request = Canonicalizer::default().canonicalize(RequestParts::new(
            "GET",
            "example.com",
            target,
        ));
        let detector = DeserializationDetector::new();
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
    fn php_shapes_block() {
        for payload in [
            "O:8:\"stdClass\":1:{s:4:\"test\";s:4:\"evil\";}",
            "a:2:{i:0;s:3:\"foo\";i:1;s:3:\"bar\";}",
        ] {
            let (rule, action) = tier(payload).expect(payload);
            assert_eq!(rule, "sem.deser.php_serialized", "{payload}");
            assert_eq!(action, Action::Block, "{payload}");
        }
    }

    #[test]
    fn dotnet_prefix_blocks() {
        let (rule, action) =
            tier("AAEAAAD/////AQAAAAAAAAAMAgAAAE5TeXN0ZW0u").expect("finding");
        assert_eq!(rule, "sem.deser.dotnet_payload");
        assert_eq!(action, Action::Block);
    }

    #[test]
    fn magic_methods_stay_weak() {
        let (rule, action) =
            tier("class Foo { public function __wakeup() {} }")
                .expect("finding");
        assert_eq!(rule, "sem.deser.magic_method");
        assert!(action < Action::Monitor);
    }

    #[test]
    fn ordinary_text_and_json_pass() {
        for value in [
            "hello world",
            "{\"name\":\"Ada\",\"age\":36}",
            "o: not a serialized object",
            "a: list of options",
        ] {
            assert!(tier(value).is_none(), "{value}");
        }
    }

    #[test]
    fn category_is_deserialization() {
        let result = query("O:8:\"stdClass\":1:{s:4:\"test\";s:4:\"evil\";}");
        assert_eq!(
            result.findings[0].category,
            AttackCategory::Deserialization
        );
    }

    #[test]
    fn oversized_values_degrade() {
        let detector = DeserializationDetector::with_max_value_len(16);
        let target = format!("/?q={}", "O:8:\"a\":1:{}".repeat(4));
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
