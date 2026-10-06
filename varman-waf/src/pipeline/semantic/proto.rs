//! Prototype pollution structural detector (Phase 6).
//!
//! Prototype pollution needs a *mutating shape*: `__proto__` as a key
//! (`"__proto__":`), a bracket path (`user[__proto__][isAdmin]=true`), a
//! dotted path (`__proto__.isAdmin`), or `constructor[prototype]`. Bare
//! mentions of `__proto__`/`constructor.prototype` occur in framework
//! documentation and stay weak:
//!
//! | Evidence | Tier |
//! | --- | --- |
//! | `"__proto__":`, `__proto__[`, `[__proto__]`, `__proto__.`, `__proto__=` | Block |
//! | `constructor[prototype]`, `constructor.prototype[` | Block |
//! | bare `__proto__` / `constructor.prototype` (documentation prose) | Log |

use super::super::{
    Action, AttackCategory, Confidence, Detector, DetectorId, DetectorResult,
    EvidenceSource, Finding, Severity,
};

use crate::canonical::CanonicalRequest;

/// Default maximum value length considered by the structural analysis.
pub const DEFAULT_MAX_VALUE_LEN: usize = 8 * 1024;

/// Mutating shapes that indicate an actual pollution attempt.
const BLOCK_SHAPES: &[&str] = &[
    "\"__proto__\":",
    "__proto__\":",
    "__proto__[",
    "[__proto__]",
    "__proto__.",
    "__proto__=",
    "constructor[prototype]",
    "constructor.prototype[",
];

struct Evidence {
    rule: &'static str,
    severity: Severity,
    action: Action,
    score: u32,
    detail: String,
}

fn analyze(value: &str) -> Option<Evidence> {
    let low = value.to_ascii_lowercase();

    if let Some(shape) = BLOCK_SHAPES.iter().find(|shape| low.contains(*shape))
    {
        return Some(Evidence {
            rule: "sem.proto.pollution_shape",
            severity: Severity::High,
            action: Action::Block,
            score: 30,
            detail: format!("prototype mutation shape {shape:?}"),
        });
    }
    if low.contains("constructor.prototype") || low.contains("__proto__") {
        return Some(Evidence {
            rule: "sem.proto.mention",
            severity: Severity::Low,
            action: Action::Log,
            score: 5,
            detail: "prototype name mentioned without a mutation shape"
                .to_string(),
        });
    }
    None
}

/// Prototype pollution structural detector.
#[derive(Debug, Clone, Copy)]
pub struct PrototypePollutionDetector {
    max_value_len: usize,
}

impl PrototypePollutionDetector {
    pub const fn new() -> Self {
        Self {
            max_value_len: DEFAULT_MAX_VALUE_LEN,
        }
    }

    pub const fn with_max_value_len(max_value_len: usize) -> Self {
        Self { max_value_len }
    }
}

impl Default for PrototypePollutionDetector {
    fn default() -> Self {
        Self::new()
    }
}

impl Detector for PrototypePollutionDetector {
    fn id(&self) -> DetectorId {
        DetectorId("semantic.proto.structural")
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
                DetectorId("semantic.proto.structural"),
                evidence.rule,
                AttackCategory::PrototypePollution,
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
                &param.name,
                EvidenceSource::Query,
                Some(&param.name),
                &mut findings,
                &mut degraded,
            );
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
    use super::PrototypePollutionDetector;
    use crate::canonical::{Canonicalizer, RequestParts};
    use crate::pipeline::{Action, AttackCategory, DetectionContext, Detector};

    fn query(value: &str) -> crate::pipeline::DetectorResult {
        let encoded = value
            .replace('%', "%25")
            .replace('&', "%26")
            .replace('#', "%23")
            .replace('=', "%3D");
        let target = format!("/?q={encoded}");
        let request = Canonicalizer::default().canonicalize(RequestParts::new(
            "GET",
            "example.com",
            target,
        ));
        let detector = PrototypePollutionDetector::new();
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
    fn json_key_shape_blocks() {
        let (rule, action) =
            tier("{\"__proto__\":{\"polluted\":true}}").expect("finding");
        assert_eq!(rule, "sem.proto.pollution_shape");
        assert_eq!(action, Action::Block);
    }

    #[test]
    fn bracket_path_blocks_even_in_parameter_name() {
        let request = Canonicalizer::default().canonicalize(RequestParts::new(
            "GET",
            "example.com",
            "/?user[__proto__][isAdmin]=true",
        ));
        let detector = PrototypePollutionDetector::new();
        let mut ctx = DetectionContext::new();
        let result = detector.inspect(&request, &mut ctx);
        assert!(result
            .findings
            .iter()
            .any(|f| f.rule_id == "sem.proto.pollution_shape"
                && f.action_hint == Action::Block));
    }

    #[test]
    fn constructor_bracket_shape_blocks() {
        let (_, action) =
            tier("constructor[prototype][polluted]=1").expect("finding");
        assert_eq!(action, Action::Block);
    }

    #[test]
    fn documentation_stays_weak() {
        let cases = [
            "The __proto__ accessor is deprecated; use Object.getPrototypeOf.",
            "constructor.prototype points at the class prototype object.",
        ];
        for case in cases {
            if let Some((_, action)) = tier(case) {
                assert!(action < Action::Monitor, "{case:?} reached {action}");
            }
        }
    }

    #[test]
    fn category_is_prototype_pollution() {
        let result = query("{\"__proto__\":{\"x\":1}}");
        assert_eq!(
            result.findings[0].category,
            AttackCategory::PrototypePollution
        );
    }

    #[test]
    fn oversized_values_degrade() {
        let detector = PrototypePollutionDetector::with_max_value_len(16);
        let target = format!("/?q={}", "__proto__[x]=1".repeat(4));
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
