//! NoSQL injection structural detector (Phase 6).
//!
//! NoSQL injection is operator-driven: MongoDB query operators in attacker
//! reach (`$where`, `$ne`, `$gt`, …), server-side JavaScript (`$where` with
//! `this`/`function`/`return`, `$func`/`$accumulator`), and PHP-style array
//! parameter injection (`user[$ne]=1`). Legitimate APIs also send operators
//! (`{"price":{"$gt":10}}`), so tiering is explicit:
//!
//! | Evidence | Tier |
//! | --- | --- |
//! | `$where`/`$func` with JavaScript content | Block |
//! | bracket operator in a parameter *name* (`user[$ne]`) | Monitor |
//! | driver syntax (`db.users.find(`) | Monitor |
//! | bare operator mention (legit API payloads, docs) | Log |

use super::super::{
    Action, AttackCategory, Confidence, Detector, DetectorId, DetectorResult,
    EvidenceSource, Finding, Severity,
};

use crate::canonical::CanonicalRequest;

/// Default maximum value length considered by the structural analysis.
pub const DEFAULT_MAX_VALUE_LEN: usize = 8 * 1024;

/// Query operators that mean nothing alone but matter in combination.
const OPERATORS: &[&str] = &[
    "$where", "$ne", "$gt", "$gte", "$lt", "$lte", "$regex", "$exists", "$in",
    "$nin", "$or", "$and", "$nor", "$expr",
];

/// Operator names that execute server-side JavaScript.
const SERVER_JS: &[&str] = &["$func", "$accumulator", "$function"];

/// JavaScript shapes inside `$where`.
const JS_IN_WHERE: &[&str] = &[
    "this.",
    "function(",
    "function (",
    "return ",
    "while(",
    "sleep(",
    "';",
    "';",
];

fn has_bracket_operator(name: &str) -> bool {
    name.contains("[$") && name.contains(']')
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

    if SERVER_JS.iter().any(|op| low.contains(op)) {
        return Some(Evidence {
            rule: "sem.nosql.server_side_js",
            severity: Severity::Critical,
            action: Action::Block,
            score: 40,
            detail: "server-side JavaScript operator".to_string(),
        });
    }
    if low.contains("$where") {
        if JS_IN_WHERE.iter().any(|shape| low.contains(shape)) {
            return Some(Evidence {
                rule: "sem.nosql.where_injection",
                severity: Severity::High,
                action: Action::Block,
                score: 30,
                detail: "$where with JavaScript content".to_string(),
            });
        }
        return Some(Evidence {
            rule: "sem.nosql.where_operator",
            severity: Severity::Medium,
            action: Action::Monitor,
            score: 15,
            detail: "unexpected $where operator".to_string(),
        });
    }
    if low.contains("db.")
        && (low.contains(".find(")
            || low.contains(".findone(")
            || low.contains(".aggregate(")
            || low.contains(".update("))
    {
        return Some(Evidence {
            rule: "sem.nosql.driver_syntax",
            severity: Severity::Medium,
            action: Action::Monitor,
            score: 15,
            detail: "database driver syntax in a value".to_string(),
        });
    }
    if OPERATORS.iter().any(|op| low.contains(op)) {
        return Some(Evidence {
            rule: "sem.nosql.operator_mention",
            severity: Severity::Low,
            action: Action::Log,
            score: 5,
            detail: "NoSQL operator mentioned in the value".to_string(),
        });
    }
    None
}

/// NoSQL injection structural detector.
#[derive(Debug, Clone, Copy)]
pub struct NosqlInjectionDetector {
    max_value_len: usize,
}

impl NosqlInjectionDetector {
    pub const fn new() -> Self {
        Self {
            max_value_len: DEFAULT_MAX_VALUE_LEN,
        }
    }

    pub const fn with_max_value_len(max_value_len: usize) -> Self {
        Self { max_value_len }
    }
}

impl Default for NosqlInjectionDetector {
    fn default() -> Self {
        Self::new()
    }
}

impl Detector for NosqlInjectionDetector {
    fn id(&self) -> DetectorId {
        DetectorId("semantic.nosql.structural")
    }

    fn inspect(
        &self,
        request: &CanonicalRequest,
        ctx: &mut super::super::DetectionContext,
    ) -> DetectorResult {
        let mut findings: Vec<Finding> = Vec::new();
        let mut degraded = None;

        let push = |rule: &'static str,
                    severity: Severity,
                    action: Action,
                    score: u32,
                    detail: String,
                    source: EvidenceSource,
                    field: Option<&str>,
                    findings: &mut Vec<Finding>| {
            let mut finding = Finding::new(
                DetectorId("semantic.nosql.structural"),
                rule,
                AttackCategory::NosqlInjection,
            )
            .confidence(match action {
                Action::Block => Confidence::High,
                Action::Monitor => Confidence::Medium,
                _ => Confidence::Low,
            })
            .severity(severity)
            .score(score)
            .action(action)
            .source(source)
            .detail(detail);
            if let Some(field) = field {
                finding = finding.field(field.to_string());
            }
            findings.push(finding);
        };

        for param in request.query() {
            if param.name.len() <= self.max_value_len
                && has_bracket_operator(&param.name)
            {
                push(
                    "sem.nosql.bracket_operator",
                    Severity::Medium,
                    Action::Monitor,
                    15,
                    "operator injected through a parameter name".to_string(),
                    EvidenceSource::Query,
                    Some(&param.name),
                    &mut findings,
                );
            }
            if param.value.len() > self.max_value_len {
                if degraded.is_none() {
                    degraded = Some("value exceeds semantic budget");
                }
                continue;
            }
            if let Some(evidence) = analyze(&param.value) {
                push(
                    evidence.rule,
                    evidence.severity,
                    evidence.action,
                    evidence.score,
                    evidence.detail,
                    EvidenceSource::Query,
                    Some(&param.name),
                    &mut findings,
                );
            }
        }
        for (name, value) in request.cookies() {
            if value.len() > self.max_value_len {
                if degraded.is_none() {
                    degraded = Some("value exceeds semantic budget");
                }
                continue;
            }
            if let Some(evidence) = analyze(value) {
                push(
                    evidence.rule,
                    evidence.severity,
                    evidence.action,
                    evidence.score,
                    evidence.detail,
                    EvidenceSource::Cookie,
                    Some(name),
                    &mut findings,
                );
            }
        }
        if let Some(body) = request.body() {
            let limit = ctx.budget().max_body_bytes.min(body.len());
            match std::str::from_utf8(&body[..limit]) {
                Ok(text) => {
                    if let Some(evidence) = analyze(text) {
                        push(
                            evidence.rule,
                            evidence.severity,
                            evidence.action,
                            evidence.score,
                            evidence.detail,
                            EvidenceSource::Body,
                            None,
                            &mut findings,
                        );
                    }
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
    use super::NosqlInjectionDetector;
    use crate::canonical::{Canonicalizer, RequestParts};
    use crate::pipeline::{Action, AttackCategory, DetectionContext, Detector};

    fn query(value: &str) -> crate::pipeline::DetectorResult {
        let encoded = value.replace('%', "%25").replace('&', "%26");
        let target = format!("/?q={encoded}");
        let request = Canonicalizer::default().canonicalize(RequestParts::new(
            "GET",
            "example.com",
            target,
        ));
        let detector = NosqlInjectionDetector::new();
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
    fn where_with_javascript_blocks() {
        for payload in [
            "{\"$where\":\"this.password.match(/.*/)\"}",
            "{\"$where\":\"sleep(5000)\"}",
            "{\"$where\":\"';return true;var foo='\"}",
        ] {
            let (rule, action) = tier(payload).expect(payload);
            assert_eq!(rule, "sem.nosql.where_injection", "{payload}");
            assert_eq!(action, Action::Block, "{payload}");
        }
    }

    #[test]
    fn server_side_javascript_operators_block() {
        for payload in [
            "{\"$func\":\"function() {}\"}",
            "{\"$accumulator\":\"...\"}",
        ] {
            let (_, action) = tier(payload).expect(payload);
            assert_eq!(action, Action::Block, "{payload}");
        }
    }

    #[test]
    fn bracket_operator_in_parameter_name_monitors() {
        let request = Canonicalizer::default().canonicalize(RequestParts::new(
            "GET",
            "example.com",
            "/?user[$ne]=1",
        ));
        let detector = NosqlInjectionDetector::new();
        let mut ctx = DetectionContext::new();
        let result = detector.inspect(&request, &mut ctx);
        let hit = result
            .findings
            .iter()
            .find(|f| f.rule_id == "sem.nosql.bracket_operator")
            .expect("finding");
        assert_eq!(hit.action_hint, Action::Monitor);
        assert_eq!(hit.category, AttackCategory::NosqlInjection);
    }

    #[test]
    fn driver_syntax_monitors() {
        // `$where` without JavaScript content monitors (prose-safe).
        let (rule, action) =
            tier("db.users.find({$where:\"1==1\"})").expect("finding");
        assert_eq!(rule, "sem.nosql.where_operator");
        assert_eq!(action, Action::Monitor);

        let (rule, action) =
            tier("db.users.find({active:true})").expect("finding");
        assert_eq!(rule, "sem.nosql.driver_syntax");
        assert_eq!(action, Action::Monitor);
    }

    #[test]
    fn legitimate_operators_stay_weak() {
        // Real MongoDB-style API payloads use operators for range queries.
        let result = query("{\"price\":{\"$gt\":10},\"stock\":{\"$ne\":0}}");
        assert!(!result.findings.is_empty());
        assert!(result
            .findings
            .iter()
            .all(|f| f.action_hint < Action::Monitor));
    }

    #[test]
    fn clean_values_produce_nothing() {
        assert!(tier("hello world").is_none());
        assert!(tier("{\"name\":\"Ada\"}").is_none());
    }

    #[test]
    fn oversized_values_degrade() {
        let detector = NosqlInjectionDetector::with_max_value_len(16);
        let target = format!("/?q={}", "{\"$where\":\"this.x\"}".repeat(3));
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
