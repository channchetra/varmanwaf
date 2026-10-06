//! GraphQL abuse detector (Phase 6).
//!
//! GraphQL attacks are *query-shape* attacks:
//!
//! | Evidence | Tier |
//! | --- | --- |
//! | introspection probes (`__schema`, `__type(`, `IntrospectionQuery`) | Monitor |
//! | nesting depth ≥ 12 inside a query/mutation document | Monitor |
//! | ≥ 8 operations batched into one document | Monitor |
//! | `__typename` / `__type` references (normal client usage) | Log |
//!
//! Nothing blocks here by default: introspection and batching are policy
//! decisions per API (dev clients introspect legitimately), so the detector
//! reports and lets site policy escalate.

use super::super::{
    Action, AttackCategory, Confidence, Detector, DetectorId, DetectorResult,
    EvidenceSource, Finding, Severity,
};

use crate::canonical::CanonicalRequest;

/// Default maximum value length considered by the structural analysis.
pub const DEFAULT_MAX_VALUE_LEN: usize = 8 * 1024;

/// Maximum nesting depth tolerated inside a query document.
const MAX_DEPTH: usize = 12;

/// Operations per document considered batched abuse.
const MAX_OPERATIONS: usize = 8;

/// Deepest `{` nesting in `value` (ignores mismatched closers).
fn max_brace_depth(value: &str) -> usize {
    let mut depth = 0usize;
    let mut max = 0usize;
    for ch in value.chars() {
        match ch {
            '{' => {
                depth += 1;
                max = max.max(depth);
            },
            '}' => depth = depth.saturating_sub(1),
            _ => {},
        }
    }
    max
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

    if low.contains("__schema")
        || low.contains("introspectionquery")
        || low.contains("__type(")
    {
        return Some(Evidence {
            rule: "sem.graphql.introspection",
            severity: Severity::Medium,
            action: Action::Monitor,
            score: 15,
            detail: "GraphQL introspection probe".to_string(),
        });
    }
    let looks_graphql = low.contains("query")
        || low.contains("mutation")
        || low.contains("subscription");
    if looks_graphql && max_brace_depth(&low) >= MAX_DEPTH {
        return Some(Evidence {
            rule: "sem.graphql.depth",
            severity: Severity::Medium,
            action: Action::Monitor,
            score: 15,
            detail: format!(
                "GraphQL document nesting depth {} exceeds {MAX_DEPTH}",
                max_brace_depth(&low)
            ),
        });
    }
    let operations = low.matches("query ").count()
        + low.matches("mutation ").count()
        + low.matches("subscription ").count();
    if operations >= MAX_OPERATIONS {
        return Some(Evidence {
            rule: "sem.graphql.batched_operations",
            severity: Severity::Medium,
            action: Action::Monitor,
            score: 15,
            detail: format!(
                "{operations} operations batched into one document"
            ),
        });
    }
    if low.contains("__typename") || low.contains("__type") {
        return Some(Evidence {
            rule: "sem.graphql.meta_field",
            severity: Severity::Low,
            action: Action::Log,
            score: 5,
            detail: "GraphQL meta-field reference".to_string(),
        });
    }
    None
}

/// GraphQL abuse detector.
#[derive(Debug, Clone, Copy)]
pub struct GraphqlAbuseDetector {
    max_value_len: usize,
}

impl GraphqlAbuseDetector {
    pub const fn new() -> Self {
        Self {
            max_value_len: DEFAULT_MAX_VALUE_LEN,
        }
    }

    pub const fn with_max_value_len(max_value_len: usize) -> Self {
        Self { max_value_len }
    }
}

impl Default for GraphqlAbuseDetector {
    fn default() -> Self {
        Self::new()
    }
}

impl Detector for GraphqlAbuseDetector {
    fn id(&self) -> DetectorId {
        DetectorId("semantic.graphql.abuse")
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
                DetectorId("semantic.graphql.abuse"),
                evidence.rule,
                AttackCategory::GraphqlAbuse,
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
    use super::GraphqlAbuseDetector;
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
        let detector = GraphqlAbuseDetector::new();
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
    fn introspection_monitors() {
        for payload in [
            "{\"query\":\"{ __schema { types { name } } }\"}",
            "{ __type(name: \"User\") { fields { name } } }",
            "{ \"operationName\":\"IntrospectionQuery\" }",
        ] {
            let (rule, action) = tier(payload).expect(payload);
            assert_eq!(rule, "sem.graphql.introspection", "{payload}");
            assert_eq!(action, Action::Monitor, "{payload}");
        }
    }

    #[test]
    fn deep_nesting_monitors() {
        let payload = "query { a { b { c { d { e { f { g { h { i { j { k { l { m } } } } } } } } } } } } }";
        let (rule, action) = tier(payload).expect("finding");
        assert_eq!(rule, "sem.graphql.depth");
        assert_eq!(action, Action::Monitor);
    }

    #[test]
    fn batched_operations_monitor() {
        let payload = (0..9)
            .map(|i| format!("query Q{i} {{ a }}"))
            .collect::<Vec<_>>()
            .join(" ");
        let (rule, action) = tier(&payload).expect("finding");
        assert_eq!(rule, "sem.graphql.batched_operations");
        assert_eq!(action, Action::Monitor);
    }

    #[test]
    fn normal_queries_and_json_pass() {
        for value in [
            "{\"query\":\"{ user(id: 1) { name email } }\"}",
            "{\"name\":\"Ada\",\"roles\":[\"admin\"]}",
            "hello world",
        ] {
            assert!(tier(value).is_none(), "{value}");
        }
    }

    #[test]
    fn meta_fields_stay_weak() {
        let (rule, action) =
            tier("{ user { __typename id } }").expect("finding");
        assert_eq!(rule, "sem.graphql.meta_field");
        assert!(action < Action::Monitor);
    }

    #[test]
    fn category_is_graphql_abuse() {
        let result = query("{ __schema }");
        assert_eq!(result.findings[0].category, AttackCategory::GraphqlAbuse);
    }

    #[test]
    fn oversized_values_degrade() {
        let detector = GraphqlAbuseDetector::with_max_value_len(16);
        let target = format!("/?q={}", "{ __schema }".repeat(3));
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
