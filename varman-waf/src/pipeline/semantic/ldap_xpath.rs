//! LDAP / XPath injection structural detector (Phase 6).
//!
//! Both families are *filter/expression grammars*: the attack is shaped by
//! brackets, boolean operators and wildcards, not by words.
//!
//! LDAP — filter injection (`*)(uid=*))(|(uid=*`) and assertion stacking
//! (`)(cn=`, `*)(objectclass=`):
//!
//! | Evidence | Tier |
//! | --- | --- |
//! | filter-break shapes (`)(|`, `)(&`, `*)(`, `)(cn=`, `)(uid=`, `)(objectclass=`) | Block |
//! | bare filter fragment (`(uid=`, `(cn=`, `(|(`, `(&(`) | Log |
//!
//! XPath — expression injection (`' or count(//*) > 0`), axis abuse
//! (`descendant-or-self::`), union breaks (`']|`):
//!
//! | Evidence | Tier |
//! | --- | --- |
//! | count/or combos, axes, union breaks | Block |
//! | bare `//*` mention | Log |

use super::super::{
    Action, AttackCategory, Confidence, Detector, DetectorId, DetectorResult,
    EvidenceSource, Finding, Severity,
};

use crate::canonical::CanonicalRequest;

/// Default maximum value length considered by the structural analysis.
pub const DEFAULT_MAX_VALUE_LEN: usize = 8 * 1024;

/// LDAP filter-break shapes.
const LDAP_BLOCK_SHAPES: &[&str] = &[
    ")(|",
    ")(&",
    "*)(",
    ")(cn=",
    ")(uid=",
    ")(objectclass=",
    ")(mail=",
    "))(|",
];

/// Bare LDAP filter fragments (documentation, framed queries).
const LDAP_LOG_FRAGMENTS: &[&str] =
    &["(uid=", "(cn=", "(|(", "(&(", "(objectclass="];

/// XPath expression shapes.
const XPATH_BLOCK_SHAPES: &[&str] = &[
    "' or count(",
    "\" or count(",
    "or count(//",
    "descendant-or-self::",
    "']|",
    "' or 1=1]",
    "\" or 1=1]",
    "position()",
];

/// XPath wildcard mention.
const XPATH_LOG_FRAGMENTS: &[&str] = &["//*", "ancestor::"];

struct Evidence {
    rule: &'static str,
    category: AttackCategory,
    severity: Severity,
    action: Action,
    score: u32,
    detail: String,
}

fn analyze(value: &str) -> Option<Evidence> {
    let low = value.to_ascii_lowercase();

    if let Some(shape) = LDAP_BLOCK_SHAPES.iter().find(|s| low.contains(*s)) {
        return Some(Evidence {
            rule: "sem.ldap.filter_injection",
            category: AttackCategory::LdapInjection,
            severity: Severity::High,
            action: Action::Block,
            score: 30,
            detail: format!("LDAP filter-break shape {shape:?}"),
        });
    }
    if let Some(shape) = XPATH_BLOCK_SHAPES.iter().find(|s| low.contains(*s)) {
        return Some(Evidence {
            rule: "sem.xpath.expression_injection",
            category: AttackCategory::XPathInjection,
            severity: Severity::High,
            action: Action::Block,
            score: 30,
            detail: format!("XPath expression shape {shape:?}"),
        });
    }
    if let Some(fragment) = LDAP_LOG_FRAGMENTS.iter().find(|s| low.contains(*s))
    {
        return Some(Evidence {
            rule: "sem.ldap.filter_fragment",
            category: AttackCategory::LdapInjection,
            severity: Severity::Low,
            action: Action::Log,
            score: 5,
            detail: format!("LDAP filter fragment {fragment:?}"),
        });
    }
    if let Some(fragment) =
        XPATH_LOG_FRAGMENTS.iter().find(|s| low.contains(*s))
    {
        return Some(Evidence {
            rule: "sem.xpath.fragment",
            category: AttackCategory::XPathInjection,
            severity: Severity::Low,
            action: Action::Log,
            score: 5,
            detail: format!("XPath wildcard fragment {fragment:?}"),
        });
    }
    None
}

/// LDAP/XPath structural detector.
#[derive(Debug, Clone, Copy)]
pub struct LdapXPathDetector {
    max_value_len: usize,
}

impl LdapXPathDetector {
    pub const fn new() -> Self {
        Self {
            max_value_len: DEFAULT_MAX_VALUE_LEN,
        }
    }

    pub const fn with_max_value_len(max_value_len: usize) -> Self {
        Self { max_value_len }
    }
}

impl Default for LdapXPathDetector {
    fn default() -> Self {
        Self::new()
    }
}

impl Detector for LdapXPathDetector {
    fn id(&self) -> DetectorId {
        DetectorId("semantic.ldap_xpath.structural")
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
                DetectorId("semantic.ldap_xpath.structural"),
                evidence.rule,
                evidence.category,
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
    use super::LdapXPathDetector;
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
        let detector = LdapXPathDetector::new();
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
    fn ldap_filter_breaks_block() {
        for payload in ["*)(uid=*))(|(uid=*", "admin)(cn=*", "*)(objectclass=*"]
        {
            let (rule, action) = tier(payload).expect(payload);
            assert_eq!(rule, "sem.ldap.filter_injection", "{payload}");
            assert_eq!(action, Action::Block, "{payload}");
        }
    }

    #[test]
    fn xpath_expressions_block() {
        for payload in [
            "' or count(//*) > 0 or '",
            "']|//user[1]|//user['",
            "/descendant-or-self::node()",
        ] {
            let (rule, action) = tier(payload).expect(payload);
            assert_eq!(rule, "sem.xpath.expression_injection", "{payload}");
            assert_eq!(action, Action::Block, "{payload}");
        }
    }

    #[test]
    fn documentation_fragments_stay_weak() {
        for case in [
            "Search filter: (uid=alice) is the LDAP bind syntax.",
            "Use //* to select every element in an XPath expression.",
        ] {
            if let Some((_, action)) = tier(case) {
                assert!(action < Action::Monitor, "{case:?} reached {action}");
            }
        }
    }

    #[test]
    fn categories_are_exposed() {
        let ldap = query("*)(uid=*");
        assert_eq!(ldap.findings[0].category, AttackCategory::LdapInjection);
        let xpath = query("' or count(//*)");
        assert_eq!(xpath.findings[0].category, AttackCategory::XPathInjection);
    }

    #[test]
    fn clean_values_produce_nothing() {
        for value in
            ["hello", "{\"name\":\"Ada\"}", "https://cdn.example.com/a"]
        {
            assert!(tier(value).is_none(), "{value}");
        }
    }

    #[test]
    fn oversized_values_degrade() {
        let detector = LdapXPathDetector::with_max_value_len(16);
        let target = format!("/?q={}", "*)(uid=*".repeat(4));
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
