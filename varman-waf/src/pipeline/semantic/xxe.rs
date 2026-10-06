//! XXE structural detector (Phase 6).
//!
//! XML external entity attacks are declaration-driven: a `DOCTYPE` with an
//! `ENTITY` whose value is an external identifier (`SYSTEM`/`PUBLIC`), or a
//! chain of entities that expands exponentially ("billion laughs"). This
//! detector distinguishes declarations from ordinary markup:
//!
//! | Evidence | Tier |
//! | --- | --- |
//! | DOCTYPE + ENTITY with `SYSTEM`/`PUBLIC` external id | Block |
//! | three or more ENTITY declarations in one value | Block (expansion) |
//! | a lone `<!ENTITY` declaration | Log |
//! | plain `<!DOCTYPE html>` | no finding |

use super::super::{
    Action, AttackCategory, Confidence, Detector, DetectorId, DetectorResult,
    EvidenceSource, Finding, Severity,
};

use crate::canonical::CanonicalRequest;

/// Default maximum value length considered by the structural analysis.
pub const DEFAULT_MAX_VALUE_LEN: usize = 8 * 1024;

struct Evidence {
    rule: &'static str,
    severity: Severity,
    action: Action,
    score: u32,
    detail: String,
}

fn analyze(value: &str) -> Option<Evidence> {
    let low = value.to_ascii_lowercase();
    let entities = low.matches("<!entity").count();
    let has_doctype = low.contains("<!doctype");

    if has_doctype
        && (low.contains("system \"")
            || low.contains("system '")
            // HTML4's `<!DOCTYPE HTML PUBLIC "…">` is legitimate; PUBLIC
            // only counts as XXE evidence alongside an entity declaration.
            || ((low.contains("public \"") || low.contains("public '"))
                && entities > 0))
    {
        return Some(Evidence {
            rule: "sem.xxe.external_entity",
            severity: Severity::High,
            action: Action::Block,
            score: 30,
            detail:
                "DOCTYPE/entity declares an external SYSTEM/PUBLIC identifier"
                    .to_string(),
        });
    }
    if entities >= 3 {
        return Some(Evidence {
            rule: "sem.xxe.entity_expansion",
            severity: Severity::High,
            action: Action::Block,
            score: 40,
            detail: format!(
                "{entities} entity declarations suggest an expansion bomb"
            ),
        });
    }
    if entities > 0 {
        return Some(Evidence {
            rule: "sem.xxe.entity_declaration",
            severity: Severity::Low,
            action: Action::Log,
            score: 5,
            detail: "entity declaration without external identifier"
                .to_string(),
        });
    }
    None
}

/// XXE structural detector.
#[derive(Debug, Clone, Copy)]
pub struct XxeDetector {
    max_value_len: usize,
}

impl XxeDetector {
    pub const fn new() -> Self {
        Self {
            max_value_len: DEFAULT_MAX_VALUE_LEN,
        }
    }

    pub const fn with_max_value_len(max_value_len: usize) -> Self {
        Self { max_value_len }
    }
}

impl Default for XxeDetector {
    fn default() -> Self {
        Self::new()
    }
}

impl Detector for XxeDetector {
    fn id(&self) -> DetectorId {
        DetectorId("semantic.xxe.structural")
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
                DetectorId("semantic.xxe.structural"),
                evidence.rule,
                AttackCategory::Xxe,
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
    use super::XxeDetector;
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
        let detector = XxeDetector::new();
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
    fn external_entities_block() {
        for payload in [
            "<!DOCTYPE foo [<!ENTITY xxe SYSTEM \"file:///etc/passwd\">]>",
            "<?xml version=\"1.0\"?><!DOCTYPE data SYSTEM \"file:///etc/passwd\">",
        ] {
            let (rule, action) = tier(payload).expect(payload);
            assert_eq!(rule, "sem.xxe.external_entity", "{payload}");
            assert_eq!(action, Action::Block, "{payload}");
        }
    }

    #[test]
    fn entity_expansion_bombs_block() {
        let payload = "<!DOCTYPE lolz [<!ENTITY lol \"lol\">\
            <!ENTITY lol2 \"&lol;&lol;\"><!ENTITY lol3 \"&lol2;&lol2;\">]>";
        let (rule, action) = tier(payload).expect("finding");
        assert_eq!(rule, "sem.xxe.entity_expansion");
        assert_eq!(action, Action::Block);
    }

    #[test]
    fn plain_doctype_is_clean() {
        assert!(tier("<!DOCTYPE html><html><body>hi</body></html>").is_none());
    }

    #[test]
    fn internal_entity_declaration_stays_weak() {
        let (rule, action) =
            tier("<!ENTITY greeting \"hello\">").expect("finding");
        assert_eq!(rule, "sem.xxe.entity_declaration");
        assert!(action < Action::Monitor);
    }

    #[test]
    fn category_is_xxe() {
        let result = query("<!DOCTYPE foo [<!ENTITY x SYSTEM \"file:///x\">]>");
        assert_eq!(result.findings[0].category, AttackCategory::Xxe);
    }

    #[test]
    fn oversized_values_degrade() {
        let detector = XxeDetector::with_max_value_len(16);
        let target = format!("/?q={}", "<!ENTITY x \"y\">".repeat(3));
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
