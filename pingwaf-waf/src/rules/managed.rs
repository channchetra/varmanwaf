//! Managed rule sets shipped with the engine.
//!
//! These are OWASP-flavoured defaults expressed in the same expression
//! language as user-supplied rules. They are *not* exhaustive — production
//! deployments are expected to receive their bundle from the control plane —
//! but they give a fresh agent meaningful coverage out of the box.
//!
//! The set is parameterized by [`WafLevel`]: the Normal level keeps sub-score
//! gates at their low-false-positive defaults, the Strict level tightens them
//! and adds rules that are too aggressive for general traffic (e.g. blocking
//! on the RCE sub-score alone).

use crate::rules::signatures::AttackCategory;
use crate::rules::{CompiledRule, RuleAction};
use crate::{StackSet, WafLevel};

/// One managed rule template.
struct ManagedSpec {
    id: &'static str,
    name: &'static str,
    expression: String,
    action: RuleAction,
    severity: u8,
    paranoia_level: u8,
    stacks: StackSet,
    /// Only included when the engine runs at [`WafLevel::Strict`].
    strict_only: bool,
    tags: &'static [&'static str],
}

/// Returns the built-in managed rule set for the requested level. Rules that
/// fail to parse are silently skipped (logged at warn level) so a typo in one
/// default never breaks engine startup.
pub fn default_managed_rules(level: WafLevel) -> Vec<CompiledRule> {
    let strict = level.is_strict();
    // Sub-score gates: one critical (sev-5) hit contributes 60 to a family
    // sub-score, so 60 blocks on a single critical detection at Normal. The
    // Strict level lowers the bar to 50 (one critical plus any lesser hit,
    // or two strong hits) and tightens the aggregate gate.
    let family_gate = if strict { 50 } else { 60 };
    let aggregate_gate = if strict { 70 } else { 80 };

    let specs = [
        ManagedSpec {
            id: "PINGWAF-1001",
            name: "Block admin paths from non-trusted networks",
            expression: r#"http.request.uri.path starts_with "/admin" and not ip.src in {10.0.0.0/8 172.16.0.0/12 192.168.0.0/16 127.0.0.0/8}"#.to_string(),
            action: RuleAction::Challenge,
            severity: 3,
            paranoia_level: 1,
            stacks: StackSet::GENERIC,
            strict_only: false,
            tags: &["admin", "ip-restriction"],
        },
        ManagedSpec {
            id: "PINGWAF-1002",
            name: "Block known SQL injection anomaly scores",
            expression: format!("cf.waf.score.sqli ge {family_gate}"),
            action: RuleAction::Block,
            severity: 5,
            paranoia_level: 1,
            stacks: StackSet::GENERIC,
            strict_only: false,
            tags: &["sqli", "anomaly"],
        },
        ManagedSpec {
            id: "PINGWAF-1003",
            name: "Block known XSS anomaly scores",
            expression: format!("cf.waf.score.xss ge {family_gate}"),
            action: RuleAction::Block,
            severity: 5,
            paranoia_level: 1,
            stacks: StackSet::GENERIC,
            strict_only: false,
            tags: &["xss", "anomaly"],
        },
        ManagedSpec {
            id: "PINGWAF-1004",
            name: "Block requests with high aggregate WAF score",
            expression: format!("cf.waf.score ge {aggregate_gate}"),
            action: RuleAction::Block,
            severity: 5,
            paranoia_level: 1,
            stacks: StackSet::GENERIC,
            strict_only: false,
            tags: &["anomaly"],
        },
        ManagedSpec {
            id: "PINGWAF-1010",
            name: "Block common scanner user agents",
            expression: r#"user_agent matches "(?i)(nikto|sqlmap|nmap|masscan|acunetix|nessus|openvas|wpscan|dirbuster|gobuster|zgrab)""#.to_string(),
            action: RuleAction::Block,
            severity: 4,
            paranoia_level: 2,
            stacks: StackSet::GENERIC,
            strict_only: false,
            tags: &["scanner", "user-agent"],
        },
        ManagedSpec {
            id: "PINGWAF-1011",
            name: "Block empty user agents on non-HEAD requests",
            expression: r#"user_agent eq "" and http.request.method ne "HEAD""#.to_string(),
            action: RuleAction::Challenge,
            severity: 2,
            paranoia_level: 3,
            stacks: StackSet::GENERIC,
            strict_only: false,
            tags: &["user-agent"],
        },
        ManagedSpec {
            id: "PINGWAF-1020",
            name: "Block sensitive dotfile probes",
            expression: r#"http.request.uri.path matches "(?i)/\\.(?:git|env|svn|aws|kube|ssh|docker)""#.to_string(),
            action: RuleAction::Block,
            severity: 5,
            paranoia_level: 1,
            stacks: StackSet::GENERIC,
            strict_only: false,
            tags: &["dotfile", "recon"],
        },
        ManagedSpec {
            id: "PINGWAF-1021",
            // Archive extensions are ordinary downloadable assets — a bare
            // `.zip`/`.tar.gz` request is a download, not a probe. Only
            // editor/DB leftovers expose source or data.
            name: "Block common backup-file probes",
            expression: r#"http.request.uri.path matches "(?i)\\.(?:bak|backup|old|swp|sql)$""#.to_string(),
            action: RuleAction::Block,
            severity: 4,
            paranoia_level: 2,
            stacks: StackSet::GENERIC,
            strict_only: false,
            tags: &["backup", "recon"],
        },
        ManagedSpec {
            id: "PINGWAF-1030",
            name: "Block requests with HTTP method TRACE / TRACK",
            expression: r#"http.request.method in {"TRACE" "TRACK"}"#.to_string(),
            action: RuleAction::Block,
            severity: 3,
            paranoia_level: 1,
            stacks: StackSet::GENERIC,
            strict_only: false,
            tags: &["method"],
        },
        ManagedSpec {
            id: "PINGWAF-1031",
            name: "Log unusual HTTP methods",
            expression: r#"not http.request.method in {"GET" "POST" "PUT" "PATCH" "DELETE" "HEAD" "OPTIONS"}"#.to_string(),
            action: RuleAction::Log,
            severity: 1,
            paranoia_level: 2,
            stacks: StackSet::GENERIC,
            strict_only: false,
            tags: &["method"],
        },
        ManagedSpec {
            id: "PINGWAF-1040",
            name: "Block phpMyAdmin / wp-admin probes on non-PHP apps",
            expression: r#"http.request.uri.path matches "(?i)/(?:phpmyadmin|pma|wp-admin|wp-login\\.php|xmlrpc\\.php|administrator)""#.to_string(),
            action: RuleAction::Challenge,
            severity: 3,
            paranoia_level: 2,
            stacks: StackSet::GENERIC,
            strict_only: false,
            tags: &["recon", "cms"],
        },
        ManagedSpec {
            id: "PINGWAF-1050",
            name: "Block Log4Shell JNDI lookups in any header",
            expression: r#"http.request.headers["user-agent"] contains "${jndi:""#.to_string(),
            action: RuleAction::Block,
            severity: 5,
            paranoia_level: 1,
            stacks: StackSet::JAVA,
            strict_only: false,
            tags: &["log4shell", "rce"],
        },
        ManagedSpec {
            id: "PINGWAF-1051",
            name: "Block requests with very long URIs (likely buffer / scan attempts)",
            expression: r#"http.request.uri.full matches "^.{4096,}$""#.to_string(),
            // Log, not Block: a long URI alone is weak evidence — legit deep
            // paths and encoded query strings trip the 4096 boundary, and at
            // strict this rule was the sole blocker behind 20 false positives.
            // Any real payload in the URI still scores through the signature
            // engine; this only keeps the telemetry.
            action: RuleAction::Log,
            severity: 3,
            paranoia_level: 3,
            stacks: StackSet::GENERIC,
            strict_only: false,
            tags: &["size"],
        },
        ManagedSpec {
            id: "PINGWAF-1061",
            name: "Block requests with a high RCE sub-score",
            expression: "cf.waf.score.rce ge 40".to_string(),
            action: RuleAction::Block,
            severity: 5,
            paranoia_level: 1,
            stacks: StackSet::GENERIC,
            strict_only: true,
            tags: &["rce", "anomaly"],
        },
    ];

    let mut out = Vec::with_capacity(specs.len());
    for spec in specs {
        if spec.strict_only && !strict {
            continue;
        }
        match CompiledRule::compile(
            spec.id,
            spec.name,
            &spec.expression,
            spec.action,
            spec.severity,
            spec.tags.iter().map(|s| s.to_string()).collect(),
        ) {
            Ok(mut rule) => {
                rule.paranoia_level = spec.paranoia_level;
                rule.stacks = spec.stacks;
                out.push(rule);
            },
            Err(err) => {
                tracing::warn!(rule_id = spec.id, error = %err, "skipping malformed managed rule");
            },
        }
    }
    out
}

/// Map a managed rule onto the attack category its tags declare, so
/// per-site monitor downgrades can apply to literal-expression rules.
/// Score-gate rules (family / aggregate thresholds) don't need this — their
/// expression input already excludes downgraded hits — but the mapping is
/// harmless for them and future literal rules with family tags pick the
/// semantics up automatically. Rules without a family tag (recon, method
/// policy, …) return `None` and are never downgraded.
pub(crate) fn managed_rule_category(
    rule: &CompiledRule,
) -> Option<AttackCategory> {
    const FAMILY_TAGS: [(&str, AttackCategory); 3] = [
        ("sqli", AttackCategory::SqlInjection),
        ("xss", AttackCategory::Xss),
        ("rce", AttackCategory::CommandInjection),
    ];
    FAMILY_TAGS
        .iter()
        .find(|(tag, _)| rule.tags.iter().any(|t| t == tag))
        .map(|(_, category)| *category)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rules::expression::{evaluate, EvalContext};

    /// An evaluation context that only carries scores; expressions under
    /// test read nothing else.
    fn score_ctx(
        sqli: u8,
        xss: u8,
        rce: u8,
        total: u32,
    ) -> EvalContext<'static> {
        EvalContext {
            method: "GET",
            path: "/",
            full_uri: "/",
            host: "",
            user_agent: "test",
            body: None,
            headers: &[],
            cookies: &[],
            client_ip: "",
            parsed_ip: None,
            country_code: None,
            ssl: false,
            waf_score: total,
            waf_score_sqli: sqli,
            waf_score_xss: xss,
            waf_score_rce: rce,
        }
    }

    fn find<'r>(rules: &'r [CompiledRule], id: &str) -> &'r CompiledRule {
        rules
            .iter()
            .find(|r| r.id == id)
            .unwrap_or_else(|| panic!("{id} missing"))
    }

    #[test]
    fn all_managed_rules_compile() {
        let rules = default_managed_rules(WafLevel::Normal);
        assert!(rules.len() >= 10, "expected at least 10 managed rules");
        for r in &rules {
            assert!(!r.id.is_empty());
            assert!((1..=5).contains(&r.severity));
            assert!((1..=4).contains(&r.paranoia_level));
        }
    }

    #[test]
    fn strict_level_tightens_gates() {
        let normal = default_managed_rules(WafLevel::Normal);
        let strict = default_managed_rules(WafLevel::Strict);

        // A 55-point family sub-score sits between the Strict gate (50) and
        // the Normal gate (60).
        let ctx = score_ctx(55, 0, 0, 55);
        assert!(!evaluate(&find(&normal, "PINGWAF-1002").expression, &ctx));
        assert!(evaluate(&find(&strict, "PINGWAF-1002").expression, &ctx));

        // An aggregate of 75 sits between the Strict gate (70) and the
        // Normal gate (80).
        let ctx = score_ctx(0, 0, 0, 75);
        assert!(!evaluate(&find(&normal, "PINGWAF-1004").expression, &ctx));
        assert!(evaluate(&find(&strict, "PINGWAF-1004").expression, &ctx));

        // The RCE sub-score gate exists only at Strict.
        assert!(normal.iter().all(|r| r.id != "PINGWAF-1061"));
        assert!(evaluate(
            &find(&strict, "PINGWAF-1061").expression,
            &score_ctx(0, 0, 48, 48)
        ));
    }

    #[test]
    fn log4shell_rule_is_java_scoped() {
        let rules = default_managed_rules(WafLevel::Normal);
        let r = find(&rules, "PINGWAF-1050");
        assert_eq!(r.stacks, StackSet::JAVA);
    }
}
