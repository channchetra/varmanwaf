//! Per-site pipeline policy: monitor-only downgrades.
//!
//! The dashboard lets a site downgrade an attack family to monitor-only
//! (`waf_settings.monitor_categories`). The legacy engine honours the list
//! through [`crate::CategorySet`]; this module applies the same policy to the
//! Varman pipeline so both engines agree: a category the site marked
//! monitor-only never blocks, whichever engine sees it first.
//!
//! Names must stay in sync with `CategorySet::parse_name` and the settings
//! API (`api::waf_settings::CATEGORIES`).

use super::{Action, AttackCategory, PipelineVerdict};

/// Monitor-set names a site can configure (dashboard order).
pub const MONITOR_CATEGORY_NAMES: [&str; 9] = [
    "sqli", "xss", "rce", "lfi", "ssrf", "deser", "crlf", "xxe", "ssti",
];

/// Map a pipeline category onto its monitor-set name. `None` for categories
/// the dashboard cannot downgrade.
pub const fn monitor_name(category: AttackCategory) -> Option<&'static str> {
    match category {
        AttackCategory::SqlInjection => Some("sqli"),
        AttackCategory::Xss => Some("xss"),
        // Log4Shell is an RCE family in the dashboard taxonomy.
        AttackCategory::CommandInjection | AttackCategory::Log4Shell => {
            Some("rce")
        },
        // File inclusion and traversal share the `lfi` switch.
        AttackCategory::LfiRfi | AttackCategory::PathTraversal => Some("lfi"),
        AttackCategory::Ssrf => Some("ssrf"),
        AttackCategory::Deserialization => Some("deser"),
        AttackCategory::CrlfInjection => Some("crlf"),
        AttackCategory::Xxe => Some("xxe"),
        AttackCategory::Ssti => Some("ssti"),
        _ => None,
    }
}

/// Downgrade every finding whose category is monitored to `Monitor` and
/// recompute the verdict action as the monotonic maximum of the remaining
/// hints.
///
/// The score is kept: a monitor-only downgrade records the event with its
/// severity but never blocks — the same semantics the legacy engine applies.
pub fn downgrade_monitored(
    verdict: &mut PipelineVerdict,
    monitored: &[String],
) {
    if monitored.is_empty() || verdict.findings.is_empty() {
        return;
    }
    let names: Vec<String> = monitored
        .iter()
        .map(|name| name.trim().to_ascii_lowercase())
        .collect();
    let mut changed = false;
    for finding in &mut verdict.findings {
        let Some(name) = monitor_name(finding.category) else {
            continue;
        };
        if finding.action_hint > Action::Monitor
            && names.iter().any(|configured| configured == name)
        {
            finding.action_hint = Action::Monitor;
            changed = true;
        }
    }
    if changed {
        verdict.action = verdict
            .findings
            .iter()
            .map(|finding| finding.action_hint)
            .max()
            .unwrap_or(Action::Pass);
    }
}

#[cfg(test)]
mod tests {
    use super::{downgrade_monitored, monitor_name};
    use crate::pipeline::{
        Action, AttackCategory, DetectorId, Finding, PipelineVerdict,
    };

    fn finding(category: AttackCategory, action: Action) -> Finding {
        Finding::new(DetectorId("test"), "test-rule", category).action(action)
    }

    fn verdict(findings: Vec<Finding>) -> PipelineVerdict {
        let action = findings
            .iter()
            .map(|finding| finding.action_hint)
            .max()
            .unwrap_or(Action::Pass);
        PipelineVerdict {
            action,
            score: 40,
            findings,
            degraded: Vec::new(),
        }
    }

    #[test]
    fn empty_list_is_a_passthrough() {
        let mut v =
            verdict(vec![finding(AttackCategory::SqlInjection, Action::Block)]);
        downgrade_monitored(&mut v, &[]);
        assert_eq!(v.action, Action::Block);
        assert_eq!(v.findings[0].action_hint, Action::Block);
    }

    #[test]
    fn monitored_category_downgrades_and_recomputes_the_action() {
        let mut v = verdict(vec![
            finding(AttackCategory::SqlInjection, Action::Block),
            finding(AttackCategory::Xss, Action::Block),
        ]);
        downgrade_monitored(&mut v, &["sqli".to_string()]);
        assert_eq!(v.findings[0].action_hint, Action::Monitor);
        assert_eq!(v.findings[1].action_hint, Action::Block);
        assert_eq!(v.action, Action::Block);
        // Score is kept (recorded, not enforced).
        assert_eq!(v.score, 40);

        downgrade_monitored(&mut v, &["sqli".to_string(), "xss".into()]);
        assert_eq!(v.action, Action::Monitor);
    }

    #[test]
    fn weaker_hints_are_never_escalated() {
        let mut v = verdict(vec![finding(AttackCategory::Xss, Action::Log)]);
        downgrade_monitored(&mut v, &["xss".to_string()]);
        assert_eq!(v.findings[0].action_hint, Action::Log);
        assert_eq!(v.action, Action::Log);
    }

    #[test]
    fn names_cover_the_dashboard_taxonomy() {
        assert_eq!(monitor_name(AttackCategory::SqlInjection), Some("sqli"));
        assert_eq!(monitor_name(AttackCategory::Log4Shell), Some("rce"));
        assert_eq!(monitor_name(AttackCategory::CommandInjection), Some("rce"));
        assert_eq!(monitor_name(AttackCategory::PathTraversal), Some("lfi"));
        assert_eq!(monitor_name(AttackCategory::LfiRfi), Some("lfi"));
        assert_eq!(monitor_name(AttackCategory::Xxe), Some("xxe"));
        // Categories outside the dashboard list cannot be downgraded.
        assert_eq!(monitor_name(AttackCategory::CredentialAbuse), None);
        assert_eq!(monitor_name(AttackCategory::SensitiveDataExposure), None);
        assert_eq!(monitor_name(AttackCategory::BotActivity), None);
    }

    #[test]
    fn name_matching_is_case_insensitive() {
        let mut v =
            verdict(vec![finding(AttackCategory::SqlInjection, Action::Block)]);
        downgrade_monitored(&mut v, &[" SQLI ".to_string()]);
        assert_eq!(v.action, Action::Monitor);
    }
}
