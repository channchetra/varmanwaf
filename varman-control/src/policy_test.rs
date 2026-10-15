//! Rule tester: evaluate one sample request against a candidate policy.
//!
//! The tester compiles the exact native engine configuration the edge would
//! receive (managed rules, custom rules, monitor/disable/score tuning,
//! target exclusions and SecLang virtual patches) and evaluates a sample
//! request against it. What it does **not** simulate is listed in
//! [`TestResult::skipped`]: rate limits, IP/geo access and bot checks are
//! edge decisions that depend on request history, so a tester that guessed
//! them would lie. The compile step mirrors `grpc::config` field by field.

use std::collections::{BTreeMap, HashSet};

use serde::{Deserialize, Serialize};
use varman_waf::canonical::CanonicalRequest;
use varman_waf::engine::{RequestData, WafEngine, WafEngineConfig, WafMode};
use varman_waf::seclang::{SecLangTransaction, SecRuleSet};
use varman_waf::{
    CategorySet, CompiledRule, RuleAction, StackSet, WafAction, WafLevel,
};

use crate::policy::EffectiveEngine;

/// A sample request to evaluate.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct TestRequestInput {
    #[serde(default = "default_method")]
    pub method: String,
    /// Request path; must start with `/`.
    pub path: String,
    #[serde(default)]
    pub query: String,
    #[serde(default)]
    pub headers: BTreeMap<String, String>,
    #[serde(default)]
    pub body: String,
    #[serde(default = "default_client_ip")]
    pub client_ip: String,
    /// Host header; empty means a placeholder is used.
    #[serde(default)]
    pub host: String,
}

fn default_method() -> String {
    "GET".to_string()
}

fn default_client_ip() -> String {
    "203.0.113.10".to_string()
}

/// One rule that contributed to the verdict.
#[derive(Clone, Debug, Serialize)]
pub struct TestHit {
    pub id: String,
    pub name: String,
    /// `managed`, `policy`, `site` or `patch`.
    pub source: &'static str,
    /// The rule's own action, or `patch` for SecLang hits.
    pub action: String,
    /// True when a monitor/disable/score override shaped the outcome.
    pub tuned: bool,
}

/// The tester's verdict.
#[derive(Clone, Debug, Serialize)]
pub struct TestResult {
    /// `pass`, `monitor`, `block` or `challenge`.
    pub action: &'static str,
    pub score: u8,
    pub details: String,
    pub matched_rules: Vec<TestHit>,
    /// Human notes about tuning that applied.
    pub notes: Vec<String>,
    /// What the evaluation covered.
    pub simulated: Vec<String>,
    /// Edge decisions the tester does not simulate.
    pub skipped: Vec<String>,
}

fn waf_mode(effective: &EffectiveEngine) -> WafMode {
    match effective.mode.as_deref() {
        Some("off") => WafMode::Off,
        Some("monitor") => WafMode::Monitor,
        // No explicit mode: the edge derives it from the rules; the tester
        // mirrors that by defaulting to blocking once rules exist.
        _ => WafMode::Block,
    }
}

fn parse_categories(names: &[String]) -> CategorySet {
    let mut set = CategorySet::EMPTY;
    for name in names {
        if let Some(category) = CategorySet::parse_name(name) {
            set = set.union(category);
        }
    }
    set
}

fn parse_stacks(names: &[String]) -> StackSet {
    let mut set = StackSet::EMPTY;
    for name in names {
        if let Some(stack) = StackSet::parse_name(name) {
            set = set.union(stack);
        }
    }
    set
}

/// Builds the engine configuration the edge would receive for the
/// candidate policy (`effective`) plus the compiled custom rules.
pub fn engine_config(
    effective: &EffectiveEngine,
    rules: Vec<CompiledRule>,
) -> WafEngineConfig {
    WafEngineConfig {
        mode: waf_mode(effective),
        level: if effective.advanced_mode {
            WafLevel::Strict
        } else {
            WafLevel::Normal
        },
        stacks: StackSet::default(),
        monitor_categories: parse_categories(&effective.monitor_categories),
        monitor_stacks: parse_stacks(&effective.monitor_stacks),
        threshold: 40,
        paranoia_level: effective.paranoia_level.clamp(1, 4) as u8,
        max_decode_layers: 3,
        rules,
        enable_managed_rules: true,
        fast_path_block_on_critical: true,
        monitor_managed_rules: effective
            .monitor_managed_rules
            .iter()
            .cloned()
            .collect::<HashSet<_>>(),
        monitor_custom_rules: HashSet::new(),
        disabled_rules: effective
            .disabled_rules
            .iter()
            .cloned()
            .collect::<HashSet<_>>(),
        rule_scores: effective.rule_scores.clone().into_iter().collect(),
        rule_target_exclusions: effective
            .rule_target_exclusions
            .clone()
            .into_iter()
            .collect(),
        path_target_exclusions: Vec::new(),
    }
}

/// Compiles one custom rule (policy or site) into an engine rule.
pub fn compile_rule(
    id: &str,
    name: &str,
    expression: &str,
    action: &str,
    mode: &str,
    severity: u8,
    tags: &[String],
) -> Option<CompiledRule> {
    compile_rule_result(id, name, expression, action, mode, severity, tags).ok()
}

/// [`compile_rule`] keeping the compile error, so draft rules can report
/// *why* they were not evaluated instead of silently not matching.
pub fn compile_rule_result(
    id: &str,
    name: &str,
    expression: &str,
    action: &str,
    mode: &str,
    severity: u8,
    tags: &[String],
) -> Result<CompiledRule, String> {
    let action = match action {
        "block" => RuleAction::Block,
        "log" => RuleAction::Log,
        "challenge" => RuleAction::Challenge,
        "js_challenge" => RuleAction::JsChallenge,
        "allow" => RuleAction::Allow,
        other => return Err(format!("unknown action '{other}'")),
    };
    // A rule in `monitor` mode is downgraded through the monitor set; the
    // id membership is applied by the caller.
    let _ = mode;
    CompiledRule::compile(
        id.to_string(),
        name.to_string(),
        expression,
        action,
        severity,
        tags.to_vec(),
    )
    .map_err(|err| err.to_string())
}

/// Evaluates one request against the compiled configuration.
pub fn evaluate(
    config: &WafEngineConfig,
    patches: Option<&str>,
    request: &TestRequestInput,
    rule_sources: &BTreeMap<String, (String, &'static str)>,
) -> TestResult {
    let engine = WafEngine::new(config);
    let waf_request = RequestData {
        method: request.method.clone(),
        path: request.path.clone(),
        query: request.query.clone(),
        headers: request
            .headers
            .iter()
            .map(|(name, value)| (name.clone(), value.clone()))
            .collect(),
        body: (!request.body.is_empty())
            .then(|| request.body.clone().into_bytes()),
        client_ip: request.client_ip.clone(),
        country_code: None,
        scheme: "https".into(),
        protocol: "HTTP/1.1".into(),
    };
    let verdict = engine.inspect(&waf_request);

    let mut matched: Vec<TestHit> = Vec::new();
    for id in &verdict.matched_rules {
        let (name, source) = rule_sources
            .get(id)
            .cloned()
            .unwrap_or_else(|| (id.clone(), "managed"));
        let (action, tuned) = match source {
            "managed" => {
                let monitored =
                    config.monitor_managed_rules.contains(id.as_str());
                let disabled = config.disabled_rules.contains(id.as_str());
                let tuned = monitored
                    || disabled
                    || config.rule_scores.contains_key(id.as_str());
                (
                    if disabled {
                        "disabled".to_string()
                    } else if monitored {
                        "monitor".to_string()
                    } else {
                        "block".to_string()
                    },
                    tuned,
                )
            },
            _ => {
                let monitored =
                    config.monitor_custom_rules.contains(id.as_str());
                (
                    if monitored {
                        "monitor".to_string()
                    } else {
                        "block".to_string()
                    },
                    monitored,
                )
            },
        };
        matched.push(TestHit {
            id: id.clone(),
            name,
            source,
            action,
            tuned,
        });
    }

    let mut action = match verdict.action {
        WafAction::Pass => "pass",
        WafAction::Monitor => "monitor",
        WafAction::Block => "block",
        WafAction::Challenge => "challenge",
    };

    // SecLang virtual patches escalate only, mirroring the edge.
    if let Some(source) = patches.filter(|source| !source.trim().is_empty()) {
        match SecRuleSet::from_source(source) {
            Ok(rules) => {
                let canonical = canonical_request(request);
                let mut txn = SecLangTransaction::from_request(&canonical);
                let hits = rules.evaluate(&mut txn);
                let mut blocking = false;
                for hit in &hits {
                    let disruptive = hit.actions.iter().any(|candidate| {
                        let candidate = candidate.trim();
                        candidate.eq_ignore_ascii_case("block")
                            || candidate.eq_ignore_ascii_case("deny")
                            || candidate.eq_ignore_ascii_case("drop")
                    });
                    let ids = hit
                        .rule_ids
                        .iter()
                        .flatten()
                        .map(|id| id.to_string())
                        .collect::<Vec<_>>();
                    if disruptive {
                        blocking = true;
                    }
                    matched.push(TestHit {
                        id: ids.join(","),
                        name: if disruptive {
                            "virtual patch (blocking)".to_string()
                        } else {
                            "virtual patch".to_string()
                        },
                        source: "patch",
                        action: if disruptive {
                            "block".to_string()
                        } else {
                            "log".to_string()
                        },
                        tuned: false,
                    });
                }
                if blocking {
                    action = "block";
                }
            },
            Err(error) => matched.push(TestHit {
                id: String::new(),
                name: format!("virtual patch failed to compile: {error}"),
                source: "patch",
                action: "none".to_string(),
                tuned: false,
            }),
        }
    }

    let mut notes = Vec::new();
    if !config.disabled_rules.is_empty() {
        notes.push(format!(
            "{} managed rule(s) disabled",
            config.disabled_rules.len()
        ));
    }
    if !config.rule_scores.is_empty() {
        notes.push(format!(
            "{} rule score override(s) applied",
            config.rule_scores.len()
        ));
    }
    if !config.monitor_managed_rules.is_empty() {
        notes.push(format!(
            "{} managed rule(s) in monitor mode",
            config.monitor_managed_rules.len()
        ));
    }
    if !config.monitor_custom_rules.is_empty() {
        notes.push(format!(
            "{} custom rule(s) in monitor mode",
            config.monitor_custom_rules.len()
        ));
    }

    TestResult {
        action,
        score: verdict.score,
        details: verdict.details,
        matched_rules: matched,
        notes,
        simulated: vec![
            "managed rules (with monitor/disable/score overrides and target exclusions)".to_string(),
            "policy and site custom rules".to_string(),
            "SecLang virtual patches".to_string(),
        ],
        skipped: vec![
            "rate limits (need request history)".to_string(),
            "IP/geo access rules (need the real client address)".to_string(),
            "bot checks (need UA/TLS/behaviour data)".to_string(),
        ],
    }
}

fn canonical_request(request: &TestRequestInput) -> CanonicalRequest {
    let authority = if request.host.is_empty() {
        "probe.local"
    } else {
        request.host.as_str()
    };
    let mut raw = request.path.clone();
    if !request.query.is_empty() {
        raw.push('?');
        raw.push_str(&request.query);
    }
    let mut canonical = CanonicalRequest::new(
        request.method.clone(),
        authority.to_string(),
        raw,
    );
    for (name, value) in &request.headers {
        canonical = canonical.with_header(name.clone(), value.clone());
    }
    if !request.body.is_empty() {
        canonical = canonical.with_body(request.body.clone().into_bytes());
    }
    canonical
}

#[cfg(test)]
mod tests {
    use super::*;

    fn request(path: &str) -> TestRequestInput {
        TestRequestInput {
            method: "GET".into(),
            path: path.into(),
            query: String::new(),
            headers: BTreeMap::new(),
            body: String::new(),
            client_ip: "203.0.113.10".into(),
            host: "example.com".into(),
        }
    }

    #[test]
    fn draft_compile_errors_are_reported() {
        // A draft rule with a broken expression keeps its error so the
        // tester can say why it was not evaluated.
        let error = compile_rule_result(
            "draft:0",
            "Broken",
            "http.request.uri.path ???",
            "block",
            "block",
            3,
            &[],
        )
        .expect_err("expression must not compile");
        assert!(!error.is_empty());

        // An unknown action is also an error, not a silent skip.
        assert!(compile_rule_result(
            "draft:1",
            "Bad action",
            "http.request.uri.path eq \"/x\"",
            "explode",
            "block",
            3,
            &[],
        )
        .is_err());

        // A valid draft compiles and carries its id.
        let compiled = compile_rule_result(
            "draft:2",
            "Fine",
            "http.request.uri.path eq \"/x\"",
            "challenge",
            "block",
            3,
            &[],
        )
        .expect("valid draft compiles");
        assert_eq!(compiled.id, "draft:2");
    }

    #[test]
    fn a_policy_rule_blocks_its_path() {
        let effective = EffectiveEngine {
            waf_enabled: true,
            mode: Some("block".into()),
            paranoia_level: 2,
            advanced_mode: false,
            engine_mode: "inherit".into(),
            monitor_categories: Vec::new(),
            monitor_stacks: Vec::new(),
            monitor_managed_rules: Vec::new(),
            disabled_rules: Vec::new(),
            rule_scores: BTreeMap::new(),
            rule_target_exclusions: BTreeMap::new(),
        };
        let rule = compile_rule(
            "policy:test:0",
            "Block probe",
            "http.request.uri.path eq \"/probe\"",
            "block",
            "block",
            4,
            &[],
        )
        .expect("rule compiles");
        let config = engine_config(&effective, vec![rule]);
        let sources = BTreeMap::from([(
            "policy:test:0".to_string(),
            ("Block probe".to_string(), "policy"),
        )]);

        let hit = evaluate(&config, None, &request("/probe"), &sources);
        assert_eq!(hit.action, "block");
        assert!(hit
            .matched_rules
            .iter()
            .any(|rule| rule.id == "policy:test:0" && rule.source == "policy"));

        let clean = evaluate(&config, None, &request("/safe"), &sources);
        assert_eq!(clean.action, "pass");
        assert!(clean.matched_rules.is_empty());
    }

    #[test]
    fn monitor_tuning_is_visible_in_the_result() {
        let mut effective = EffectiveEngine {
            waf_enabled: true,
            mode: Some("block".into()),
            paranoia_level: 2,
            advanced_mode: false,
            engine_mode: "inherit".into(),
            monitor_categories: Vec::new(),
            monitor_stacks: Vec::new(),
            monitor_managed_rules: vec!["VARMAN-1020".into()],
            disabled_rules: vec!["VARMAN-1010".into()],
            rule_scores: BTreeMap::from([("VARMAN-1021".to_string(), 1u32)]),
            rule_target_exclusions: BTreeMap::new(),
        };
        effective.mode = Some("monitor".into());
        let config = engine_config(&effective, Vec::new());
        // A dotfile probe is the managed rule that is monitored here.
        let result =
            evaluate(&config, None, &request("/.git/config"), &BTreeMap::new());
        assert_eq!(result.action, "monitor");
        assert!(result
            .matched_rules
            .iter()
            .any(|hit| hit.id == "VARMAN-1020" && hit.tuned));
        assert!(!result.notes.is_empty());
        assert!(!result.skipped.is_empty());
    }

    #[test]
    fn a_seclang_patch_escalates_the_verdict() {
        let effective = EffectiveEngine {
            waf_enabled: true,
            mode: Some("monitor".into()),
            paranoia_level: 2,
            advanced_mode: false,
            engine_mode: "inherit".into(),
            monitor_categories: Vec::new(),
            monitor_stacks: Vec::new(),
            monitor_managed_rules: Vec::new(),
            disabled_rules: Vec::new(),
            rule_scores: BTreeMap::new(),
            rule_target_exclusions: BTreeMap::new(),
        };
        let config = engine_config(&effective, Vec::new());
        let patch = "SecRule REQUEST_URI \"@contains /vp-block\" \
                     \"id:900001,phase:1,block,msg:'test patch'\"";
        let result = evaluate(
            &config,
            Some(patch),
            &request("/vp-block"),
            &BTreeMap::new(),
        );
        assert_eq!(result.action, "block");
        assert!(result.matched_rules.iter().any(|hit| hit.source == "patch"));

        // A broken patch is reported, not silently skipped.
        let broken = evaluate(
            &config,
            Some("SecRule BOGUS x y"),
            &request("/"),
            &BTreeMap::new(),
        );
        assert!(broken
            .matched_rules
            .iter()
            .any(|hit| hit.name.contains("failed to compile")));
    }
}
