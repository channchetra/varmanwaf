//! WAF policies: named, revisioned, layered configuration shared by sites.
//!
//! A policy carries up to one document per layer kind:
//!
//! - `engine` - the posture knobs of `waf_settings` (switch, mode, paranoia,
//!   advanced mode, engine selection, monitor-only sets).
//! - `crs` - the managed-rule monitor list.
//! - `custom_rules` - an ordered, reusable custom-rule list.
//!
//! Sites opt in through `site_waf_policies`; `site_waf_policy_overrides`
//! carries a site's sparse deltas on top. Resolution precedence is
//! **overlay > policy > the site's own settings**, so a site that is not
//! assigned to any policy behaves exactly as it did before policies existed.
//!
//! Everything a layer can say is validated here before it is stored
//! ([`validate_layer`]) and parsed back without re-validation on the hot
//! bundle path ([`resolve`], [`Resolved::effective_engine`]).

use std::collections::BTreeMap;
use std::sync::LazyLock;

use chrono::Utc;
use sea_orm::{
    ActiveModelTrait, ColumnTrait, DatabaseConnection, DbErr, EntityTrait,
    QueryFilter, QueryOrder, Set,
};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use uuid::Uuid;

use crate::api::waf_settings::{CATEGORIES, ENGINE_MODES, MANAGED_RULES, STACKS};
use crate::models::{
    action, mode, site_waf_policy, site_waf_policy_override, waf_policy,
    waf_policy_layer, waf_policy_version, waf_settings,
};

/// Engine layer kind: posture knobs, same meaning as `waf_settings`.
pub const LAYER_ENGINE: &str = "engine";
/// CRS layer kind: managed-ruleset tuning (monitor downgrades for now).
pub const LAYER_CRS: &str = "crs";
/// Custom-rules layer kind: `{ "rules": [ ... ] }`, ordered as written.
pub const LAYER_CUSTOM_RULES: &str = "custom_rules";
/// Rule-overrides layer kind: `{ "overrides": [ ... ] }`, per-managed-rule
/// tuning (disable / monitor / score override) in data.
pub const LAYER_RULE_OVERRIDES: &str = "rule_overrides";
/// Virtual-patches layer kind: `{ "source": "<seclang>" }`.
pub const LAYER_VIRTUAL_PATCHES: &str = "virtual_patches";
/// API-schema layer kind: `{ "openapi_spec": "<json>" }`.
pub const LAYER_API_SCHEMA: &str = "api_schema";
/// Rate-limit layer kind: `{ "rules": [ ... ] }`, shared rate limits.
pub const LAYER_RATE_LIMIT: &str = "rate_limit";
/// IP-access layer kind: `{ "rules": [ ... ] }`, shared allow/block rules.
pub const LAYER_IP_ACCESS: &str = "ip_access";
/// Bot-protection layer kind: bot posture overrides.
pub const LAYER_BOT: &str = "bot";
/// CRS-import layer kind: `{ "ruleset_id": "<uuid>", … }` binding an
/// imported CRS ruleset (with optional paranoia ceiling and categories)
/// to the policy.
pub const LAYER_CRS_IMPORT: &str = "crs_import";

/// Every layer kind a policy (or a site override) may carry.
pub const LAYER_KINDS: [&str; 10] = [
    LAYER_ENGINE,
    LAYER_CRS,
    LAYER_CUSTOM_RULES,
    LAYER_RULE_OVERRIDES,
    LAYER_VIRTUAL_PATCHES,
    LAYER_API_SCHEMA,
    LAYER_RATE_LIMIT,
    LAYER_IP_ACCESS,
    LAYER_BOT,
    LAYER_CRS_IMPORT,
];

/// Longest accepted custom rule expression.
const MAX_EXPRESSION_LEN: usize = 4096;
/// Longest accepted rule name / description / tag.
const MAX_NAME_LEN: usize = 120;
const MAX_DESCRIPTION_LEN: usize = 512;
const MAX_TAG_LEN: usize = 64;
/// Upper bounds that keep one layer payload bounded.
const MAX_RULES_PER_LAYER: usize = 200;
const MAX_TAGS_PER_RULE: usize = 16;
const MAX_OVERRIDES_PER_LAYER: usize = 200;
/// Bound on stored SecLang virtual-patch source (64 KiB).
pub const MAX_VIRTUAL_PATCH_BYTES: usize = 64 * 1024;
/// Bound on the stored OpenAPI document (1 MiB).
pub const MAX_OPENAPI_BYTES: usize = 1024 * 1024;

/// Actions a managed-rule override can take.
pub mod override_action {
    /// Clears an override; only meaningful in a site overlay, where it
    /// removes the policy's entry for that rule.
    pub const DEFAULT: &str = "default";
    /// Skips the rule entirely: no match, no score, no event.
    pub const DISABLE: &str = "disable";
    /// Matches and records the rule, never enforces its action.
    pub const MONITOR: &str = "monitor";
    /// Replaces the rule's anomaly contribution with `score`; the rule's
    /// own action still applies.
    pub const SCORE_OVERRIDE: &str = "score_override";

    /// Every accepted action, in documentation order.
    pub const ALL: [&str; 4] = [DEFAULT, DISABLE, MONITOR, SCORE_OVERRIDE];
}

/// One managed-rule tuning entry inside a `rule_overrides` layer.
///
/// The entry addresses rules in exactly one of three ways: by `rule_id`
/// (a single managed rule), by `tags` (every catalogue rule carrying any of
/// the tags) or by `severity_min` (every rule at or above the level).
/// Selector entries expand at resolution time; exact rule-id entries apply
/// afterwards and therefore always win.
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RuleOverrideEntry {
    /// Managed rule id (`VARMAN-…`); empty when a selector is used.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub rule_id: String,
    /// Selector: rules carrying any of these tags.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub tags: Vec<String>,
    /// Selector: rules with severity at or above this level.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub severity_min: Option<u8>,
    pub action: String,
    /// Required for `score_override`; rejected for the other actions.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub score: Option<u32>,
    /// Request targets excluded from the addressed rules' evaluation.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub exclude_targets: Vec<String>,
}

/// Request targets a rule override may exclude from evaluation.
pub const EXCLUSION_TARGETS: [&str; 8] = [
    "path",
    "query",
    "body",
    "header",
    "cookie",
    "user_agent",
    "host",
    "method",
];

/// The managed-rule catalogue, built once: selector expansion and tag
/// validation read it on every resolution.
static CATALOGUE: LazyLock<Vec<varman_waf::ManagedRuleInfo>> = LazyLock::new(
    || varman_waf::managed_rule_catalogue(varman_waf::WafLevel::Strict),
);

/// Every tag the catalogue knows, for selector validation.
fn catalogue_tags() -> std::collections::BTreeSet<&'static str> {
    CATALOGUE
        .iter()
        .flat_map(|info| info.tags.iter().map(String::as_str))
        .collect()
}

impl RuleOverrideEntry {
    fn validate(&self) -> Result<(), String> {
        let addressings = usize::from(!self.rule_id.is_empty())
            + usize::from(!self.tags.is_empty())
            + usize::from(self.severity_min.is_some());
        if addressings != 1 {
            return Err(
                "exactly one of 'rule_id', 'tags' or 'severity_min' is required"
                    .to_string(),
            );
        }
        if !self.rule_id.is_empty() && !MANAGED_RULES.contains(&self.rule_id.as_str()) {
            return Err(format!(
                "unknown managed rule '{}' (expected one of: {})",
                self.rule_id,
                MANAGED_RULES.join(", ")
            ));
        }
        for tag in &self.tags {
            if tag.trim().is_empty() || tag.chars().count() > 64 {
                return Err("each tag must be 1-64 characters".to_string());
            }
            if !catalogue_tags().contains(tag.as_str()) {
                return Err(format!(
                    "unknown tag '{tag}' (expected one of: {})",
                    catalogue_tags().into_iter().collect::<Vec<_>>().join(", ")
                ));
            }
        }
        if let Some(min) = self.severity_min {
            if !(1..=5).contains(&min) {
                return Err(
                    "'severity_min' must be between 1 and 5".to_string()
                );
            }
        }
        if !override_action::ALL.contains(&self.action.as_str()) {
            return Err(format!(
                "unknown action '{}' (expected one of: {})",
                self.action,
                override_action::ALL.join(", ")
            ));
        }
        match (self.action.as_str(), self.score) {
            (override_action::SCORE_OVERRIDE, Some(score)) => {
                if !(1..=255).contains(&score) {
                    return Err("'score' must be between 1 and 255".to_string());
                }
            }
            (override_action::SCORE_OVERRIDE, None) => {
                return Err(
                    "'score' is required for the score_override action".to_string()
                );
            }
            (_, Some(_)) => {
                return Err(
                    "'score' is only valid with the score_override action"
                        .to_string(),
                );
            }
            _ => {}
        }
        for target in &self.exclude_targets {
            if !EXCLUSION_TARGETS.contains(&target.as_str()) {
                return Err(format!(
                    "unknown exclusion target '{target}' (expected one of: {})",
                    EXCLUSION_TARGETS.join(", ")
                ));
            }
        }
        Ok(())
    }
}

/// True when `kind` names a layer this build understands.
pub fn is_layer_kind(kind: &str) -> bool {
    LAYER_KINDS.contains(&kind)
}

/// One custom rule authored inside a policy or site override.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PolicyRule {
    pub name: String,
    #[serde(default)]
    pub description: String,
    pub expression: String,
    pub action: String,
    #[serde(default = "default_severity")]
    pub severity: u8,
    #[serde(default)]
    pub tags: Vec<String>,
    #[serde(default = "default_enabled")]
    pub enabled: bool,
    #[serde(default = "default_rule_mode")]
    pub mode: String,
    #[serde(default)]
    pub priority: i32,
}

fn default_severity() -> u8 {
    3
}

fn default_enabled() -> bool {
    true
}

fn default_rule_mode() -> String {
    mode::BLOCK.to_string()
}

impl PolicyRule {
    /// Semantic checks serde cannot express (ranges, membership, lengths).
    fn validate(&self) -> Result<(), String> {
        if self.name.trim().is_empty() {
            return Err("'name' must not be empty".to_string());
        }
        if self.name.chars().count() > MAX_NAME_LEN {
            return Err(format!("'name' must be at most {MAX_NAME_LEN} characters"));
        }
        if self.expression.trim().is_empty() {
            return Err("'expression' must not be empty".to_string());
        }
        if self.expression.len() > MAX_EXPRESSION_LEN {
            return Err(format!(
                "'expression' must be at most {MAX_EXPRESSION_LEN} bytes"
            ));
        }
        if self.description.chars().count() > MAX_DESCRIPTION_LEN {
            return Err(format!(
                "'description' must be at most {MAX_DESCRIPTION_LEN} characters"
            ));
        }
        if !action::is_valid(&self.action) {
            return Err(format!(
                "unknown action '{}' (expected one of: {})",
                self.action,
                action::ALL.join(", ")
            ));
        }
        if !(1..=5).contains(&self.severity) {
            return Err("'severity' must be between 1 and 5".to_string());
        }
        if !mode::is_valid(&self.mode) {
            return Err(format!(
                "unknown mode '{}' (expected one of: off, monitor, block)",
                self.mode
            ));
        }
        if self.tags.len() > MAX_TAGS_PER_RULE {
            return Err(format!(
                "'tags' must hold at most {MAX_TAGS_PER_RULE} entries"
            ));
        }
        for tag in &self.tags {
            if tag.trim().is_empty() || tag.chars().count() > MAX_TAG_LEN {
                return Err(format!(
                    "each tag must be 1-{MAX_TAG_LEN} characters"
                ));
            }
        }
        Ok(())
    }
}

/// Validates one layer payload against its kind's schema.
///
/// Unknown kinds and unknown keys are rejected: a typo must fail at write
/// time instead of silently never taking effect at the edge.
pub fn validate_layer(kind: &str, config: &Value) -> Result<(), String> {
    match kind {
        LAYER_ENGINE => validate_engine(config),
        LAYER_CRS => validate_crs(config),
        LAYER_CUSTOM_RULES => validate_custom_rules(config),
        LAYER_RULE_OVERRIDES => validate_rule_overrides(config),
        LAYER_VIRTUAL_PATCHES => validate_virtual_patches(config),
        LAYER_API_SCHEMA => validate_api_schema(config),
        LAYER_RATE_LIMIT => validate_rate_limit(config),
        LAYER_IP_ACCESS => validate_ip_access(config),
        LAYER_BOT => validate_bot(config),
        LAYER_CRS_IMPORT => validate_crs_import(config),
        other => Err(format!(
            "unknown layer kind '{other}' (expected one of: {})",
            LAYER_KINDS.join(", ")
        )),
    }
}

fn as_object<'a>(kind: &str, config: &'a Value) -> Result<&'a Map<String, Value>, String> {
    config
        .as_object()
        .ok_or_else(|| format!("the {kind} layer must be a JSON object"))
}

fn expect_bool(key: &str, value: &Value) -> Result<bool, String> {
    value
        .as_bool()
        .ok_or_else(|| format!("'{key}' must be a boolean"))
}

fn expect_str<'a>(key: &str, value: &'a Value) -> Result<&'a str, String> {
    value
        .as_str()
        .ok_or_else(|| format!("'{key}' must be a string"))
}

fn expect_i64(key: &str, value: &Value) -> Result<i64, String> {
    value
        .as_i64()
        .ok_or_else(|| format!("'{key}' must be an integer"))
}

/// Validates a string array whose entries must come from `allowed`
/// (duplicates collapse; order is kept).
fn expect_subset(
    key: &str,
    value: &Value,
    allowed: &[&str],
) -> Result<Vec<String>, String> {
    let items = value
        .as_array()
        .ok_or_else(|| format!("'{key}' must be an array of strings"))?;
    let mut out: Vec<String> = Vec::with_capacity(items.len());
    for item in items {
        let entry = item
            .as_str()
            .ok_or_else(|| format!("'{key}' must be an array of strings"))?;
        if !allowed.contains(&entry) {
            return Err(format!(
                "unknown value '{entry}' for '{key}' (expected one of: {})",
                allowed.join(", ")
            ));
        }
        if !out.iter().any(|seen| seen == entry) {
            out.push(entry.to_string());
        }
    }
    Ok(out)
}

fn validate_engine(config: &Value) -> Result<(), String> {
    let map = as_object(LAYER_ENGINE, config)?;
    for (key, value) in map {
        match key.as_str() {
            "waf_enabled" | "advanced_mode" => {
                expect_bool(key, value)?;
            }
            "mode" => {
                let mode = expect_str(key, value)?;
                if !mode::is_valid(mode) {
                    return Err(format!(
                        "unknown mode '{mode}' (expected one of: off, monitor, block)"
                    ));
                }
            }
            "paranoia_level" => {
                let level = expect_i64(key, value)?;
                if !(1..=4).contains(&level) {
                    return Err("'paranoia_level' must be between 1 and 4".to_string());
                }
            }
            "engine_mode" => {
                let engine = expect_str(key, value)?;
                if !ENGINE_MODES.contains(&engine) {
                    return Err(format!(
                        "unknown engine_mode '{engine}' (expected one of: {})",
                        ENGINE_MODES.join(", ")
                    ));
                }
            }
            "monitor_categories" => {
                expect_subset(key, value, &CATEGORIES)?;
            }
            "monitor_stacks" => {
                expect_subset(key, value, &STACKS)?;
            }
            other => {
                return Err(format!("unknown engine key '{other}'"));
            }
        }
    }
    Ok(())
}

fn validate_crs(config: &Value) -> Result<(), String> {
    let map = as_object(LAYER_CRS, config)?;
    for (key, value) in map {
        match key.as_str() {
            "monitor_managed_rules" => {
                expect_subset(key, value, &MANAGED_RULES)?;
            }
            other => {
                return Err(format!("unknown crs key '{other}'"));
            }
        }
    }
    Ok(())
}

fn validate_custom_rules(config: &Value) -> Result<(), String> {
    let map = as_object(LAYER_CUSTOM_RULES, config)?;
    for (key, value) in map {
        match key.as_str() {
            "rules" => {
                let items = value.as_array().ok_or_else(|| {
                    "'rules' must be an array of rule objects".to_string()
                })?;
                if items.len() > MAX_RULES_PER_LAYER {
                    return Err(format!(
                        "'rules' must hold at most {MAX_RULES_PER_LAYER} entries"
                    ));
                }
                for (index, item) in items.iter().enumerate() {
                    parse_rule(item)
                        .map_err(|err| format!("rules[{index}]: {err}"))?;
                }
            }
            other => {
                return Err(format!("unknown custom_rules key '{other}'"));
            }
        }
    }
    Ok(())
}

/// Parses and validates one custom-rule object.
fn parse_rule(value: &Value) -> Result<PolicyRule, String> {
    let rule: PolicyRule = serde_json::from_value(value.clone())
        .map_err(|err| err.to_string())?;
    rule.validate()?;
    Ok(rule)
}

/// Parses a validated `custom_rules` payload into rules.
///
/// Stored payloads were validated on write; a later schema change that
/// cannot parse an old entry drops it rather than breaking every bundle.
fn parse_rules(config: &Value) -> Vec<PolicyRule> {
    config
        .get("rules")
        .and_then(Value::as_array)
        .map(|items| {
            items
                .iter()
                .filter_map(|item| {
                    serde_json::from_value::<PolicyRule>(item.clone()).ok()
                })
                .collect()
        })
        .unwrap_or_default()
}

/// Parses a validated `custom_rules` payload into rules (public wrapper for
/// the recipe merge path).
pub fn rules_from_layer(config: &Value) -> Vec<PolicyRule> {
    parse_rules(config)
}

fn validate_virtual_patches(config: &Value) -> Result<(), String> {
    let map = as_object(LAYER_VIRTUAL_PATCHES, config)?;
    for (key, value) in map {
        match key.as_str() {
            "source" => {
                let source = expect_str(key, value)?;
                if source.len() > MAX_VIRTUAL_PATCH_BYTES {
                    return Err(format!(
                        "'source' must be at most {MAX_VIRTUAL_PATCH_BYTES} bytes"
                    ));
                }
            }
            other => {
                return Err(format!("unknown virtual_patches key '{other}'"));
            }
        }
    }
    Ok(())
}

fn validate_api_schema(config: &Value) -> Result<(), String> {
    let map = as_object(LAYER_API_SCHEMA, config)?;
    for (key, value) in map {
        match key.as_str() {
            "openapi_spec" => {
                let spec = expect_str(key, value)?;
                if spec.len() > MAX_OPENAPI_BYTES {
                    return Err(format!(
                        "'openapi_spec' must be at most {MAX_OPENAPI_BYTES} bytes"
                    ));
                }
                if !spec.trim().is_empty() {
                    let parsed: Value = serde_json::from_str(spec)
                        .map_err(|err| {
                            format!("'openapi_spec' must be a JSON document: {err}")
                        })?;
                    let object = parsed.as_object().ok_or_else(|| {
                        "'openapi_spec' must be a JSON object".to_string()
                    })?;
                    // Engine parity: the data plane rejects a document
                    // without a `paths` object, so the write is refused too.
                    if !object
                        .get("paths")
                        .is_some_and(Value::is_object)
                    {
                        return Err(
                            "'openapi_spec' must contain a 'paths' object"
                                .to_string(),
                        );
                    }
                }
            }
            other => {
                return Err(format!("unknown api_schema key '{other}'"));
            }
        }
    }
    Ok(())
}

fn validate_crs_import(config: &Value) -> Result<(), String> {
    let map = as_object(LAYER_CRS_IMPORT, config)?;
    for (key, value) in map {
        match key.as_str() {
            "ruleset_id" => {
                let raw = expect_str(key, value)?;
                if Uuid::parse_str(raw.trim()).is_err() {
                    return Err("'ruleset_id' must be a UUID".to_string());
                }
            }
            "paranoia_level_max" => {
                let level = expect_i64(key, value)?;
                if !(1..=4).contains(&level) {
                    return Err(
                        "'paranoia_level_max' must be between 1 and 4"
                            .to_string(),
                    );
                }
            }
            "categories" => {
                let items = value.as_array().ok_or_else(|| {
                    "'categories' must be an array of strings".to_string()
                })?;
                if items.len() > 20 {
                    return Err(
                        "'categories' must hold at most 20 entries".to_string()
                    );
                }
                for item in items {
                    let entry = item.as_str().ok_or_else(|| {
                        "'categories' must be an array of strings".to_string()
                    })?;
                    if entry.trim().is_empty() || entry.chars().count() > 64 {
                        return Err(
                            "each category must be 1-64 characters"
                                .to_string(),
                        );
                    }
                }
            }
            other => {
                return Err(format!("unknown crs_import key '{other}'"));
            }
        }
    }
    Ok(())
}

fn validate_bot(config: &Value) -> Result<(), String> {    let map = as_object(LAYER_BOT, config)?;
    for (key, value) in map {
        match key.as_str() {
            "enabled"
            | "js_detection"
            | "tls_fingerprint"
            | "behavioral_analysis"
            | "ip_verification_enabled"
            | "dns_verification_enabled" => {
                expect_bool(key, value)?;
            }
            "action" => {
                let action = expect_str(key, value)?;
                if !matches!(
                    action,
                    "block" | "challenge" | "js_challenge" | "log" | "allow"
                ) {
                    return Err(format!(
                        "unknown bot action '{action}' (expected one of: block, challenge, js_challenge, log, allow)"
                    ));
                }
            }
            "known_bots_whitelist" => {
                let items = value.as_array().ok_or_else(|| {
                    "'known_bots_whitelist' must be an array of strings"
                        .to_string()
                })?;
                if items.len() > 100 {
                    return Err(
                        "'known_bots_whitelist' must hold at most 100 entries"
                            .to_string(),
                    );
                }
                for item in items {
                    let entry = item.as_str().ok_or_else(|| {
                        "'known_bots_whitelist' must be an array of strings"
                            .to_string()
                    })?;
                    if entry.trim().is_empty() || entry.chars().count() > 128 {
                        return Err(
                            "each whitelist entry must be 1-128 characters"
                                .to_string(),
                        );
                    }
                }
            }
            other => {
                return Err(format!("unknown bot key '{other}'"));
            }
        }
    }
    Ok(())
}

fn validate_rate_limit(config: &Value) -> Result<(), String> {
    let map = as_object(LAYER_RATE_LIMIT, config)?;
    for (key, value) in map {
        match key.as_str() {
            "rules" => {
                let items = value.as_array().ok_or_else(|| {
                    "'rules' must be an array of rule objects".to_string()
                })?;
                if items.len() > 100 {
                    return Err(
                        "'rules' must hold at most 100 entries".to_string()
                    );
                }
                for (index, item) in items.iter().enumerate() {
                    validate_rate_limit_rule(item)
                        .map_err(|err| format!("rules[{index}]: {err}"))?;
                }
            }
            other => {
                return Err(format!("unknown rate_limit key '{other}'"));
            }
        }
    }
    Ok(())
}

fn validate_rate_limit_rule(value: &Value) -> Result<(), String> {
    let map = value
        .as_object()
        .ok_or_else(|| "each rule must be an object".to_string())?;
    for (key, value) in map {
        match key.as_str() {
            "name" => {
                let name = expect_str(key, value)?;
                if name.trim().is_empty() || name.chars().count() > 200 {
                    return Err(
                        "'name' must be 1-200 characters".to_string()
                    );
                }
            }
            "expression" => {
                let expression = expect_str(key, value)?;
                if expression.len() > 4096 {
                    return Err(
                        "'expression' must be at most 4096 bytes".to_string()
                    );
                }
            }
            "characteristics" => {
                let items = value.as_array().ok_or_else(|| {
                    "'characteristics' must be an array of strings".to_string()
                })?;
                if items.is_empty() || items.len() > 10 {
                    return Err(
                        "'characteristics' must hold 1-10 entries".to_string()
                    );
                }
                for item in items {
                    let entry = item.as_str().ok_or_else(|| {
                        "'characteristics' must be an array of strings"
                            .to_string()
                    })?;
                    if !crate::models::characteristic::is_valid(entry) {
                        return Err(format!(
                            "unknown rate limit characteristic '{entry}'"
                        ));
                    }
                }
            }
            "period_seconds" => {
                let period = expect_i64(key, value)?;
                if !(1..=86_400).contains(&period) {
                    return Err(
                        "'period_seconds' must be between 1 and 86400"
                            .to_string(),
                    );
                }
            }
            "threshold" => {
                let threshold = expect_i64(key, value)?;
                if !(1..=10_000_000).contains(&threshold) {
                    return Err(
                        "'threshold' must be between 1 and 10000000"
                            .to_string(),
                    );
                }
            }
            "action" => {
                let action = expect_str(key, value)?;
                if !action::is_valid(action) {
                    return Err(format!(
                        "unknown action '{action}' (expected one of: {})",
                        action::ALL.join(", ")
                    ));
                }
            }
            "mitigation_timeout_seconds" => {
                let mitigation = expect_i64(key, value)?;
                if !(0..=86_400).contains(&mitigation) {
                    return Err(
                        "'mitigation_timeout_seconds' must be between 0 and 86400"
                            .to_string(),
                    );
                }
            }
            "enabled" => {
                expect_bool(key, value)?;
            }
            "priority" => {
                let priority = expect_i64(key, value)?;
                if priority < 0 {
                    return Err("'priority' must not be negative".to_string());
                }
            }
            other => {
                return Err(format!("unknown rate limit rule key '{other}'"));
            }
        }
    }
    Ok(())
}

fn validate_ip_access(config: &Value) -> Result<(), String> {
    let map = as_object(LAYER_IP_ACCESS, config)?;
    for (key, value) in map {
        match key.as_str() {
            "rules" => {
                let items = value.as_array().ok_or_else(|| {
                    "'rules' must be an array of rule objects".to_string()
                })?;
                if items.len() > 200 {
                    return Err(
                        "'rules' must hold at most 200 entries".to_string()
                    );
                }
                for (index, item) in items.iter().enumerate() {
                    validate_ip_access_rule(item)
                        .map_err(|err| format!("rules[{index}]: {err}"))?;
                }
            }
            other => {
                return Err(format!("unknown ip_access key '{other}'"));
            }
        }
    }
    Ok(())
}

fn validate_ip_access_rule(value: &Value) -> Result<(), String> {
    let map = value
        .as_object()
        .ok_or_else(|| "each rule must be an object".to_string())?;
    for (key, value) in map {
        match key.as_str() {
            "name" => {
                let name = expect_str(key, value)?;
                if name.trim().is_empty() || name.chars().count() > 200 {
                    return Err(
                        "'name' must be 1-200 characters".to_string()
                    );
                }
            }
            "ip_ranges" => {
                let items = value.as_array().ok_or_else(|| {
                    "'ip_ranges' must be an array of strings".to_string()
                })?;
                if items.is_empty() {
                    return Err(
                        "'ip_ranges' must hold at least one range".to_string()
                    );
                }
                for item in items {
                    let entry = item.as_str().ok_or_else(|| {
                        "'ip_ranges' must be an array of strings".to_string()
                    })?;
                    let trimmed = entry.trim();
                    let base = trimmed.split('/').next().unwrap_or(trimmed);
                    if base.parse::<std::net::IpAddr>().is_err() {
                        return Err(format!(
                            "invalid IP address or CIDR: '{trimmed}'"
                        ));
                    }
                }
            }
            "action" => {
                let ip_action = expect_str(key, value)?;
                if !crate::api::ip_rules::ip_action::is_valid(ip_action) {
                    return Err(format!("unknown ip action '{ip_action}'"));
                }
            }
            "note" => {
                let note = expect_str(key, value)?;
                if note.chars().count() > 500 {
                    return Err(
                        "'note' must be at most 500 characters".to_string()
                    );
                }
            }
            "enabled" => {
                expect_bool(key, value)?;
            }
            other => {
                return Err(format!("unknown ip_access rule key '{other}'"));
            }
        }
    }
    Ok(())
}

fn validate_rule_overrides(config: &Value) -> Result<(), String> {
    let map = as_object(LAYER_RULE_OVERRIDES, config)?;
    for (key, value) in map {
        match key.as_str() {
            "overrides" => {
                let items = value.as_array().ok_or_else(|| {
                    "'overrides' must be an array of rule override objects"
                        .to_string()
                })?;
                if items.len() > MAX_OVERRIDES_PER_LAYER {
                    return Err(format!(
                        "'overrides' must hold at most {MAX_OVERRIDES_PER_LAYER} entries"
                    ));
                }
                for (index, item) in items.iter().enumerate() {
                    parse_override(item)
                        .map_err(|err| format!("overrides[{index}]: {err}"))?;
                }
            }
            other => {
                return Err(format!("unknown rule_overrides key '{other}'"));
            }
        }
    }
    Ok(())
}

/// Parses and validates one override entry.
fn parse_override(value: &Value) -> Result<RuleOverrideEntry, String> {
    let entry: RuleOverrideEntry = serde_json::from_value(value.clone())
        .map_err(|err| err.to_string())?;
    entry.validate()?;
    Ok(entry)
}

/// Parses a validated `rule_overrides` payload into entries (tolerating
/// unparseable stored entries, like [`parse_rules`]).
fn parse_overrides(config: &Value) -> Vec<RuleOverrideEntry> {
    config
        .get("overrides")
        .and_then(Value::as_array)
        .map(|items| {
            items
                .iter()
                .filter_map(|item| {
                    serde_json::from_value::<RuleOverrideEntry>(item.clone())
                        .ok()
                })
                .collect()
        })
        .unwrap_or_default()
}

/// Identity of an override entry: exact rule id, tag selector or severity
/// selector. Used so an overlay can replace or clear exactly one entry.
fn entry_key(entry: &RuleOverrideEntry) -> String {
    if !entry.rule_id.is_empty() {
        return format!("id:{}", entry.rule_id);
    }
    if !entry.tags.is_empty() {
        let mut tags = entry.tags.clone();
        tags.sort();
        return format!("tags:{}", tags.join(","));
    }
    format!("sev:{}", entry.severity_min.unwrap_or(0))
}

/// Merges overlay overrides on top of the accumulated set: an entry
/// replaces the one with the same key, `default` clears it. The result is
/// ordered by key so resolution stays deterministic.
fn merge_overrides(
    target: &mut Vec<RuleOverrideEntry>,
    patch: &[RuleOverrideEntry],
) {
    for entry in patch {
        let key = entry_key(entry);
        target.retain(|existing| entry_key(existing) != key);
        if entry.action != override_action::DEFAULT {
            target.push(entry.clone());
        }
    }
    target.sort_by_key(entry_key);
}

/// Applies one override entry to the effective tuning of the addressed
/// rule ids. Monitor / disable / score are mutually exclusive per rule;
/// exclusions persist until a `default` entry clears them.
fn apply_override(
    ids: &[String],
    entry: &RuleOverrideEntry,
    monitor: &mut Vec<String>,
    disabled: &mut Vec<String>,
    rule_scores: &mut BTreeMap<String, u32>,
    exclusions: &mut BTreeMap<String, Vec<String>>,
) {
    for id in ids {
        match entry.action.as_str() {
            override_action::DEFAULT => {
                monitor.retain(|existing| existing != id);
                disabled.retain(|existing| existing != id);
                rule_scores.remove(id);
                exclusions.remove(id);
                continue;
            }
            override_action::DISABLE => {
                monitor.retain(|existing| existing != id);
                rule_scores.remove(id);
                if !disabled.contains(id) {
                    disabled.push(id.clone());
                }
            }
            override_action::MONITOR => {
                disabled.retain(|existing| existing != id);
                rule_scores.remove(id);
                if !monitor.contains(id) {
                    monitor.push(id.clone());
                }
            }
            override_action::SCORE_OVERRIDE => {
                monitor.retain(|existing| existing != id);
                disabled.retain(|existing| existing != id);
                if let Some(score) = entry.score {
                    rule_scores.insert(id.clone(), score);
                }
            }
            _ => {}
        }
        if !entry.exclude_targets.is_empty() {
            exclusions.insert(id.clone(), entry.exclude_targets.clone());
        }
    }
}

/// Parses a string array, dropping non-strings and duplicates so typed
/// views are deterministic sets no matter how the payload was written.
fn string_array(value: &Value) -> Option<Vec<String>> {
    let items = value.as_array()?;
    let mut out: Vec<String> = Vec::with_capacity(items.len());
    for item in items {
        if let Some(entry) = item.as_str() {
            if !out.iter().any(|seen| seen == entry) {
                out.push(entry.to_string());
            }
        }
    }
    Some(out)
}

/// Typed view of an effective `engine` layer.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct EngineOverrides {
    pub waf_enabled: Option<bool>,
    pub mode: Option<String>,
    pub paranoia_level: Option<i32>,
    pub advanced_mode: Option<bool>,
    pub engine_mode: Option<String>,
    pub monitor_categories: Option<Vec<String>>,
    pub monitor_stacks: Option<Vec<String>>,
}

impl EngineOverrides {
    pub fn from_map(map: &Map<String, Value>) -> Self {
        Self {
            waf_enabled: map.get("waf_enabled").and_then(Value::as_bool),
            mode: map.get("mode").and_then(Value::as_str).map(str::to_string),
            paranoia_level: map
                .get("paranoia_level")
                .and_then(Value::as_i64)
                .map(|level| level as i32),
            advanced_mode: map.get("advanced_mode").and_then(Value::as_bool),
            engine_mode: map
                .get("engine_mode")
                .and_then(Value::as_str)
                .map(str::to_string),
            monitor_categories: map
                .get("monitor_categories")
                .and_then(string_array),
            monitor_stacks: map.get("monitor_stacks").and_then(string_array),
        }
    }

    pub fn is_empty(&self) -> bool {
        self == &EngineOverrides::default()
    }
}

/// Typed view of an effective `crs` layer.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct CrsOverrides {
    pub monitor_managed_rules: Option<Vec<String>>,
}

impl CrsOverrides {
    pub fn from_map(map: &Map<String, Value>) -> Self {
        Self {
            monitor_managed_rules: map
                .get("monitor_managed_rules")
                .and_then(string_array),
        }
    }

    pub fn is_empty(&self) -> bool {
        self == &CrsOverrides::default()
    }
}

/// The resolved effective configuration of one site.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct Resolved {
    pub policy_id: Option<Uuid>,
    pub policy_name: Option<String>,
    /// Revision of the assigned policy (`0` when none).
    pub revision: i32,
    /// Effective `engine` layer after the site overlay was applied.
    pub engine: Map<String, Value>,
    /// Effective `crs` layer after the site overlay was applied.
    pub crs: Map<String, Value>,
    /// Policy rules followed by overlay rules, as written.
    pub rules: Vec<PolicyRule>,
    /// Effective managed-rule overrides (policy first, overlay applied on
    /// top), ordered by rule id.
    pub overrides: Vec<RuleOverrideEntry>,
    /// Effective payloads of the extra layers (`virtual_patches`,
    /// `api_schema`, `rate_limit`, `ip_access`, `bot`), merged policy-first
    /// with the overlay on top.
    pub layers: BTreeMap<String, Value>,
    /// Layer kinds the site overlay contributed to, in [`LAYER_KINDS`] order.
    pub override_kinds: Vec<String>,
}

impl Resolved {
    /// True when no policy (or overlay) contributes anything.
    pub fn is_empty(&self) -> bool {
        self.engine.is_empty()
            && self.crs.is_empty()
            && self.rules.is_empty()
            && self.overrides.is_empty()
            && self.layers.is_empty()
            && self.override_kinds.is_empty()
    }

    /// True when a site overlay contributed at least one layer.
    pub fn overridden(&self) -> bool {
        !self.override_kinds.is_empty()
    }

    /// The engine knobs a bundle will carry for this site: the site's own
    /// `waf_settings` row with the policy layers applied. `mode` stays
    /// `None` when neither source pins it (the edge then derives it from
    /// the site's rules, exactly as it did before policies existed).
    pub fn effective_engine(
        &self,
        settings: Option<&waf_settings::Model>,
    ) -> EffectiveEngine {
        let engine = EngineOverrides::from_map(&self.engine);
        let crs = CrsOverrides::from_map(&self.crs);
        // Effective managed-rule tuning: the crs layer (or the site's own
        // monitor list) is the base; overrides apply on top, where
        // disable / monitor / score are mutually exclusive per rule.
        let mut monitor_managed_rules = crs
            .monitor_managed_rules
            .or_else(|| settings.map(|row| row.monitor_managed_rules.clone()))
            .unwrap_or_default();
        let mut disabled_rules: Vec<String> = Vec::new();
        let mut rule_scores: BTreeMap<String, u32> = BTreeMap::new();
        let mut rule_target_exclusions: BTreeMap<String, Vec<String>> =
            BTreeMap::new();
        // Selector entries expand against the catalogue first; exact
        // rule-id entries then apply on top, so they always win.
        for entry in &self.overrides {
            if !entry.rule_id.is_empty() {
                continue;
            }
            let ids: Vec<String> = CATALOGUE
                .iter()
                .filter(|info| {
                    (!entry.tags.is_empty()
                        && info
                            .tags
                            .iter()
                            .any(|tag| entry.tags.contains(tag)))
                        || entry
                            .severity_min
                            .is_some_and(|min| info.severity >= min)
                })
                .map(|info| info.id.clone())
                .collect();
            apply_override(
                &ids,
                entry,
                &mut monitor_managed_rules,
                &mut disabled_rules,
                &mut rule_scores,
                &mut rule_target_exclusions,
            );
        }
        for entry in &self.overrides {
            if entry.rule_id.is_empty() {
                continue;
            }
            apply_override(
                std::slice::from_ref(&entry.rule_id),
                entry,
                &mut monitor_managed_rules,
                &mut disabled_rules,
                &mut rule_scores,
                &mut rule_target_exclusions,
            );
        }
        EffectiveEngine {
            waf_enabled: engine
                .waf_enabled
                .or_else(|| settings.map(|row| row.waf_enabled))
                .unwrap_or(true),
            mode: engine.mode.clone().or_else(|| {
                settings
                    .map(|row| row.mode.clone())
                    .filter(|mode| !mode.is_empty())
            }),
            paranoia_level: engine
                .paranoia_level
                .or_else(|| settings.map(|row| row.paranoia_level))
                .unwrap_or(2),
            advanced_mode: engine
                .advanced_mode
                .or_else(|| settings.map(|row| row.advanced_mode))
                .unwrap_or(false),
            engine_mode: engine
                .engine_mode
                .clone()
                .or_else(|| {
                    settings
                        .map(|row| row.engine_mode.clone())
                        .filter(|mode| !mode.is_empty())
                })
                .unwrap_or_else(|| "inherit".to_string()),
            monitor_categories: engine
                .monitor_categories
                .or_else(|| settings.map(|row| row.monitor_categories.clone()))
                .unwrap_or_default(),
            monitor_stacks: engine
                .monitor_stacks
                .or_else(|| settings.map(|row| row.monitor_stacks.clone()))
                .unwrap_or_default(),
            monitor_managed_rules,
            disabled_rules,
            rule_scores,
            rule_target_exclusions,
        }
    }
}

/// Dashboard-facing view of the effective engine knobs (see
/// [`Resolved::effective_engine`]).
#[derive(Clone, Debug, PartialEq, Serialize)]
pub struct EffectiveEngine {
    pub waf_enabled: bool,
    pub mode: Option<String>,
    pub paranoia_level: i32,
    pub advanced_mode: bool,
    pub engine_mode: String,
    pub monitor_categories: Vec<String>,
    pub monitor_stacks: Vec<String>,
    pub monitor_managed_rules: Vec<String>,
    /// Managed rules skipped entirely.
    pub disabled_rules: Vec<String>,
    /// Per-rule score overrides (`rule id -> points`).
    pub rule_scores: BTreeMap<String, u32>,
    /// Per-rule excluded request targets (`rule id -> targets`).
    pub rule_target_exclusions: BTreeMap<String, Vec<String>>,
}

/// Resolves one site's effective policy layers.
///
/// A missing assignment, a missing/disabled policy or missing layers all
/// degrade to "nothing contributed": the caller then runs the site's own
/// settings untouched.
pub async fn resolve(
    db: &DatabaseConnection,
    site_id: Uuid,
) -> Result<Resolved, DbErr> {
    let assignment =
        site_waf_policy::Entity::find_by_id(site_id).one(db).await?;
    let Some(assignment) = assignment else {
        return Ok(Resolved::default());
    };
    let Some(policy) =
        waf_policy::Entity::find_by_id(assignment.policy_id).one(db).await?
    else {
        return Ok(Resolved::default());
    };
    if !policy.enabled {
        return Ok(Resolved::default());
    }

    let layer_rows = waf_policy_layer::Entity::find()
        .filter(waf_policy_layer::Column::PolicyId.eq(policy.id))
        .all(db)
        .await?;
    let mut resolved = Resolved {
        policy_id: Some(policy.id),
        policy_name: Some(policy.name.clone()),
        revision: policy.revision,
        ..Resolved::default()
    };
    for kind in LAYER_KINDS {
        if let Some(row) = layer_rows.iter().find(|row| row.kind == kind) {
            apply_layer(&mut resolved, kind, &row.config);
        }
    }

    // The site overlay is applied last and only adds/overrides the keys it
    // names, so everything else keeps inheriting from the policy.
    let overlay =
        site_waf_policy_override::Entity::find_by_id(site_id).one(db).await?;
    let Some(overlay_map) = overlay
        .as_ref()
        .and_then(|row| row.config.as_object().cloned())
    else {
        return Ok(resolved);
    };
    apply_overlay(&mut resolved, &overlay_map);
    Ok(resolved)
}

/// Applies one layer payload onto a resolved view (policy layers and site
/// overlay patches share this merge).
fn apply_layer(resolved: &mut Resolved, kind: &str, config: &Value) {
    match kind {
        LAYER_ENGINE => {
            if let Some(map) = config.as_object() {
                for (key, value) in map {
                    resolved.engine.insert(key.clone(), value.clone());
                }
            }
        }
        LAYER_CRS => {
            if let Some(map) = config.as_object() {
                for (key, value) in map {
                    resolved.crs.insert(key.clone(), value.clone());
                }
            }
        }
        LAYER_CUSTOM_RULES => {
            resolved.rules.extend(parse_rules(config));
        }
        LAYER_RULE_OVERRIDES => {
            merge_overrides(&mut resolved.overrides, &parse_overrides(config));
        }
        LAYER_VIRTUAL_PATCHES | LAYER_API_SCHEMA | LAYER_BOT | LAYER_CRS_IMPORT => {
            // Key-level merge: overlay keys win over the policy's.
            let entry = resolved
                .layers
                .entry(kind.to_string())
                .or_insert_with(|| Value::Object(Map::new()));
            if let (Some(target), Some(source)) =
                (entry.as_object_mut(), config.as_object())
            {
                for (key, value) in source {
                    target.insert(key.clone(), value.clone());
                }
            }
        }
        LAYER_RATE_LIMIT | LAYER_IP_ACCESS => {
            // Rule lists merge by name: an overlay entry replaces the
            // policy's rule of the same name.
            let mut merged = resolved
                .layers
                .get(kind)
                .and_then(|value| value.get("rules"))
                .and_then(Value::as_array)
                .cloned()
                .unwrap_or_default();
            if let Some(patch) = config.get("rules").and_then(Value::as_array)
            {
                for entry in patch {
                    let name = entry
                        .get("name")
                        .and_then(Value::as_str)
                        .unwrap_or_default()
                        .to_string();
                    merged.retain(|existing| {
                        existing.get("name").and_then(Value::as_str)
                            != Some(name.as_str())
                    });
                    merged.push(entry.clone());
                }
            }
            resolved.layers.insert(
                kind.to_string(),
                serde_json::json!({ "rules": merged }),
            );
        }
        _ => {}
    }
}

/// Applies the site overlay patch on top of a resolved policy view.
fn apply_overlay(resolved: &mut Resolved, overlay_map: &Map<String, Value>) {
    for kind in LAYER_KINDS {
        let Some(patch) = overlay_map.get(kind) else {
            continue;
        };
        if patch.as_object().is_some_and(|map| !map.is_empty()) {
            resolved.override_kinds.push(kind.to_string());
        }
        apply_layer(resolved, kind, patch);
    }
}

/// Resolves a synthetic view from raw layer payloads (used by the preview
/// endpoint): the same merge rules as [`resolve`], without database access.
pub fn resolve_maps(
    policy_id: Option<Uuid>,
    policy_name: Option<String>,
    revision: i32,
    layers: &BTreeMap<String, Value>,
    overlay: Option<&Value>,
) -> Resolved {
    let mut resolved = Resolved {
        policy_id,
        policy_name,
        revision,
        ..Resolved::default()
    };
    for kind in LAYER_KINDS {
        if let Some(config) = layers.get(kind) {
            apply_layer(&mut resolved, kind, config);
        }
    }
    if let Some(Value::Object(overlay_map)) = overlay {
        apply_overlay(&mut resolved, overlay_map);
    }
    resolved
}

/// The managed-rule catalogue (built once).
pub fn catalogue() -> &'static [varman_waf::ManagedRuleInfo] {
    &CATALOGUE
}

/// One row of the compiled rule plan: what the data plane will do with a
/// managed rule for a site.
#[derive(Clone, Debug, PartialEq, Serialize)]
pub struct RulePlan {
    pub id: String,
    pub name: String,
    pub severity: u8,
    pub action: String,
    pub tags: Vec<String>,
    pub stacks: Vec<String>,
    pub strict_only: bool,
    /// `enforce`, `monitor` or `disabled`.
    pub effective: &'static str,
    /// Anomaly points the rule contributes (override or severity default).
    pub score: u32,
    pub exclusions: Vec<String>,
}

/// Builds the compiled rule plan for an effective engine view.
pub fn rule_plan(effective: &EffectiveEngine) -> Vec<RulePlan> {
    CATALOGUE
        .iter()
        .map(|info| {
            let disabled = effective.disabled_rules.contains(&info.id);
            let monitored =
                effective.monitor_managed_rules.contains(&info.id);
            RulePlan {
                id: info.id.clone(),
                name: info.name.clone(),
                severity: info.severity,
                action: info.action.clone(),
                tags: info.tags.clone(),
                stacks: info.stacks.clone(),
                strict_only: info.strict_only,
                effective: if disabled {
                    "disabled"
                } else if monitored {
                    "monitor"
                } else {
                    "enforce"
                },
                score: effective
                    .rule_scores
                    .get(&info.id)
                    .copied()
                    .unwrap_or_else(|| {
                        varman_waf::AnomalyScorer::points_for_severity(
                            info.severity,
                        )
                    }),
                exclusions: effective
                    .rule_target_exclusions
                    .get(&info.id)
                    .cloned()
                    .unwrap_or_default(),
            }
        })
        .collect()
}

/* ── Version history ───────────────────────────────────────────────────── */

/// Snapshot content of a policy: fields plus every layer payload.
fn snapshot_of(
    policy: &waf_policy::Model,
    layers: &[waf_policy_layer::Model],
) -> Value {
    let mut layer_map = Map::new();
    for row in layers {
        layer_map.insert(row.kind.clone(), row.config.clone());
    }
    serde_json::json!({
        "name": policy.name,
        "description": policy.description,
        "enabled": policy.enabled,
        "layers": Value::Object(layer_map),
    })
}

/// SHA-256 over the canonical snapshot JSON.
fn snapshot_hash(snapshot: &Value) -> String {
    use sha2::{Digest, Sha256};
    let canonical = serde_json::to_string(snapshot).unwrap_or_default();
    let mut hasher = Sha256::new();
    hasher.update(canonical.as_bytes());
    hasher
        .finalize()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

/// Per-layer entry counts for cheap summaries.
fn summarise(snapshot: &Value) -> Value {
    let mut summary = Map::new();
    if let Some(layers) = snapshot.get("layers").and_then(Value::as_object) {
        for (kind, config) in layers {
            let count = match kind.as_str() {
                LAYER_CUSTOM_RULES => config
                    .get("rules")
                    .and_then(Value::as_array)
                    .map_or(0, Vec::len),
                LAYER_RULE_OVERRIDES => config
                    .get("overrides")
                    .and_then(Value::as_array)
                    .map_or(0, Vec::len),
                _ => config.as_object().map_or(0, Map::len),
            };
            summary.insert(kind.clone(), serde_json::json!(count));
        }
    }
    Value::Object(summary)
}

/// Records an immutable version of the policy, deduplicated by content hash
/// against the latest version. Returns `None` when nothing changed.
pub async fn record_version(
    db: &DatabaseConnection,
    policy_id: Uuid,
    actor: Option<&str>,
    source: &str,
) -> Result<Option<waf_policy_version::Model>, DbErr> {
    let Some(policy) =
        waf_policy::Entity::find_by_id(policy_id).one(db).await?
    else {
        return Ok(None);
    };
    let layers = waf_policy_layer::Entity::find()
        .filter(waf_policy_layer::Column::PolicyId.eq(policy_id))
        .all(db)
        .await?;
    let snapshot = snapshot_of(&policy, &layers);
    let config_hash = snapshot_hash(&snapshot);
    if let Some(latest) = waf_policy_version::Entity::find()
        .filter(waf_policy_version::Column::PolicyId.eq(policy_id))
        .order_by_desc(waf_policy_version::Column::Id)
        .one(db)
        .await?
    {
        if latest.config_hash == config_hash {
            return Ok(None);
        }
    }
    let summary = summarise(&snapshot);
    let row = waf_policy_version::ActiveModel {
        id: Default::default(),
        policy_id: Set(policy_id),
        revision: Set(policy.revision),
        config_hash: Set(config_hash),
        source: Set(source.to_string()),
        actor: Set(actor.map(str::to_string)),
        summary: Set(Some(summary)),
        snapshot: Set(snapshot),
        created_at: Set(Utc::now()),
    }
    .insert(db)
    .await?;
    tracing::info!(
        policy_id = %policy_id,
        version = row.id,
        revision = row.revision,
        source = %row.source,
        "policy version recorded"
    );
    Ok(Some(row))
}

/// Restores a recorded version's content as a **new** revision: fields and
/// layers are replaced and the revision bumps; the caller records the
/// rollback version. History is never rewritten.
pub async fn restore_version(
    db: &DatabaseConnection,
    policy: &waf_policy::Model,
    snapshot: &Value,
) -> Result<waf_policy::Model, DbErr> {
    let mut active: waf_policy::ActiveModel = policy.clone().into();
    if let Some(name) = snapshot.get("name").and_then(Value::as_str) {
        active.name = Set(name.to_string());
    }
    if let Some(description) =
        snapshot.get("description").and_then(Value::as_str)
    {
        active.description = Set(description.to_string());
    }
    if let Some(enabled) = snapshot.get("enabled").and_then(Value::as_bool) {
        active.enabled = Set(enabled);
    }
    active.revision = Set(policy.revision + 1);
    active.updated_at = Set(Utc::now());
    let updated = active.update(db).await?;

    waf_policy_layer::Entity::delete_many()
        .filter(waf_policy_layer::Column::PolicyId.eq(policy.id))
        .exec(db)
        .await?;
    if let Some(layers) = snapshot.get("layers").and_then(Value::as_object) {
        for (kind, config) in layers {
            if !is_layer_kind(kind) {
                continue;
            }
            waf_policy_layer::ActiveModel {
                id: Set(Uuid::new_v4()),
                policy_id: Set(policy.id),
                kind: Set(kind.clone()),
                config: Set(config.clone()),
                updated_at: Set(Utc::now()),
            }
            .insert(db)
            .await?;
        }
    }
    Ok(updated)
}

/// One changed layer in a version diff.
#[derive(Clone, Debug, PartialEq, Serialize)]
pub struct LayerDiff {
    pub kind: String,
    pub added: Vec<String>,
    pub removed: Vec<String>,
    pub changed: Vec<String>,
}

/// Diff between two snapshots: changed policy fields plus per-layer entry
/// deltas (rules by name, overrides by entry key, other layers by key).
#[derive(Clone, Debug, PartialEq, Serialize)]
pub struct VersionDiff {
    pub fields: Vec<String>,
    pub layers: Vec<LayerDiff>,
}

pub fn version_diff(from: &Value, to: &Value) -> VersionDiff {
    let mut fields = Vec::new();
    for field in ["name", "description", "enabled"] {
        if from.get(field) != to.get(field) {
            fields.push(field.to_string());
        }
    }
    let from_layers = from.get("layers").and_then(Value::as_object);
    let to_layers = to.get("layers").and_then(Value::as_object);
    let mut layers = Vec::new();
    for kind in LAYER_KINDS {
        let before =
            layer_entries(kind, from_layers.and_then(|map| map.get(kind)));
        let after =
            layer_entries(kind, to_layers.and_then(|map| map.get(kind)));
        let mut added = Vec::new();
        let mut removed = Vec::new();
        let mut changed = Vec::new();
        for (key, value) in &after {
            match before.get(key) {
                None => added.push(key.clone()),
                Some(old) if old != value => changed.push(key.clone()),
                _ => {}
            }
        }
        for key in before.keys() {
            if !after.contains_key(key) {
                removed.push(key.clone());
            }
        }
        if !(added.is_empty() && removed.is_empty() && changed.is_empty()) {
            layers.push(LayerDiff {
                kind: kind.to_string(),
                added,
                removed,
                changed,
            });
        }
    }
    VersionDiff { fields, layers }
}

/// Flattens one layer into comparable entries keyed by identity.
fn layer_entries(
    kind: &str,
    config: Option<&Value>,
) -> BTreeMap<String, String> {
    let mut out = BTreeMap::new();
    let Some(config) = config else {
        return out;
    };
    match kind {
        LAYER_CUSTOM_RULES => {
            for rule in parse_rules(config) {
                out.insert(
                    rule.name.clone(),
                    serde_json::to_string(&rule).unwrap_or_default(),
                );
            }
        }
        LAYER_RULE_OVERRIDES => {
            for entry in parse_overrides(config) {
                out.insert(
                    entry_key(&entry),
                    serde_json::to_string(&entry).unwrap_or_default(),
                );
            }
        }
        _ => {
            if let Some(map) = config.as_object() {
                for (key, value) in map {
                    out.insert(key.clone(), value.to_string());
                }
            }
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    #[test]
    fn engine_layer_accepts_documented_knobs() {
        let config = json!({
            "waf_enabled": true,
            "mode": "monitor",
            "paranoia_level": 3,
            "advanced_mode": true,
            "engine_mode": "varman",
            "monitor_categories": ["sqli", "xss", "sqli"],
            "monitor_stacks": ["java"]
        });
        assert!(validate_layer(LAYER_ENGINE, &config).is_ok());

        // Duplicates collapse in the typed view.
        let map = config.as_object().expect("object");
        let overrides = EngineOverrides::from_map(map);
        assert_eq!(
            overrides.monitor_categories,
            Some(vec!["sqli".to_string(), "xss".to_string()])
        );
    }

    #[test]
    fn engine_layer_rejects_unknown_keys_and_values() {
        assert!(validate_layer(LAYER_ENGINE, &json!({"mode": "detect"}))
            .unwrap_err()
            .contains("unknown mode"));
        assert!(validate_layer(LAYER_ENGINE, &json!({"paranoia_level": 5}))
            .unwrap_err()
            .contains("between 1 and 4"));
        assert!(validate_layer(LAYER_ENGINE, &json!({"engine_mode": "native"}))
            .unwrap_err()
            .contains("unknown engine_mode"));
        assert!(
            validate_layer(LAYER_ENGINE, &json!({"monitor_categories": ["nope"]}))
                .unwrap_err()
                .contains("unknown value")
        );
        // A typo must fail at write time, not silently never apply.
        assert!(validate_layer(LAYER_ENGINE, &json!({"waf_enable": true}))
            .unwrap_err()
            .contains("unknown engine key"));
        assert!(validate_layer(LAYER_ENGINE, &json!(["mode"]))
            .unwrap_err()
            .contains("must be a JSON object"));
    }

    #[test]
    fn crs_layer_only_monitors_known_managed_rules() {
        assert!(validate_layer(
            LAYER_CRS,
            &json!({"monitor_managed_rules": [MANAGED_RULES[0]]})
        )
        .is_ok());
        assert!(validate_layer(
            LAYER_CRS,
            &json!({"monitor_managed_rules": ["VARMAN-9999"]})
        )
        .is_err());
        assert!(validate_layer(LAYER_CRS, &json!({"paranoia_level": 2}))
            .unwrap_err()
            .contains("unknown crs key"));
    }

    #[test]
    fn custom_rules_layer_validates_each_rule() {
        let ok = json!({"rules": [
            {
                "name": "Block probe",
                "expression": "http.request.uri.path eq \"/probe\"",
                "action": "block"
            },
            {
                "name": "Watch login",
                "description": "monitor login attempts",
                "expression": "http.request.uri.path starts_with \"/login\"",
                "action": "log",
                "severity": 2,
                "tags": ["auth"],
                "enabled": false,
                "mode": "monitor",
                "priority": 10
            }
        ]});
        assert!(validate_layer(LAYER_CUSTOM_RULES, &ok).is_ok());

        let bad_action = json!({"rules": [
            {"name": "x", "expression": "true", "action": "drop"}
        ]});
        assert!(validate_layer(LAYER_CUSTOM_RULES, &bad_action)
            .unwrap_err()
            .contains("unknown action"));

        let empty_name = json!({"rules": [
            {"name": "  ", "expression": "true", "action": "block"}
        ]});
        assert!(validate_layer(LAYER_CUSTOM_RULES, &empty_name)
            .unwrap_err()
            .contains("'name' must not be empty"));

        let typo = json!({"rules": [
            {"name": "x", "expression": "true", "action": "block",
             "enabld": true}
        ]});
        assert!(validate_layer(LAYER_CUSTOM_RULES, &typo).is_err());

        assert!(validate_layer(LAYER_CUSTOM_RULES, &json!({"rulez": []}))
            .unwrap_err()
            .contains("unknown custom_rules key"));
    }

    #[test]
    fn unknown_layer_kind_is_named_in_the_error() {
        let err = validate_layer("body", &json!({})).unwrap_err();
        assert!(err.contains("unknown layer kind 'body'"));
        assert!(err.contains(LAYER_ENGINE));
    }

    #[test]
    fn rule_overrides_layer_validates_entries() {
        let ok = json!({"overrides": [
            {"rule_id": "VARMAN-1010", "action": "monitor"},
            {"rule_id": "VARMAN-1020", "action": "score_override", "score": 1},
            {"rule_id": "VARMAN-1002", "action": "disable"}
        ]});
        assert!(validate_layer(LAYER_RULE_OVERRIDES, &ok).is_ok());

        assert!(validate_layer(
            LAYER_RULE_OVERRIDES,
            &json!({"overrides": [{"rule_id": "VARMAN-9999", "action": "disable"}]})
        )
        .unwrap_err()
        .contains("unknown managed rule"));

        assert!(validate_layer(
            LAYER_RULE_OVERRIDES,
            &json!({"overrides": [{"rule_id": "VARMAN-1010", "action": "drop"}]})
        )
        .unwrap_err()
        .contains("unknown action"));

        assert!(validate_layer(
            LAYER_RULE_OVERRIDES,
            &json!({"overrides": [{"rule_id": "VARMAN-1010", "action": "score_override"}]})
        )
        .unwrap_err()
        .contains("'score' is required"));

        assert!(validate_layer(
            LAYER_RULE_OVERRIDES,
            &json!({"overrides": [{"rule_id": "VARMAN-1010", "action": "disable", "score": 5}]})
        )
        .unwrap_err()
        .contains("only valid with the score_override"));

        assert!(validate_layer(LAYER_RULE_OVERRIDES, &json!({"rules": []}))
            .unwrap_err()
            .contains("unknown rule_overrides key"));
    }

    #[test]
    fn overrides_apply_on_top_of_the_monitor_base() {
        let mut settings = waf_settings_row(true, "block", 2, "inherit");
        settings.monitor_managed_rules = vec!["VARMAN-1010".to_string()];

        let resolved = Resolved {
            overrides: vec![
                RuleOverrideEntry {
                    rule_id: "VARMAN-1010".into(),
                    action: "score_override".into(),
                    score: Some(2),
                    ..RuleOverrideEntry::default()
                },
                RuleOverrideEntry {
                    rule_id: "VARMAN-1020".into(),
                    action: "disable".into(),
                    ..RuleOverrideEntry::default()
                },
                RuleOverrideEntry {
                    rule_id: "VARMAN-1002".into(),
                    action: "monitor".into(),
                    ..RuleOverrideEntry::default()
                },
            ],
            ..Resolved::default()
        };

        let effective = resolved.effective_engine(Some(&settings));
        // The site's monitor entry is replaced by the score override; the
        // disabled and monitor entries land in their own buckets.
        assert!(!effective
            .monitor_managed_rules
            .contains(&"VARMAN-1010".to_string()));
        assert_eq!(effective.rule_scores.get("VARMAN-1010"), Some(&2));
        assert!(effective.disabled_rules.contains(&"VARMAN-1020".to_string()));
        assert!(effective
            .monitor_managed_rules
            .contains(&"VARMAN-1002".to_string()));
    }

    #[test]
    fn overlay_default_clears_a_policy_override() {
        let mut target = vec![RuleOverrideEntry {
            rule_id: "VARMAN-1010".into(),
            action: "disable".into(),
            ..RuleOverrideEntry::default()
        }];
        merge_overrides(
            &mut target,
            &[RuleOverrideEntry {
                rule_id: "VARMAN-1010".into(),
                action: "default".into(),
                ..RuleOverrideEntry::default()
            }],
        );
        assert!(target.is_empty());

        merge_overrides(
            &mut target,
            &[RuleOverrideEntry {
                rule_id: "VARMAN-1002".into(),
                action: "monitor".into(),
                ..RuleOverrideEntry::default()
            }],
        );
        assert_eq!(target.len(), 1);
        assert_eq!(target[0].rule_id, "VARMAN-1002");
    }

    #[test]
    fn selector_validation_requires_exactly_one_addressing() {
        // No addressing at all.
        assert!(validate_layer(
            LAYER_RULE_OVERRIDES,
            &json!({"overrides": [{"action": "monitor"}]})
        )
        .unwrap_err()
        .contains("exactly one"));

        // Two addressings at once.
        assert!(validate_layer(
            LAYER_RULE_OVERRIDES,
            &json!({"overrides": [
                {"rule_id": "VARMAN-1010", "tags": ["scanner"], "action": "monitor"}
            ]})
        )
        .unwrap_err()
        .contains("exactly one"));

        // Unknown tag.
        assert!(validate_layer(
            LAYER_RULE_OVERRIDES,
            &json!({"overrides": [{"tags": ["nope"], "action": "monitor"}]})
        )
        .unwrap_err()
        .contains("unknown tag"));

        // Unknown exclusion target.
        assert!(validate_layer(
            LAYER_RULE_OVERRIDES,
            &json!({"overrides": [
                {"rule_id": "VARMAN-1010", "action": "monitor",
                 "exclude_targets": ["referer"]}
            ]})
        )
        .unwrap_err()
        .contains("unknown exclusion target"));

        // Valid selector entries with exclusions.
        assert!(validate_layer(
            LAYER_RULE_OVERRIDES,
            &json!({"overrides": [
                {"tags": ["scanner"], "action": "monitor",
                 "exclude_targets": ["header", "query"]},
                {"severity_min": 4, "action": "disable"}
            ]})
        )
        .is_ok());
    }

    #[test]
    fn selector_entries_expand_and_exact_entries_win() {
        let resolved = Resolved {
            overrides: vec![
                // Tag selector: every dotfile-tagged rule goes monitor.
                RuleOverrideEntry {
                    tags: vec!["dotfile".to_string()],
                    action: "monitor".to_string(),
                    ..RuleOverrideEntry::default()
                },
                // Severity selector: every critical rule disabled.
                RuleOverrideEntry {
                    severity_min: Some(5),
                    action: "disable".to_string(),
                    ..RuleOverrideEntry::default()
                },
                // Exact entry wins over both selectors for one rule.
                RuleOverrideEntry {
                    rule_id: "VARMAN-1020".to_string(),
                    action: "score_override".to_string(),
                    score: Some(2),
                    ..RuleOverrideEntry::default()
                },
            ],
            ..Resolved::default()
        };

        let effective = resolved.effective_engine(None);
        assert_eq!(effective.rule_scores.get("VARMAN-1020"), Some(&2));
        assert!(!effective
            .disabled_rules
            .contains(&"VARMAN-1020".to_string()));
        assert!(!effective
            .monitor_managed_rules
            .contains(&"VARMAN-1020".to_string()));
        // The severity selector disabled the other critical rules.
        assert!(effective
            .disabled_rules
            .contains(&"VARMAN-1002".to_string()));
        assert!(effective
            .disabled_rules
            .contains(&"VARMAN-1050".to_string()));
    }

    #[test]
    fn rule_plan_reports_effective_state() {        let resolved = Resolved {
            overrides: vec![
                RuleOverrideEntry {
                    rule_id: "VARMAN-1020".into(),
                    action: "score_override".into(),
                    score: Some(2),
                    ..RuleOverrideEntry::default()
                },
                RuleOverrideEntry {
                    rule_id: "VARMAN-1010".into(),
                    action: "monitor".into(),
                    ..RuleOverrideEntry::default()
                },
                RuleOverrideEntry {
                    rule_id: "VARMAN-1002".into(),
                    action: "disable".into(),
                    ..RuleOverrideEntry::default()
                },
                RuleOverrideEntry {
                    rule_id: "VARMAN-1004".into(),
                    action: "monitor".into(),
                    exclude_targets: vec!["query".into()],
                    ..RuleOverrideEntry::default()
                },
            ],
            ..Resolved::default()
        };
        let effective = resolved.effective_engine(None);
        let plan = rule_plan(&effective);
        let row = |id: &str| {
            plan.iter()
                .find(|row| row.id == id)
                .expect("catalogue row")
        };
        assert_eq!(row("VARMAN-1020").effective, "enforce");
        assert_eq!(row("VARMAN-1020").score, 2);
        assert_eq!(row("VARMAN-1010").effective, "monitor");
        assert_eq!(row("VARMAN-1002").effective, "disabled");
        assert_eq!(row("VARMAN-1004").exclusions, vec!["query".to_string()]);
        // Severity default when no override: VARMAN-1003 is critical.
        assert_eq!(row("VARMAN-1003").score, 5);
    }

    #[test]
    fn effective_engine_applies_layers_over_settings() {
        let settings = waf_settings_row(true, "block", 2, "inherit");
        let mut resolved = Resolved::default();
        resolved
            .engine
            .insert("mode".into(), json!("monitor"));
        resolved
            .engine
            .insert("paranoia_level".into(), json!(3));
        resolved
            .crs
            .insert("monitor_managed_rules".into(), json!(["VARMAN-1010"]));

        let effective = resolved.effective_engine(Some(&settings));
        assert!(effective.waf_enabled);
        assert_eq!(effective.mode.as_deref(), Some("monitor"));
        assert_eq!(effective.paranoia_level, 3);
        assert_eq!(effective.monitor_managed_rules, vec!["VARMAN-1010"]);
        // Untouched knobs keep inheriting from the site's own row.
        assert_eq!(effective.engine_mode, "inherit");
    }

    #[test]
    fn effective_engine_without_sources_leaves_mode_unset() {
        let effective =
            Resolved::default().effective_engine(None);
        assert!(effective.waf_enabled);
        assert_eq!(effective.mode, None);
        assert_eq!(effective.paranoia_level, 2);
        assert_eq!(effective.engine_mode, "inherit");
    }

    fn waf_settings_row(
        waf_enabled: bool,
        mode: &str,
        paranoia_level: i32,
        engine_mode: &str,
    ) -> waf_settings::Model {
        let now = chrono::Utc::now();
        waf_settings::Model {
            id: Uuid::nil(),
            site_id: Uuid::nil(),
            waf_enabled,
            mode: mode.to_string(),
            paranoia_level,
            advanced_mode: false,
            engine_mode: engine_mode.to_string(),
            virtual_patches: String::new(),
            openapi_spec: String::new(),
            monitor_categories: Vec::new(),
            monitor_stacks: Vec::new(),
            monitor_managed_rules: Vec::new(),
            created_at: now,
            updated_at: now,
        }
    }

    #[test]
    fn extra_layers_validate_their_payloads() {
        // Virtual patches (SecLang source).
        assert!(validate_layer(
            LAYER_VIRTUAL_PATCHES,
            &json!({"source": "SecRule REQUEST_URI \"@streq /x\" \"id:1,phase:1,deny\""})
        )
        .is_ok());
        assert!(validate_layer(LAYER_VIRTUAL_PATCHES, &json!({"src": "x"}))
            .unwrap_err()
            .contains("unknown virtual_patches key"));

        // OpenAPI document must be a JSON object with a `paths` object
        // (the data plane rejects a document without one).
        assert!(validate_layer(
            LAYER_API_SCHEMA,
            &json!({"openapi_spec": "{\"openapi\":\"3.0.0\",\"paths\":{}}"})
        )
        .is_ok());
        assert!(validate_layer(
            LAYER_API_SCHEMA,
            &json!({"openapi_spec": "not json"})
        )
        .unwrap_err()
        .contains("must be a JSON document"));
        assert!(validate_layer(LAYER_API_SCHEMA, &json!({"openapi_spec": "[1]"}))
            .unwrap_err()
            .contains("must be a JSON object"));
        assert!(validate_layer(
            LAYER_API_SCHEMA,
            &json!({"openapi_spec": "{\"openapi\":\"3.0.0\"}"})
        )
        .unwrap_err()
        .contains("'paths' object"));

        // Bot posture.
        assert!(validate_layer(
            LAYER_BOT,
            &json!({"enabled": true, "action": "challenge",
                    "known_bots_whitelist": ["Googlebot"],
                    "tls_fingerprint": true})
        )
        .is_ok());
        assert!(validate_layer(LAYER_BOT, &json!({"action": "drop"}))
            .unwrap_err()
            .contains("unknown bot action"));
        assert!(validate_layer(
            LAYER_BOT,
            &json!({"known_bots_whitelist": [1]})
        )
        .unwrap_err()
        .contains("array of strings"));

        // Rate limits.
        assert!(validate_layer(
            LAYER_RATE_LIMIT,
            &json!({"rules": [{
                "name": "Login burst",
                "expression": "path starts_with \"/login\"",
                "characteristics": ["ip", "header:x-key"],
                "period_seconds": 60,
                "threshold": 10,
                "action": "challenge"
            }]})
        )
        .is_ok());
        assert!(validate_layer(
            LAYER_RATE_LIMIT,
            &json!({"rules": [{"name": "x", "characteristics": ["nope"]}]})
        )
        .unwrap_err()
        .contains("unknown rate limit characteristic"));
        assert!(validate_layer(
            LAYER_RATE_LIMIT,
            &json!({"rules": [{"name": "x", "characteristics": ["ip"],
                              "period_seconds": 0}]})
        )
        .unwrap_err()
        .contains("period_seconds"));
        assert!(validate_layer(
            LAYER_RATE_LIMIT,
            &json!({"rules": [{"name": "x", "characteristics": ["ip"],
                              "action": "explode"}]})
        )
        .unwrap_err()
        .contains("unknown action"));

        // IP access.
        assert!(validate_layer(
            LAYER_IP_ACCESS,
            &json!({"rules": [{"name": "Office",
                              "ip_ranges": ["10.0.0.0/8", "192.168.1.5"],
                              "action": "allow"}]})
        )
        .is_ok());
        assert!(validate_layer(
            LAYER_IP_ACCESS,
            &json!({"rules": [{"name": "x", "ip_ranges": ["nope"],
                              "action": "allow"}]})
        )
        .unwrap_err()
        .contains("invalid IP address"));
        assert!(validate_layer(
            LAYER_IP_ACCESS,
            &json!({"rules": [{"name": "x", "ip_ranges": ["10.0.0.0/8"],
                              "action": "drop"}]})
        )
        .unwrap_err()
        .contains("unknown ip action"));
        assert!(validate_layer(
            LAYER_IP_ACCESS,
            &json!({"rules": [{"name": "x", "ip_ranges": [],
                              "action": "allow"}]})
        )
        .unwrap_err()
        .contains("at least one range"));

        // CRS import binding.
        assert!(validate_layer(
            LAYER_CRS_IMPORT,
            &json!({
                "ruleset_id": "0b3f2b6e-4f11-4a5e-9d3e-3a0a5f6c9d21",
                "paranoia_level_max": 2,
                "categories": ["sqli"]
            })
        )
        .is_ok());
        assert!(validate_layer(LAYER_CRS_IMPORT, &json!({"ruleset_id": "nope"}))
            .unwrap_err()
            .contains("must be a UUID"));
        assert!(validate_layer(
            LAYER_CRS_IMPORT,
            &json!({"ruleset_id": "0b3f2b6e-4f11-4a5e-9d3e-3a0a5f6c9d21",
                    "paranoia_level_max": 9})
        )
        .unwrap_err()
        .contains("between 1 and 4"));
        assert!(validate_layer(
            LAYER_CRS_IMPORT,
            &json!({"ruleset_id": "0b3f2b6e-4f11-4a5e-9d3e-3a0a5f6c9d21",
                    "extra": true})
        )
        .unwrap_err()
        .contains("unknown crs_import key"));
    }

    #[test]
    fn extra_layers_merge_policy_first_overlay_on_top() {
        let policy_layers: BTreeMap<String, Value> = [
            (
                LAYER_BOT.to_string(),
                json!({"enabled": true, "action": "challenge"}),
            ),
            (
                LAYER_RATE_LIMIT.to_string(),
                json!({"rules": [
                    {"name": "Login", "characteristics": ["ip"], "threshold": 5},
                    {"name": "Api", "characteristics": ["ip"], "threshold": 50}
                ]}),
            ),
        ]
        .into_iter()
        .collect();

        let base = resolve_maps(None, None, 0, &policy_layers, None);
        assert_eq!(
            base.layers
                .get(LAYER_BOT)
                .and_then(|value| value.get("action"))
                .and_then(Value::as_str),
            Some("challenge")
        );
        assert_eq!(
            base.layers
                .get(LAYER_RATE_LIMIT)
                .and_then(|value| value.get("rules"))
                .and_then(Value::as_array)
                .map(Vec::len),
            Some(2)
        );

        // Overlay: bot action replaced, one rate-limit rule replaced by name.
        let overlay = json!({
            "bot": {"action": "block"},
            "rate_limit": {"rules": [
                {"name": "Login", "characteristics": ["ip"], "threshold": 2}
            ]}
        });
        let merged =
            resolve_maps(None, None, 0, &policy_layers, Some(&overlay));
        assert_eq!(
            merged
                .layers
                .get(LAYER_BOT)
                .and_then(|value| value.get("action"))
                .and_then(Value::as_str),
            Some("block")
        );
        // Untouched bot keys keep the policy's value.
        assert_eq!(
            merged
                .layers
                .get(LAYER_BOT)
                .and_then(|value| value.get("enabled"))
                .and_then(Value::as_bool),
            Some(true)
        );
        let rules = merged
            .layers
            .get(LAYER_RATE_LIMIT)
            .and_then(|value| value.get("rules"))
            .and_then(Value::as_array)
            .cloned()
            .unwrap_or_default();
        assert_eq!(rules.len(), 2);
        let login = rules
            .iter()
            .find(|rule| {
                rule.get("name").and_then(Value::as_str) == Some("Login")
            })
            .expect("login rule");
        assert_eq!(
            login.get("threshold").and_then(Value::as_i64),
            Some(2)
        );
        assert!(merged.override_kinds.contains(&LAYER_BOT.to_string()));
    }

    #[test]
    fn snapshot_hash_is_content_addressed() {
        let a = json!({"name": "p", "description": "", "enabled": true, "layers": {}});
        let b = json!({"name": "p", "description": "", "enabled": true, "layers": {}});
        let c = json!({"name": "p", "description": "", "enabled": false, "layers": {}});
        assert_eq!(snapshot_hash(&a), snapshot_hash(&b));
        assert_ne!(snapshot_hash(&a), snapshot_hash(&c));
        assert_eq!(snapshot_hash(&a).len(), 64);
    }

    #[test]
    fn version_diff_reports_layer_deltas() {
        let from = json!({
            "name": "A", "description": "", "enabled": true,
            "layers": {
                "engine": {"mode": "block"},
                "rule_overrides": {"overrides": [
                    {"rule_id": "VARMAN-1010", "action": "monitor"}
                ]}
            }
        });
        let to = json!({
            "name": "B", "description": "", "enabled": true,
            "layers": {
                "engine": {"mode": "monitor"},
                "rule_overrides": {"overrides": [
                    {"rule_id": "VARMAN-1010", "action": "monitor"},
                    {"rule_id": "VARMAN-1020", "action": "disable"}
                ]},
                "crs": {"monitor_managed_rules": ["VARMAN-1002"]}
            }
        });
        let diff = version_diff(&from, &to);
        assert_eq!(diff.fields, vec!["name".to_string()]);

        let engine =
            diff.layers.iter().find(|l| l.kind == "engine").expect("engine");
        assert_eq!(engine.changed, vec!["mode".to_string()]);
        assert!(engine.added.is_empty());

        let overrides = diff
            .layers
            .iter()
            .find(|l| l.kind == "rule_overrides")
            .expect("overrides");
        assert_eq!(overrides.added, vec!["id:VARMAN-1020".to_string()]);
        assert!(overrides.changed.is_empty());

        let crs = diff.layers.iter().find(|l| l.kind == "crs").expect("crs");
        assert_eq!(crs.added, vec!["monitor_managed_rules".to_string()]);

        // Layers that did not change are absent from the diff.
        assert!(!diff.layers.iter().any(|l| l.kind == "custom_rules"));
    }
}
