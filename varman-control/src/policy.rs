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

use sea_orm::{
    ColumnTrait, DatabaseConnection, DbErr, EntityTrait, QueryFilter,
};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use uuid::Uuid;

use crate::api::waf_settings::{CATEGORIES, ENGINE_MODES, MANAGED_RULES, STACKS};
use crate::models::{
    action, mode, site_waf_policy, site_waf_policy_override, waf_policy,
    waf_policy_layer, waf_settings,
};

/// Engine layer kind: posture knobs, same meaning as `waf_settings`.
pub const LAYER_ENGINE: &str = "engine";
/// CRS layer kind: managed-ruleset tuning (monitor downgrades for now).
pub const LAYER_CRS: &str = "crs";
/// Custom-rules layer kind: `{ "rules": [ ... ] }`, ordered as written.
pub const LAYER_CUSTOM_RULES: &str = "custom_rules";

/// Every layer kind a policy (or a site override) may carry.
pub const LAYER_KINDS: [&str; 3] = [LAYER_ENGINE, LAYER_CRS, LAYER_CUSTOM_RULES];

/// Longest accepted custom rule expression.
const MAX_EXPRESSION_LEN: usize = 4096;
/// Longest accepted rule name / description / tag.
const MAX_NAME_LEN: usize = 120;
const MAX_DESCRIPTION_LEN: usize = 512;
const MAX_TAG_LEN: usize = 64;
/// Upper bounds that keep one layer payload bounded.
const MAX_RULES_PER_LAYER: usize = 200;
const MAX_TAGS_PER_RULE: usize = 16;

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
    /// Layer kinds the site overlay contributed to, in [`LAYER_KINDS`] order.
    pub override_kinds: Vec<String>,
}

impl Resolved {
    /// True when no policy (or overlay) contributes anything.
    pub fn is_empty(&self) -> bool {
        self.engine.is_empty()
            && self.crs.is_empty()
            && self.rules.is_empty()
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
            monitor_managed_rules: crs
                .monitor_managed_rules
                .or_else(|| settings.map(|row| row.monitor_managed_rules.clone()))
                .unwrap_or_default(),
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
    let by_kind: BTreeMap<&str, &Value> = layer_rows
        .iter()
        .filter(|row| is_layer_kind(&row.kind))
        .map(|row| (row.kind.as_str(), &row.config))
        .collect();

    let mut resolved = Resolved {
        policy_id: Some(policy.id),
        policy_name: Some(policy.name.clone()),
        revision: policy.revision,
        ..Resolved::default()
    };
    if let Some(Value::Object(engine)) = by_kind.get(LAYER_ENGINE) {
        resolved.engine = engine.clone();
    }
    if let Some(Value::Object(crs)) = by_kind.get(LAYER_CRS) {
        resolved.crs = crs.clone();
    }
    if let Some(config) = by_kind.get(LAYER_CUSTOM_RULES) {
        resolved.rules = parse_rules(config);
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
    for kind in LAYER_KINDS {
        let Some(patch) = overlay_map.get(kind) else {
            continue;
        };
        match kind {
            LAYER_ENGINE => {
                if let Some(engine) = patch.as_object() {
                    for (key, value) in engine {
                        resolved.engine.insert(key.clone(), value.clone());
                    }
                    resolved.override_kinds.push(kind.to_string());
                }
            }
            LAYER_CRS => {
                if let Some(crs) = patch.as_object() {
                    for (key, value) in crs {
                        resolved.crs.insert(key.clone(), value.clone());
                    }
                    resolved.override_kinds.push(kind.to_string());
                }
            }
            LAYER_CUSTOM_RULES => {
                let extra = parse_rules(patch);
                if !extra.is_empty() || patch.get("rules").is_some() {
                    resolved.override_kinds.push(kind.to_string());
                }
                resolved.rules.extend(extra);
            }
            _ => {}
        }
    }
    Ok(resolved)
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
}
