//! Site-level WAF grading settings: advanced mode and per-category/stack
//! monitor lists.

use axum::extract::{Path, State};
use axum::routing::get;
use axum::Json;
use axum::Router;
use sea_orm::{ActiveModelTrait, ColumnTrait, EntityTrait, QueryFilter, Set};
use serde::Deserialize;
use uuid::Uuid;

use crate::api::common::{load_site_read, load_site_write, parse_uuid};
use crate::api::error::ApiError;
use crate::api::sites::touch_site;
use crate::api::state::AppState;
use crate::auth::AuthUser;
use crate::grpc::notify_config_changed;
use crate::models::waf_settings;

/// Attack categories a site can downgrade to monitor-only. Must stay in sync
/// with `CategorySet::parse_name` in `varman-waf`.
pub const CATEGORIES: [&str; 9] = [
    "sqli", "xss", "rce", "lfi", "ssrf", "deser", "crlf", "xxe", "ssti",
];

/// Backend stacks a site can downgrade to monitor-only. Must stay in sync
/// with `StackSet::parse_name` in `varman-waf`.
pub const STACKS: [&str; 4] = ["java", "php", "python", "node"];

/// Built-in managed rules a site can downgrade to monitor-only, by id.
/// Mirrors `varman_waf::MANAGED_RULE_IDS` (whitelisted through the crate so
/// a new managed rule cannot be configured before the engine knows it).
pub const MANAGED_RULES: [&str; 14] = varman_waf::MANAGED_RULE_IDS;

/// Engine modes a site can select. `inherit` keeps the process-wide
/// `VARMAN_WAF_ENGINE`; the others override it for this site.
pub const ENGINE_MODES: [&str; 4] = ["inherit", "legacy", "shadow", "varman"];

#[derive(Debug, Deserialize)]
pub struct UpdateWafSettingsRequest {
    #[serde(default)]
    pub waf_enabled: Option<bool>,
    #[serde(default)]
    pub mode: Option<String>,
    #[serde(default)]
    pub paranoia_level: Option<i32>,
    #[serde(default)]
    pub advanced_mode: Option<bool>,
    #[serde(default)]
    pub engine_mode: Option<String>,
    #[serde(default)]
    pub virtual_patches: Option<String>,
    #[serde(default)]
    pub openapi_spec: Option<String>,
    #[serde(default)]
    pub monitor_categories: Option<Vec<String>>,
    #[serde(default)]
    pub monitor_stacks: Option<Vec<String>>,
    #[serde(default)]
    pub monitor_managed_rules: Option<Vec<String>>,
}

/// Dashboard-facing metadata for one built-in managed rule.
#[derive(serde::Serialize)]
pub struct ManagedRuleEntry {
    pub id: String,
    pub name: String,
    pub action: String,
    pub severity: u8,
    pub tags: Vec<String>,
    pub stacks: Vec<String>,
    /// Attack family (`sqli`/`xss`/`rce`) whose per-category downgrade also
    /// affects this rule, or `None` for policy/recon rules.
    pub category: Option<String>,
    pub strict_only: bool,
}

/// Routes contributed to `/api/v1`.
pub fn routes() -> Router<AppState> {
    Router::new()
        .route(
            "/sites/{site_id}/waf/settings",
            get(get_waf_settings).put(update_waf_settings),
        )
        .route("/sites/{site_id}/waf/posture", get(get_waf_posture))
        .route("/managed-rules", get(list_managed_rules))
}

/// `GET /api/v1/managed-rules` — catalogue of the built-in managed rules.
///
/// Listed at the Strict level so the strict-only gate (VARMAN-1061) shows
/// too; a site running the Normal level simply never matches it, and the
/// `strict_only` flag tells the dashboard.
async fn list_managed_rules() -> Json<Vec<ManagedRuleEntry>> {
    Json(
        varman_waf::managed_rule_catalogue(varman_waf::WafLevel::Strict)
            .into_iter()
            .map(|rule| ManagedRuleEntry {
                id: rule.id,
                name: rule.name,
                action: rule.action,
                severity: rule.severity,
                tags: rule.tags,
                stacks: rule.stacks,
                category: rule.category,
                strict_only: rule.strict_only,
            })
            .collect(),
    )
}

/// `GET /api/v1/sites/{site_id}/waf/settings`
async fn get_waf_settings(
    State(state): State<AppState>,
    current: AuthUser,
    Path(site_id): Path<String>,
) -> Result<Json<waf_settings::Model>, ApiError> {
    let id = parse_uuid(&site_id, "site id")?;
    load_site_read(&state.db, id, &current).await?;

    let row = find_or_create(&state, id).await?;
    Ok(Json(row))
}

/// `PUT /api/v1/sites/{site_id}/waf/settings`
///
/// Patch semantics: omitted fields keep their current value.
async fn update_waf_settings(
    State(state): State<AppState>,
    current: AuthUser,
    Path(site_id): Path<String>,
    Json(payload): Json<UpdateWafSettingsRequest>,
) -> Result<Json<waf_settings::Model>, ApiError> {
    let id = parse_uuid(&site_id, "site id")?;
    load_site_write(&state.db, id, &current).await?;

    let row = find_or_create(&state, id).await?;
    let mut active: waf_settings::ActiveModel = row.into();

    if let Some(waf_enabled) = payload.waf_enabled {
        active.waf_enabled = Set(waf_enabled);
    }
    if let Some(mode) = payload.mode {
        let mode = normalise_mode(&mode)?;
        active.mode = Set(mode);
    }
    if let Some(paranoia_level) = payload.paranoia_level {
        if !(1..=4).contains(&paranoia_level) {
            return Err(ApiError::BadRequest(
                "paranoia_level must be between 1 and 4".to_string(),
            ));
        }
        active.paranoia_level = Set(paranoia_level);
    }
    if let Some(advanced) = payload.advanced_mode {
        active.advanced_mode = Set(advanced);
    }
    if let Some(engine_mode) = payload.engine_mode {
        let engine_mode = engine_mode.trim().to_ascii_lowercase();
        if !ENGINE_MODES.contains(&engine_mode.as_str()) {
            return Err(ApiError::BadRequest(format!(
                "unknown engine_mode value '{engine_mode}'; allowed: {}",
                ENGINE_MODES.join(", ")
            )));
        }
        active.engine_mode = Set(engine_mode);
    }
    if let Some(virtual_patches) = payload.virtual_patches {
        validate_virtual_patches(&virtual_patches)?;
        active.virtual_patches = Set(virtual_patches);
    }
    if let Some(openapi_spec) = payload.openapi_spec {
        validate_openapi_spec(&openapi_spec)?;
        active.openapi_spec = Set(openapi_spec);
    }
    if let Some(categories) = payload.monitor_categories {
        active.monitor_categories = Set(normalise_list(
            &categories,
            &CATEGORIES,
            "monitor_categories",
        )?);
    }
    if let Some(stacks) = payload.monitor_stacks {
        active.monitor_stacks =
            Set(normalise_list(&stacks, &STACKS, "monitor_stacks")?);
    }
    if let Some(rules) = payload.monitor_managed_rules {
        active.monitor_managed_rules =
            Set(normalise_rule_ids(&rules, "monitor_managed_rules")?);
    }
    // An update whose every field stays unchanged is silently dropped by
    // SeaORM; touching updated_at guarantees the row round-trips.
    active.updated_at = Set(chrono::Utc::now());

    let updated = active.update(&state.db).await?;
    tracing::info!(site_id = %id, "waf settings updated");
    touch_site(&state, id).await?;
    notify_config_changed(&state, id, Some(&current.email)).await;

    Ok(Json(updated))
}

/* ── Effective posture ────────────────────────────────────────────── */

/// The site's effective WAF posture: what the data plane actually enforces
/// right now, aggregated from the rules, settings and global switches.
#[derive(Debug, serde::Serialize)]
pub struct WafPosture {
    /// Explicit engine switch (`"on"` / `"off"`).
    pub engine: &'static str,
    pub detection: WafPostureDetection,
    pub enforcement: WafPostureEnforcement,
}

#[derive(Debug, serde::Serialize)]
pub struct WafPostureDetection {
    /// The managed ruleset is always loaded by the data plane.
    pub managed: bool,
    /// At least one enabled custom rule is active.
    pub custom: bool,
    /// Advanced mode: strict level + body deep inspection.
    pub deep_inspection: bool,
    /// Under Attack mode is on (challenge settings enabled and switched on).
    pub under_attack: bool,
}

#[derive(Debug, serde::Serialize)]
pub struct WafPostureEnforcement {
    /// Explicit site-level enforcement mode (`off`/`monitor`/`block`).
    /// Falls back to the legacy rule derivation when no posture row exists.
    pub mode: String,
    /// Managed ruleset action per attack category (`sqli`, `xss`, ...):
    /// `"monitor"` when the category is downgraded, `"block"` otherwise.
    pub managed: std::collections::BTreeMap<String, String>,
    /// Aggregate custom-rule mode: block > monitor > off.
    pub custom_rules: String,
    /// Strongest action among enabled rate-limit rules, or `"off"`.
    pub cc: String,
    /// Bot protection action, or `"off"` when disabled/absent.
    pub bot: String,
    /// Global observation mode: protective actions become observe-only.
    pub observation_mode: bool,
}

/// Rate-limit actions ordered strongest-first; `allow` never mitigates and
/// is treated as `off`.
const CC_ACTION_STRENGTH: [&str; 4] =
    ["block", "challenge", "js_challenge", "log"];

/// `GET /api/v1/sites/{site_id}/waf/posture`
async fn get_waf_posture(
    State(state): State<AppState>,
    current: AuthUser,
    Path(site_id): Path<String>,
) -> Result<Json<WafPosture>, ApiError> {
    use crate::models::{
        bot_protection, challenge_settings, defense_settings, mode,
        rate_limit_rules, rule,
    };

    let id = parse_uuid(&site_id, "site id")?;
    load_site_read(&state.db, id, &current).await?;

    let settings = waf_settings::Entity::find()
        .filter(waf_settings::Column::SiteId.eq(id))
        .one(&state.db)
        .await?;
    let engine_on = settings.as_ref().map(|s| s.waf_enabled).unwrap_or(true);

    let active_rules = rule::Entity::find()
        .filter(rule::Column::SiteId.eq(id))
        .filter(rule::Column::Enabled.eq(true))
        .all(&state.db)
        .await?;
    let custom_mode =
        if active_rules.iter().any(|rule| rule.mode == mode::BLOCK) {
            "block".to_string()
        } else if active_rules.iter().any(|rule| rule.mode == mode::MONITOR) {
            "monitor".to_string()
        } else {
            "off".to_string()
        };
    // The explicit site mode wins; the rule derivation is only the fallback
    // for a site that never got a posture row.
    let site_mode = settings
        .as_ref()
        .map(|s| s.mode.clone())
        .unwrap_or_else(|| custom_mode.clone());

    let rate_limits = rate_limit_rules::Entity::find()
        .filter(rate_limit_rules::Column::SiteId.eq(id))
        .filter(rate_limit_rules::Column::Enabled.eq(true))
        .all(&state.db)
        .await?;
    let cc = CC_ACTION_STRENGTH
        .iter()
        .find(|strongest| {
            rate_limits.iter().any(|rule| &rule.action == *strongest)
        })
        .map(|strongest| strongest.to_string())
        .unwrap_or_else(|| "off".to_string());

    let bot = bot_protection::Entity::find()
        .filter(bot_protection::Column::SiteId.eq(id))
        .one(&state.db)
        .await?
        .filter(|row| row.enabled)
        .map(|row| row.action)
        .unwrap_or_else(|| "off".to_string());

    let under_attack = challenge_settings::Entity::find()
        .filter(challenge_settings::Column::SiteId.eq(id))
        .one(&state.db)
        .await?
        .filter(|row| row.enabled)
        .is_some_and(|row| row.under_attack_mode);

    // A missing global row means observation mode was never switched on.
    let observation_mode = defense_settings::Entity::find_by_id(1)
        .one(&state.db)
        .await?
        .is_some_and(|row| row.observation_mode);

    let managed: std::collections::BTreeMap<String, String> = CATEGORIES
        .iter()
        .map(|category| {
            let action = if settings.as_ref().is_some_and(|s| {
                s.monitor_categories.iter().any(|m| m == category)
            }) {
                "monitor"
            } else {
                "block"
            };
            (category.to_string(), action.to_string())
        })
        .collect();

    Ok(Json(WafPosture {
        engine: if engine_on { "on" } else { "off" },
        detection: WafPostureDetection {
            managed: true,
            custom: !active_rules.is_empty(),
            deep_inspection: settings
                .as_ref()
                .map(|s| s.advanced_mode)
                .unwrap_or(false),
            under_attack,
        },
        enforcement: WafPostureEnforcement {
            mode: site_mode,
            managed,
            custom_rules: custom_mode,
            cc,
            bot,
            observation_mode,
        },
    }))
}

/// Trims and lowercase-validates the site enforcement mode.
fn normalise_mode(raw: &str) -> Result<String, ApiError> {
    use crate::models::mode;
    let value = raw.trim().to_ascii_lowercase();
    if !mode::is_valid(&value) {
        return Err(ApiError::BadRequest(format!(
            "unknown mode value '{value}'; allowed: {}, {}, {}",
            mode::OFF,
            mode::MONITOR,
            mode::BLOCK
        )));
    }
    Ok(value)
}

/// Validates a SecLang virtual-patch source by compiling it with the native
/// engine: an invalid rule is rejected at the API, never shipped to the edge.
fn validate_virtual_patches(source: &str) -> Result<(), ApiError> {
    if source.trim().is_empty() {
        return Ok(());
    }
    varman_waf::seclang::SecRuleSet::from_source(source).map_err(|error| {
        ApiError::BadRequest(format!("invalid SecLang virtual patch: {error}"))
    })?;
    Ok(())
}

/// Validates an OpenAPI document: JSON object with a `paths` object.
fn validate_openapi_spec(source: &str) -> Result<(), ApiError> {
    if source.trim().is_empty() {
        return Ok(());
    }
    let value: serde_json::Value =
        serde_json::from_str(source).map_err(|error| {
            ApiError::BadRequest(format!(
                "OpenAPI spec is not valid JSON: {error}"
            ))
        })?;
    let Some(object) = value.as_object() else {
        return Err(ApiError::BadRequest(
            "OpenAPI spec must be a JSON object".to_string(),
        ));
    };
    if !object
        .get("paths")
        .is_some_and(serde_json::Value::is_object)
    {
        return Err(ApiError::BadRequest(
            "OpenAPI spec must contain a `paths` object".to_string(),
        ));
    }
    Ok(())
}
/// Trims, lowercases, de-duplicates and whitelist-checks a monitor list.
fn normalise_list(
    raw: &[String],
    allowed: &[&str],
    field: &str,
) -> Result<Vec<String>, ApiError> {
    let mut out: Vec<String> = Vec::with_capacity(raw.len());
    for value in raw {
        let value = value.trim().to_ascii_lowercase();
        if value.is_empty() {
            continue;
        }
        if !allowed.contains(&value.as_str()) {
            return Err(ApiError::BadRequest(format!(
                "unknown {field} value '{value}'; allowed: {}",
                allowed.join(", ")
            )));
        }
        if !out.contains(&value) {
            out.push(value);
        }
    }
    Ok(out)
}

/// Trims, de-duplicates and whitelist-checks a managed-rule id list. Unlike
/// category/stack names, ids keep their case (`VARMAN-1010`).
fn normalise_rule_ids(
    raw: &[String],
    field: &str,
) -> Result<Vec<String>, ApiError> {
    let mut out: Vec<String> = Vec::with_capacity(raw.len());
    for value in raw {
        let value = value.trim().to_string();
        if value.is_empty() {
            continue;
        }
        if !MANAGED_RULES.contains(&value.as_str()) {
            return Err(ApiError::BadRequest(format!(
                "unknown {field} value '{value}'; allowed: {}",
                MANAGED_RULES.join(", ")
            )));
        }
        if !out.contains(&value) {
            out.push(value);
        }
    }
    Ok(out)
}

/// Derives the legacy site mode from the site's enabled custom rules
/// (block > monitor > off). Used exactly once when the posture row is first
/// created so a lazy-created row matches the historical behavior; afterwards
/// the stored explicit value wins.
async fn derive_site_mode(
    db: &sea_orm::DatabaseConnection,
    site_id: Uuid,
) -> Result<String, ApiError> {
    use crate::models::{mode, rule};
    let active = rule::Entity::find()
        .filter(rule::Column::SiteId.eq(site_id))
        .filter(rule::Column::Enabled.eq(true))
        .all(db)
        .await?;
    let derived = if active.iter().any(|rule| rule.mode == mode::BLOCK) {
        mode::BLOCK
    } else if active.iter().any(|rule| rule.mode == mode::MONITOR) {
        mode::MONITOR
    } else {
        mode::OFF
    };
    Ok(derived.to_string())
}

/// Finds the waf_settings row for a site, creating a default (enforce
/// everything, no advanced mode) one if absent. The freshly created row
/// seeds `mode` from the site's enabled rules once, matching the legacy
/// derivation the data plane used before the explicit column existed.
async fn find_or_create(
    state: &AppState,
    site_id: Uuid,
) -> Result<waf_settings::Model, ApiError> {
    if let Some(row) = waf_settings::Entity::find()
        .filter(waf_settings::Column::SiteId.eq(site_id))
        .one(&state.db)
        .await?
    {
        return Ok(row);
    }

    let now = chrono::Utc::now();
    let model = waf_settings::ActiveModel {
        id: Set(Uuid::new_v4()),
        site_id: Set(site_id),
        waf_enabled: Set(true),
        mode: Set(derive_site_mode(&state.db, site_id).await?),
        paranoia_level: Set(2),
        advanced_mode: Set(false),
        engine_mode: Set("inherit".to_string()),
        virtual_patches: Set(String::new()),
        openapi_spec: Set(String::new()),
        monitor_categories: Set(Vec::new()),
        monitor_stacks: Set(Vec::new()),
        monitor_managed_rules: Set(Vec::new()),
        created_at: Set(now),
        updated_at: Set(now),
    }
    .insert(&state.db)
    .await?;

    Ok(model)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::api::error::ApiError;

    #[test]
    fn normalise_list_trims_lowercases_and_deduplicates() {
        let out = normalise_list(
            &[" SQLI ".into(), "sqli".into(), "SSTI".into(), "".into()],
            &CATEGORIES,
            "monitor_categories",
        )
        .unwrap();
        assert_eq!(out, vec!["sqli", "ssti"]);
    }

    #[test]
    fn normalise_rule_ids_keeps_case_and_validates() {
        let out = normalise_rule_ids(
            &[" VARMAN-1010 ".into(), "VARMAN-1010".into()],
            "monitor_managed_rules",
        )
        .unwrap();
        assert_eq!(out, vec!["VARMAN-1010"]);

        let err = normalise_rule_ids(
            &["VARMAN-9999".into()],
            "monitor_managed_rules",
        )
        .unwrap_err();
        assert!(matches!(err, ApiError::BadRequest(_)));
        assert!(err.to_string().contains("VARMAN-9999"));
    }

    #[test]
    fn normalise_list_rejects_unknown_values() {
        let err = normalise_list(
            &["sqli".into(), "bogus".into()],
            &CATEGORIES,
            "monitor_categories",
        )
        .unwrap_err();
        assert!(matches!(err, ApiError::BadRequest(_)));
        assert!(err.to_string().contains("bogus"));
    }

    #[test]
    fn normalise_mode_trims_and_validates() {
        assert_eq!(normalise_mode(" Block ").unwrap(), "block");
        assert_eq!(normalise_mode("MONITOR").unwrap(), "monitor");

        let err = normalise_mode("bogus").unwrap_err();
        assert!(matches!(err, ApiError::BadRequest(_)));
        assert!(err.to_string().contains("bogus"));
    }

    #[test]
    fn the_whitelists_cover_every_engine_name() {
        // Every whitelisted name must be parseable by the engine, so a value
        // accepted by the API is never silently ignored by the data plane.
        for name in CATEGORIES {
            assert!(
                varman_waf::CategorySet::parse_name(name).is_some(),
                "{name} not parseable by CategorySet"
            );
        }
        for name in STACKS {
            assert!(
                varman_waf::StackSet::parse_name(name).is_some(),
                "{name} not parseable by StackSet"
            );
        }
    }
}
