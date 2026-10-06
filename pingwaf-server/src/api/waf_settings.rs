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
/// with `CategorySet::parse_name` in `pingwaf-waf`.
pub const CATEGORIES: [&str; 9] = [
    "sqli", "xss", "rce", "lfi", "ssrf", "deser", "crlf", "xxe", "ssti",
];

/// Backend stacks a site can downgrade to monitor-only. Must stay in sync
/// with `StackSet::parse_name` in `pingwaf-waf`.
pub const STACKS: [&str; 4] = ["java", "php", "python", "node"];

#[derive(Debug, Deserialize)]
pub struct UpdateWafSettingsRequest {
    #[serde(default)]
    pub advanced_mode: Option<bool>,
    #[serde(default)]
    pub monitor_categories: Option<Vec<String>>,
    #[serde(default)]
    pub monitor_stacks: Option<Vec<String>>,
}

/// Routes contributed to `/api/v1`.
pub fn routes() -> Router<AppState> {
    Router::new().route(
        "/sites/{site_id}/waf/settings",
        get(get_waf_settings).put(update_waf_settings),
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

    if let Some(advanced) = payload.advanced_mode {
        active.advanced_mode = Set(advanced);
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
    // An update whose every field stays unchanged is silently dropped by
    // SeaORM; touching updated_at guarantees the row round-trips.
    active.updated_at = Set(chrono::Utc::now());

    let updated = active.update(&state.db).await?;
    tracing::info!(site_id = %id, "waf settings updated");
    touch_site(&state, id).await?;
    notify_config_changed(&state, id).await;

    Ok(Json(updated))
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

/// Finds the waf_settings row for a site, creating a default (enforce
/// everything, no advanced mode) one if absent.
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
        advanced_mode: Set(false),
        monitor_categories: Set(Vec::new()),
        monitor_stacks: Set(Vec::new()),
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
    fn the_whitelists_cover_every_engine_name() {
        // Every whitelisted name must be parseable by the engine, so a value
        // accepted by the API is never silently ignored by the data plane.
        for name in CATEGORIES {
            assert!(
                pingwaf_waf::CategorySet::parse_name(name).is_some(),
                "{name} not parseable by CategorySet"
            );
        }
        for name in STACKS {
            assert!(
                pingwaf_waf::StackSet::parse_name(name).is_some(),
                "{name} not parseable by StackSet"
            );
        }
    }
}
