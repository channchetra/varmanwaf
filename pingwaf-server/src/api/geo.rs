//! Geo restriction management: per-site geographic blocking/allowing.

use axum::extract::{Path, State};
use axum::routing::get;
use axum::Json;
use axum::Router;
use sea_orm::{ActiveModelTrait, ColumnTrait, EntityTrait, QueryFilter, Set};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::api::common::{
    load_site_read, load_site_write, parse_uuid, query_all,
};
use crate::api::error::ApiError;
use crate::api::sites::touch_site;
use crate::api::state::AppState;
use crate::auth::AuthUser;
use crate::grpc::notify_config_changed;
use crate::models::{action, geo_rules};

/// Valid geo modes.
mod geo_mode {
    pub const BLOCK_LIST: &str = "block_list";
    pub const ALLOW_LIST: &str = "allow_list";

    pub fn is_valid(mode: &str) -> bool {
        matches!(mode, BLOCK_LIST | ALLOW_LIST)
    }
}

#[derive(Debug, Deserialize)]
pub struct UpdateGeoRequest {
    #[serde(default)]
    pub enabled: Option<bool>,
    #[serde(default)]
    pub mode: Option<String>,
    #[serde(default)]
    pub countries: Option<Vec<String>>,
    #[serde(default)]
    pub blocked_asns: Option<Vec<String>>,
    #[serde(default)]
    pub block_unknown: Option<bool>,
    #[serde(default)]
    pub action: Option<String>,
}

/// How far back the country statistics look.
const STATS_WINDOW_HOURS: i64 = 24;
/// Countries returned by the statistics endpoint.
const STATS_LIMIT: i64 = 20;

/// One country's request count over the trailing window.
#[derive(Debug, Serialize)]
pub struct CountryStat {
    pub country_code: String,
    pub requests: i64,
}

/// Routes contributed to `/api/v1`.
pub fn routes() -> Router<AppState> {
    Router::new()
        .route("/sites/{site_id}/geo", get(get_geo).put(update_geo))
        .route("/sites/{site_id}/geo/stats", get(geo_stats))
}

/// `GET /api/v1/sites/{site_id}/geo/stats`
///
/// Requests per country over the last 24 hours, for the bar chart next to the
/// policy editor. Traffic whose country could not be resolved is skipped.
async fn geo_stats(
    State(state): State<AppState>,
    current: AuthUser,
    Path(site_id): Path<String>,
) -> Result<Json<Vec<CountryStat>>, ApiError> {
    let id = parse_uuid(&site_id, "site id")?;
    load_site_read(&state.db, id, &current).await?;

    let since =
        chrono::Utc::now() - chrono::Duration::hours(STATS_WINDOW_HOURS);
    let rows = query_all(
        &state.db,
        "SELECT country_code, COUNT(*) AS requests \
         FROM access_logs \
         WHERE site_id = $1 AND timestamp >= $2 \
           AND country_code IS NOT NULL AND country_code <> '' \
         GROUP BY country_code ORDER BY requests DESC LIMIT $3",
        vec![id.into(), since.into(), STATS_LIMIT.into()],
    )
    .await?;

    Ok(Json(
        rows.iter()
            .map(|row| CountryStat {
                country_code: row
                    .try_get::<String>("", "country_code")
                    .unwrap_or_default(),
                requests: row
                    .try_get::<i64>("", "requests")
                    .unwrap_or_default(),
            })
            .collect(),
    ))
}

/// `GET /api/v1/sites/{site_id}/geo`
async fn get_geo(
    State(state): State<AppState>,
    current: AuthUser,
    Path(site_id): Path<String>,
) -> Result<Json<geo_rules::Model>, ApiError> {
    let id = parse_uuid(&site_id, "site id")?;
    load_site_read(&state.db, id, &current).await?;

    let row = find_or_create(&state, id).await?;
    Ok(Json(row))
}

/// `PUT /api/v1/sites/{site_id}/geo`
async fn update_geo(
    State(state): State<AppState>,
    current: AuthUser,
    Path(site_id): Path<String>,
    Json(payload): Json<UpdateGeoRequest>,
) -> Result<Json<geo_rules::Model>, ApiError> {
    let id = parse_uuid(&site_id, "site id")?;
    load_site_write(&state.db, id, &current).await?;

    let row = find_or_create(&state, id).await?;
    let mut active: geo_rules::ActiveModel = row.into();

    if let Some(enabled) = payload.enabled {
        active.enabled = Set(enabled);
    }
    if let Some(mode) = payload.mode {
        if !geo_mode::is_valid(&mode) {
            return Err(ApiError::BadRequest(format!(
                "invalid geo mode '{mode}'; expected block_list or allow_list"
            )));
        }
        active.mode = Set(mode);
    }
    if let Some(countries) = payload.countries {
        let normalised: Vec<String> = countries
            .iter()
            .map(|c| c.trim().to_uppercase())
            .filter(|c| {
                c.len() == 2 && c.chars().all(|ch| ch.is_ascii_alphabetic())
            })
            .collect();
        active.countries = Set(normalised);
    }
    if let Some(asns) = payload.blocked_asns {
        let normalised: Vec<String> = asns
            .iter()
            .map(|a| a.trim().to_uppercase())
            .filter(|a| !a.is_empty())
            .collect();
        active.blocked_asns = Set(normalised);
    }
    if let Some(block_unknown) = payload.block_unknown {
        active.block_unknown = Set(block_unknown);
    }
    if let Some(action_str) = payload.action {
        if !action::is_valid_geo(&action_str) {
            return Err(ApiError::BadRequest(format!(
                "invalid geo action '{action_str}'; expected block, challenge, js_challenge or basic_auth"
            )));
        }
        active.action = Set(action_str);
    }
    active.updated_at = Set(chrono::Utc::now());

    let updated = active.update(&state.db).await?;
    tracing::info!(site_id = %id, "geo rules updated");
    touch_site(&state, id).await?;
    notify_config_changed(&state, id).await;

    Ok(Json(updated))
}

/// Finds the geo_rules row for a site, creating a default one if absent.
async fn find_or_create(
    state: &AppState,
    site_id: Uuid,
) -> Result<geo_rules::Model, ApiError> {
    if let Some(row) = geo_rules::Entity::find()
        .filter(geo_rules::Column::SiteId.eq(site_id))
        .one(&state.db)
        .await?
    {
        return Ok(row);
    }

    let now = chrono::Utc::now();
    let model = geo_rules::ActiveModel {
        id: Set(Uuid::new_v4()),
        site_id: Set(site_id),
        enabled: Set(false),
        mode: Set(geo_mode::BLOCK_LIST.to_string()),
        countries: Set(Vec::new()),
        blocked_asns: Set(Vec::new()),
        block_unknown: Set(false),
        action: Set(action::BLOCK.to_string()),
        updated_at: Set(now),
    }
    .insert(&state.db)
    .await?;

    Ok(model)
}
