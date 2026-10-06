//! Challenge/CC protection settings management per site.

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
use crate::models::challenge_settings;

/// Valid challenge levels.
pub mod challenge_level {
    pub const NONE: &str = "none";
    pub const NON_INTERACTIVE: &str = "non_interactive";
    pub const MANAGED: &str = "managed";
    pub const INTERACTIVE: &str = "interactive";

    pub fn is_valid(level: &str) -> bool {
        matches!(level, NONE | NON_INTERACTIVE | MANAGED | INTERACTIVE)
    }

    /// Maps to proto `ChallengeLevel` enum.
    pub fn to_proto(level: &str) -> i32 {
        match level {
            NONE => 0,
            NON_INTERACTIVE => 1,
            MANAGED => 2,
            INTERACTIVE => 3,
            _ => 1,
        }
    }
}

#[derive(Debug, Deserialize)]
pub struct UpdateChallengeRequest {
    #[serde(default)]
    pub enabled: Option<bool>,
    #[serde(default)]
    pub under_attack_mode: Option<bool>,
    #[serde(default)]
    pub default_level: Option<String>,
    #[serde(default)]
    pub clearance_duration_secs: Option<i32>,
    #[serde(default)]
    pub rate_threshold: Option<i32>,
    #[serde(default)]
    pub exempt_paths: Option<Vec<String>>,
    #[serde(default)]
    pub browser_integrity_check: Option<bool>,
    #[serde(default)]
    pub tls_fingerprint_check: Option<bool>,
    #[serde(default)]
    pub cookie_secret: Option<String>,
}

/// Routes contributed to `/api/v1`.
pub fn routes() -> Router<AppState> {
    Router::new().route(
        "/sites/{site_id}/challenge",
        get(get_challenge).put(update_challenge),
    )
}

/// `GET /api/v1/sites/{site_id}/challenge`
async fn get_challenge(
    State(state): State<AppState>,
    current: AuthUser,
    Path(site_id): Path<String>,
) -> Result<Json<challenge_settings::Model>, ApiError> {
    let id = parse_uuid(&site_id, "site id")?;
    load_site_read(&state.db, id, &current).await?;

    let row = find_or_create(&state, id).await?;
    Ok(Json(row))
}

/// `PUT /api/v1/sites/{site_id}/challenge`
async fn update_challenge(
    State(state): State<AppState>,
    current: AuthUser,
    Path(site_id): Path<String>,
    Json(payload): Json<UpdateChallengeRequest>,
) -> Result<Json<challenge_settings::Model>, ApiError> {
    let id = parse_uuid(&site_id, "site id")?;
    load_site_write(&state.db, id, &current).await?;

    let row = find_or_create(&state, id).await?;
    let mut active: challenge_settings::ActiveModel = row.into();

    if let Some(enabled) = payload.enabled {
        active.enabled = Set(enabled);
    }
    if let Some(uam) = payload.under_attack_mode {
        active.under_attack_mode = Set(uam);
        // Under-attack mode is meaningless without the challenge gate: the
        // engine short-circuits to Pass when `enabled` is false, so turning
        // the banner on forces the gate on. Turning it off leaves `enabled`
        // alone — the operator may still want plain CC protection.
        if uam {
            active.enabled = Set(true);
        }
    }
    if let Some(level) = payload.default_level {
        if !challenge_level::is_valid(&level) {
            return Err(ApiError::BadRequest(format!(
                "invalid challenge level '{level}'; expected none, non_interactive, managed, interactive"
            )));
        }
        active.default_level = Set(level);
    }
    if let Some(duration) = payload.clearance_duration_secs {
        if !(60..=86400).contains(&duration) {
            return Err(ApiError::BadRequest(
                "clearance_duration_secs must be between 60 and 86400"
                    .to_string(),
            ));
        }
        active.clearance_duration_secs = Set(duration);
    }
    if let Some(threshold) = payload.rate_threshold {
        if !(1..=10_000_000).contains(&threshold) {
            return Err(ApiError::BadRequest(
                "rate_threshold must be between 1 and 10000000".to_string(),
            ));
        }
        active.rate_threshold = Set(threshold);
    }
    if let Some(paths) = payload.exempt_paths {
        let normalised: Vec<String> = paths
            .iter()
            .map(|p| p.trim().to_string())
            .filter(|p| !p.is_empty())
            .collect();
        active.exempt_paths = Set(normalised);
    }
    if let Some(bic) = payload.browser_integrity_check {
        active.browser_integrity_check = Set(bic);
    }
    if let Some(tls) = payload.tls_fingerprint_check {
        active.tls_fingerprint_check = Set(tls);
    }
    if let Some(secret) = payload.cookie_secret {
        active.cookie_secret = Set(if secret.trim().is_empty() {
            None
        } else {
            Some(secret)
        });
    }
    active.updated_at = Set(chrono::Utc::now());

    let updated = active.update(&state.db).await?;
    tracing::info!(site_id = %id, "challenge settings updated");
    touch_site(&state, id).await?;
    notify_config_changed(&state, id).await;

    Ok(Json(updated))
}

/// Finds the challenge_settings row for a site, creating a default one if absent.
async fn find_or_create(
    state: &AppState,
    site_id: Uuid,
) -> Result<challenge_settings::Model, ApiError> {
    if let Some(row) = challenge_settings::Entity::find()
        .filter(challenge_settings::Column::SiteId.eq(site_id))
        .one(&state.db)
        .await?
    {
        return Ok(row);
    }

    let now = chrono::Utc::now();
    let model = challenge_settings::ActiveModel {
        id: Set(Uuid::new_v4()),
        site_id: Set(site_id),
        enabled: Set(false),
        under_attack_mode: Set(false),
        default_level: Set(challenge_level::NON_INTERACTIVE.to_string()),
        clearance_duration_secs: Set(1800),
        rate_threshold: Set(100),
        exempt_paths: Set(Vec::new()),
        browser_integrity_check: Set(true),
        tls_fingerprint_check: Set(false),
        cookie_secret: Set(None),
        updated_at: Set(now),
    }
    .insert(&state.db)
    .await?;

    Ok(model)
}
