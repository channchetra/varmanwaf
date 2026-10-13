//! Bot protection settings management per site.

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
use crate::models::bot_protection;

/// Valid bot protection actions.
fn is_valid_action(action: &str) -> bool {
    matches!(
        action,
        "block" | "challenge" | "js_challenge" | "log" | "allow"
    )
}

#[derive(Debug, Deserialize)]
pub struct UpdateBotRequest {
    #[serde(default)]
    pub enabled: Option<bool>,
    #[serde(default)]
    pub ua_analysis: Option<bool>,
    #[serde(default)]
    pub js_detection: Option<bool>,
    #[serde(default)]
    pub tls_fingerprint: Option<bool>,
    #[serde(default)]
    pub behavioral_analysis: Option<bool>,
    #[serde(default)]
    pub action: Option<String>,
    #[serde(default)]
    pub known_bots_whitelist: Option<serde_json::Value>,
    #[serde(default)]
    pub ip_verification_enabled: Option<bool>,
    #[serde(default)]
    pub dns_verification_enabled: Option<bool>,
    /// IP group treated as verified bot networks. A value replaces the
    /// reference (an empty string clears it); omission leaves it unchanged.
    #[serde(default)]
    pub verified_ip_group_id: Option<String>,
}

/// Routes contributed to `/api/v1`.
pub fn routes() -> Router<AppState> {
    Router::new().route(
        "/sites/{site_id}/bot-protection",
        get(get_bot).put(update_bot),
    )
}

/// `GET /api/v1/sites/{site_id}/bot-protection`
async fn get_bot(
    State(state): State<AppState>,
    current: AuthUser,
    Path(site_id): Path<String>,
) -> Result<Json<bot_protection::Model>, ApiError> {
    let id = parse_uuid(&site_id, "site id")?;
    load_site_read(&state.db, id, &current).await?;

    let row = find_or_create(&state, id).await?;
    Ok(Json(row))
}

/// `PUT /api/v1/sites/{site_id}/bot-protection`
async fn update_bot(
    State(state): State<AppState>,
    current: AuthUser,
    Path(site_id): Path<String>,
    Json(payload): Json<UpdateBotRequest>,
) -> Result<Json<bot_protection::Model>, ApiError> {
    let id = parse_uuid(&site_id, "site id")?;
    load_site_write(&state.db, id, &current).await?;

    let row = find_or_create(&state, id).await?;
    let mut active: bot_protection::ActiveModel = row.into();

    if let Some(enabled) = payload.enabled {
        active.enabled = Set(enabled);
    }
    if let Some(ua) = payload.ua_analysis {
        active.ua_analysis = Set(ua);
    }
    if let Some(js) = payload.js_detection {
        active.js_detection = Set(js);
    }
    if let Some(tls) = payload.tls_fingerprint {
        active.tls_fingerprint = Set(tls);
    }
    if let Some(behavioral) = payload.behavioral_analysis {
        active.behavioral_analysis = Set(behavioral);
    }
    if let Some(action) = payload.action {
        if !is_valid_action(&action) {
            return Err(ApiError::BadRequest(format!(
                "unknown bot action '{action}'"
            )));
        }
        active.action = Set(action);
    }
    if let Some(whitelist) = payload.known_bots_whitelist {
        if !whitelist.is_array() {
            return Err(ApiError::BadRequest(
                "known_bots_whitelist must be a JSON array".to_string(),
            ));
        }
        active.known_bots_whitelist = Set(whitelist);
    }
    if let Some(enabled) = payload.ip_verification_enabled {
        active.ip_verification_enabled = Set(enabled);
    }
    if let Some(enabled) = payload.dns_verification_enabled {
        active.dns_verification_enabled = Set(enabled);
    }
    if let Some(group) = payload.verified_ip_group_id {
        if group.is_empty() {
            active.verified_ip_group_id = Set(None);
        } else {
            let group_id = parse_uuid(&group, "verified ip group id")?;
            ensure_verified_group_usable(&state, id, group_id).await?;
            active.verified_ip_group_id = Set(Some(group_id));
        }
    }
    active.updated_at = Set(chrono::Utc::now());

    let updated = active.update(&state.db).await?;
    tracing::info!(site_id = %id, "bot protection updated");
    touch_site(&state, id).await?;
    notify_config_changed(&state, id, Some(&current.email)).await;

    Ok(Json(updated))
}

/// Ensures the IP group referenced as the verified-bot source is usable: it
/// must exist, be enabled and be reachable by this site (global or linked).
async fn ensure_verified_group_usable(
    state: &AppState,
    site_id: Uuid,
    group_id: Uuid,
) -> Result<(), ApiError> {
    let group = crate::models::ip_groups::Entity::find_by_id(group_id)
        .one(&state.db)
        .await?
        .ok_or_else(|| ApiError::NotFound("ip group not found".to_string()))?;
    if !group.enabled {
        return Err(ApiError::BadRequest(
            "the referenced ip group is disabled".to_string(),
        ));
    }
    if group.is_global {
        return Ok(());
    }
    let linked = crate::models::ip_group_sites::Entity::find()
        .filter(crate::models::ip_group_sites::Column::SiteId.eq(site_id))
        .filter(crate::models::ip_group_sites::Column::IpGroupId.eq(group_id))
        .one(&state.db)
        .await?
        .is_some();
    if !linked {
        return Err(ApiError::BadRequest(
            "the referenced ip group is not linked to this site".to_string(),
        ));
    }
    Ok(())
}

/// Finds the bot_protection row for a site, creating a default one if absent.
async fn find_or_create(
    state: &AppState,
    site_id: Uuid,
) -> Result<bot_protection::Model, ApiError> {
    if let Some(row) = bot_protection::Entity::find()
        .filter(bot_protection::Column::SiteId.eq(site_id))
        .one(&state.db)
        .await?
    {
        return Ok(row);
    }

    let now = chrono::Utc::now();
    let model = bot_protection::ActiveModel {
        id: Set(Uuid::new_v4()),
        site_id: Set(site_id),
        enabled: Set(false),
        ua_analysis: Set(true),
        js_detection: Set(true),
        tls_fingerprint: Set(false),
        behavioral_analysis: Set(false),
        action: Set("challenge".to_string()),
        known_bots_whitelist: Set(serde_json::json!([])),
        verified_ip_group_id: Set(None),
        ip_verification_enabled: Set(false),
        dns_verification_enabled: Set(false),
        updated_at: Set(now),
    }
    .insert(&state.db)
    .await?;

    Ok(model)
}
