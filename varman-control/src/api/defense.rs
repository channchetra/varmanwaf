//! Global defense settings: the observation mode switch.
//!
//! With observation mode on, the data plane keeps every detection running
//! (WAF, IP/geo rules, bot protection, rate limiting) but only records what
//! it would have blocked — the request itself proceeds. The flag is shipped
//! to the agents inside each `RuleBundle`, so flipping it here takes effect
//! on the next configuration push.
//!
//! The settings row, its defaults and the out-of-band watcher live in
//! [`crate::defense_service`]; this module only exposes the routes.

use axum::extract::State;
use axum::routing::get;
use axum::Json;
use axum::Router;
use chrono::Utc;
use sea_orm::{ActiveModelTrait, Set};
use serde::Deserialize;

use crate::api::common::require_write;
use crate::api::error::ApiError;
use crate::api::state::AppState;
use crate::auth::AuthUser;
use crate::grpc::notify_all_config_changed;
use crate::models::defense_settings;

// Kept for the `varman` binary, which still reads the row through the API
// module; api handlers below use the same re-export.
pub use crate::defense_service::load;

/// Routes contributed to `/api/v1`.
pub fn routes() -> Router<AppState> {
    Router::new().route("/settings/defense", get(show).put(update))
}

#[derive(Debug, Deserialize)]
pub struct UpdateDefenseRequest {
    /// When present, sets the observation mode switch.
    #[serde(default)]
    pub observation_mode: Option<bool>,
    /// When present, sets the default disconnected behaviour for sites
    /// whose `failover_policy` is `inherit`.
    #[serde(default)]
    pub default_fail_open: Option<bool>,
}

/// `GET /api/v1/settings/defense` — administrators only.
async fn show(
    State(state): State<AppState>,
    current: AuthUser,
) -> Result<Json<defense_settings::Model>, ApiError> {
    current.require_admin().map_err(ApiError::from)?;
    Ok(Json(load(&state.db).await?))
}

/// `PUT /api/v1/settings/defense` — administrators only.
async fn update(
    State(state): State<AppState>,
    current: AuthUser,
    Json(payload): Json<UpdateDefenseRequest>,
) -> Result<Json<defense_settings::Model>, ApiError> {
    current.require_admin().map_err(ApiError::from)?;
    require_write(&current)?;

    if payload.observation_mode.is_none() && payload.default_fail_open.is_none()
    {
        return Err(ApiError::BadRequest(
            "provide observation_mode or default_fail_open".to_string(),
        ));
    }

    let row = load(&state.db).await?;
    let mut active: defense_settings::ActiveModel = row.into();
    if let Some(observation_mode) = payload.observation_mode {
        active.observation_mode = Set(observation_mode);
    }
    if let Some(default_fail_open) = payload.default_fail_open {
        active.default_fail_open = Set(default_fail_open);
    }
    active.updated_at = Set(Utc::now());

    let updated = active.update(&state.db).await?;
    tracing::info!(
        actor = %current.id,
        observation_mode = updated.observation_mode,
        default_fail_open = updated.default_fail_open,
        "defense settings updated"
    );

    // The flag rides inside every rule bundle, so each site's fingerprint
    // changes; push the new configuration now instead of waiting for the
    // watcher or the next periodic sync.
    notify_all_config_changed(&state, None).await;

    Ok(Json(updated))
}
