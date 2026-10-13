//! Global defense settings: the observation mode switch.
//!
//! With observation mode on, the data plane keeps every detection running
//! (WAF, IP/geo rules, bot protection, rate limiting) but only records what
//! it would have blocked — the request itself proceeds. The flag is shipped
//! to the agents inside each `RuleBundle`, so flipping it here takes effect
//! on the next configuration push.

use std::time::Duration;

use axum::extract::State;
use axum::routing::get;
use axum::Json;
use axum::Router;
use chrono::{DateTime, Utc};
use sea_orm::sea_query::OnConflict;
use sea_orm::{ActiveModelTrait, DatabaseConnection, DbErr, EntityTrait, Set};
use serde::Deserialize;

use crate::api::error::ApiError;
use crate::api::state::AppState;
use crate::auth::AuthUser;
use crate::grpc::notify_all_config_changed;
use crate::models::defense_settings;

/// Primary key of the single row.
const SETTINGS_ID: i32 = 1;

/// How often [`start_watch_task`] re-reads the settings row.
const WATCH_INTERVAL: Duration = Duration::from_secs(15);

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

/// Background task: pushes the observation mode to the agents when another
/// process flips it — the `varman mode observe` CLI writes the row
/// directly, so nothing would call [`notify_all_config_changed`] for it.
///
/// The API handler pushes immediately as well; the duplicate delivery is
/// harmless (the agent applies the same configuration and the data plane
/// reload watcher sees an unchanged hash).
pub async fn start_watch_task(state: AppState) -> tokio::task::JoinHandle<()> {
    let initial: Option<DateTime<Utc>> =
        load(&state.db).await.ok().map(|row| row.updated_at);
    tokio::spawn(async move {
        let mut last = initial;
        loop {
            tokio::time::sleep(WATCH_INTERVAL).await;
            let Ok(row) = load(&state.db).await else {
                continue;
            };
            let previous = last.replace(row.updated_at);
            if previous == Some(row.updated_at) {
                continue;
            }
            tracing::info!(
                observation_mode = row.observation_mode,
                "defense settings changed outside the API, pushing to agents"
            );
            notify_all_config_changed(&state, None).await;
        }
    })
}

/// Reads the settings row, creating it with the defaults if it is missing.
///
/// Shared with the gRPC layer, which stamps the observation flag onto every
/// rule bundle it builds.
pub async fn load(
    db: &DatabaseConnection,
) -> Result<defense_settings::Model, ApiError> {
    if let Some(row) = defense_settings::Entity::find_by_id(SETTINGS_ID)
        .one(db)
        .await?
    {
        return Ok(row);
    }

    let insert = defense_settings::ActiveModel {
        id: Set(SETTINGS_ID),
        observation_mode: Set(false),
        default_fail_open: Set(true),
        updated_at: Set(Utc::now()),
    };
    let ignore_conflict = OnConflict::column(defense_settings::Column::Id)
        .do_nothing()
        .to_owned();
    match defense_settings::Entity::insert(insert)
        .on_conflict(ignore_conflict)
        .exec(db)
        .await
    {
        Ok(_) | Err(DbErr::RecordNotInserted) => {},
        Err(err) => return Err(err.into()),
    }

    defense_settings::Entity::find_by_id(SETTINGS_ID)
        .one(db)
        .await?
        .ok_or_else(|| {
            ApiError::Internal("defense settings row vanished".to_string())
        })
}
