//! Global log retention settings.
//!
//! How long the access log and the security events are kept is a deployment
//! wide decision, so the two windows live in one single-row table and are
//! edited from the settings page. The background sweeper reads this row; the
//! manual `DELETE /logs/purge` endpoint stays independent of it.

use axum::extract::State;
use axum::routing::get;
use axum::Json;
use axum::Router;
use chrono::Utc;
use sea_orm::sea_query::OnConflict;
use sea_orm::{ActiveModelTrait, DatabaseConnection, DbErr, EntityTrait, Set};
use serde::Deserialize;

use crate::api::error::ApiError;
use crate::api::state::AppState;
use crate::auth::AuthUser;
use crate::models::log_retention;

/// Primary key of the single row.
const SETTINGS_ID: i32 = 1;

/// Routes contributed to `/api/v1`.
pub fn routes() -> Router<AppState> {
    Router::new().route("/settings/log-retention", get(show).put(update))
}

#[derive(Debug, Deserialize)]
pub struct UpdateLogRetentionRequest {
    /// Days a row of `access_logs` is kept before the sweeper deletes it.
    #[serde(default)]
    pub access_log_retention_days: Option<i32>,
    /// Days a row of `security_events` is kept.
    #[serde(default)]
    pub security_event_retention_days: Option<i32>,
}

/// `GET /api/v1/settings/log-retention` — administrators only.
async fn show(
    State(state): State<AppState>,
    current: AuthUser,
) -> Result<Json<log_retention::Model>, ApiError> {
    current.require_admin().map_err(ApiError::from)?;
    Ok(Json(load(&state.db).await?))
}

/// `PUT /api/v1/settings/log-retention` — administrators only.
async fn update(
    State(state): State<AppState>,
    current: AuthUser,
    Json(payload): Json<UpdateLogRetentionRequest>,
) -> Result<Json<log_retention::Model>, ApiError> {
    current.require_admin().map_err(ApiError::from)?;

    if payload.access_log_retention_days.is_none()
        && payload.security_event_retention_days.is_none()
    {
        return Err(ApiError::BadRequest(
            "provide at least one retention window".to_string(),
        ));
    }

    let row = load(&state.db).await?;
    let mut active: log_retention::ActiveModel = row.into();

    if let Some(days) = payload.access_log_retention_days {
        active.access_log_retention_days =
            Set(validate_days(days, "access log")?);
    }
    if let Some(days) = payload.security_event_retention_days {
        active.security_event_retention_days =
            Set(validate_days(days, "security event")?);
    }
    active.updated_at = Set(Utc::now());

    let updated = active.update(&state.db).await?;
    tracing::info!(
        actor = %current.id,
        access_days = updated.access_log_retention_days,
        security_days = updated.security_event_retention_days,
        "log retention settings updated"
    );

    Ok(Json(updated))
}

fn validate_days(days: i32, label: &str) -> Result<i32, ApiError> {
    if !(log_retention::MIN_RETENTION_DAYS..=log_retention::MAX_RETENTION_DAYS)
        .contains(&days)
    {
        return Err(ApiError::BadRequest(format!(
            "{label} retention must be between {} and {} days",
            log_retention::MIN_RETENTION_DAYS,
            log_retention::MAX_RETENTION_DAYS
        )));
    }
    Ok(days)
}

/// Reads the settings row, creating it with the defaults if it is missing.
///
/// `on_conflict_do_nothing` keeps two concurrent first requests from racing
/// each other into a duplicate-key error; whoever lost the insert reads the
/// row the winner wrote.
pub async fn load(
    db: &DatabaseConnection,
) -> Result<log_retention::Model, ApiError> {
    if let Some(row) = log_retention::Entity::find_by_id(SETTINGS_ID)
        .one(db)
        .await?
    {
        return Ok(row);
    }

    let insert = log_retention::ActiveModel {
        id: Set(SETTINGS_ID),
        access_log_retention_days: Set(log_retention::DEFAULT_RETENTION_DAYS),
        security_event_retention_days: Set(
            log_retention::DEFAULT_RETENTION_DAYS,
        ),
        updated_at: Set(Utc::now()),
    };
    let ignore_conflict = OnConflict::column(log_retention::Column::Id)
        .do_nothing()
        .to_owned();
    match log_retention::Entity::insert(insert)
        .on_conflict(ignore_conflict)
        .exec(db)
        .await
    {
        Ok(_) | Err(DbErr::RecordNotInserted) => {},
        Err(err) => return Err(err.into()),
    }

    log_retention::Entity::find_by_id(SETTINGS_ID)
        .one(db)
        .await?
        .ok_or_else(|| {
            ApiError::Internal(
                "log retention settings row vanished".to_string(),
            )
        })
}
