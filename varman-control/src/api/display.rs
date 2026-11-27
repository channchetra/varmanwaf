//! Display settings: the instance timezone.
//!
//! One setting drives both halves. The console renders every absolute
//! timestamp in it (the web applies it to its `Intl` formatters), and the
//! server interprets date-only report bounds and daily buckets in it, so
//! "2026-10-14" means the operator's day, not UTC's.

use axum::extract::State;
use axum::routing::get;
use axum::{Json, Router};
use chrono_tz::Tz;
use sea_orm::{ActiveModelTrait, EntityTrait, Set};

use crate::api::common::require_write;
use crate::api::error::ApiError;
use crate::api::state::AppState;
use crate::auth::AuthUser;
use crate::time_util::SETTINGS_KEY;

pub use crate::time_util::{load, resolve, timezone, DisplaySettings};

/// Routes contributed to `/api/v1`.
pub fn routes() -> Router<AppState> {
    Router::new().route("/settings/display", get(show).put(save))
}

/// `GET /api/v1/settings/display` — any signed-in user: the console needs
/// the timezone to render timestamps.
async fn show(
    State(state): State<AppState>,
    _current: AuthUser,
) -> Result<Json<DisplaySettings>, ApiError> {
    Ok(Json(load(&state.db).await))
}

/// `PUT /api/v1/settings/display` — administrators only.
async fn save(
    State(state): State<AppState>,
    current: AuthUser,
    Json(payload): Json<DisplaySettings>,
) -> Result<Json<DisplaySettings>, ApiError> {
    current.require_admin().map_err(ApiError::from)?;
    require_write(&current)?;
    let timezone = payload.timezone.trim().to_string();
    if timezone.parse::<Tz>().is_err() {
        return Err(ApiError::BadRequest(format!(
            "unknown timezone '{timezone}' (use an IANA name like \
             Asia/Phnom_Penh, or UTC)"
        )));
    }
    let settings = DisplaySettings { timezone };
    store(&state.db, &settings).await?;
    tracing::info!(timezone = %settings.timezone, "display settings saved");
    Ok(Json(settings))
}

async fn store(
    db: &sea_orm::DatabaseConnection,
    settings: &DisplaySettings,
) -> Result<(), ApiError> {
    use crate::models::instance_setting;

    let value = serde_json::to_string(settings)
        .map_err(|err| ApiError::Internal(err.to_string()))?;
    let existing = instance_setting::Entity::find_by_id(SETTINGS_KEY)
        .one(db)
        .await?;
    match existing {
        Some(row) => {
            let mut active: instance_setting::ActiveModel = row.into();
            active.value = Set(value);
            active.updated_at = Set(chrono::Utc::now());
            active.update(db).await?;
        },
        None => {
            instance_setting::ActiveModel {
                key: Set(SETTINGS_KEY.to_string()),
                value: Set(value),
                updated_at: Set(chrono::Utc::now()),
            }
            .insert(db)
            .await?;
        },
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn resolve_parses_iana_names_and_defaults_to_utc() {
        assert_eq!(resolve("Asia/Phnom_Penh"), Tz::Asia__Phnom_Penh);
        assert_eq!(resolve("  UTC "), Tz::UTC);
        assert_eq!(resolve("not/a-zone"), Tz::UTC);
        assert_eq!(resolve(""), Tz::UTC);
    }
}
