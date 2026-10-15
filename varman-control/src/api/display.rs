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
use serde::{Deserialize, Serialize};

use crate::api::error::ApiError;
use crate::api::state::AppState;
use crate::auth::AuthUser;

/// Key of the display settings row in `instance_settings`.
const SETTINGS_KEY: &str = "display_settings";

/// Routes contributed to `/api/v1`.
pub fn routes() -> Router<AppState> {
    Router::new().route("/settings/display", get(show).put(save))
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DisplaySettings {
    /// IANA timezone name; `UTC` by default.
    #[serde(default = "default_timezone")]
    pub timezone: String,
}

fn default_timezone() -> String {
    "UTC".to_string()
}

impl Default for DisplaySettings {
    fn default() -> Self {
        Self {
            timezone: default_timezone(),
        }
    }
}

/// Loads the display settings; defaults when absent or unparsable.
pub async fn load(db: &sea_orm::DatabaseConnection) -> DisplaySettings {
    use crate::models::instance_setting;

    let stored = instance_setting::Entity::find_by_id(SETTINGS_KEY)
        .one(db)
        .await
        .ok()
        .flatten();
    match stored {
        Some(row) => serde_json::from_str(&row.value).unwrap_or_default(),
        None => DisplaySettings::default(),
    }
}

/// The configured timezone, falling back to UTC when unset or invalid.
/// Writes are validated, so the fallback only covers old rows.
pub async fn timezone(db: &sea_orm::DatabaseConnection) -> Tz {
    resolve(&load(db).await.timezone)
}

/// Parses a timezone name, defaulting to UTC.
pub fn resolve(name: &str) -> Tz {
    name.trim().parse::<Tz>().unwrap_or(Tz::UTC)
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
