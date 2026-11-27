//! Timezone and timestamp helpers shared by the REST API and the control-plane
//! services.
//!
//! The display settings row drives both the console and the report bounds, so
//! resolving it lives at the crate root rather than in the HTTP layer. The
//! [`crate::api::display`] module re-exports the items for the handlers.

use chrono::{DateTime, Utc};
use chrono_tz::Tz;
use sea_orm::{DatabaseConnection, EntityTrait};
use serde::{Deserialize, Serialize};

/// Key of the display settings row in `instance_settings`.
pub(crate) const SETTINGS_KEY: &str = "display_settings";

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
pub async fn load(db: &DatabaseConnection) -> DisplaySettings {
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
pub async fn timezone(db: &DatabaseConnection) -> Tz {
    resolve(&load(db).await.timezone)
}

/// Parses a timezone name, defaulting to UTC.
pub fn resolve(name: &str) -> Tz {
    name.trim().parse::<Tz>().unwrap_or(Tz::UTC)
}

/// `time` (used by rcgen) to `chrono` (used by the database models).
pub(crate) fn to_utc(value: time::OffsetDateTime) -> DateTime<Utc> {
    DateTime::from_timestamp(value.unix_timestamp(), 0).unwrap_or_else(Utc::now)
}
