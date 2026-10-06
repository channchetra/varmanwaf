//! `log_retention_settings` — one global row holding how long the two log
//! tables are kept, in days.

use sea_orm::entity::prelude::*;
use serde::{Deserialize, Serialize};

#[derive(
    Clone, Debug, PartialEq, DeriveEntityModel, Serialize, Deserialize,
)]
#[sea_orm(table_name = "log_retention_settings")]
pub struct Model {
    /// Always `1`: the settings are global, not per-site.
    #[sea_orm(primary_key, auto_increment = false)]
    pub id: i32,
    pub access_log_retention_days: i32,
    pub security_event_retention_days: i32,
    pub updated_at: DateTimeUtc,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {}

impl ActiveModelBehavior for ActiveModel {}

/// Accepted retention windows, matching the manual purge endpoint.
pub const MIN_RETENTION_DAYS: i32 = 1;
pub const MAX_RETENTION_DAYS: i32 = 3650;
/// Retention a settings row is created with.
pub const DEFAULT_RETENTION_DAYS: i32 = 180;
