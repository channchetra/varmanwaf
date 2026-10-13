//! `ip_groups` — named collections of IP ranges that can be applied globally
//! or to specific sites as allow/block lists.

use sea_orm::entity::prelude::*;
use serde::{Deserialize, Serialize};

#[derive(
    Clone, Debug, PartialEq, DeriveEntityModel, Serialize, Deserialize,
)]
#[sea_orm(table_name = "ip_groups")]
pub struct Model {
    #[sea_orm(primary_key, auto_increment = false)]
    pub id: Uuid,
    pub name: String,
    #[sea_orm(column_type = "Text")]
    pub description: Option<String>,
    pub ip_ranges: Vec<String>,
    pub action: String,
    pub is_global: bool,
    /// Subscription source kind: `builtin` (compiled-in vendor snapshot),
    /// `url` (operator-supplied source), `None` (manual ranges only).
    pub subscription_kind: Option<String>,
    /// Whether the automatic sync scheduler refreshes this group.
    pub subscription_enabled: bool,
    #[sea_orm(column_type = "Text")]
    pub source_url: Option<String>,
    pub sync_interval_minutes: Option<i32>,
    pub last_synced_at: Option<DateTimeUtc>,
    /// Why the most recent subscription sync failed; `None` when the last sync
    /// succeeded (or none has run yet).
    #[sea_orm(column_type = "Text")]
    pub last_sync_error: Option<String>,
    pub enabled: bool,
    pub created_at: DateTimeUtc,
    pub updated_at: DateTimeUtc,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {}

impl ActiveModelBehavior for ActiveModel {}
