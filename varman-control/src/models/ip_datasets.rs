//! `ip_datasets` - IP range datasets synced from ipverse.
//!
//! One row per country (`kind = country`, `dataset_key = US`) or autonomous
//! system (`kind = asn`, `dataset_key = 13335`). The geo policy and the
//! client-IP analysis enforce with these ranges; a listed key without a row
//! is surfaced as missing and is not enforced.

use sea_orm::entity::prelude::*;
use serde::{Deserialize, Serialize};

#[derive(
    Clone, Debug, PartialEq, DeriveEntityModel, Serialize, Deserialize,
)]
#[sea_orm(table_name = "ip_datasets")]
pub struct Model {
    #[sea_orm(primary_key, auto_increment = false)]
    pub id: Uuid,
    /// `country` or `asn`.
    pub kind: String,
    /// Normalised key: `US` (upper-case ISO code) or `13335` (bare digits).
    pub dataset_key: String,
    pub ipv4_ranges: Vec<String>,
    pub ipv6_ranges: Vec<String>,
    /// The ipverse URL the ranges came from (IPv4; IPv6 is its sibling).
    pub source_url: String,
    /// Refresh cadence for the sweep; `None` disables automatic refresh.
    pub refresh_interval_minutes: Option<i32>,
    pub last_synced_at: Option<DateTimeUtc>,
    /// Why the most recent sync failed; `None` when the last sync succeeded.
    #[sea_orm(column_type = "Text")]
    pub last_error: Option<String>,
    pub created_at: DateTimeUtc,
    pub updated_at: DateTimeUtc,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {}

impl ActiveModelBehavior for ActiveModel {}
