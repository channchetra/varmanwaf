//! `waf_settings` — per-site WAF posture configuration.
//!
//! Holds the detection knobs that are not derivable from the rules table:
//! the advanced-mode switch (strict level + body deep inspection) and the
//! monitor-only downgrade sets for attack categories and backend stacks.
//! A missing row means "enforce everything at the normal level" — the
//! historical default.

use sea_orm::entity::prelude::*;
use serde::{Deserialize, Serialize};

#[derive(
    Clone, Debug, PartialEq, DeriveEntityModel, Serialize, Deserialize,
)]
#[sea_orm(table_name = "waf_settings")]
pub struct Model {
    #[sea_orm(primary_key, auto_increment = false)]
    pub id: Uuid,
    #[sea_orm(unique)]
    pub site_id: Uuid,
    /// Explicit engine switch; `false` short-circuits WAF evaluation for the
    /// site regardless of rules or posture. A missing row means `true`.
    pub waf_enabled: bool,
    /// Site-level enforcement mode (`off` / `monitor` / `block`). This is the
    /// authoritative switch; rule modes only feed the one-time migration
    /// backfill. A missing row falls back to the legacy rule derivation.
    pub mode: String,
    /// Detection sensitivity (1-4). Decoupled from rule severity: a missing
    /// row means the default 2.
    pub paranoia_level: i32,
    pub advanced_mode: bool,
    /// Per-site engine mode: `inherit` (process default), `legacy`, `shadow`
    /// or `varman`.
    pub engine_mode: String,
    /// SecLang virtual-patch source evaluated by the native engine.
    pub virtual_patches: String,
    /// OpenAPI document (JSON) used for request-shape validation.
    pub openapi_spec: String,
    pub monitor_categories: Vec<String>,
    pub monitor_stacks: Vec<String>,
    pub monitor_managed_rules: Vec<String>,
    pub created_at: DateTimeUtc,
    pub updated_at: DateTimeUtc,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {}

impl ActiveModelBehavior for ActiveModel {}
