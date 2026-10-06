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
    pub advanced_mode: bool,
    pub monitor_categories: Vec<String>,
    pub monitor_stacks: Vec<String>,
    pub created_at: DateTimeUtc,
    pub updated_at: DateTimeUtc,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {}

impl ActiveModelBehavior for ActiveModel {}
