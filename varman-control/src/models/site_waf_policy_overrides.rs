//! `site_waf_policy_overrides` - the sparse per-site delta on a policy.
//!
//! An object keyed by layer kind (`engine`, `crs`, `custom_rules`) holding
//! only the keys this site changes. Resolution applies the policy layer
//! first and this patch second, so an override wins over the shared policy
//! while everything unmentioned keeps inheriting from it.

use sea_orm::entity::prelude::*;
use serde::{Deserialize, Serialize};

#[derive(
    Clone, Debug, PartialEq, DeriveEntityModel, Serialize, Deserialize,
)]
#[sea_orm(table_name = "site_waf_policy_overrides")]
pub struct Model {
    #[sea_orm(primary_key, auto_increment = false)]
    pub site_id: Uuid,
    /// `{ "engine": {...}, "crs": {...}, "custom_rules": {...} }`, each key
    /// optional; validated with the same schemas as policy layers.
    #[sea_orm(column_type = "JsonBinary")]
    pub config: Json,
    pub updated_at: DateTimeUtc,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {}

impl ActiveModelBehavior for ActiveModel {}
