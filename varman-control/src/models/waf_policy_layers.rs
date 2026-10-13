//! `waf_policy_layers` - the typed documents a policy is composed of.
//!
//! One row per `(policy, kind)`; writing a layer replaces the row. The
//! `config` JSONB payload is validated per kind by [`crate::policy`] before
//! it is stored (unknown kinds and keys are rejected), so the resolution
//! path can parse without re-validating on every bundle build.

use sea_orm::entity::prelude::*;
use serde::{Deserialize, Serialize};

#[derive(
    Clone, Debug, PartialEq, DeriveEntityModel, Serialize, Deserialize,
)]
#[sea_orm(table_name = "waf_policy_layers")]
pub struct Model {
    #[sea_orm(primary_key, auto_increment = false)]
    pub id: Uuid,
    pub policy_id: Uuid,
    /// `engine`, `crs` or `custom_rules` (see [`crate::policy::LAYER_KINDS`]).
    pub kind: String,
    /// Validated JSON payload of the layer.
    #[sea_orm(column_type = "JsonBinary")]
    pub config: Json,
    pub updated_at: DateTimeUtc,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {}

impl ActiveModelBehavior for ActiveModel {}
