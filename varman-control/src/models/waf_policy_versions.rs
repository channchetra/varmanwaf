//! `waf_policy_versions` - immutable policy snapshots.
//!
//! Each row captures a policy's fields and layers at one revision, with a
//! content hash for deduplication and the actor who made the change.
//! Rollback reads a row and records a new one, so history is append-only.

use sea_orm::entity::prelude::*;
use serde::{Deserialize, Serialize};

#[derive(
    Clone, Debug, PartialEq, DeriveEntityModel, Serialize, Deserialize,
)]
#[sea_orm(table_name = "waf_policy_versions")]
pub struct Model {
    #[sea_orm(primary_key)]
    pub id: i64,
    pub policy_id: Uuid,
    /// Policy revision this snapshot was taken at.
    pub revision: i32,
    /// SHA-256 of the canonical snapshot content (dedup + display).
    pub config_hash: String,
    /// `api` or `rollback`.
    pub source: String,
    pub actor: Option<String>,
    /// Per-layer entry counts, so the console can summarise cheaply.
    #[sea_orm(column_type = "JsonBinary")]
    pub summary: Option<Json>,
    /// `{ name, description, enabled, layers: { kind: config } }`.
    #[sea_orm(column_type = "JsonBinary")]
    pub snapshot: Json,
    pub created_at: DateTimeUtc,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {}

impl ActiveModelBehavior for ActiveModel {}

/// Where a version was recorded from.
pub mod source {
    pub const API: &str = "api";
    pub const ROLLBACK: &str = "rollback";
}
