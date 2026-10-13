//! `waf_policies` - named, revisioned WAF policy documents.
//!
//! A policy is a shared configuration document that sites opt into: its
//! typed layers live in `waf_policy_layers`, its site bindings in
//! `site_waf_policies`. Editing any layer or field bumps `revision`, so the
//! value is a cheap optimistic-concurrency token and the future home of
//! published policy versions.

use sea_orm::entity::prelude::*;
use serde::{Deserialize, Serialize};

#[derive(
    Clone, Debug, PartialEq, DeriveEntityModel, Serialize, Deserialize,
)]
#[sea_orm(table_name = "waf_policies")]
pub struct Model {
    #[sea_orm(primary_key, auto_increment = false)]
    pub id: Uuid,
    /// Human name, unique across the deployment.
    #[sea_orm(unique)]
    pub name: String,
    pub description: String,
    /// Disabled policies resolve to nothing, so every member site falls back
    /// to its own settings without losing the assignment.
    pub enabled: bool,
    /// Monotonic revision, bumped on every change.
    pub revision: i32,
    pub created_at: DateTimeUtc,
    pub updated_at: DateTimeUtc,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {}

impl ActiveModelBehavior for ActiveModel {}
