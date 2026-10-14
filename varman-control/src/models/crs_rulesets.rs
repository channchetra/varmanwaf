//! `crs_rulesets` - imported CRS archives with parse counts.
//!
//! One row per imported archive: name/version/source, the archive
//! fingerprint (deduplication + integrity display) and the parse outcome —
//! how many rules compiled, how many did not and how many directives were
//! recorded without compiling.

use sea_orm::entity::prelude::*;
use serde::{Deserialize, Serialize};

#[derive(
    Clone, Debug, PartialEq, DeriveEntityModel, Serialize, Deserialize,
)]
#[sea_orm(table_name = "crs_rulesets")]
pub struct Model {
    #[sea_orm(primary_key, auto_increment = false)]
    pub id: Uuid,
    pub name: String,
    /// Version/tag the archive came from (`4.30.0`, `main`, or empty).
    pub version: String,
    /// `github:v4.30.0`, `url:…` or `archive`.
    pub source: String,
    /// SHA-256 of the archive bytes.
    pub fingerprint: String,
    pub rule_count: i32,
    pub supported_count: i32,
    pub unsupported_count: i32,
    pub directive_count: i32,
    pub imported_at: DateTimeUtc,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {}

impl ActiveModelBehavior for ActiveModel {}
