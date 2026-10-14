//! `crs_rules` - the parsed catalogue of one imported CRS ruleset.
//!
//! One row per logical statement: `kind = "rule"` rows are SecLang rules
//! (with extracted id/message/severity/paranoia level/category/phase and
//! file+line provenance); `kind = "directive"` rows are directives that
//! are recorded but not compiled. `supported` marks rules this engine can
//! compile; unsupported rows keep the parser error so nothing disappears
//! silently.

use sea_orm::entity::prelude::*;
use serde::{Deserialize, Serialize};

#[derive(
    Clone, Debug, PartialEq, DeriveEntityModel, Serialize, Deserialize,
)]
#[sea_orm(table_name = "crs_rules")]
pub struct Model {
    #[sea_orm(primary_key, auto_increment = false)]
    pub id: Uuid,
    pub ruleset_id: Uuid,
    /// CRS rule id (`942100`); empty for anonymous/directive statements.
    pub rule_id: String,
    /// `rule` or `directive`.
    pub kind: String,
    pub file: String,
    pub line: i32,
    pub phase: Option<i32>,
    pub severity: String,
    pub paranoia_level: Option<i32>,
    pub category: String,
    pub message: String,
    /// The SecLang statement text (used to compile the edge source).
    pub source: String,
    pub supported: bool,
    /// Parser error for unsupported rules; empty when supported.
    pub error: String,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {}

impl ActiveModelBehavior for ActiveModel {}
