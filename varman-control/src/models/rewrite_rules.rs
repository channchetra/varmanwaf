//! `rewrite_rules` — per-site request/response rewrite rules.

use sea_orm::entity::prelude::*;
use serde::{Deserialize, Serialize};

#[derive(
    Clone, Debug, PartialEq, DeriveEntityModel, Serialize, Deserialize,
)]
#[sea_orm(table_name = "rewrite_rules")]
pub struct Model {
    #[sea_orm(primary_key, auto_increment = false)]
    pub id: Uuid,
    pub site_id: Uuid,
    pub name: String,
    pub direction: String,
    #[sea_orm(column_type = "Text")]
    pub condition_expr: Option<String>,
    #[sea_orm(column_type = "JsonBinary")]
    pub operations: Json,
    pub priority: i32,
    pub enabled: bool,
    pub created_at: DateTimeUtc,
    pub updated_at: DateTimeUtc,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {}

impl ActiveModelBehavior for ActiveModel {}
