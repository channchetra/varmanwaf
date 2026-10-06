//! `rate_limit_stats` — distributed rate-limit counting across agents.

use sea_orm::entity::prelude::*;
use serde::{Deserialize, Serialize};

#[derive(
    Clone, Debug, PartialEq, DeriveEntityModel, Serialize, Deserialize,
)]
#[sea_orm(table_name = "rate_limit_stats")]
pub struct Model {
    #[sea_orm(primary_key)]
    pub id: i64,
    pub site_id: Option<Uuid>,
    pub agent_id: Option<Uuid>,
    pub rule_id: Option<Uuid>,
    pub characteristic_key: String,
    pub window_start: DateTimeUtc,
    pub request_count: i32,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {}

impl ActiveModelBehavior for ActiveModel {}
