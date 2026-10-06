//! `bot_protection` — per-site bot detection configuration.

use sea_orm::entity::prelude::*;
use serde::{Deserialize, Serialize};

#[derive(
    Clone, Debug, PartialEq, DeriveEntityModel, Serialize, Deserialize,
)]
#[sea_orm(table_name = "bot_protection")]
pub struct Model {
    #[sea_orm(primary_key, auto_increment = false)]
    pub id: Uuid,
    #[sea_orm(unique)]
    pub site_id: Uuid,
    pub enabled: bool,
    pub ua_analysis: bool,
    pub js_detection: bool,
    pub tls_fingerprint: bool,
    pub behavioral_analysis: bool,
    pub action: String,
    #[sea_orm(column_type = "JsonBinary")]
    pub known_bots_whitelist: Json,
    pub updated_at: DateTimeUtc,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {}

impl ActiveModelBehavior for ActiveModel {}
