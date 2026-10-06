//! `site_basic_auth` — per-site HTTP basic authentication.
//!
//! Passwords are stored in the clear (the project keeps mTLS keys and the
//! Elasticsearch password the same way) and are base64-encoded only when the
//! bundle is built for the data plane.

use sea_orm::entity::prelude::*;
use serde::{Deserialize, Serialize};

#[derive(
    Clone, Debug, PartialEq, DeriveEntityModel, Serialize, Deserialize,
)]
#[sea_orm(table_name = "site_basic_auth")]
pub struct Model {
    #[sea_orm(primary_key, auto_increment = false)]
    pub id: Uuid,
    #[sea_orm(unique)]
    pub site_id: Uuid,
    pub enabled: bool,
    pub realm: String,
    /// JSON array of `{username, password}` objects, in the clear.
    #[sea_orm(column_type = "JsonBinary")]
    pub credentials: Json,
    pub delay_seconds: i32,
    pub hide_credentials: bool,
    pub created_at: DateTimeUtc,
    pub updated_at: DateTimeUtc,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {}

impl ActiveModelBehavior for ActiveModel {}
