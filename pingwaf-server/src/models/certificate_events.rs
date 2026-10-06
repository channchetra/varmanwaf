//! `certificate_events` — audit trail for ACME certificate lifecycle events.

use sea_orm::entity::prelude::*;
use serde::{Deserialize, Serialize};

#[derive(
    Clone, Debug, PartialEq, DeriveEntityModel, Serialize, Deserialize,
)]
#[sea_orm(table_name = "certificate_events")]
pub struct Model {
    #[sea_orm(primary_key, auto_increment = false)]
    pub id: Uuid,
    /// `None` for raw agent-emitted events that predate a matching
    /// `site_certificates` row.
    pub certificate_id: Option<Uuid>,
    pub site_id: Option<Uuid>,
    pub event_type: String,
    #[sea_orm(column_type = "Text")]
    pub message: String,
    #[sea_orm(column_type = "JsonBinary")]
    pub details: Option<Json>,
    pub created_at: DateTimeUtc,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {}

impl ActiveModelBehavior for ActiveModel {}
