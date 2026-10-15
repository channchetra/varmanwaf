//! `api_learned_schemas` - bounded structural learning for API assets.
//!
//! One row per observed (method, path): the merged structure of the JSON
//! request bodies and query parameters - keys, types and counts, never
//! values. Rows are written only by an explicit learn run.

use sea_orm::entity::prelude::*;
use serde::{Deserialize, Serialize};

#[derive(
    Clone, Debug, PartialEq, DeriveEntityModel, Serialize, Deserialize,
)]
#[sea_orm(table_name = "api_learned_schemas")]
pub struct Model {
    #[sea_orm(primary_key, auto_increment = false)]
    pub id: Uuid,
    pub site_id: Uuid,
    pub method: String,
    /// The observed path (exact; the draft templatizes numeric/uuid
    /// segments).
    #[sea_orm(column_type = "Text")]
    pub path: String,
    /// Merged JSON structure of the request bodies; `None` when no JSON
    /// body was observed.
    #[sea_orm(column_type = "JsonBinary")]
    pub request_schema: Option<Json>,
    /// Query parameters: name -> { types, count }.
    #[sea_orm(column_type = "JsonBinary")]
    pub query_schema: Json,
    /// JSON bodies merged into this row.
    pub sample_count: i64,
    pub first_seen: Option<DateTimeUtc>,
    pub last_seen: Option<DateTimeUtc>,
    pub updated_at: DateTimeUtc,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {}

impl ActiveModelBehavior for ActiveModel {}
