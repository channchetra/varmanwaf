//! Entity for the edge metrics shipped by agents.
//!
//! The table is append-only: rows are written in batches from the
//! `ShipMetrics` stream and aggregated by the agent metrics API, so the model
//! carries `Serialize` but never `Deserialize`.

use sea_orm::entity::prelude::*;
use serde::Serialize;

/// `agent_metrics` — one row per metric sample shipped by an agent.
pub mod agent_metrics {
    use super::*;

    #[derive(Clone, Debug, PartialEq, DeriveEntityModel, Serialize)]
    #[sea_orm(table_name = "agent_metrics")]
    pub struct Model {
        #[sea_orm(primary_key)]
        pub id: i64,
        pub agent_id: Uuid,
        pub name: String,
        #[sea_orm(column_type = "JsonBinary")]
        pub labels: Json,
        pub value: f64,
        pub metric_type: i32,
        pub recorded_at: DateTimeUtc,
        pub created_at: DateTimeUtc,
    }

    #[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
    pub enum Relation {}

    impl ActiveModelBehavior for ActiveModel {}
}
