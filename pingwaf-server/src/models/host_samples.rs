//! Entity for the host probe samples shipped by agents.
//!
//! The table is append-only: rows are written in batches from the heartbeat
//! stream and read back by the agent detail API, so the model carries
//! `Serialize` but never `Deserialize`.

use sea_orm::entity::prelude::*;
use serde::Serialize;

/// `host_samples` — one row per host probe sample (5-second cadence).
pub mod host_samples {
    use super::*;

    #[derive(Clone, Debug, PartialEq, DeriveEntityModel, Serialize)]
    #[sea_orm(table_name = "host_samples")]
    pub struct Model {
        #[sea_orm(primary_key)]
        pub id: i64,
        pub agent_id: Uuid,
        pub sampled_at: DateTimeUtc,
        pub cpu_usage_percent: Option<f64>,
        pub load1: Option<f64>,
        pub load5: Option<f64>,
        pub load15: Option<f64>,
        pub memory_total_bytes: Option<i64>,
        pub memory_used_bytes: Option<i64>,
        pub memory_available_bytes: Option<i64>,
        pub swap_total_bytes: Option<i64>,
        pub swap_used_bytes: Option<i64>,
        pub disk_total_bytes: Option<i64>,
        pub disk_used_bytes: Option<i64>,
        pub net_rx_bytes: Option<i64>,
        pub net_tx_bytes: Option<i64>,
        pub disk_read_bytes: Option<i64>,
        pub disk_write_bytes: Option<i64>,
        pub process_count: Option<i32>,
        pub tcp_connections: Option<i32>,
        pub uptime_secs: Option<i64>,
        pub created_at: DateTimeUtc,
    }

    #[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
    pub enum Relation {}

    impl ActiveModelBehavior for ActiveModel {}
}
