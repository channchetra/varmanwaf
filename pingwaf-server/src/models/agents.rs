//! Entity for registered PingWAF agents.

use sea_orm::entity::prelude::*;
use serde::{Deserialize, Serialize};

/// Connectivity state reported by the control plane.
pub mod agent_status {
    pub const ONLINE: &str = "online";
    pub const OFFLINE: &str = "offline";
    pub const DEGRADED: &str = "degraded";

    pub fn is_valid(status: &str) -> bool {
        matches!(status, ONLINE | OFFLINE | DEGRADED)
    }

    /// Maps `pingwaf::AgentHealthStatus` onto the persisted status string.
    pub fn from_proto_health(health: i32) -> &'static str {
        match health {
            1 => ONLINE,
            2 => DEGRADED,
            3 => OFFLINE,
            _ => ONLINE,
        }
    }
}

/// `agents` — one row per registered agent process.
pub mod agents {
    use super::*;

    #[derive(
        Clone, Debug, PartialEq, DeriveEntityModel, Serialize, Deserialize,
    )]
    #[sea_orm(table_name = "agents")]
    pub struct Model {
        #[sea_orm(primary_key, auto_increment = false)]
        pub id: Uuid,
        pub site_id: Option<Uuid>,
        pub hostname: String,
        pub ip_address: String,
        /// Egress address as seen by the public internet, empty when unknown.
        pub public_ip: Option<String>,
        /// First non-virtual LAN address reported by the probe.
        pub private_ip: Option<String>,
        pub version: Option<String>,
        pub os_info: Option<String>,
        pub cpu_cores: Option<i32>,
        pub memory_bytes: Option<i64>,
        pub status: String,
        pub api_key_id: Option<Uuid>,
        pub config_hash: Option<String>,
        pub last_heartbeat: Option<DateTimeUtc>,
        pub registered_at: DateTimeUtc,
    }

    #[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
    pub enum Relation {}

    impl ActiveModelBehavior for ActiveModel {}
}
