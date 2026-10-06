//! Entity for the control plane's mirror of agent-enforced dynamic IP blocks.
//!
//! Rows are reconciled from every heartbeat (replace-per-agent semantics), so
//! the model carries `Serialize` but never `Deserialize`.

use sea_orm::entity::prelude::*;
use serde::Serialize;

/// `agent_blocked_ips` — one row per (agent, site, ip) block in force.
pub mod agent_blocked_ips {
    use super::*;

    #[derive(Clone, Debug, PartialEq, DeriveEntityModel, Serialize)]
    #[sea_orm(table_name = "agent_blocked_ips")]
    pub struct Model {
        #[sea_orm(primary_key)]
        pub id: i64,
        pub agent_id: Uuid,
        pub site_id: Uuid,
        pub ip: String,
        /// Why the edge refused the client (e.g. `waf: <rule>`).
        #[sea_orm(column_type = "Text")]
        pub reason: Option<String>,
        pub blocked_at: DateTimeUtc,
        /// None = permanent block (no automatic expiry).
        pub expires_at: Option<DateTimeUtc>,
        pub created_at: DateTimeUtc,
        pub updated_at: DateTimeUtc,
    }

    #[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
    pub enum Relation {}

    impl ActiveModelBehavior for ActiveModel {}
}
