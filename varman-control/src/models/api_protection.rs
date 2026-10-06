//! Entities for the control plane's self-protection.
//!
//! `api_protection_settings` is the single-row settings table for the 9080
//! listener (access log, IP allowlist, WAF). `control_plane_access_logs` is
//! the append-only log the middleware on that listener writes and the
//! dashboard reads back, so its model carries `Serialize` but no
//! `Deserialize` — rows are only ever built server side.

use sea_orm::entity::prelude::*;
use serde::{Deserialize, Serialize};

/// `api_protection_settings` — global switches for the control plane listener.
pub mod api_protection_settings {
    use super::*;

    #[derive(
        Clone, Debug, PartialEq, DeriveEntityModel, Serialize, Deserialize,
    )]
    #[sea_orm(table_name = "api_protection_settings")]
    pub struct Model {
        /// Always `1`.
        #[sea_orm(primary_key, auto_increment = false)]
        pub id: i32,
        /// Record one row per request into `control_plane_access_logs`.
        pub access_log_enabled: bool,
        /// Days a control plane access log row is kept.
        pub access_log_retention_days: i32,
        /// Restrict the API to the allowlist below (plus the referenced group).
        pub ip_allowlist_enabled: bool,
        /// Inline IP ranges (address or CIDR) that may call the API.
        pub ip_allowlist_ranges: Vec<String>,
        /// An `ip_groups` row whose ranges are merged into the allowlist.
        pub ip_allowlist_group_id: Option<Uuid>,
        /// Inspect API requests with the embedded WAF engine.
        pub waf_enabled: bool,
        /// `block` or `monitor`; monitor only records matches.
        pub waf_mode: String,
        pub updated_at: DateTimeUtc,
    }

    #[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
    pub enum Relation {}

    impl ActiveModelBehavior for ActiveModel {}
}

/// Accepted WAF modes for the control plane listener.
pub mod waf_mode {
    pub const BLOCK: &str = "block";
    pub const MONITOR: &str = "monitor";

    pub fn is_valid(mode: &str) -> bool {
        matches!(mode, BLOCK | MONITOR)
    }
}

/// Retention bounds, matching the log retention settings.
pub const MIN_RETENTION_DAYS: i32 = 1;
pub const MAX_RETENTION_DAYS: i32 = 3650;
pub const DEFAULT_RETENTION_DAYS: i32 = 30;

/// Actions recorded on `control_plane_access_logs.action`.
pub mod action {
    /// The request passed every check.
    pub const ALLOWED: &str = "allowed";
    /// Refused by the IP allowlist.
    pub const BLOCKED_ALLOWLIST: &str = "blocked_allowlist";
    /// Refused by the control plane WAF.
    pub const BLOCKED_WAF: &str = "blocked_waf";
    /// A WAF match recorded in monitor mode; the request passed.
    pub const OBSERVED_WAF: &str = "observed_waf";
}

/// `control_plane_access_logs` — one row per request the 9080 listener served.
pub mod control_plane_access_logs {
    use super::*;

    #[derive(Clone, Debug, PartialEq, DeriveEntityModel, Serialize)]
    #[sea_orm(table_name = "control_plane_access_logs")]
    pub struct Model {
        #[sea_orm(primary_key)]
        pub id: i64,
        pub request_id: Option<String>,
        pub timestamp: DateTimeUtc,
        pub client_ip: String,
        pub method: String,
        pub host: Option<String>,
        pub path: String,
        #[sea_orm(column_type = "Text")]
        pub query_string: Option<String>,
        pub scheme: Option<String>,
        pub protocol: Option<String>,
        pub status_code: Option<i32>,
        pub latency_ms: Option<i64>,
        #[sea_orm(column_type = "Text")]
        pub user_agent: Option<String>,
        #[sea_orm(column_type = "Text")]
        pub referer: Option<String>,
        pub user_id: Option<Uuid>,
        pub user_email: Option<String>,
        /// One of [`super::action`].
        pub action: String,
        #[sea_orm(column_type = "Text")]
        pub reason: Option<String>,
    }

    #[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
    pub enum Relation {}

    impl ActiveModelBehavior for ActiveModel {}
}
