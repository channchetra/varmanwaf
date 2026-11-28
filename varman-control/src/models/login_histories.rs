//! `login_history` — one row per successful control-plane login.
//!
//! Written by the login handlers (password and passkey) with the resolved
//! client IP and, best effort, its geolocation. The anomaly detector
//! (`crate::notify::login_anomaly`) compares a login's country against the
//! most recent resolved entries of the same account; the dashboard reads
//! the rows back for the login audit view.

use sea_orm::entity::prelude::*;
use serde::Serialize;

/// `login_history`
pub mod login_history {
    use super::*;

    #[derive(Clone, Debug, PartialEq, DeriveEntityModel, Serialize)]
    #[sea_orm(table_name = "login_history")]
    pub struct Model {
        #[sea_orm(primary_key, auto_increment = false)]
        pub id: Uuid,
        pub user_id: Uuid,
        pub email: String,
        /// Resolved client IP (dotted string; IPv6 in its textual form).
        pub ip: String,
        pub user_agent: Option<String>,
        /// ISO country code from the geo lookup; NULL when the lookup
        /// failed or the IP is private.
        pub country_code: Option<String>,
        pub region: Option<String>,
        pub city: Option<String>,
        /// Where the geo data came from: `local` (uploaded mmdb), `online`
        /// (web API), `private` (RFC1918/loopback, no lookup) or `unknown`
        /// (lookup attempted and failed).
        pub geo_source: String,
        pub created_at: DateTimeUtc,
    }

    #[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
    pub enum Relation {}

    impl ActiveModelBehavior for ActiveModel {}
}

/// Where a login row's geo data came from.
pub mod geo_source {
    /// Resolved from the uploaded mmdb database.
    pub const LOCAL: &str = "local";
    /// Resolved from the configured online geo API.
    pub const ONLINE: &str = "online";
    /// Private/loopback address — never looked up.
    pub const PRIVATE: &str = "private";
    /// Lookup attempted but failed; geo fields stay NULL and the row does
    /// not participate in the anomaly baseline.
    pub const UNKNOWN: &str = "unknown";

    pub const ALL: [&str; 4] = [LOCAL, ONLINE, PRIVATE, UNKNOWN];
}
