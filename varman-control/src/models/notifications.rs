//! Notification entities: delivery channels and the dispatched-event history.
//!
//! Each table lives in its own inner module ΓÇö the shape `DeriveEntityModel`
//! generates ΓÇö re-exported under their singular names from [`super`].

/// Delivery channel kinds.
pub mod channel_kind {
    pub const EMAIL: &str = "email";
    pub const WECOM: &str = "wecom";
    pub const DINGTALK: &str = "dingtalk";
    /// Generic JSON webhook: the full event payload is POSTed as-is.
    pub const WEBHOOK: &str = "webhook";
    /// Telegram bot API: a bot token (sealed) plus a chat id.
    pub const TELEGRAM: &str = "telegram";

    pub const ALL: [&str; 5] = [EMAIL, WECOM, DINGTALK, WEBHOOK, TELEGRAM];
}

/// Event types emitted by the control plane.
pub mod event_type {
    /// An agent stopped sending heartbeats.
    pub const AGENT_OFFLINE: &str = "agent.offline";
    /// An agent came back after being marked offline.
    pub const AGENT_ONLINE: &str = "agent.online";
    /// An agent's CPU, memory or disk usage crossed its threshold.
    pub const AGENT_RESOURCE: &str = "agent.resource";
    /// The control plane's own CPU, memory or disk usage crossed a threshold.
    pub const CONTROL_PLANE_RESOURCE: &str = "control_plane.resource";
    /// An ACME issuance or renewal attempt failed.
    pub const CERT_RENEWAL_FAILED: &str = "cert.renewal_failed";
    /// A certificate expires within the warning window.
    pub const CERT_EXPIRING: &str = "cert.expiring";
    /// A certificate has expired.
    pub const CERT_EXPIRED: &str = "cert.expired";
    /// Syncing configuration or an IP group subscription to the edge failed.
    pub const CONFIG_SYNC_FAILED: &str = "config.sync_failed";
    /// A site's disconnected (failover) policy was changed ΓÇö an
    /// availability/security-relevant decision worth an audit trail.
    pub const SITE_FAILOVER_CHANGED: &str = "site.failover_changed";
    /// An admin signed in from a country outside their recent-login
    /// baseline (see `crate::notify::login_anomaly`).
    pub const AUTH_LOGIN_ANOMALY: &str = "auth.login_anomaly";
    /// A security alert rule fired (see [`crate::alerts`]).
    pub const SECURITY_ALERT: &str = "security.alert";
    /// A scheduled interception report was generated and dispatched.
    pub const REPORT_SCHEDULED: &str = "report.scheduled";

    pub const ALL: [&str; 11] = [
        AGENT_OFFLINE,
        AGENT_ONLINE,
        AGENT_RESOURCE,
        CONTROL_PLANE_RESOURCE,
        CERT_RENEWAL_FAILED,
        CERT_EXPIRING,
        CERT_EXPIRED,
        CONFIG_SYNC_FAILED,
        SITE_FAILOVER_CHANGED,
        AUTH_LOGIN_ANOMALY,
        SECURITY_ALERT,
    ];
}

/// Event severities, ordered from least to most urgent.
pub mod severity {
    pub const INFO: &str = "info";
    pub const WARNING: &str = "warning";
    pub const CRITICAL: &str = "critical";

    pub const ALL: [&str; 3] = [INFO, WARNING, CRITICAL];
}

/// `notification_channels` ΓÇö user-configured alert targets.
pub mod notification_channels {
    use sea_orm::entity::prelude::*;
    use serde::{Deserialize, Serialize};

    #[derive(
        Clone, Debug, PartialEq, DeriveEntityModel, Serialize, Deserialize,
    )]
    #[sea_orm(table_name = "notification_channels")]
    pub struct Model {
        #[sea_orm(primary_key, auto_increment = false)]
        pub id: Uuid,
        pub name: String,
        /// One of [`channel_kind`].
        pub kind: String,
        /// Channel-specific settings; see the senders in [`crate::notify`].
        #[sea_orm(column_type = "JsonBinary")]
        pub config: Json,
        /// Event types the channel subscribed to; empty receives everything.
        #[sea_orm(column_type = "JsonBinary")]
        pub events: Json,
        pub enabled: bool,
        pub created_at: DateTimeUtc,
        pub updated_at: DateTimeUtc,
    }

    #[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
    pub enum Relation {}

    impl ActiveModelBehavior for ActiveModel {}
}

/// `notification_events` ΓÇö one row per dispatched alert, for the dashboard.
pub mod notification_events {
    use sea_orm::entity::prelude::*;
    use serde::{Deserialize, Serialize};

    #[derive(
        Clone, Debug, PartialEq, DeriveEntityModel, Serialize, Deserialize,
    )]
    #[sea_orm(table_name = "notification_events")]
    pub struct Model {
        #[sea_orm(primary_key, auto_increment = false)]
        pub id: Uuid,
        /// One of [`event_type`].
        pub event_type: String,
        /// One of [`severity`].
        pub severity: String,
        pub title: String,
        #[sea_orm(column_type = "Text")]
        pub message: String,
        #[sea_orm(column_type = "JsonBinary")]
        pub details: Option<Json>,
        pub created_at: DateTimeUtc,
    }

    #[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
    pub enum Relation {}

    impl ActiveModelBehavior for ActiveModel {}
}
