//! SeaORM entities for every table created by [`crate::migration`].
//!
//! Each table lives in an inner module named after the table (the shape
//! `DeriveEntityModel` generates: `Entity`, `Model`, `ActiveModel`, `Column`,
//! `Relation`). The inner modules are re-exported here under their singular
//! names so call sites read as `models::site::Entity` instead of
//! `models::sites::sites::Entity`.
//!
//! The inner module names necessarily match their file names (SeaORM's
//! `DeriveEntityModel` shape), so `module_inception` is expected here.
#![allow(clippy::module_inception)]

pub mod agent_blocked_ips;
pub mod agent_metrics;
pub mod agents;
pub mod ai;
pub mod api_protection;
pub mod bot_protection;
pub mod certificate_events;
pub mod certificates;
pub mod challenge_settings;
pub mod control_plane_tls;
pub mod defense_settings;
pub mod error_pages;
pub mod geo_rules;
pub mod host_samples;
pub mod ip_access_rules;
pub mod ip_group_sites;
pub mod ip_groups;
pub mod log_retention;
pub mod mtls;
pub mod passkeys;
pub mod rate_limit_stats;
pub mod rewrite_rules;
pub mod rules;
pub mod security_events;
pub mod site_basic_auth;
pub mod sites;
pub mod users;
pub mod waf_settings;

pub use agent_blocked_ips::agent_blocked_ips as agent_blocked_ip;
pub use agent_metrics::agent_metrics as agent_metric;
pub use agents::{agent_status, agents as agent};
pub use ai::{
    ai_conversations as ai_conversation, ai_defaults,
    ai_messages as ai_message, ai_settings as ai_setting, message_role,
};
pub use api_protection::{
    api_protection_settings as api_protection_setting,
    control_plane_access_logs as control_plane_access_log,
};
pub use certificates::site_certificates;
pub use control_plane_tls::{
    control_plane_certificates as control_plane_certificate,
    source as tls_source,
};
pub use host_samples::host_samples as host_sample;
pub use mtls::{
    ca_source, client_cert_status, mtls_cas as mtls_ca,
    mtls_client_certificates as mtls_client_certificate,
};
pub use passkeys::{
    passkey_credentials as passkey_credential, passkey_states as passkey_state,
};
pub use rules::{
    action, cache_rules, characteristic, mode, rate_limit_rules, rule_groups,
    rules as rule,
};
pub use security_events::{
    access_logs as access_log, security_events as security_event,
};
pub use sites::{
    acme_challenge, route_match_type, site_routes, site_ssl, site_status,
    site_upstream_pools, site_upstreams, sites as site, tls_version,
};
pub use users::{api_keys as api_key, permission, role, users as user};

/// Convenience alias used across the API and gRPC layers.
pub type DbErr = sea_orm::DbErr;
