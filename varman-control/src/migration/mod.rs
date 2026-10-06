//! Database schema migrations.
//!
//! The migrations are applied at startup by [`crate::start_server`] through
//! [`Migrator::up`]; `sea-orm-migration` records the applied versions in the
//! `seaql_migrations` table, so restarting the control plane is a no-op once the
//! schema is current.

pub mod m20240101_000001_create_users;
pub mod m20240101_000002_create_sites;
pub mod m20240101_000003_create_rules;
pub mod m20240101_000004_create_agents;
pub mod m20240101_000005_create_logs;
pub mod m20240101_000006_create_additional_tables;
pub mod m20240101_000007_site_settings;
pub mod m20240101_000008_agent_host_samples;
pub mod m20240101_000009_create_certificate_events;
pub mod m20240101_000010_create_ip_groups;
pub mod m20240101_000011_site_origin_pools;
pub mod m20240101_000012_acme_events_and_ip_rule_groups;
pub mod m20240101_000013_access_log_request_detail;
pub mod m20240101_000014_ip_group_sync_error;
pub mod m20240101_000015_create_agent_metrics;
pub mod m20240101_000016_access_log_response_detail;
pub mod m20240101_000017_site_routes_ip_group;
pub mod m20240101_000018_mtls_certificates;
pub mod m20240101_000019_passkey_credentials;
pub mod m20240101_000020_control_plane_tls;
pub mod m20240101_000021_site_alternate_domains;
pub mod m20240101_000022_log_retention_settings;
pub mod m20240101_000023_global_error_pages;
pub mod m20240101_000024_site_basic_auth;
pub mod m20240101_000025_defense_settings;
pub mod m20240101_000026_api_protection;
pub mod m20240101_000027_ai_agent;
pub mod m20240101_000028_access_log_search_indexes;
pub mod m20240101_000029_agent_blocked_ips;
pub mod m20240101_000030_waf_settings;

use sea_orm_migration::prelude::*;

/// Ordered list of every schema change the control plane knows about.
pub struct Migrator;

#[async_trait::async_trait]
impl MigratorTrait for Migrator {
    fn migrations() -> Vec<Box<dyn MigrationTrait>> {
        vec![
            Box::new(m20240101_000001_create_users::Migration),
            Box::new(m20240101_000002_create_sites::Migration),
            Box::new(m20240101_000003_create_rules::Migration),
            Box::new(m20240101_000004_create_agents::Migration),
            Box::new(m20240101_000005_create_logs::Migration),
            Box::new(m20240101_000006_create_additional_tables::Migration),
            Box::new(m20240101_000007_site_settings::Migration),
            Box::new(m20240101_000008_agent_host_samples::Migration),
            Box::new(m20240101_000009_create_certificate_events::Migration),
            Box::new(m20240101_000010_create_ip_groups::Migration),
            Box::new(m20240101_000011_site_origin_pools::Migration),
            Box::new(
                m20240101_000012_acme_events_and_ip_rule_groups::Migration,
            ),
            Box::new(m20240101_000013_access_log_request_detail::Migration),
            Box::new(m20240101_000014_ip_group_sync_error::Migration),
            Box::new(m20240101_000015_create_agent_metrics::Migration),
            Box::new(m20240101_000016_access_log_response_detail::Migration),
            Box::new(m20240101_000017_site_routes_ip_group::Migration),
            Box::new(m20240101_000018_mtls_certificates::Migration),
            Box::new(m20240101_000019_passkey_credentials::Migration),
            Box::new(m20240101_000020_control_plane_tls::Migration),
            Box::new(m20240101_000021_site_alternate_domains::Migration),
            Box::new(m20240101_000022_log_retention_settings::Migration),
            Box::new(m20240101_000023_global_error_pages::Migration),
            Box::new(m20240101_000024_site_basic_auth::Migration),
            Box::new(m20240101_000025_defense_settings::Migration),
            Box::new(m20240101_000026_api_protection::Migration),
            Box::new(m20240101_000027_ai_agent::Migration),
            Box::new(m20240101_000028_access_log_search_indexes::Migration),
            Box::new(m20240101_000029_agent_blocked_ips::Migration),
            Box::new(m20240101_000030_waf_settings::Migration),
        ]
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn migrations_are_ordered_and_unique() {
        let migrations = Migrator::migrations();
        assert_eq!(migrations.len(), 30);
        let names: Vec<String> =
            migrations.iter().map(|m| m.name().to_owned()).collect();
        let mut sorted = names.clone();
        sorted.sort();
        assert_eq!(names, sorted, "migrations must be listed in name order");
        let unique: std::collections::BTreeSet<&String> =
            names.iter().collect();
        assert_eq!(unique.len(), names.len(), "duplicate migration name");
    }
}
