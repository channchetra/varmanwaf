// Copyright 2024-2025 Tree xie.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//! VarmanWAF mode startup logic.
//!
//! Handles the three operating modes: Server (control plane only),
//! Agent (data plane only), and AllInOne (both in a single process).

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use crate::certificates::{new_certificate_provider, try_update_certificates};
use crate::cli::{
    AgentOpts, AllInOneOpts, CommonOpts, ServerOpts, VarmanCli, VarmanCommand,
};
use crate::config_manager::try_init_memory_config_manager;
use crate::locations::{new_location_provider, try_init_locations};
use crate::plugin::{new_plugin_provider, try_init_plugins};
use crate::server_locations::{
    new_server_locations_provider, try_init_server_locations,
};
use crate::upstreams::{new_upstream_provider, try_init_upstreams};
use pingap_acme::new_lets_encrypt_service;
use pingap_config::{
    BasicConf, CertificateConf, LocationConf, PingapConfig, PingapTomlConfig,
    PluginConf, ServerConf as PingapServerConf, UpstreamConf,
    normalize_dns_provider,
};
use pingap_core::BackgroundTaskService;
use pingap_proxy::{
    AppContext, Server as ProxyServer, ServerConf, parse_from_conf,
};
use pingap_upstream::new_upstream_health_check_task;
use pingora::server;
use pingora::server::configuration::Opt;
use pingora::services::background::background_service;
use tracing::{error, info, warn};
use varman_agent::cache::{
    CachedRules, HealthCheckConfig, RuleCache, SslConfig,
};
use varman_agent::config::AgentConfig;
use varman_control::ServerConfig;

/// The operating mode for VarmanWAF.
pub enum RunMode {
    /// Control plane only: REST API + gRPC server + PostgreSQL
    Server(Box<ServerConfig>),
    /// Data plane only: connects to a remote control plane
    Agent(Box<AgentConfig>),
    /// Both control plane and data plane in a single process
    AllInOne(Box<ServerConfig>, Box<AgentConfig>),
}

/// Convert CLI server options into a `ServerConfig`.
fn server_config_from_opts(opts: &ServerOpts) -> ServerConfig {
    let mut config = ServerConfig::from_env();
    // CLI flags override environment
    config.db_url = opts.common.db_url.clone();
    config.http_addr = opts.common.admin_addr.clone();
    config.grpc_addr = opts.common.grpc_addr.clone();
    config.grpc_tls_cert = opts.common.grpc_tls_cert.clone();
    config.grpc_tls_key = opts.common.grpc_tls_key.clone();
    config.grpc_tls_mode = opts.common.grpc_tls_mode;
    config.jwt_secret = opts.jwt_secret.clone();
    config.default_admin_email = opts.admin_email.clone();
    config.default_admin_password = opts.admin_password.clone();
    config.serve_frontend = opts.serve_frontend;
    apply_tls_opts(&mut config, &opts.common);
    config
}

/// Convert CLI all-in-one options into a `ServerConfig`.
fn server_config_from_all_in_one(opts: &AllInOneOpts) -> ServerConfig {
    let mut config = ServerConfig::from_env();
    config.db_url = opts.common.db_url.clone();
    config.http_addr = opts.common.admin_addr.clone();
    config.grpc_addr = opts.common.grpc_addr.clone();
    config.grpc_tls_cert = opts.common.grpc_tls_cert.clone();
    config.grpc_tls_key = opts.common.grpc_tls_key.clone();
    config.grpc_tls_mode = opts.common.grpc_tls_mode;
    config.jwt_secret = opts.jwt_secret.clone();
    config.default_admin_email = opts.admin_email.clone();
    config.default_admin_password = opts.admin_password.clone();
    config.serve_frontend = opts.serve_frontend;
    apply_tls_opts(&mut config, &opts.common);
    config
}

/// Layers the shared TLS options onto a server config.
///
/// The SAN list is only replaced when the operator actually spelled one out,
/// so the built-in defaults survive an invocation without `--tls-sans`.
fn apply_tls_opts(config: &mut ServerConfig, opts: &CommonOpts) {
    config.tls_enabled = opts.tls_enabled;
    if !opts.tls_sans.is_empty() {
        config.tls_sans = opts.tls_sans.clone();
    }
    config.public_host = opts.public_host.clone();
}

/// Convert CLI agent options into an `AgentConfig`.
fn agent_config_from_opts(opts: &AgentOpts) -> AgentConfig {
    AgentConfig {
        server_url: opts.server_url.clone(),
        api_key: opts.api_key.clone(),
        agent_id: String::new(),
        server_ca_cert: opts.server_ca_cert.clone(),
        server_ca_pem: None,
        server_tls_name: None,
        heartbeat_interval_secs: opts.heartbeat_interval_secs,
        cache_dir: opts.cache_dir.clone(),
        log_batch_size: opts.log_batch_size,
        log_flush_interval_secs: opts.log_flush_interval_secs,
        max_body_log_size: opts.max_body_log_size,
        reconnect_initial_delay_ms: 1000,
        reconnect_max_delay_ms: 60000,
        fail_open: opts.fail_open,
        probe_interval_secs: varman_agent::probe::DEFAULT_INTERVAL_SECS,
        probe_disk_path: "/".to_string(),
        metrics_ship_interval_secs: opts.metrics_ship_interval_secs,
    }
}

/// Convert CLI all-in-one options into an `AgentConfig`.
///
/// In all-in-one mode the agent connects to the local server via loopback.
/// TLS is the default: the URL switches to `https://` and the CA is resolved
/// at boot (an explicitly configured certificate file is trusted directly;
/// otherwise `run` injects the self-signed control-plane certificate as
/// inline PEM once the database is reachable).
fn agent_config_from_all_in_one(opts: &AllInOneOpts) -> AgentConfig {
    // Derive the loopback gRPC URL from the configured gRPC address
    let port = extract_port(&opts.common.grpc_addr);
    let (server_url, server_ca_cert) =
        match (&opts.common.grpc_tls_cert, &opts.common.grpc_tls_key) {
            (Some(cert), Some(_)) => {
                (format!("https://127.0.0.1:{port}"), Some(cert.clone()))
            },
            _ => match opts.common.grpc_tls_mode {
                varman_control::config::GrpcTlsMode::Off => {
                    (format!("http://127.0.0.1:{port}"), None)
                },
                varman_control::config::GrpcTlsMode::Tls => {
                    (format!("https://127.0.0.1:{port}"), None)
                },
            },
        };
    AgentConfig {
        server_url,
        api_key: opts.api_key.clone(),
        agent_id: String::new(),
        server_ca_cert,
        server_ca_pem: None,
        server_tls_name: None,
        heartbeat_interval_secs: opts.heartbeat_interval_secs,
        cache_dir: opts.cache_dir.clone(),
        log_batch_size: opts.log_batch_size,
        log_flush_interval_secs: opts.log_flush_interval_secs,
        max_body_log_size: opts.max_body_log_size,
        reconnect_initial_delay_ms: 1000,
        reconnect_max_delay_ms: 60000,
        fail_open: opts.fail_open,
        probe_interval_secs: varman_agent::probe::DEFAULT_INTERVAL_SECS,
        probe_disk_path: "/".to_string(),
        metrics_ship_interval_secs: opts.metrics_ship_interval_secs,
    }
}

/// Extract port from an address string like "0.0.0.0:9090".
fn extract_port(addr: &str) -> &str {
    addr.rsplit(':').next().unwrap_or("9090")
}

/// Whether this command runs against the database and exits.
///
/// Every variant that is not a run mode must be listed here: `main` routes
/// these to [`crate::admin::run`], and [`build_run_mode`] treats anything
/// else as unreachable. Omitting one (Config was) panics the CLI.
fn is_maintenance_command(command: &VarmanCommand) -> bool {
    matches!(
        command,
        VarmanCommand::User { .. }
            | VarmanCommand::Mode { .. }
            | VarmanCommand::Security { .. }
            | VarmanCommand::Config { .. }
    )
}

/// Build the `RunMode` from the parsed CLI.
///
/// The maintenance commands never reach this: [`main`] routes them to
/// [`crate::admin::run`] before a run mode is built, and a panic here means
/// that routing was broken.
pub fn build_run_mode(cli: VarmanCli) -> RunMode {
    match cli.command {
        VarmanCommand::Server(ref opts) => {
            RunMode::Server(Box::new(server_config_from_opts(opts)))
        },
        VarmanCommand::Agent(ref opts) => {
            RunMode::Agent(Box::new(agent_config_from_opts(opts)))
        },
        VarmanCommand::AllInOne(ref opts) => {
            let server_config = server_config_from_all_in_one(opts);
            let agent_config = agent_config_from_all_in_one(opts);
            RunMode::AllInOne(Box::new(server_config), Box::new(agent_config))
        },
        VarmanCommand::User { .. }
        | VarmanCommand::Mode { .. }
        | VarmanCommand::Security { .. }
        | VarmanCommand::Config { .. } => {
            unreachable!("maintenance commands do not build a run mode")
        },
    }
}

/// Sanitize a control-plane LB algorithm into a pingap `algo` value.
///
/// pingap accepts `round_robin` (its default), `random`,
/// `least_connections` and `hash:<type>[:<key>]` with type in {ip, url,
/// path, header, cookie, query}; anything else — including legacy enum
/// Debug names such as `lbconsistenthash` — is a hard error at upstream
/// construction, so it must collapse to the default here.
mod data_plane;
use data_plane::start_data_plane;

/// Run VarmanWAF in the specified mode.
///
/// This function blocks until shutdown is signalled (SIGINT / SIGTERM).
pub async fn run(mode: RunMode) -> anyhow::Result<()> {
    match mode {
        RunMode::Server(config) => {
            info!(
                http_addr = %config.http_addr,
                grpc_addr = %config.grpc_addr,
                "starting VarmanWAF in Server mode (control plane only)"
            );
            varman_control::start_server(*config).await
        },
        RunMode::Agent(config) => {
            info!(
                server_url = %config.server_url,
                cache_dir = %config.cache_dir,
                "starting VarmanWAF in Agent mode (data plane only)"
            );
            let agent = varman_agent::start_agent(*config).await?;
            info!("VarmanWAF agent is running, starting data plane proxy");

            // Start the data plane proxy in the background
            let rule_cache = Arc::clone(&agent.rule_cache);
            let proxy_handle = tokio::spawn(async move {
                if let Err(e) = start_data_plane(rule_cache).await {
                    error!(error = %e, "data plane proxy exited with error");
                }
            });

            // Wait for shutdown signal
            shutdown_signal().await;
            agent.shutdown().await;
            proxy_handle.abort();
            Ok(())
        },
        RunMode::AllInOne(server_config, mut agent_config) => {
            info!(
                http_addr = %server_config.http_addr,
                grpc_addr = %server_config.grpc_addr,
                "starting VarmanWAF in All-in-One mode (control plane + data plane)"
            );
            // The dashboard's ACME certificate is issued by the edge: both
            // halves share this process, so the control plane may arm it.
            varman_control::management_cert::set_available(true);

            // Auto-provision a bootstrap API key when none is configured so the
            // embedded agent can authenticate with the local gRPC server.
            if agent_config.api_key.is_empty() {
                match bootstrap_agent_key(&server_config).await {
                    Ok(key) => {
                        agent_config.api_key = key;
                    },
                    Err(e) => {
                        error!(error = %e, "failed to create bootstrap API key for embedded agent");
                    },
                }
            }

            // Pin the gRPC listener certificate: all-in-one serves TLS by
            // default, so the embedded agent needs the console certificate
            // (or the explicitly configured one) as its trust anchor.
            match varman_control::embedded_agent_ca_pem(&server_config).await {
                Ok(Some(tls)) => {
                    agent_config.server_ca_pem = Some(tls.ca_pem);
                    // The gRPC listener serves the active certificate, which
                    // may be an ACME IP certificate; tell the loopback client
                    // which name that certificate actually covers.
                    agent_config.server_tls_name = tls.tls_name;
                    info!(
                        tls_name = ?agent_config.server_tls_name,
                        "embedded agent gRPC certificate name"
                    );
                },
                Ok(None) => {},
                Err(e) => {
                    error!(
                        error = %e,
                        "failed to resolve the gRPC CA for the embedded agent; \
                         it will fall back to its configured CA settings"
                    );
                },
            }

            // Start the agent in the background first.
            // It will retry connecting to the server until it comes up.
            let agent = match varman_agent::start_agent(*agent_config).await {
                Ok(agent) => Some(agent),
                Err(e) => {
                    error!(error = %e, "failed to start agent, continuing with server only");
                    None
                },
            };

            // Start the data plane proxy if the agent is running
            let proxy_handle = if let Some(ref agent) = agent {
                let rule_cache = Arc::clone(&agent.rule_cache);
                Some(tokio::spawn(async move {
                    if let Err(e) = start_data_plane(rule_cache).await {
                        error!(error = %e, "data plane proxy exited with error");
                    }
                }))
            } else {
                None
            };

            // Run the server (blocks until shutdown signal)
            let result = varman_control::start_server(*server_config).await;

            // Gracefully shut down the agent
            if let Some(agent) = agent {
                agent.shutdown().await;
            }
            if let Some(handle) = proxy_handle {
                handle.abort();
            }

            result
        },
    }
}

/// Connect to the database, run migrations, and create a bootstrap API key
/// for the embedded agent in all-in-one mode.
async fn bootstrap_agent_key(
    config: &varman_control::ServerConfig,
) -> anyhow::Result<String> {
    varman_control::bootstrap_and_seed_api_key(config).await
}

/// Wait for SIGINT or SIGTERM.
async fn shutdown_signal() {
    let ctrl_c = async {
        tokio::signal::ctrl_c()
            .await
            .expect("failed to install Ctrl+C handler");
    };

    #[cfg(unix)]
    let terminate = async {
        tokio::signal::unix::signal(
            tokio::signal::unix::SignalKind::terminate(),
        )
        .expect("failed to install SIGTERM handler")
        .recv()
        .await;
    };

    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        _ = ctrl_c => info!("received SIGINT"),
        _ = terminate => info!("received SIGTERM"),
    }
}

/// Entry point called from main.rs when VarmanWAF mode is detected.
pub fn main() {
    // The dependency graph enables BOTH rustls crypto providers (ring via
    // varman-server's rustls/tonic, aws-lc-rs via instant-acme/reqwest), so
    // rustls refuses to pick one implicitly and panics on first TLS use.
    // Install ring explicitly — the same provider the pingora rustls backend
    // uses. `install_default` returns Err when already installed; ignore it.
    let _ = rustls::crypto::ring::default_provider().install_default();

    // Initialize tracing
    init_tracing();

    let cli = crate::cli::parse_varman_cli();

    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .expect("failed to create tokio runtime");

    let result = if is_maintenance_command(&cli.command) {
        rt.block_on(crate::admin::run(cli))
    } else {
        rt.block_on(run(build_run_mode(cli)))
    };

    if let Err(e) = result {
        error!(error = %e, "VarmanWAF exited with error");
        eprintln!("VarmanWAF error: {e}");
        std::process::exit(1);
    }
}

/// Initialize tracing subscriber for VarmanWAF modes.
fn init_tracing() {
    use tracing_subscriber::{fmt, prelude::*};

    let filter = log_filter();

    // Siphons pingap's raw ACME events into the buffer the agent ships to the
    // control plane, so certificate-issuance logs show up on the admin panel.
    tracing_subscriber::registry()
        .with(filter)
        .with(fmt::layer().with_target(true))
        .with(varman_agent::cert_events::AcmeCaptureLayer)
        .init();
}

/// The log filter for VarmanWAF modes.
///
/// `RUST_LOG` wins whenever it is set. The default asks for `info` while
/// keeping sqlx at `warn`, because sqlx logs the text and parameters of every
/// query at `INFO` and that buries the control plane's own messages. An
/// operator who names `sqlx` in `RUST_LOG` gets exactly what they asked for.
fn log_filter() -> tracing_subscriber::EnvFilter {
    tracing_subscriber::EnvFilter::new(log_directives(
        std::env::var("RUST_LOG").ok().as_deref(),
    ))
}

/// The directives [`log_filter`] builds its filter from.
fn log_directives(rust_log: Option<&str>) -> String {
    let value = rust_log.unwrap_or_default().trim();
    if value.is_empty() {
        "info,sqlx=warn".to_string()
    } else if value.contains("sqlx") {
        value.to_string()
    } else {
        format!("{value},sqlx=warn")
    }
}

#[cfg(test)]
mod tests {
    use super::data_plane::{
        CACHE_PLUGIN_NAME, acme_certificate_conf,
        cached_rules_to_pingap_config, health_check_url, merge_config_state,
        sanitize_algo,
    };
    use clap::Parser;

    #[test]
    fn config_is_a_maintenance_command() {
        let cli = VarmanCli::try_parse_from(["varman", "config", "history"])
            .expect("config history must parse");
        assert!(
            is_maintenance_command(&cli.command),
            "config must be routed to the maintenance runner, not build_run_mode"
        );
    }
    use super::*;
    use varman_agent::cache::{
        CacheRule as AgentCacheRule, CachedRules, GlobalCacheSettings,
        ProxyTrustConfig, RouteConfig, SiteRules, UpstreamConfig, UpstreamPeer,
    };

    #[test]
    fn log_directives_keep_sqlx_quiet_unless_named() {
        // Nothing set: the default, with sqlx kept out of the way.
        assert_eq!(log_directives(None), "info,sqlx=warn");
        assert_eq!(log_directives(Some("  ")), "info,sqlx=warn");

        // An operator level applies, but statements stay quiet.
        assert_eq!(log_directives(Some("debug")), "debug,sqlx=warn");
        assert_eq!(
            log_directives(Some("varman=debug")),
            "varman=debug,sqlx=warn"
        );

        // Naming sqlx is an explicit request for its logs.
        assert_eq!(log_directives(Some("sqlx=debug")), "sqlx=debug");
        assert_eq!(log_directives(Some("info,sqlx=trace")), "info,sqlx=trace");
    }

    fn site_rules(site_id: &str, domain: &str) -> SiteRules {
        SiteRules {
            site_id: site_id.to_string(),
            domain: domain.to_string(),
            alternate_domains: vec![],
            config_hash: String::new(),
            status: "active".to_string(),
            waf_config: None,
            rate_limit_rules: vec![],
            ip_access_rules: vec![],
            geo_config: None,
            cache_rules: vec![],
            challenge_config: None,
            rewrite_rules: vec![],
            error_pages: vec![],
            ssl_config: None,
            upstreams: vec![],
            routes: vec![],
            bot_protection: None,
            basic_auth: None,
            observation_mode: false,
            proxy_trust: ProxyTrustConfig::default(),
            cache_settings: None,
        }
    }

    fn pool(pool_id: &str, peers: Vec<UpstreamPeer>) -> UpstreamConfig {
        UpstreamConfig {
            name: pool_id.to_string(),
            peers,
            algorithm: String::new(),
            health_check: None,
            connection_timeout_ms: 0,
            read_timeout_ms: 0,
            write_timeout_ms: 0,
            pool_id: pool_id.to_string(),
            algo: String::new(),
            sni: String::new(),
            verify_cert: None,
            is_default: false,
        }
    }

    fn peer(address: &str) -> UpstreamPeer {
        UpstreamPeer {
            address: address.to_string(),
            weight: 1,
            tls: false,
        }
    }

    fn route(
        id: &str,
        match_type: &str,
        path: &str,
        pool_id: &str,
    ) -> RouteConfig {
        RouteConfig {
            id: id.to_string(),
            name: id.to_string(),
            match_type: match_type.to_string(),
            path: path.to_string(),
            priority: None,
            enabled: true,
            pool_id: pool_id.to_string(),
            ip_ranges: vec![],
        }
    }

    fn one_site_cache(site: SiteRules) -> CachedRules {
        let mut cached = CachedRules::default();
        cached.sites.insert(site.site_id.clone(), Arc::new(site));
        cached
    }

    fn enabled_cache_rule(disk_quota_mb: u32) -> AgentCacheRule {
        AgentCacheRule {
            id: "rule-1".to_string(),
            name: "static".to_string(),
            match_expression: String::new(),
            edge_ttl_seconds: 300,
            browser_ttl_seconds: 60,
            disk_quota_mb,
            cache_eligible: true,
            cache_key_headers: Vec::new(),
            respect_origin_headers: true,
            stale_while_revalidate_seconds: 0,
            enabled: true,
        }
    }

    #[test]
    fn cache_plugin_conf_follows_global_settings() {
        // Defaults (no global_cache): the historical shape — 16 MiB cap, no
        // budget, no fallback TTL.
        let mut site = site_rules("site1", "a.example.com");
        site.cache_rules = vec![enabled_cache_rule(0)];
        site.upstreams = vec![pool("", vec![peer("10.0.0.1:8080")])];
        let mut cached = one_site_cache(site);
        let config = cached_rules_to_pingap_config(
            &cached,
            Path::new("/tmp/varman-test-cache"),
        )
        .expect("config should build");
        let cache_conf =
            config.plugins.get(CACHE_PLUGIN_NAME).expect("cache plugin");
        assert_eq!(
            cache_conf.get("max_file_size").and_then(|v| v.as_str()),
            Some("16mb")
        );
        assert_eq!(
            cache_conf.get("directory").and_then(|v| v.as_str()),
            Some("/tmp/varman-test-cache")
        );
        assert_eq!(cache_conf.get("max_ttl"), None);

        // Global settings: cap, budget and fallback TTL all land in the
        // generated configuration.
        cached.global_cache = Some(GlobalCacheSettings {
            max_file_size_mb: Some(64),
            max_space_mb: Some(2048),
            master_enabled: Some(true),
            default_edge_ttl_seconds: Some(600),
        });
        let config = cached_rules_to_pingap_config(
            &cached,
            Path::new("/tmp/varman-test-cache"),
        )
        .expect("config should build");
        let cache_conf =
            config.plugins.get(CACHE_PLUGIN_NAME).expect("cache plugin");
        assert_eq!(
            cache_conf.get("max_file_size").and_then(|v| v.as_str()),
            Some("64mb")
        );
        assert_eq!(
            cache_conf.get("directory").and_then(|v| v.as_str()),
            Some("/tmp/varman-test-cache?max_size=2048mb")
        );
        assert_eq!(
            cache_conf.get("max_ttl").and_then(|v| v.as_str()),
            Some("600s")
        );

        // Master switch off: no cache plugin at all, not even in locations.
        cached.global_cache = Some(GlobalCacheSettings {
            master_enabled: Some(false),
            ..Default::default()
        });
        let config = cached_rules_to_pingap_config(
            &cached,
            Path::new("/tmp/varman-test-cache"),
        )
        .expect("config should build");
        assert!(!config.plugins.contains_key(CACHE_PLUGIN_NAME));
        for loc in config.locations.values() {
            let plugins = loc.plugins.as_deref().unwrap_or(&[]);
            assert!(
                !plugins.iter().any(|name| name == CACHE_PLUGIN_NAME),
                "master-off must drop the cache plugin from locations"
            );
        }
    }

    #[test]
    fn single_pool_without_routes_matches_legacy_layout() {
        let mut site = site_rules("site1", "a.example.com");
        site.upstreams = vec![pool("", vec![peer("10.0.0.1:8080")])];
        let config = cached_rules_to_pingap_config(
            &one_site_cache(site),
            Path::new("/tmp/varman-test-cache"),
        )
        .expect("config should build");

        let upstream = config
            .upstreams
            .get("site1_upstream")
            .expect("legacy upstream key");
        assert_eq!(upstream.addrs, vec!["10.0.0.1:8080"]);
        assert_eq!(upstream.algo, None);

        let loc = config
            .locations
            .get("site1_loc")
            .expect("fallback location");
        assert_eq!(loc.path.as_deref(), Some("/"));
        assert_eq!(loc.upstream.as_deref(), Some("site1_upstream"));
        assert_eq!(loc.host.as_deref(), Some("a.example.com"));
        // The catch-all sorts behind every route: pinned to the floor so
        // even priority-1 routes match first (see
        // low_priority_routes_still_beat_the_site_fallback).
        assert_eq!(loc.weight, Some(0));
    }

    #[test]
    fn multi_peer_pool_defaults_to_stats_and_breaker() {
        // P0-2 (NODE-EVALUATION-REPORT-20261009): the control plane exposes
        // no knobs for backend stats or circuit breaking, so multi-node pools
        // must get request-level protection by default — otherwise a bad
        // origin is only caught by the 10s TCP probe and 5xx-style soft
        // failures are never accounted for.
        let mut site = site_rules("site1", "a.example.com");
        site.upstreams =
            vec![pool("", vec![peer("10.0.0.1:8080"), peer("10.0.0.2:8080")])];
        let config = cached_rules_to_pingap_config(
            &one_site_cache(site),
            Path::new("/tmp/varman-test-cache"),
        )
        .expect("config should build");

        let upstream = config
            .upstreams
            .get("site1_upstream")
            .expect("legacy upstream key");
        assert_eq!(upstream.enable_backend_stats, Some(true));
        assert_eq!(upstream.circuit_break_max_consecutive_failures, Some(5));
        assert_eq!(upstream.circuit_break_max_failure_percent, Some(50));
        assert_eq!(upstream.circuit_break_min_requests_threshold, Some(10));
        assert_eq!(
            upstream.circuit_break_open_duration,
            Some(Duration::from_secs(10))
        );
        // A misjudged health check or an all-open breaker must degrade to
        // the least-bad origin instead of failing the site with 503s.
        assert_eq!(upstream.enable_unhealthy_fallback, Some(true));

        // Single-node pools stay untouched: with no alternative backend an
        // open breaker would only short-circuit requests into 503.
        let mut site = site_rules("site2", "b.example.com");
        site.upstreams = vec![pool("", vec![peer("10.0.0.3:8080")])];
        let config = cached_rules_to_pingap_config(
            &one_site_cache(site),
            Path::new("/tmp/varman-test-cache"),
        )
        .expect("config should build");

        let upstream = config
            .upstreams
            .get("site2_upstream")
            .expect("single upstream key");
        assert_eq!(upstream.enable_backend_stats, None);
        assert_eq!(upstream.circuit_break_max_consecutive_failures, None);
        assert_eq!(upstream.circuit_break_max_failure_percent, None);
        assert_eq!(upstream.enable_unhealthy_fallback, None);
    }

    #[test]
    fn health_check_url_synthesis() {
        let hc = HealthCheckConfig {
            enabled: true,
            path: "/healthz".to_string(),
            interval_seconds: 15,
            timeout_ms: 2000,
            unhealthy_threshold: 3,
            healthy_threshold: 2,
        };
        assert_eq!(
            health_check_url("site1_upstream", &hc),
            "http://site1_upstream/healthz?check_frequency=15s&\
             connection_timeout=2000ms&read_timeout=2000ms&failure=3&\
             success=2"
        );

        // Missing leading slash is normalized, empty path becomes "/".
        let mut hc = hc.clone();
        hc.path = "ping".to_string();
        assert!(health_check_url("u", &hc).contains("u/ping?"));
        hc.path = String::new();
        assert!(health_check_url("u", &hc).contains("u/?"));

        // Zeroes from a corrupt cache entry clamp to safe probe values.
        let corrupt = HealthCheckConfig {
            enabled: true,
            path: "/".to_string(),
            interval_seconds: 0,
            timeout_ms: 0,
            unhealthy_threshold: 0,
            healthy_threshold: 0,
        };
        let url = health_check_url("u", &corrupt);
        assert!(url.contains("check_frequency=1s&"));
        assert!(url.contains("connection_timeout=1ms&"));
        assert!(url.contains("failure=1&success=1"));
    }

    /// End-to-end over the config path: the server-side shape of a pool
    /// carrying a health check (proto message → agent cache struct) must
    /// survive the translation into a data-plane `UpstreamConf`, and the
    /// synthesized URL must be accepted by `pingap-health` when the data
    /// plane actually builds the upstream.
    #[test]
    fn health_check_flows_end_to_end_into_the_data_plane() {
        let mut up =
            pool("", vec![peer("10.0.0.1:8080"), peer("10.0.0.2:8080")]);
        up.health_check = Some(HealthCheckConfig {
            enabled: true,
            path: "/healthz".to_string(),
            interval_seconds: 15,
            timeout_ms: 2000,
            unhealthy_threshold: 3,
            healthy_threshold: 2,
        });
        let mut site = site_rules("site1", "a.example.com");
        site.upstreams = vec![up];
        let config = cached_rules_to_pingap_config(
            &one_site_cache(site),
            Path::new("/tmp/varman-test-cache"),
        )
        .expect("config should build");

        let conf = config
            .upstreams
            .get("site1_upstream")
            .expect("multi-node upstream key");
        assert_eq!(
            conf.health_check.as_deref(),
            Some(
                "http://site1_upstream/healthz?check_frequency=15s&\
                 connection_timeout=2000ms&read_timeout=2000ms&failure=3&\
                 success=2"
            )
        );

        // Building the upstream parses the health check URL for real: a
        // malformed synthesis fails right here instead of at traffic time.
        pingap_upstream::Upstream::new("site1_upstream", conf, None)
            .expect("the synthesized health check URL must build");

        // A disabled check keeps the data plane on its TCP-probe default.
        let mut up = pool("", vec![peer("10.0.0.1:8080")]);
        up.health_check = Some(HealthCheckConfig {
            enabled: false,
            path: "/healthz".to_string(),
            interval_seconds: 15,
            timeout_ms: 2000,
            unhealthy_threshold: 3,
            healthy_threshold: 2,
        });
        let mut site = site_rules("site2", "b.example.com");
        site.upstreams = vec![up];
        let config = cached_rules_to_pingap_config(
            &one_site_cache(site),
            Path::new("/tmp/varman-test-cache"),
        )
        .expect("config should build");
        let conf = config
            .upstreams
            .get("site2_upstream")
            .expect("single upstream key");
        assert_eq!(conf.health_check, None);
    }

    #[test]
    fn legacy_multi_pool_cache_falls_back_to_first_pool() {
        // Before pools existed each upstream entry overwrote the site's
        // single location; now the first pool deterministically serves.
        let mut site = site_rules("site1", "a.example.com");
        site.upstreams = vec![
            pool("", vec![peer("10.0.0.1:8080")]),
            pool("", vec![peer("10.0.0.2:8080")]),
        ];
        let config = cached_rules_to_pingap_config(
            &one_site_cache(site),
            Path::new("/tmp/varman-test-cache"),
        )
        .expect("config should build");

        assert!(config.upstreams.contains_key("site1_upstream_0"));
        assert!(config.upstreams.contains_key("site1_upstream_1"));
        let loc = config.locations.get("site1_loc").expect("location");
        assert_eq!(loc.upstream.as_deref(), Some("site1_upstream_0"));
        assert_eq!(config.locations.len(), 1);
    }

    #[test]
    fn pools_and_routes_build_separate_locations() {
        let mut site = site_rules("site1", "a.example.com");
        let mut default_pool = pool(
            "pool-a",
            vec![
                peer("10.0.0.1:8080"),
                UpstreamPeer {
                    address: "10.0.0.2:8080".to_string(),
                    weight: 3,
                    tls: false,
                },
            ],
        );
        default_pool.is_default = true;
        let second_pool = pool("pool-b", vec![peer("10.0.0.3:9090")]);
        // Empty pools are skipped entirely.
        site.upstreams =
            vec![default_pool, second_pool, pool("pool-empty", vec![])];

        let mut r1 = route("r1", "prefix", "/api", "pool-b");
        r1.priority = Some(100);
        let r2 = route("r2", "exact", "/healthz", "pool-a");
        let r3 = route("r3", "regex", r"^/static/.*", "pool-b");
        let mut disabled = route("r4", "prefix", "/gone", "pool-b");
        disabled.enabled = false;
        // Route referencing the skipped empty pool falls back to the
        // site's default pool instead of disappearing.
        let orphan = route("r5", "prefix", "/orphan", "pool-empty");
        site.routes = vec![r1, r2, r3, disabled, orphan];

        let config = cached_rules_to_pingap_config(
            &one_site_cache(site),
            Path::new("/tmp/varman-test-cache"),
        )
        .expect("config should build");

        assert_eq!(config.upstreams.len(), 2);
        let default_upstream =
            config.upstreams.get("pool-a").expect("pool-a upstream");
        assert!(
            default_upstream
                .addrs
                .contains(&"10.0.0.2:8080 3".to_string())
        );

        let fallback = config
            .locations
            .get("site1_loc")
            .expect("default pool fallback location");
        assert_eq!(fallback.upstream.as_deref(), Some("pool-a"));
        assert_eq!(fallback.path.as_deref(), Some("/"));
        assert_eq!(fallback.weight, Some(0));

        let api = config
            .locations
            .get("site1_route_r1")
            .expect("prefix route location");
        assert_eq!(api.path.as_deref(), Some("/api"));
        assert_eq!(api.upstream.as_deref(), Some("pool-b"));
        assert_eq!(api.weight, Some(100));

        let healthz = config
            .locations
            .get("site1_route_r2")
            .expect("exact route location");
        assert_eq!(healthz.path.as_deref(), Some("=/healthz"));
        assert_eq!(healthz.upstream.as_deref(), Some("pool-a"));
        assert_eq!(healthz.weight, None);

        let static_route = config
            .locations
            .get("site1_route_r3")
            .expect("regex route location");
        assert_eq!(static_route.path.as_deref(), Some("~^/static/.*"));

        assert!(!config.locations.contains_key("site1_route_r4"));
        let orphan = config
            .locations
            .get("site1_route_r5")
            .expect("orphan route falls back to the default pool");
        assert_eq!(orphan.upstream.as_deref(), Some("pool-a"));
    }

    #[test]
    fn sni_verify_cert_and_algo_pass_through() {
        let mut site = site_rules("site1", "a.example.com");
        let mut tls_pool = pool("pool-a", vec![peer("https://10.0.0.1:8443")]);
        tls_pool.is_default = true;
        tls_pool.sni = "origin.example.com".to_string();
        tls_pool.verify_cert = Some(false);
        tls_pool.algo = "hash:cookie:session".to_string();
        site.upstreams = vec![tls_pool];

        // A cache restored from the persisted snapshot carries `null`: the
        // default must be lenient, not pingora's strict.
        let mut snapshot_pool =
            pool("pool-c", vec![peer("https://10.0.0.3:8443")]);
        snapshot_pool.sni = "origin.example.com".to_string();
        snapshot_pool.verify_cert = None;
        site.upstreams.push(snapshot_pool);

        // Strict stays strict: an operator who opted in keeps it.
        let mut strict_pool =
            pool("pool-d", vec![peer("https://10.0.0.4:8443")]);
        strict_pool.sni = "origin.example.com".to_string();
        strict_pool.verify_cert = Some(true);
        site.upstreams.push(strict_pool);

        let mut legacy_pool = pool("pool-b", vec![peer("10.0.0.2:8080")]);
        legacy_pool.algo = "lbconsistenthash".to_string();
        site.upstreams.push(legacy_pool);

        let config = cached_rules_to_pingap_config(
            &one_site_cache(site),
            Path::new("/tmp/varman-test-cache"),
        )
        .expect("config should build");

        let tls = config.upstreams.get("pool-a").expect("tls pool");
        assert_eq!(tls.sni.as_deref(), Some("origin.example.com"));
        assert_eq!(tls.verify_cert, Some(false));
        assert_eq!(
            tls.algo.as_deref(),
            Some("hash:cookie:session"),
            "valid hash algo passes through"
        );
        assert_eq!(
            tls.addrs,
            vec!["10.0.0.1:8443"],
            "scheme is stripped from peer addresses"
        );

        assert_eq!(
            config.upstreams.get("pool-b").unwrap().algo,
            None,
            "legacy enum debug names collapse to the round_robin default"
        );

        assert_eq!(
            config.upstreams.get("pool-c").unwrap().verify_cert,
            Some(false),
            "snapshot null becomes the lenient default"
        );
        assert_eq!(
            config.upstreams.get("pool-d").unwrap().verify_cert,
            Some(true),
            "explicit opt-in keeps strict verification"
        );
    }

    #[test]
    fn sanitize_algo_rejects_unknown_names() {
        assert_eq!(sanitize_algo(""), None);
        assert_eq!(sanitize_algo("round_robin"), None);
        assert_eq!(
            sanitize_algo("least_connections"),
            Some("least_connections".to_string())
        );
        assert_eq!(sanitize_algo("random"), Some("random".to_string()));
        assert_eq!(sanitize_algo("lbconsistenthash"), None);
        assert_eq!(sanitize_algo("hash:"), None);
        assert_eq!(sanitize_algo("hash:bogus"), None);
        assert_eq!(sanitize_algo("hash:ip"), Some("hash:ip".to_string()));
        assert_eq!(sanitize_algo("hash:url"), Some("hash:url".to_string()));
        assert_eq!(sanitize_algo("hash:path"), Some("hash:path".to_string()));
        assert_eq!(
            sanitize_algo("hash:header:x-user"),
            Some("hash:header:x-user".to_string())
        );
        assert_eq!(
            sanitize_algo("hash:cookie:session_id"),
            Some("hash:cookie:session_id".to_string())
        );
        assert_eq!(
            sanitize_algo("hash:query:q"),
            Some("hash:query:q".to_string())
        );
    }

    #[test]
    fn empty_cache_and_empty_sites_produce_no_config() {
        assert!(
            cached_rules_to_pingap_config(
                &CachedRules::default(),
                Path::new("/tmp/varman-test-cache")
            )
            .is_none()
        );

        let mut site = site_rules("site1", "");
        site.upstreams = vec![pool("", vec![peer("10.0.0.1:8080")])];
        assert!(
            cached_rules_to_pingap_config(
                &one_site_cache(site),
                Path::new("/tmp/varman-test-cache")
            )
            .is_none()
        );
    }

    #[test]
    fn waf_plugin_is_injected_and_referenced_by_every_location() {
        let mut site = site_rules("site1", "a.example.com");
        let mut default_pool = pool("pool1", vec![peer("10.0.0.1:8080")]);
        default_pool.is_default = true;
        site.upstreams = vec![default_pool];
        site.routes = vec![route("r1", "prefix", "/api", "pool1")];
        let config = cached_rules_to_pingap_config(
            &one_site_cache(site),
            Path::new("/tmp/varman-test-cache"),
        )
        .expect("config should build");

        let category = config
            .plugins
            .get("varman:waf")
            .and_then(|c| c.get("category"))
            .and_then(|v| v.as_str());
        assert_eq!(category, Some("waf"));

        assert!(config.locations.contains_key("site1_loc"));
        assert!(config.locations.contains_key("site1_route_r1"));
        for (name, loc) in &config.locations {
            assert_eq!(
                loc.plugins.as_deref(),
                Some(
                    [
                        "varman:waf".to_string(),
                        "varman:challenge".to_string(),
                        "varman:rewrite".to_string(),
                        "varman:error_page".to_string(),
                    ]
                    .as_slice()
                ),
                "location {name} must reference the waf and challenge plugins"
            );
        }
    }

    fn cache_rule(enabled: bool) -> varman_agent::cache::CacheRule {
        varman_agent::cache::CacheRule {
            id: "cr1".to_string(),
            name: "static assets".to_string(),
            match_expression: r#"path starts_with "/assets/""#.to_string(),
            edge_ttl_seconds: 300,
            browser_ttl_seconds: 60,
            disk_quota_mb: 0,
            cache_eligible: true,
            cache_key_headers: vec![],
            respect_origin_headers: true,
            stale_while_revalidate_seconds: 0,
            enabled,
        }
    }

    #[test]
    fn cache_plugin_is_wired_when_a_site_has_cache_rules() {
        let mut site = site_rules("site1", "a.example.com");
        let mut default_pool = pool("pool1", vec![peer("10.0.0.1:8080")]);
        default_pool.is_default = true;
        site.upstreams = vec![default_pool];
        site.cache_rules = vec![cache_rule(true)];
        let config = cached_rules_to_pingap_config(
            &one_site_cache(site),
            Path::new("/var/lib/varman/cache"),
        )
        .expect("config should build");

        let conf = config
            .plugins
            .get("varman:cache")
            .expect("cache plugin must be present");
        assert_eq!(
            conf.get("category").and_then(|v| v.as_str()),
            Some("cache")
        );
        assert_eq!(
            conf.get("directory").and_then(|v| v.as_str()),
            Some("/var/lib/varman/cache")
        );
        for (name, loc) in &config.locations {
            assert_eq!(
                loc.plugins.as_deref(),
                Some(
                    [
                        "varman:waf".to_string(),
                        "varman:challenge".to_string(),
                        "varman:rewrite".to_string(),
                        "varman:error_page".to_string(),
                        "varman:cache".to_string(),
                    ]
                    .as_slice()
                ),
                "location {name} must reference the cache plugin"
            );
        }
    }

    #[test]
    fn cache_plugin_is_absent_without_enabled_cache_rules() {
        let mut site = site_rules("site1", "a.example.com");
        let mut default_pool = pool("pool1", vec![peer("10.0.0.1:8080")]);
        default_pool.is_default = true;
        site.upstreams = vec![default_pool];
        // Disabled rules must not pull the plugin in.
        site.cache_rules = vec![cache_rule(false)];
        let config = cached_rules_to_pingap_config(
            &one_site_cache(site),
            Path::new("/var/lib/varman/cache"),
        )
        .expect("config should build");

        assert!(!config.plugins.contains_key("varman:cache"));
        for (name, loc) in &config.locations {
            assert_eq!(
                loc.plugins.as_deref(),
                Some(
                    [
                        "varman:waf".to_string(),
                        "varman:challenge".to_string(),
                        "varman:rewrite".to_string(),
                        "varman:error_page".to_string(),
                    ]
                    .as_slice()
                ),
                "location {name} must not reference the cache plugin"
            );
        }
    }

    #[test]
    fn certified_sites_split_plaintext_and_tls_servers() {
        let mut site = site_rules("site1", "a.example.com");
        let mut default_pool = pool("pool1", vec![peer("10.0.0.1:8080")]);
        default_pool.is_default = true;
        site.upstreams = vec![default_pool];
        site.ssl_config = Some(acme_ssl());
        let config = cached_rules_to_pingap_config(
            &one_site_cache(site),
            Path::new("/tmp/varman-test-cache"),
        )
        .expect("config should build");

        assert_eq!(config.servers.len(), 2);
        let http = config.servers.get("varman").expect("http server");
        assert_eq!(http.addr, "0.0.0.0:80");
        assert_eq!(http.global_certificates, Some(false));
        let tls = config.servers.get("varman_tls").expect("tls server");
        assert_eq!(tls.addr, "0.0.0.0:443");
        assert_eq!(tls.global_certificates, Some(true));
        let names = tls.locations.as_deref().expect("tls locations");
        assert_eq!(names, http.locations.as_deref().expect("http locations"));
        assert!(names.contains(&"site1_loc".to_string()));
    }

    #[test]
    fn mtls_sites_contribute_their_ca_to_the_tls_listener() {
        let mut site = site_rules("site1", "a.example.com");
        let mut default_pool = pool("pool1", vec![peer("10.0.0.1:8080")]);
        default_pool.is_default = true;
        site.upstreams = vec![default_pool];
        let mut ssl = acme_ssl();
        ssl.mtls_enabled = true;
        ssl.mtls_client_ca = "-----BEGIN CERTIFICATE-----\nCA1\n".to_string();
        site.ssl_config = Some(ssl);
        let mut second = site_rules("site2", "b.example.com");
        second.upstreams = vec![pool("pool2", vec![peer("10.0.0.2:8080")])];
        let mut second_ssl = acme_ssl();
        second_ssl.mtls_enabled = true;
        second_ssl.mtls_client_ca =
            "-----BEGIN CERTIFICATE-----\nCA2".to_string();
        second.ssl_config = Some(second_ssl);
        // A site with the plain TLS posture must not add an anchor.
        let mut plain = site_rules("site3", "c.example.com");
        plain.upstreams = vec![pool("pool3", vec![peer("10.0.0.3:8080")])];
        plain.ssl_config = Some(acme_ssl());

        let mut cache = one_site_cache(site);
        cache.sites.insert("site2".to_string(), Arc::new(second));
        cache.sites.insert("site3".to_string(), Arc::new(plain));
        let config = cached_rules_to_pingap_config(
            &cache,
            Path::new("/tmp/varman-test-cache"),
        )
        .expect("config should build");

        let tls = config.servers.get("varman_tls").expect("tls server");
        let bundle = tls.client_ca_pem.as_deref().expect("client ca bundle");
        assert!(bundle.contains("CA1"), "{bundle}");
        assert!(bundle.contains("CA2"), "{bundle}");
        // The plaintext listener never verifies client certificates.
        let http = config.servers.get("varman").expect("http server");
        assert_eq!(http.client_ca_pem, None);
    }

    #[test]
    fn sites_without_mtls_leave_client_verification_off() {
        let mut site = site_rules("site1", "a.example.com");
        let mut default_pool = pool("pool1", vec![peer("10.0.0.1:8080")]);
        default_pool.is_default = true;
        site.upstreams = vec![default_pool];
        // mTLS disabled even though an anchor is on file.
        let mut ssl = acme_ssl();
        ssl.mtls_client_ca = "-----BEGIN CERTIFICATE-----\nCA1".to_string();
        site.ssl_config = Some(ssl);

        let config = cached_rules_to_pingap_config(
            &one_site_cache(site),
            Path::new("/tmp/varman-test-cache"),
        )
        .expect("config should build");

        let tls = config.servers.get("varman_tls").expect("tls server");
        assert_eq!(tls.client_ca_pem, None);
    }

    #[test]
    fn sites_without_certificates_still_bind_tls() {
        // 443 comes up even with an empty certificate provider: handshakes
        // fail until the first certificate lands, but the port is listening
        // and the certificate takes effect without a restart.
        let mut site = site_rules("site1", "a.example.com");
        let mut default_pool = pool("pool1", vec![peer("10.0.0.1:8080")]);
        default_pool.is_default = true;
        site.upstreams = vec![default_pool];
        let config = cached_rules_to_pingap_config(
            &one_site_cache(site),
            Path::new("/tmp/varman-test-cache"),
        )
        .expect("config should build");

        assert_eq!(config.servers.len(), 2);
        let server = config.servers.get("varman").expect("server");
        assert_eq!(server.addr, "0.0.0.0:80");
        assert_eq!(server.global_certificates, Some(false));
        let tls = config.servers.get("varman_tls").expect("tls server");
        assert_eq!(tls.addr, "0.0.0.0:443");
        assert_eq!(tls.global_certificates, Some(true));
    }

    #[test]
    fn low_priority_routes_still_beat_the_site_fallback() {
        // Regression: the fallback location used to carry the auto weight
        // (128), so a route with priority ≤ 127 sorted behind the catch-all
        // `/` location and never matched. The fallback now pins weight 0.
        let mut site = site_rules("site1", "a.example.com");
        let mut default_pool = pool("pool1", vec![peer("10.0.0.1:8080")]);
        default_pool.is_default = true;
        site.upstreams = vec![default_pool];
        let mut routed_pool = pool("pool2", vec![peer("10.0.0.2:8080")]);
        routed_pool.is_default = false;
        site.upstreams.push(routed_pool);
        let mut r = route("r1", "prefix", "/api", "pool2");
        r.priority = Some(1);
        site.routes.push(r);

        let config = cached_rules_to_pingap_config(
            &one_site_cache(site),
            Path::new("/tmp/varman-test-cache"),
        )
        .expect("config should build");

        let fallback = config
            .locations
            .get("site1_loc")
            .expect("fallback location");
        assert_eq!(fallback.weight, Some(0));
        let routed = config
            .locations
            .get("site1_route_r1")
            .expect("route location");
        assert_eq!(routed.weight, Some(1));
    }

    #[test]
    fn routes_fall_back_to_the_default_pool_when_theirs_is_empty() {
        let mut site = site_rules("site1", "a.example.com");
        let mut default_pool = pool("pool1", vec![peer("10.0.0.1:8080")]);
        default_pool.is_default = true;
        site.upstreams = vec![default_pool];
        let mut empty_pool = pool("pool2", vec![]);
        empty_pool.is_default = false;
        site.upstreams.push(empty_pool);
        site.routes.push(route("r1", "prefix", "/api", "pool2"));
        let config = cached_rules_to_pingap_config(
            &one_site_cache(site),
            Path::new("/tmp/varman-test-cache"),
        )
        .expect("config should build");

        let location = config
            .locations
            .get("site1_route_r1")
            .expect("route location should exist");
        assert_eq!(location.upstream.as_deref(), Some("pool1"));
    }

    #[test]
    fn hsts_and_https_redirect_are_wired_per_site() {
        let mut site = site_rules("site1", "a.example.com");
        site.upstreams = vec![pool("pool1", vec![peer("10.0.0.1:8080")])];
        let mut ssl = acme_ssl();
        ssl.hsts_enabled = true;
        ssl.hsts_max_age = 15_552_000;
        ssl.always_use_https = true;
        site.ssl_config = Some(ssl);

        let config = cached_rules_to_pingap_config(
            &one_site_cache(site),
            Path::new("/tmp/varman-test-cache"),
        )
        .expect("config should build");

        let hsts = config.plugins.get("site1_hsts").expect("hsts plugin");
        assert_eq!(
            hsts.get("category").and_then(|v| v.as_str()),
            Some("response_headers")
        );
        let add_headers = hsts
            .get("add_headers")
            .and_then(|v| v.as_array())
            .expect("add_headers list");
        assert_eq!(
            add_headers[0].as_str(),
            Some("Strict-Transport-Security: max-age=15552000")
        );

        let redirect =
            config.plugins.get("site1_https").expect("redirect plugin");
        assert_eq!(
            redirect.get("category").and_then(|v| v.as_str()),
            Some("redirect")
        );
        assert_eq!(
            redirect.get("http_to_https").and_then(|v| v.as_bool()),
            Some(true)
        );
        assert_eq!(
            redirect.get("status").and_then(|v| v.as_integer()),
            Some(301)
        );

        let names = config
            .locations
            .get("site1_loc")
            .and_then(|loc| loc.plugins.clone())
            .unwrap_or_default();
        assert!(names.contains(&"site1_hsts".to_string()), "{names:?}");
        assert!(names.contains(&"site1_https".to_string()), "{names:?}");
    }

    #[test]
    fn hsts_and_redirect_plugins_are_absent_when_not_configured() {
        let mut site = site_rules("site1", "a.example.com");
        site.upstreams = vec![pool("pool1", vec![peer("10.0.0.1:8080")])];
        let mut ssl = acme_ssl();
        ssl.hsts_enabled = true;
        // A zero window means "send no header", not "pin max-age=0".
        ssl.hsts_max_age = 0;
        ssl.always_use_https = false;
        site.ssl_config = Some(ssl);

        let config = cached_rules_to_pingap_config(
            &one_site_cache(site),
            Path::new("/tmp/varman-test-cache"),
        )
        .expect("config should build");

        assert!(!config.plugins.contains_key("site1_hsts"));
        assert!(!config.plugins.contains_key("site1_https"));
        let names = config
            .locations
            .get("site1_loc")
            .and_then(|loc| loc.plugins.clone())
            .unwrap_or_default();
        assert!(
            !names
                .iter()
                .any(|name| name.contains("_hsts") || name.contains("_https")),
            "{names:?}"
        );
    }

    fn acme_ssl() -> SslConfig {
        SslConfig {
            cert_pem: String::new(),
            key_pem: String::new(),
            acme_enabled: true,
            acme_email: "admin@example.com".to_string(),
            acme_challenge_type: "AcmeHttp01".to_string(),
            acme_dns_provider: String::new(),
            acme_dns_config: HashMap::new(),
            min_tls_version: String::new(),
            hsts_enabled: false,
            hsts_max_age: 0,
            always_use_https: false,
            enabled: true,
            max_tls_version: String::new(),
            self_signed: false,
            mtls_enabled: false,
            mtls_client_ca: String::new(),
            certificate_id: String::new(),
            domains: vec![],
            mtls_revoked_fingerprints: vec![],
            mtls_organization: String::new(),
            mtls_require_client_cert: Some(false),
        }
    }

    #[test]
    fn acme_http01_conf_marks_acme_without_dns_fields() {
        let ssl = acme_ssl();
        let cert = acme_certificate_conf(&ssl, "a.example.com".to_string())
            .expect("plain hostnames issue over http-01");
        assert_eq!(cert.acme.as_deref(), Some("http://admin@example.com"));
        assert_eq!(cert.domains.as_deref(), Some("a.example.com"));
        assert_eq!(cert.dns_challenge, None);
        assert_eq!(cert.dns_provider, None);
    }

    #[test]
    fn acme_wildcards_are_skipped_unless_dns01_is_usable() {
        // http-01 cannot validate a wildcard: the order is dropped instead
        // of retried forever.
        let ssl = acme_ssl();
        assert!(
            acme_certificate_conf(&ssl, "*.example.com".to_string()).is_none()
        );
        assert!(
            acme_certificate_conf(
                &ssl,
                "example.com,*.example.com".to_string()
            )
            .is_none()
        );

        // dns-01 with a provider that resolves to no endpoint falls back to
        // http-01, so a wildcard is dropped there too.
        let mut ssl = acme_ssl();
        ssl.acme_challenge_type = "AcmeDns01".to_string();
        ssl.acme_dns_provider = "not-a-provider".to_string();
        assert!(
            acme_certificate_conf(&ssl, "*.example.com".to_string()).is_none()
        );

        // Manual mode renders no DNS challenge either.
        ssl.acme_dns_provider = "manual".to_string();
        assert!(
            acme_certificate_conf(&ssl, "*.example.com".to_string()).is_none()
        );

        // A real provider issues the wildcard through dns-01.
        ssl.acme_dns_provider = "ali".to_string();
        let cert = acme_certificate_conf(&ssl, "*.example.com".to_string())
            .expect("dns-01 issues wildcards");
        assert_eq!(cert.dns_challenge, Some(true));
        assert_eq!(cert.dns_provider.as_deref(), Some("ali"));

        // The unknown-provider fallback still serves plain hostnames.
        ssl.acme_challenge_type = "AcmeDns01".to_string();
        ssl.acme_dns_provider = "not-a-provider".to_string();
        assert!(
            acme_certificate_conf(&ssl, "a.example.com".to_string()).is_some()
        );
    }

    #[test]
    fn acme_dns01_conf_builds_provider_endpoint_with_credentials() {
        let mut ssl = acme_ssl();
        ssl.acme_challenge_type = "AcmeDns01".to_string();
        // "aliyun" is an accepted alias; the canonical name the config
        // carries is "ali".
        ssl.acme_dns_provider = "aliyun".to_string();
        ssl.acme_dns_config
            .insert("access_key_id".to_string(), "AK 1/2".to_string());
        ssl.acme_dns_config
            .insert("access_key_secret".to_string(), "s3cret".to_string());

        let cert = acme_certificate_conf(&ssl, "a.example.com".to_string())
            .expect("ali resolves to an endpoint");
        assert_eq!(cert.dns_challenge, Some(true));
        assert_eq!(cert.dns_provider.as_deref(), Some("ali"));
        let url = cert.dns_service_url.expect("service url");
        assert!(url.starts_with("https://alidns.aliyuncs.com?"), "{url}");
        assert!(url.contains("access_key_id=AK%201%2F2"), "{url}");
        assert!(url.contains("access_key_secret=s3cret"), "{url}");
    }

    #[test]
    fn acme_dns01_unknown_provider_stays_on_http01() {
        let mut ssl = acme_ssl();
        ssl.acme_challenge_type = "AcmeDns01".to_string();
        ssl.acme_dns_provider = "not-a-provider".to_string();

        let cert = acme_certificate_conf(&ssl, "a.example.com".to_string())
            .expect("unknown providers fall back to http-01");
        assert_eq!(cert.dns_challenge, None);
        assert_eq!(cert.dns_provider, None);
    }

    #[test]
    fn merge_config_state_empty_prev_is_identity() {
        let new_toml = "[certificates.c1]\ntls_key = \"k\"\n";
        assert_eq!(merge_config_state(new_toml, ""), new_toml);
    }

    #[test]
    fn merge_config_state_carries_issued_pems_and_storages() {
        let prev_toml = "\
[certificates.c1]
tls_cert = \"ISSUED\"
tls_key = \"KEY\"

[certificates.c2]
tls_cert = \"UPLOAD\"
tls_key = \"UPKEY\"

[storages.acme]
type = \"file\"
path = \"/tmp/acme\"
";
        let new_toml = "\
[certificates.c1]
acme = \"http://a@example.com\"

[certificates.c2]
tls_cert = \"NEWUPLOAD\"
tls_key = \"NEWKEY\"
";
        let merged = merge_config_state(new_toml, prev_toml)
            .parse::<toml::Table>()
            .expect("merged config must parse");

        let c1 = merged
            .get("certificates")
            .and_then(|v| v.get("c1"))
            .expect("c1 entry");
        assert_eq!(
            c1.get("tls_cert").and_then(|v| v.as_str()),
            Some("ISSUED"),
            "issued pem must be carried over"
        );
        assert_eq!(
            c1.get("tls_key").and_then(|v| v.as_str()),
            Some("KEY"),
            "issued key must be carried over"
        );

        let c2 = merged
            .get("certificates")
            .and_then(|v| v.get("c2"))
            .expect("c2 entry");
        assert_eq!(
            c2.get("tls_cert").and_then(|v| v.as_str()),
            Some("NEWUPLOAD"),
            "fresh upload must win over the previous pem"
        );

        let storages = merged.get("storages").expect("storages section");
        assert_eq!(
            storages
                .get("acme")
                .and_then(|v| v.get("path"))
                .and_then(|v| v.as_str()),
            Some("/tmp/acme")
        );
    }
}
