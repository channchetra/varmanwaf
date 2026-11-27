use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use pingap_acme::new_lets_encrypt_service;
use pingap_config::PingapTomlConfig;
use pingap_core::BackgroundTaskService;
use pingap_proxy::{
    AppContext, Server as ProxyServer, ServerConf, parse_from_conf,
};
use pingap_upstream::new_upstream_health_check_task;
use pingora::server;
use pingora::server::configuration::Opt;
use pingora::services::background::background_service;
use tracing::{error, info, warn};
use varman_agent::cache::RuleCache;

use crate::certificates::{new_certificate_provider, try_update_certificates};
use crate::config_manager::try_init_memory_config_manager;
use crate::locations::{new_location_provider, try_init_locations};
use crate::plugin::{new_plugin_provider, try_init_plugins};
use crate::server_locations::{
    new_server_locations_provider, try_init_server_locations,
};
use crate::upstreams::{new_upstream_provider, try_init_upstreams};

use super::acme::{
    acme_state_path, merge_config_state, publish_management_certificate,
};
use super::bundle_config::build_pingap_config;

/// Start the Pingora-based data plane proxy from the agent's cached rules.
///
/// Waits for the agent to receive its initial configuration from the
/// control plane, then builds a PingapConfig and starts the reverse proxy
/// on ports 80 and 443.
pub(super) async fn start_data_plane(
    rule_cache: Arc<RuleCache>,
) -> anyhow::Result<()> {
    // Wait for the agent to receive initial config from the control plane
    for i in 0..30 {
        let cached = rule_cache.all_sites();
        if !cached.sites.is_empty() {
            break;
        }
        if i == 0 {
            info!("data plane: waiting for control plane configuration...");
        }
        tokio::time::sleep(Duration::from_secs(1)).await;
    }

    let config = match build_pingap_config(&rule_cache) {
        Some(config) => config,
        None => {
            warn!("data plane: no sites configured, proxy not started");
            // Keep waiting — the agent may receive config later
            loop {
                tokio::time::sleep(Duration::from_secs(5)).await;
                if let Some(config) = build_pingap_config(&rule_cache) {
                    break config;
                }
            }
        },
    };

    let site_count = config
        .servers
        .values()
        .flat_map(|s| s.locations.as_deref().unwrap_or_default())
        .count();
    info!(
        upstreams = config.upstreams.len(),
        locations = config.locations.len(),
        certificates = config.certificates.len(),
        "data plane: starting reverse proxy with {} site(s)",
        site_count,
    );

    // Serialize to TOML and create a memory-backed config manager. The
    // freshly converted config is merged with the ACME state left by the
    // previous run first, so already-issued certificates are served (and
    // not reordered) from the first request on.
    let toml_str = toml::to_string_pretty(&config).map_err(|e| {
        anyhow::anyhow!("failed to serialize proxy config: {}", e)
    })?;
    let acme_state = acme_state_path(&rule_cache);
    let toml_str = merge_config_state(
        &toml_str,
        &std::fs::read_to_string(&acme_state).unwrap_or_default(),
    );
    let config_manager =
        try_init_memory_config_manager(&toml_str, Some(acme_state)).map_err(
            |e| anyhow::anyhow!("failed to init config manager: {}", e),
        )?;

    // The lets-encrypt task scans current_config for certificates to issue,
    // so it must reflect the merged state; validation keeps a malformed
    // merge from taking the proxy down (falls back to the fresh config).
    let config = match PingapTomlConfig::from_toml(&toml_str)
        .and_then(|toml_config| toml_config.to_pingap_config(true))
    {
        Ok(merged) => merged,
        Err(e) => {
            warn!(
                error = %e,
                "data plane: merged config failed validation, using freshly converted config"
            );
            config
        },
    };
    config_manager.set_current_config(config.clone());
    publish_management_certificate(&config);

    // Initialize providers from the (merged) config
    try_init_upstreams(&config.upstreams, crate::webhook::get_webhook_sender())
        .map_err(|e| anyhow::anyhow!("failed to init upstreams: {}", e))?;
    try_init_locations(&config.locations)
        .map_err(|e| anyhow::anyhow!("failed to init locations: {}", e))?;
    try_init_server_locations(&config.servers, &config.locations).map_err(
        |e| anyhow::anyhow!("failed to init server locations: {}", e),
    )?;

    // Activate the WAF plugin: without it the data plane forwards traffic
    // uninspected and no access/security events are ever emitted.
    let (updated_plugins, plugin_errors) = try_init_plugins(&config.plugins);
    if !updated_plugins.is_empty() {
        info!(
            plugins = updated_plugins.join(","),
            "data plane: plugins initialized"
        );
    }
    if !plugin_errors.is_empty() {
        error!(error = plugin_errors, "data plane: plugin init errors");
    }

    // Initialize certificates
    let cert_provider = new_certificate_provider();
    if !config.certificates.is_empty() {
        let (updated, errors) = try_update_certificates(&config.certificates);
        if !updated.is_empty() {
            info!(certs = updated.join(","), "data plane: certificates loaded");
        }
        if !errors.is_empty() {
            error!(error = errors, "data plane: certificate parse errors");
        }
    }

    // Let the agent report certificate state: the ACME task writes issued PEMs
    // into the provider below, and without this the control plane keeps showing
    // the certificate as pending forever. Certificates generated from site
    // config are named `{site_id}_cert`, which is how a status is attributed
    // back to its site.
    {
        let provider = cert_provider.clone();
        varman_agent::cert_status::set_snapshot(Some(Arc::new(move || {
            let now = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map(|elapsed| elapsed.as_secs() as i64)
                .unwrap_or_default();
            let mut statuses = HashMap::new();
            for cert in provider.list().values() {
                let Some(site_id) = cert
                    .name
                    .as_deref()
                    .and_then(|name| name.strip_suffix("_cert"))
                else {
                    continue;
                };
                let Some(info) = cert.info.as_ref() else {
                    continue;
                };
                if info.not_after == 0 {
                    continue;
                }
                let remaining = info.not_after - now;
                let status = if remaining <= 0 {
                    "expired"
                } else if remaining <= 2 * 24 * 3600 {
                    "expiring_soon"
                } else {
                    "valid"
                };
                // One certificate is listed under every domain it serves; the
                // entries agree, so the first one wins.
                statuses.entry(site_id.to_string()).or_insert(
                    varman_agent::cert_status::CertStatus {
                        status,
                        expires_at: info.not_after,
                    },
                );
            }
            statuses
        })));
    }

    // Create the Pingora server
    let opt = Opt::default();
    let server_conf = crate::new_server_config_from(false, None, &config);
    let mut my_server =
        server::Server::new_with_opt_and_conf(Some(opt), server_conf);
    let bootstrap_handle = my_server.bootstrap_as_a_service();

    // ACME (Let's Encrypt): issue and renew certificates for sites whose
    // The ACME task must exist even when no certificate is configured at
    // start-up: certificates are created at runtime (the console, the API)
    // and the task re-reads the live config every cycle, so a task that was
    // never registered leaves runtime-created orders unprocessed - the row
    // sits `pending` and the stale sweeper eventually fails it with a
    // generic reason. With no ACME certificates the task is a cheap no-op.
    // PINGAP_DISABLE_ACME opts out entirely.
    let acme_enabled = std::env::var("PINGAP_DISABLE_ACME")
        .unwrap_or_default()
        .is_empty();
    let mut background_tasks = BackgroundTaskService::new(
        "data_plane_background_tasks",
        Duration::from_secs(60),
        vec![],
    );
    background_tasks.set_immediately(true);
    background_tasks.set_initial_delay(Some(Duration::from_secs(3)));
    // A stalled ACME cycle is mirrored onto the `pingap::acme` target, which
    // the agent's certificate-event capture ships to the control plane — so
    // an issuance that hangs shows up in the panel's certificate log instead
    // of only in the data plane's own log file.
    background_tasks.set_on_stalled(Some(Box::new(|name, tasks, elapsed| {
        warn!(
            target: "pingap::acme",
            name,
            tasks,
            elapsed,
            "background tasks still running past the interval"
        );
    })));
    // The same loops the file-configured data plane registers. Without them
    // an agent-hosted plane never notices an expiring certificate, never
    // rotates a stale self-signed pair and never clears old storage.
    background_tasks.add_task(
        "validity_checker",
        pingap_certificate::new_certificate_validity_service(
            cert_provider.clone(),
            crate::webhook::get_webhook_sender(),
        ),
    );
    background_tasks.add_task(
        "self_signed_certificate_stale",
        pingap_certificate::new_self_signed_certificate_validity_service(),
    );
    background_tasks.add_task(
        "performance_metrics",
        pingap_performance::new_performance_metrics_log_service(
            new_location_provider(),
            new_upstream_provider(),
        ),
    );
    if let Some(task) = pingap_cache::new_storage_clear_service() {
        background_tasks.add_task("storage_clear", task);
    }
    if acme_enabled {
        background_tasks.add_task(
            "lets_encrypt",
            new_lets_encrypt_service(
                config_manager.clone(),
                cert_provider.clone(),
                crate::webhook::get_webhook_sender(),
            ),
        );
        info!("data plane: ACME certificate management enabled");
    }
    let background_tasks_name = background_tasks.name().to_string();
    my_server.add_service(background_service(
        &background_tasks_name,
        background_tasks,
    ));

    // Parse server configs and start proxy servers
    let server_conf_list: Vec<ServerConf> = parse_from_conf(config.clone());

    for server_conf in server_conf_list {
        let ctx = AppContext {
            server_locations_provider: new_server_locations_provider(),
            location_provider: new_location_provider(),
            upstream_provider: new_upstream_provider(),
            plugin_provider: new_plugin_provider(),
            certificate_provider: cert_provider.clone(),
            config_manager: config_manager.clone(),
            logger: None,
        };
        let mut ps = ProxyServer::new(&server_conf, ctx)?;
        // The HTTP-01 challenge must be reachable on port 80, so every
        // data-plane server whose address list includes :80 intercepts
        // /.well-known/acme-challenge before proxying.
        if acme_enabled
            && server_conf
                .addr
                .split(',')
                .any(|addr| addr.trim().ends_with(":80"))
        {
            ps.enable_lets_encrypt();
        }
        let services = ps.run(my_server.configuration.clone())?;
        my_server
            .add_service(services.lb)
            .add_dependency(&bootstrap_handle);
    }

    info!(
        addrs = %config
            .servers
            .values()
            .map(|s| s.addr.as_str())
            .collect::<Vec<_>>()
            .join(", "),
        "data plane: proxy server is running"
    );

    // Start the upstream health check background task.
    // This also drives periodic DNS discovery updates — without it,
    // DNS-based backends are never resolved and requests get 503.
    let upstream_health_check_task = new_upstream_health_check_task(
        new_upstream_provider(),
        Duration::from_secs(10),
        None,
    );
    let hc_name = upstream_health_check_task.name().to_string();
    info!(
        service_name = %hc_name,
        "data plane: registering upstream health check background service"
    );
    my_server
        .add_service(background_service(&hc_name, upstream_health_check_task));

    // Run Pingora in a dedicated OS thread. Do NOT join it here —
    // joining would block the tokio worker thread permanently and starve
    // the control-plane REST/gRPC servers (especially on small machines).
    // The thread exits when the process shuts down.
    std::thread::spawn(move || {
        my_server.run_forever();
    });

    // Access log entries are held until the response body completes so the
    // log can carry the response payload. A client that disconnects mid-body
    // never fires the end-of-stream callback, so stale entries are swept
    // periodically: they are still emitted (flagged truncated) so the request
    // never vanishes from the log, and the map cannot grow without bound.
    tokio::spawn(async move {
        loop {
            tokio::time::sleep(Duration::from_secs(5)).await;
            let swept = pingap_plugin::sweep_stale_access(
                pingap_plugin::PENDING_ACCESS_SWEEP_TTL,
            );
            if swept > 0 {
                info!(
                    count = swept,
                    "data plane: swept stale pending access entries"
                );
            }
        }
    });

    // Hot-reload watcher: poll the rule cache config hash and re-init the
    // ArcSwap providers when the control plane pushes new rules. The proxy
    // reads these providers per request, so no restart is needed. The config
    // manager itself is updated in place: on every reload the freshly
    // converted config is merged with the previous document (preserving
    // issued PEMs and ACME state such as challenge tokens and the account
    // key) and set as current, so the ACME renewal task keeps working.
    let watcher_cache = Arc::clone(&rule_cache);
    let watcher_config_manager = Arc::clone(&config_manager);
    let mut last_hash = watcher_cache.data_plane_hash();
    let mut last_management = varman_control::management_cert::revision();
    tokio::spawn(async move {
        loop {
            tokio::time::sleep(Duration::from_secs(5)).await;
            let hash = watcher_cache.data_plane_hash();
            let management = varman_control::management_cert::revision();
            if hash == last_hash && management == last_management {
                continue;
            }
            info!(
                old = %last_hash,
                new = %hash,
                "data plane: rule change detected, reloading"
            );
            let Some(converted) = build_pingap_config(&watcher_cache) else {
                warn!(
                    "data plane: reload produced no usable config, keeping current"
                );
                last_hash = hash;
                last_management = management;
                continue;
            };
            let Ok(new_toml) = toml::to_string_pretty(&converted) else {
                error!(
                    "data plane: reload config serialization failed, keeping current"
                );
                last_hash = hash;
                last_management = management;
                continue;
            };
            // Fetch-merge-save must be atomic with respect to ACME's own
            // read-modify-write: an issuance completing while the reload was
            // reading a PEM-less snapshot used to be clobbered by the reload
            // save, dropping the certificate from storage (and then from the
            // SNI table on the next provider rebuild).
            let config = match watcher_config_manager
                .update_raw(|prev_toml| {
                    merge_config_state(&new_toml, &prev_toml)
                })
                .await
            {
                Ok(config) => config,
                Err(e) => {
                    warn!(
                        error = %e,
                        "data plane: merged reload config failed, using freshly converted config"
                    );
                    converted
                },
            };
            watcher_config_manager.set_current_config(config.clone());
            publish_management_certificate(&config);
            if let Err(e) = try_init_upstreams(&config.upstreams, None) {
                error!(error = %e, "data plane: reload upstreams failed");
            }
            if let Err(e) = try_init_locations(&config.locations) {
                error!(error = %e, "data plane: reload locations failed");
            }
            if let Err(e) =
                try_init_server_locations(&config.servers, &config.locations)
            {
                error!(error = %e, "data plane: reload server locations failed");
            }
            let (updated, errors) =
                try_update_certificates(&config.certificates);
            if !updated.is_empty() {
                info!(
                    certs = updated.join(","),
                    "data plane: certificates reloaded"
                );
            }
            if !errors.is_empty() {
                error!(error = errors, "data plane: certificate reload errors");
            }
            let (updated_plugins, plugin_errors) =
                try_init_plugins(&config.plugins);
            if !updated_plugins.is_empty() {
                info!(
                    plugins = updated_plugins.join(","),
                    "data plane: plugins reloaded"
                );
            }
            if !plugin_errors.is_empty() {
                error!(
                    error = plugin_errors,
                    "data plane: plugin reload errors"
                );
            }
            last_hash = hash;
            last_management = management;
        }
    });

    // The ACME task fills the `__management` entry in place, without changing
    // the config hash, so the reload hooks above never see the issued material.
    // Publish it on a timer instead: the installer compares fingerprints, so
    // repeating the same certificate is a no-op.
    let management_config = Arc::clone(&config_manager);
    tokio::spawn(async move {
        loop {
            tokio::time::sleep(Duration::from_secs(15)).await;
            publish_management_certificate(
                &management_config.get_current_config(),
            );
        }
    });

    // Keep the async task alive until the tokio runtime shuts down.
    // The caller (run()) aborts this task on shutdown signal.
    std::future::pending::<()>().await;
    Ok(())
}
