use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use pingap_acme::new_lets_encrypt_service;
use pingap_config::PingapTomlConfig;
use pingap_proxy::{Server as ProxyServer, parse_from_conf};
use pingap_upstream::new_upstream_health_check_task;
use pingora::services::background::background_service;
use tracing::{error, info, warn};
use varman_agent::cache::RuleCache;

use crate::certificates::try_update_certificates;
use crate::config_manager::try_init_memory_config_manager;
use crate::data_plane::{DataPlaneOptions, assemble};
use crate::locations::try_init_locations;
use crate::plugin::try_init_plugins;
use crate::server_locations::try_init_server_locations;
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

    // Assemble the shared data plane: providers, pingora server, the four
    // common background loops. `background_tasks` stays here because this root
    // adds ACME to it and registers it before its listeners.
    let mut assembled = assemble(
        &config,
        DataPlaneOptions {
            daemon: false,
            upgrade: false,
            threads: None,
            extra_plugins: HashMap::new(),
            background_tasks: Some("data_plane_background_tasks"),
            admin_only: false,
        },
    )?;

    // Activate the WAF plugin: without it the data plane forwards traffic
    // uninspected and no access/security events are ever emitted.
    if !assembled.plugins.updated.is_empty() {
        info!(
            plugins = assembled.plugins.updated.join(","),
            "data plane: plugins initialized"
        );
    }
    if !assembled.plugins.errors.is_empty() {
        error!(
            error = assembled.plugins.errors.as_str(),
            "data plane: plugin init errors"
        );
    }

    // Initialize certificates
    let cert_provider = assembled.certificate_provider.clone();
    if !config.certificates.is_empty() {
        if !assembled.certificates.updated.is_empty() {
            info!(
                certs = assembled.certificates.updated.join(","),
                "data plane: certificates loaded"
            );
        }
        if !assembled.certificates.errors.is_empty() {
            error!(
                error = assembled.certificates.errors.as_str(),
                "data plane: certificate parse errors"
            );
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
    let mut background_tasks = assembled
        .background_tasks
        .take()
        .expect("assemble builds the background tasks for a data plane");
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
    assembled.server.add_service(background_service(
        &background_tasks_name,
        background_tasks,
    ));

    // Parse server configs and start proxy servers
    let server_conf_list = parse_from_conf(config.clone());

    for server_conf in server_conf_list {
        let mut ps =
            ProxyServer::new(&server_conf, assembled.app_context(None))?;
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
        let services = ps.run(assembled.server.configuration.clone())?;
        assembled
            .server
            .add_service(services.lb)
            .add_dependency(&assembled.bootstrap);
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
    assembled
        .server
        .add_service(background_service(&hc_name, upstream_health_check_task));

    let my_server = assembled.server;
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
