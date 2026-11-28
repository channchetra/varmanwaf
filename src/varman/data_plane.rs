use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use pingap_certificate::CertificateProvider;
use pingap_config::{ConfigManager, PingapConfig, PingapTomlConfig};
use pingap_proxy::{Server as ProxyServer, parse_from_conf};
use pingap_upstream::new_upstream_health_check_task;
use pingora::services::background::background_service;
use tracing::{error, info, warn};
use varman_agent::cache::RuleCache;

use crate::config_apply::{
    ApplyOptions, ApplyOutcome, apply_config, commit_if_applied,
};
use crate::config_manager::build_memory_config_manager;
use crate::data_plane::{DataPlaneOptions, assemble};

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
    let config = wait_for_config(&rule_cache).await;
    log_start(&config);
    let (config_manager, config) = config_manager_for(&rule_cache, config)?;

    // Assemble the shared data plane: providers, pingora server, the four
    // common background loops. `background_tasks` stays here because this root
    // adds ACME to it and registers it before its listeners.
    let mut assembled = assemble(
        &config,
        config_manager.clone(),
        DataPlaneOptions::data_plane(
            false,
            false,
            None,
            None,
            "data_plane_background_tasks",
        ),
    )?;

    // Activate the WAF plugin: without it the data plane forwards traffic
    // uninspected and no access/security events are ever emitted.
    let cert_provider = assembled.providers.certificates.clone();
    crate::data_plane::report_provider_updates(
        &assembled.plugins,
        &assembled.certificates,
    );
    install_certificate_status_snapshot(cert_provider.clone());

    let acme_enabled = crate::acme_enabled();
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
        crate::data_plane::add_acme_task(
            &mut background_tasks,
            config_manager.clone(),
            cert_provider,
            Some(crate::webhook::get_webhook_sender()),
        );
        info!("data plane: ACME certificate management enabled");
    }
    register_background_tasks(&mut assembled, background_tasks);

    start_proxy_servers(&mut assembled, &config, acme_enabled)?;
    start_upstream_health_check(&mut assembled);

    let my_server = assembled.server;
    // Run Pingora in a dedicated OS thread. Do NOT join it here —
    // joining would block the tokio worker thread permanently and starve
    // the control-plane REST/gRPC servers (especially on small machines).
    // The thread exits when the process shuts down.
    std::thread::spawn(move || {
        my_server.run_forever();
    });

    spawn_pending_access_sweeper();
    spawn_rule_reload_watcher(
        rule_cache,
        config_manager.clone(),
        assembled.providers.clone(),
    );
    spawn_management_certificate_publisher(config_manager);

    // Keep the async task alive until the tokio runtime shuts down.
    // The caller (run()) aborts this task on shutdown signal.
    std::future::pending::<()>().await;
    Ok(())
}

/// Waits for the first control-plane rules, then keeps waiting until they
/// produce a usable proxy config.
async fn wait_for_config(rule_cache: &Arc<RuleCache>) -> PingapConfig {
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

    match build_pingap_config(rule_cache) {
        Some(config) => config,
        None => {
            warn!("data plane: no sites configured, proxy not started");
            loop {
                tokio::time::sleep(Duration::from_secs(5)).await;
                if let Some(config) = build_pingap_config(rule_cache) {
                    break config;
                }
            }
        },
    }
}

fn log_start(config: &PingapConfig) {
    let location_count = config
        .servers
        .values()
        .flat_map(|s| s.locations.as_deref().unwrap_or_default())
        .count();
    info!(
        upstreams = config.upstreams.len(),
        locations = config.locations.len(),
        certificates = config.certificates.len(),
        "data plane: starting reverse proxy with {} location(s)",
        location_count,
    );
}

/// Serializes the freshly converted config, merges the ACME state left by the
/// previous run, and builds the memory-backed manager.
fn config_manager_for(
    rule_cache: &Arc<RuleCache>,
    config: PingapConfig,
) -> anyhow::Result<(Arc<ConfigManager>, PingapConfig)> {
    let toml_str = toml::to_string_pretty(&config).map_err(|e| {
        anyhow::anyhow!("failed to serialize proxy config: {}", e)
    })?;
    let acme_state = acme_state_path(rule_cache);
    let toml_str = merge_config_state(
        &toml_str,
        &std::fs::read_to_string(&acme_state).unwrap_or_default(),
    );
    let config_manager =
        build_memory_config_manager(&toml_str, Some(acme_state)).map_err(
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
    Ok((config_manager, config))
}

/// Builds the site → certificate status map from the provider's current
/// entries. Certificates generated from site config are named
/// `{site_id}_cert`, which is how a status is attributed back to its site.
fn certificate_statuses(
    provider: &dyn CertificateProvider,
    now: i64,
) -> HashMap<String, varman_agent::cert_status::CertStatus> {
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
        // One certificate is listed under every domain it serves; the entries
        // agree, so the first one wins.
        statuses.entry(site_id.to_string()).or_insert(
            varman_agent::cert_status::CertStatus {
                status,
                expires_at: info.not_after,
            },
        );
    }
    statuses
}

/// Lets the agent report certificate state: the ACME task writes issued PEMs
/// into the provider, and without this the control plane keeps showing the
/// certificate as pending forever.
fn install_certificate_status_snapshot(provider: Arc<dyn CertificateProvider>) {
    varman_agent::cert_status::set_snapshot(Some(Arc::new(move || {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|elapsed| elapsed.as_secs() as i64)
            .unwrap_or_default();
        certificate_statuses(provider.as_ref(), now)
    })));
}

fn register_background_tasks(
    assembled: &mut crate::data_plane::AssembledPlane,
    background_tasks: pingap_core::BackgroundTaskService,
) {
    let name = background_tasks.name().to_string();
    assembled
        .server
        .add_service(background_service(&name, background_tasks));
}

fn start_proxy_servers(
    assembled: &mut crate::data_plane::AssembledPlane,
    config: &PingapConfig,
    acme_enabled: bool,
) -> anyhow::Result<()> {
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
    Ok(())
}

fn start_upstream_health_check(
    assembled: &mut crate::data_plane::AssembledPlane,
) {
    // This also drives periodic DNS discovery updates — without it, DNS-based
    // backends are never resolved and requests get 503.
    let task = new_upstream_health_check_task(
        assembled.providers.upstreams.clone(),
        Duration::from_secs(10),
        None,
    );
    let name = task.name().to_string();
    info!(
        service_name = %name,
        "data plane: registering upstream health check background service"
    );
    assembled
        .server
        .add_service(background_service(&name, task));
}

/// Access log entries are held until the response body completes so the log
/// can carry the response payload. A client that disconnects mid-body never
/// fires the end-of-stream callback, so stale entries are swept periodically.
fn spawn_pending_access_sweeper() {
    tokio::spawn(async move {
        loop {
            tokio::time::sleep(Duration::from_secs(5)).await;
            let swept = varman_plugin::sweep_stale_access(
                varman_plugin::PENDING_ACCESS_SWEEP_TTL,
            );
            if swept > 0 {
                info!(
                    count = swept,
                    "data plane: swept stale pending access entries"
                );
            }
        }
    });
}

/// Polls the rule cache config hash and re-inits the ArcSwap providers when
/// the control plane pushes new rules. The proxy reads these providers per
/// request, so no restart is needed.
fn spawn_rule_reload_watcher(
    rule_cache: Arc<RuleCache>,
    config_manager: Arc<ConfigManager>,
    providers: crate::data_plane::ProviderSet,
) {
    let watcher_cache = rule_cache;
    let watcher_config_manager = config_manager;
    let watcher_providers = providers;
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
            // Providers first: a config whose entries failed to rebuild must
            // never become current, or the next diff would be empty and the
            // failed entries would never be retried. On failure the previous
            // config stays current and the bookkeeping below is left alone,
            // so the next tick retries this document.
            let previous = watcher_config_manager.get_current_config();
            let outcome = apply_config(
                &previous,
                &config,
                &ApplyOptions::agent_data_plane(),
                None,
                &watcher_config_manager,
                &watcher_providers,
            )
            .await;
            if let ApplyOutcome::Failed(message) = &outcome {
                error!(
                    error = %message,
                    "data plane: config reload failed, keeping current config"
                );
            }
            if !commit_if_applied(
                &watcher_config_manager,
                config.clone(),
                &outcome,
            ) {
                continue;
            }
            publish_management_certificate(&config);
            last_hash = hash;
            last_management = management;
        }
    });
}

/// The ACME task fills the `__management` entry in place, without changing
/// the config hash, so the reload hooks never see the issued material.
/// Publish it on a timer instead; the installer compares fingerprints, so
/// repeating the same certificate is a no-op.
fn spawn_management_certificate_publisher(config_manager: Arc<ConfigManager>) {
    tokio::spawn(async move {
        loop {
            tokio::time::sleep(Duration::from_secs(15)).await;
            publish_management_certificate(
                &config_manager.get_current_config(),
            );
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;
    use pingap_certificate::{Certificate, TlsCertificate};

    fn site_certificate(site: &str, not_after: i64) -> TlsCertificate {
        TlsCertificate {
            name: Some(format!("{site}_cert")),
            info: Some(Certificate {
                not_after,
                ..Default::default()
            }),
            ..Default::default()
        }
    }

    #[test]
    fn certificate_status_uses_the_protocol_vocabulary() {
        let provider = crate::certificates::Provider::new();
        let now = 1_700_000_000;
        let mut certs: pingap_certificate::DynamicCertificates =
            ahash::AHashMap::new();
        certs.insert(
            "valid_cert".to_string(),
            Arc::new(site_certificate("valid", now + 30 * 24 * 3600)),
        );
        certs.insert(
            "soon_cert".to_string(),
            Arc::new(site_certificate("soon", now + 3600)),
        );
        certs.insert(
            "expired_cert".to_string(),
            Arc::new(site_certificate("expired", now - 1)),
        );
        // Not named `{site}_cert`: it is a management or uploaded
        // certificate, not a per-site certificate the heartbeat reports.
        certs.insert(
            "panel".to_string(),
            Arc::new(TlsCertificate {
                name: Some("panel".to_string()),
                info: Some(Certificate {
                    not_after: now + 3600,
                    ..Default::default()
                }),
                ..Default::default()
            }),
        );
        provider.store(certs);

        let statuses = certificate_statuses(&provider, now);
        assert_eq!(3, statuses.len());
        assert_eq!("valid", statuses["valid"].status);
        assert_eq!("expiring_soon", statuses["soon"].status);
        assert_eq!("expired", statuses["expired"].status);
        assert_eq!(now + 3600, statuses["soon"].expires_at);
    }

    #[test]
    fn certificate_status_skips_entries_without_expiry_or_info() {
        let provider = crate::certificates::Provider::new();
        let mut certs: pingap_certificate::DynamicCertificates =
            ahash::AHashMap::new();
        certs.insert(
            "unknown_cert".to_string(),
            Arc::new(TlsCertificate {
                name: Some("unknown_cert".to_string()),
                ..Default::default()
            }),
        );
        certs.insert(
            "zero_cert".to_string(),
            Arc::new(site_certificate("zero", 0)),
        );
        provider.store(certs);

        assert!(certificate_statuses(&provider, 1_700_000_000).is_empty());
    }
}
