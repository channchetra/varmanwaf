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

//! The single assembly owner for the proxy data plane.
//!
//! Three entry points bring the same Pingora data plane up: the
//! file-configured daemon (`run()`), its `--cp` admin-only node, and
//! the agent-hosted plane (`src/varman/data_plane.rs`). They differ in what
//! they do *around* the plane, never in how the plane itself is wired, so the
//! wiring lives here and each root adds only its own pieces afterwards.
//!
//! Kept out of the assembler on purpose, because the roots genuinely differ:
//!
//! * proxy listener configs (`parse_from_conf`) - `run` mutates the list to
//!   add the admin server and the port-80 ACME listener, while the `--cp`
//!   node builds its only listener from `parse_admin_plugin` instead;
//! * per-listener access loggers and OTLP/pyroscope/sentry services - only
//!   `run` has them;
//! * registering the shared background-task service - each root adds its own
//!   tasks and registers it at its historical point in start-up;
//! * the Prometheus upstream-provider hook - only `run` has ever set it, and
//!   the setter is a process-wide `OnceLock`.

use std::sync::Arc;
use std::time::Duration;
use tracing::{error, info};

use bytes::BytesMut;
use pingap_acme::new_lets_encrypt_service;
use pingap_cache::new_storage_clear_service;
use pingap_certificate::CertificateProvider;
use pingap_certificate::{
    new_certificate_validity_service,
    new_self_signed_certificate_validity_service,
};
use pingap_config::{ConfigManager, PingapConfig, PluginConf};
use pingap_core::{BackgroundTaskService, NotificationSender};
use pingap_performance::new_performance_metrics_log_service;
use pingap_proxy::AppContext;
use pingora::server;
use pingora::server::configuration::Opt;
use pingora::services::ServiceHandle;
use tokio::sync::mpsc::Sender;

use crate::provider::ProviderUpdate;
use crate::webhook::get_webhook_sender;

/// Interval of the shared background-task service.
const BACKGROUND_TASK_INTERVAL: Duration = Duration::from_secs(60);
/// Grace period before its first pass, so start-up work is not contended.
const BACKGROUND_TASK_INITIAL_DELAY: Duration = Duration::from_secs(3);

const DEFAULT_UPGRADE_SOCK: &str = "/tmp/pingap_upgrade.sock";

/// pingora's upgrade socket for this deployment: `basic.upgrade_sock`, or the
/// path pingap has always defaulted to.
/// Logs the outcome both data-plane roots used to print themselves.
pub(crate) fn report_provider_updates(
    plugins: &ProviderUpdate,
    certificates: &ProviderUpdate,
) {
    if !plugins.updated.is_empty() {
        info!(plugins = plugins.updated.join(","), "plugins initialized");
    }
    if !plugins.errors.is_empty() {
        error!(error = plugins.errors.as_str(), "plugin init errors");
    }
    if !certificates.updated.is_empty() {
        info!(
            certs = certificates.updated.join(","),
            "certificates loaded"
        );
    }
    if !certificates.errors.is_empty() {
        error!(
            error = certificates.errors.as_str(),
            "certificate parse errors"
        );
    }
}

/// Registers the shared ACME task on the plane's background service.
pub(crate) fn add_acme_task(
    tasks: &mut BackgroundTaskService,
    config_manager: Arc<ConfigManager>,
    provider: Arc<dyn CertificateProvider>,
    sender: Option<Arc<NotificationSender>>,
) {
    tasks.add_task(
        "lets_encrypt",
        new_lets_encrypt_service(config_manager, provider, sender),
    );
}

/// The upgrade socket for a plane, defaulting to the historical path.
pub(crate) fn upgrade_sock_path(
    basic_conf: &pingap_config::BasicConf,
) -> String {
    basic_conf
        .upgrade_sock
        .clone()
        .unwrap_or_else(|| DEFAULT_UPGRADE_SOCK.to_string())
}

/// The pingora server configuration derived from `basic`, shared by every
/// entry point.
pub(crate) fn new_server_config_from(
    daemon: bool,
    threads: Option<usize>,
    conf: &PingapConfig,
) -> server::configuration::ServerConf {
    let basic_conf = &conf.basic;
    let mut server_conf = server::configuration::ServerConf {
        pid_file: basic_conf.get_pid_file(),
        upgrade_sock: upgrade_sock_path(basic_conf),
        user: basic_conf.user.clone(),
        group: basic_conf.group.clone(),
        daemon,
        // Pingora only redirects the daemon's stderr when this is set;
        // otherwise it keeps the inherited one, which is `/dev/null` for a
        // process started by an auto restart.
        error_log: basic_conf.error_log.clone(),
        ..Default::default()
    };
    if let Some(value) = basic_conf.grace_period {
        server_conf.grace_period_seconds = Some(value.as_secs());
    }
    if let Some(value) = basic_conf.graceful_shutdown_timeout {
        server_conf.graceful_shutdown_timeout_seconds = Some(value.as_secs());
    }
    if let Some(upstream_keepalive_pool_size) =
        basic_conf.upstream_keepalive_pool_size
    {
        server_conf.upstream_keepalive_pool_size = upstream_keepalive_pool_size;
    }
    if let Some(threads) = basic_conf.threads {
        server_conf.threads = threads.max(1);
    }
    if let Some(threads) = threads {
        server_conf.threads = threads.max(1);
    }
    if let Some(max_blocking_threads) = basic_conf.max_blocking_threads {
        server_conf.max_blocking_threads = Some(max_blocking_threads);
    }
    if let Some(work_stealing) = basic_conf.work_stealing {
        server_conf.work_stealing = work_stealing
    }
    if let Some(listener_tasks_per_fd) = basic_conf.listener_tasks_per_fd {
        server_conf.listener_tasks_per_fd = listener_tasks_per_fd;
    }
    // Downstream TLS handshake offload. pingora reads the pair back from this
    // conf when each TLS listener calls
    // `TlsSettings::set_offload_threadpool_from_server_conf`, so copying the
    // values is all that is needed here.
    server_conf.downstream_tls_offload_threadpools =
        basic_conf.downstream_tls_offload_threadpools;
    server_conf.downstream_tls_offload_thread_per_pool =
        basic_conf.downstream_tls_offload_thread_per_pool;
    // Upstream connect offload needs nothing on pingap's side beyond this:
    // pingora-proxy builds its connector with
    // `ConnectorOptions::from_server_conf`, which reads the pair back.
    server_conf.upstream_connect_offload_threadpools =
        basic_conf.upstream_connect_offload_threadpools;
    server_conf.upstream_connect_offload_thread_per_pool =
        basic_conf.upstream_connect_offload_thread_per_pool;
    if let Some(dir) = &basic_conf.working_directory {
        server_conf.working_directory = Some(std::path::PathBuf::from(dir));
    }
    // pingora's own `daemon_wait_for_ready` stays off on purpose. Its parent
    // side waits on a tokio SIGUSR1 listener, and tokio's signal wake-up pipe
    // is process-global: pingap has already created it before the fork (the
    // config is loaded on a tokio runtime), so the daemon inherits the same
    // pipe, its runtimes drain the wake-up, and the parent never sees the
    // signal - it waits the full timeout and exits 1 while the daemon runs
    // fine. The readiness hand-over pingap needs lives in
    // `process::restart_now` instead, over a unix socket of its own.

    server_conf
}

/// What an entry point can vary about the assembled plane.
///
/// Everything else - provider init order, the pingora constructor, the shared
/// background loops - is fixed by [`assemble`].
pub struct DataPlaneOptions {
    /// `-d`: run pingora in the background.
    daemon: bool,
    /// `-u`: hot upgrade from a running instance. Only the file-configured
    /// daemon asks for it.
    upgrade: bool,
    /// `--threads`, overriding `basic.threads` for every runtime.
    threads: Option<usize>,
    /// Plugins built in addition to `config.plugins`. The `--cp` node and
    /// the file-configured daemon pass the admin listener parsed from
    /// `--admin` here; the agent-hosted plane has none.
    admin_plugin: Option<(String, PluginConf)>,
    /// Name of the shared background-task service. The file-configured daemon
    /// and the agent-hosted plane have always reported different names and
    /// both are kept. `None` for the `--cp` admin node, which runs no
    /// data-plane loop.
    background_task_service_name: Option<&'static str>,
    /// The `--cp` control-panel node: it serves the admin plugin only and
    /// loads no configuration, so it keeps pingora's built-in server
    /// configuration (its own pid file and upgrade socket) instead of one
    /// derived from `basic`.
    admin_only: bool,
}

impl DataPlaneOptions {
    /// The normal proxy plane: listeners, providers and the background
    /// loops.
    pub fn data_plane(
        daemon: bool,
        upgrade: bool,
        threads: Option<usize>,
        admin_plugin: Option<crate::provider::AdminPluginEntry>,
        background_task_service_name: &'static str,
    ) -> Self {
        Self {
            daemon,
            upgrade,
            threads,
            admin_plugin,
            background_task_service_name: Some(background_task_service_name),
            admin_only: false,
        }
    }

    /// The `--cp` control-panel node: the admin plugin only, no data-plane
    /// loops, and pingora's built-in server configuration.
    pub fn admin_only(
        daemon: bool,
        threads: Option<usize>,
        admin_plugin: Option<crate::provider::AdminPluginEntry>,
    ) -> Self {
        Self {
            daemon,
            upgrade: false,
            threads,
            admin_plugin,
            background_task_service_name: None,
            admin_only: true,
        }
    }
}

/// The assembled plane, plus the pieces each root still has to place itself.
/// The five registries one plane owns, so every listener context and every
/// background task of this plane uses the same instances instead of
/// re-resolving process globals.
#[derive(Clone)]
pub struct ProviderSet {
    pub upstreams: Arc<crate::upstreams::Provider>,
    pub locations: Arc<crate::locations::Provider>,
    pub server_locations: Arc<crate::server_locations::Provider>,
    pub plugins: Arc<crate::plugin::Provider>,
    pub certificates: Arc<crate::certificates::Provider>,
}

impl ProviderSet {
    /// Five empty registries that share no state with any other set.
    pub fn new() -> Self {
        Self {
            upstreams: Arc::new(crate::upstreams::Provider::new()),
            locations: Arc::new(crate::locations::Provider::new()),
            server_locations: Arc::new(crate::server_locations::Provider::new()),
            plugins: Arc::new(crate::plugin::Provider::new()),
            certificates: Arc::new(crate::certificates::Provider::new()),
        }
    }
}

impl Default for ProviderSet {
    fn default() -> Self {
        Self::new()
    }
}

pub struct AssembledPlane {
    /// pingora's server. The caller owns its lifetime: `run` + webhook flush,
    /// `run_forever`, or a dedicated thread for the agent-hosted plane.
    pub server: server::Server,
    /// Bootstrap service handle. Every listener has to depend on it: a
    /// listening service builds its sockets from inherited fds when it
    /// starts, and would bind fresh ones if it ran before bootstrap.
    pub bootstrap: ServiceHandle,
    /// The caller's config manager, the instance [`assemble`] was handed.
    pub config_manager: Arc<ConfigManager>,
    /// The providers this assembly initialised.
    pub providers: ProviderSet,
    /// The four common loops, when the caller runs a data plane: certificate
    /// validity, self-signed rotation, performance metrics and storage clear.
    /// The caller adds its own tasks (ACME, Prometheus push, log handling)
    /// and registers the service at its historical point in start-up.
    pub background_tasks: Option<BackgroundTaskService>,
    /// Plugin rebuild results, for the caller to log in its own words.
    pub plugin_update: ProviderUpdate,
    /// Certificate load results, for the caller to log in its own words.
    pub certificate_update: ProviderUpdate,
}

impl AssembledPlane {
    /// Adds one listener and makes it wait for the bootstrap service.
    ///
    /// Every listener must depend on bootstrap: without it a restarted
    /// process binds fresh sockets instead of building them from the
    /// inherited fds, and the zero-downtime hand-over fails.
    pub(crate) fn add_listener(
        &mut self,
        services: pingap_proxy::ServerServices,
    ) {
        self.server
            .add_service(services.lb)
            .add_dependency(&self.bootstrap);
    }

    /// Builds the per-listener [`AppContext`] on the shared providers.
    ///
    /// `logger` is the listener's access logger; only the file-configured
    /// daemon builds one, from the listener's `access_log` directive.
    pub fn app_context(&self, logger: Option<Sender<BytesMut>>) -> AppContext {
        AppContext {
            server_locations_provider: self.providers.server_locations.clone(),
            location_provider: self.providers.locations.clone(),
            upstream_provider: self.providers.upstreams.clone(),
            plugin_provider: self.providers.plugins.clone(),
            certificate_provider: self.providers.certificates.clone(),
            config_manager: self.config_manager.clone(),
            logger,
        }
    }
}

/// Initialises the shared providers, builds the pingora server and registers
/// the common background loops.
///
/// The provider order is the one every entry point has always used: upstreams
/// (locations resolve them by name), locations, server locations, then the
/// plugins they reference. The server is built with
/// `Server::new_with_opt_and_conf`, never `Server::new` followed by assigning
/// `configuration`: the constructor snapshots the configuration into its
/// private bootstrap, and that snapshot - not `Server::configuration` - is
/// what the receiving half of a hot upgrade reads `upgrade_sock` from.
///
/// `config_manager` is the caller's already initialised manager. It is used
/// for provider construction and handed back in the result; assembly never
/// reads the process-global slot, so it has no hidden initialisation order.
pub fn assemble(
    config: &PingapConfig,
    config_manager: Arc<ConfigManager>,
    options: DataPlaneOptions,
) -> anyhow::Result<AssembledPlane> {
    // The plane owns its registries: this set is the only place they live, so
    // two assemblies (or a test) never share upstream, location, plugin or
    // certificate state. The order is the one every entry point has always
    // used: upstreams (locations resolve them by name), locations, the server
    // index built from those locations, then the plugins they reference and
    // the certificates.
    let providers = ProviderSet::new();
    providers
        .upstreams
        .replace_upstreams(&config.upstreams, Some(get_webhook_sender()))
        .map_err(|e| anyhow::anyhow!("failed to init upstreams: {e}"))?;
    providers
        .locations
        .replace_locations(&config.locations)
        .map_err(|e| anyhow::anyhow!("failed to init locations: {e}"))?;
    providers
        .server_locations
        .replace_server_locations(
            providers.locations.as_ref(),
            &config.servers,
            &config.locations,
        )
        .map_err(|e| anyhow::anyhow!("failed to init server locations: {e}"))?;

    let plugins = providers.plugins.replace_plugins(
        &config.plugins,
        options.admin_plugin,
        config_manager.clone(),
        &providers,
    );

    // Nothing configured (the `--cp` node) leaves the provider untouched
    // instead of replacing it with an empty one.
    let certificates = if config.certificates.is_empty() {
        ProviderUpdate::default()
    } else {
        providers
            .certificates
            .replace_certificates(&config.certificates)
            .map_err(|e| anyhow::anyhow!("failed to init certificates: {e}"))?
    };

    let opt = Opt {
        upgrade: options.upgrade,
        daemon: options.daemon,
        ..Default::default()
    };
    let server_conf = if options.admin_only {
        // The admin node never loads a configuration, so it has nothing to
        // derive the paths from and keeps what `Server::new` used to build:
        // pingora's built-in defaults. Deriving them from an empty `basic`
        // instead would move a daemonized `--cp` node onto the same pid file
        // as the file-configured daemon.
        server::configuration::ServerConf::new_with_opt_override(&opt)
            .expect("pingora's built-in server configuration always parses")
    } else {
        new_server_config_from(options.daemon, options.threads, config)
    };
    let mut server =
        server::Server::new_with_opt_and_conf(Some(opt), server_conf);
    let bootstrap = server.bootstrap_as_a_service();

    let background_tasks = options.background_task_service_name.map(|name| {
        let mut tasks = BackgroundTaskService::new(
            name,
            BACKGROUND_TASK_INTERVAL,
            vec![
                (
                    "validity_checker".to_string(),
                    new_certificate_validity_service(
                        providers.certificates.clone(),
                        Some(get_webhook_sender()),
                    ),
                ),
                (
                    "self_signed_certificate_stale".to_string(),
                    new_self_signed_certificate_validity_service(),
                ),
                (
                    "performance_metrics".to_string(),
                    new_performance_metrics_log_service(
                        providers.locations.clone(),
                        providers.upstreams.clone(),
                    ),
                ),
            ],
        );
        tasks.set_immediately(true);
        tasks.set_initial_delay(Some(BACKGROUND_TASK_INITIAL_DELAY));
        if let Some(task) = new_storage_clear_service() {
            tasks.add_task("storage_clear", task);
        }
        tasks
    });

    Ok(AssembledPlane {
        server,
        bootstrap,
        config_manager,
        providers,
        background_tasks,
        plugin_update: plugins,
        certificate_update: certificates,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use pingap_config::BasicConf;

    /// A local manager: `assemble` takes the instance as a parameter, so the
    /// tests no longer have to install anything process-wide first.
    fn new_config_manager() -> Arc<ConfigManager> {
        crate::config_manager::build_memory_config_manager("[basic]\n", None)
            .expect("test manager")
    }

    #[test]
    fn upgrade_socket_falls_back_to_the_historical_path() {
        let basic = BasicConf::default();
        assert_eq!(DEFAULT_UPGRADE_SOCK, upgrade_sock_path(&basic));

        let basic = BasicConf {
            upgrade_sock: Some("/run/custom.sock".to_string()),
            ..Default::default()
        };
        assert_eq!("/run/custom.sock", upgrade_sock_path(&basic));
    }

    /// Two independently constructed sets must not share a registry: the
    /// provider state is per-plane now, never process-wide.
    #[test]
    fn independently_constructed_provider_sets_do_not_share_state() {
        use pingap_config::LocationConf;
        use pingap_location::LocationProvider;
        use std::collections::HashMap;

        let first = ProviderSet::new();
        let second = ProviderSet::new();
        first
            .locations
            .replace_locations(&HashMap::from([(
                "provider-set-local".to_string(),
                LocationConf {
                    path: Some("/local".to_string()),
                    ..Default::default()
                },
            )]))
            .expect("a valid location path");

        assert!(first.locations.get("provider-set-local").is_some());
        assert!(
            second.locations.get("provider-set-local").is_none(),
            "the second set must not see the first set's locations"
        );
    }

    /// The daemon and thread overrides have to reach pingora's configuration,
    /// and a data plane gets the shared background loops.
    #[test]
    fn data_plane_assembly_applies_the_cli_overrides() {
        let config_manager = new_config_manager();
        let assembled = assemble(
            &PingapConfig::default(),
            config_manager.clone(),
            DataPlaneOptions::data_plane(
                true,
                false,
                Some(3),
                None,
                "test_background_service",
            ),
        )
        .expect("assembly must succeed on the default config");

        assert!(assembled.server.configuration.daemon);
        assert_eq!(3, assembled.server.configuration.threads);
        assert!(assembled.background_tasks.is_some());
        // The manager that was passed in is the one handed back and the one
        // every listener context is built on - not a process-global lookup.
        assert!(Arc::ptr_eq(&config_manager, &assembled.config_manager));
        let ctx = assembled.app_context(None);
        assert!(Arc::ptr_eq(&config_manager, &ctx.config_manager));
        assert!(ctx.logger.is_none(), "no access logger without a directive");
    }

    /// The `--cp` node serves the admin plugin only: it keeps pingora's
    /// built-in server configuration (its own pid file) and starts none of
    /// the data-plane loops.
    #[test]
    fn admin_only_assembly_keeps_pingora_defaults() {
        let config_manager = new_config_manager();
        let assembled = assemble(
            &PingapConfig::default(),
            config_manager,
            DataPlaneOptions::admin_only(false, None, None),
        )
        .expect("assembly must succeed on the default config");

        assert!(assembled.background_tasks.is_none());
        assert_eq!(
            server::configuration::ServerConf::default().pid_file,
            assembled.server.configuration.pid_file,
            "the admin node must not take over the data plane's pid file"
        );
    }
}
