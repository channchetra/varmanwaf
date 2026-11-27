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

#[cfg(all(feature = "openssl", feature = "tls-rustls"))]
compile_error!(
    "the `openssl` and `tls-rustls` features are mutually exclusive; build rustls with `--no-default-features --features tls-rustls[,full]`"
);
#[cfg(not(any(feature = "openssl", feature = "tls-rustls")))]
compile_error!(
    "pingap needs a TLS backend: enable `openssl` (default) or build with `--no-default-features --features tls-rustls`"
);

use crate::config_manager::{
    get_config_manager, try_init_config_manager, try_init_memory_config_manager,
};
use crate::upstreams::new_upstream_provider;
use bytes::BytesMut;
use clap::Parser;
use crossbeam_channel::Receiver;
use pingap_acme::new_lets_encrypt_service;
use pingap_certificate::{
    install_default_crypto_provider, validate_servers_tls_for_backend,
};
use pingap_config::PingapConfig;
use pingap_config::{ConfigManager, ETCD_PROTOCOL};
use pingap_logger::parse_access_log_directive;
use pingap_logger::{
    AsyncLoggerTask, LogCompressParams, new_async_logger,
    new_log_compress_service,
};
#[cfg(feature = "full")]
use pingap_otel::TracerService;
#[cfg(feature = "tracing")]
use pingap_performance::set_metrics_upstream_provider;
use pingap_plugin::get_plugin_factory;
use pingap_proxy::{Server, ServerConf, parse_from_conf};
use pingap_upstream::new_upstream_health_check_task;
use pingora::server;
use pingora::services::background::background_service;
use process::{
    init_start_time, new_auto_restart_service, new_observer_service,
};
use std::error::Error;
use std::ffi::OsString;
use std::future::Future;
use std::str::FromStr;
use std::sync::Arc;
use std::time::Duration;
use sysinfo::System;

use tracing::{error, info, warn};

mod certificates;
mod cli;
mod config_apply;
mod config_file;
mod config_manager;
mod data_plane;
mod locations;
mod maintenance;
mod plugin;
mod process;
mod quick_start;
mod server_locations;
mod upstreams;
mod varman;
mod webhook;

// Avoid musl's default allocator due to lackluster performance
// https://nickb.dev/blog/default-musl-allocator-considered-harmful-to-performance
#[cfg(target_env = "musl")]
#[global_allocator]
static GLOBAL: mimalloc::MiMalloc = mimalloc::MiMalloc;

static TEMPLATE_CONFIG: &str = r###"
[basic]
log_level = "INFO"
name = "pingap"
pid_file = "/run/pingap.pid"

[locations.httpLocation]
path = "/"
upstream = "httpUpstream"

[servers.httpServer]
access_log = "combined"
addr = "0.0.0.0:80"
locations = ["httpLocation"]

[upstreams.httpUpstream]
addrs = ["127.0.0.1:5000"]
"###;

use std::sync::LazyLock;

static LOG_TARGET: &str = "main";

/// The commit this binary was built from, or "unknown" when the tree had no
/// git metadata (a source export or a crates.io tarball; see build.rs).
pub(crate) fn git_hash() -> &'static str {
    match env!("VERGEN_GIT_SHA") {
        "VERGEN_IDEMPOTENT_OUTPUT" => "unknown",
        sha => sha,
    }
}

static LONG_VERSION: LazyLock<String> = LazyLock::new(|| {
    format!(
        "{} ({}, tls={})",
        env!("CARGO_PKG_VERSION"),
        git_hash(),
        pingap_certificate::TLS_BACKEND,
    )
});

/// The version banner: crate version, build commit and TLS backend. Shared
/// by `--version` and the VarmanWAF-mode CLI, which answers the flag itself.
pub(crate) fn version_banner() -> &'static str {
    &LONG_VERSION
}

/// Command line arguments structure for the pingap.
/// A reverse proxy like nginx.
#[derive(Parser, Debug, Default)]
#[command(
    name = env!("CARGO_BIN_NAME"),
    author,
    version,
    about,
    long_version = LONG_VERSION.as_str(),
    long_about = None
)]
struct Args {
    /// The config file or directory path
    #[arg(short, long, required_unless_present = "upstream")]
    conf: Option<String>,
    /// Upstream addresses ("host:port", comma separated). Starts a proxy
    /// straight from the command line, without a config file
    #[arg(long, conflicts_with = "conf")]
    upstream: Option<String>,
    /// Domains served by the command line proxy (comma separated)
    #[arg(long, requires = "upstream", conflicts_with = "conf")]
    domain: Option<String>,
    /// TLS certificate for the command line proxy: a PEM file, or a directory
    /// containing one (fullchain.pem, cert.pem, tls.crt, ...)
    #[arg(long, requires = "upstream", conflicts_with = "conf")]
    cert: Option<String>,
    /// TLS private key for the command line proxy, defaults to the key found
    /// next to the certificate
    #[arg(long, requires = "cert", conflicts_with = "conf")]
    key: Option<String>,
    /// Listen address of the command line proxy, defaults to 0.0.0.0:443 with
    /// a certificate and 0.0.0.0:80 without
    #[arg(long, requires = "upstream", conflicts_with = "conf")]
    addr: Option<String>,
    /// Run server in background mode
    #[arg(short, long)]
    daemon: bool,
    /// Enable hot upgrade from a running old server instance
    #[arg(short, long)]
    upgrade: bool,
    /// Validate configuration without starting the server
    #[arg(short, long)]
    test: bool,
    /// Custom log file location
    #[arg(long)]
    log: Option<String>,
    /// Admin server address for management interface
    #[arg(long)]
    admin: Option<String>,
    /// Enable control panel mode (admin-only, no service running)
    #[arg(long, conflicts_with = "upstream")]
    cp: bool,
    /// Enable automatic server restart capability
    #[arg(short, long)]
    autorestart: bool,
    /// Enable automatic config reload capability
    #[arg(long)]
    autoreload: bool,
    /// Sync configuration to specified storage location
    #[arg(long)]
    sync: Option<String>,
    /// Output template configuration
    #[arg(long)]
    template: bool,
    /// Convert configuration to HCL format and output
    #[arg(long)]
    to_hcl: bool,
    /// Convert configuration to KDL format and output
    #[arg(long)]
    to_kdl: bool,
    /// Default threads for each server
    #[arg(long)]
    threads: Option<usize>,
}

async fn migrate_config_layout(config_manager: &ConfigManager) {
    match config_manager.migrate_layout().await {
        Ok(retired) => {
            for item in retired {
                // use println because log is not init during normal startup
                println!("config layout migrated: {item}");
            }
        },
        Err(e) => {
            println!("config layout migration fail, {e}");
        },
    }
}

/// Run one startup task on its own thread and runtime, handing the result
/// back synchronously.
///
/// Startup runs before the logger exists, so failures are printed. The
/// runtime is created inside the child thread, which keeps the bridge safe
/// across the daemon fork.
fn run_startup<T, F, Fut, E>(task: F, runtime_error: E) -> Receiver<T>
where
    T: Send + 'static,
    F: FnOnce() -> Fut + Send + 'static,
    Fut: Future<Output = T> + Send + 'static,
    E: FnOnce(String) -> T + Send + 'static,
{
    let (s, r) = crossbeam_channel::bounded(0);
    std::thread::spawn(move || {
        let result = match tokio::runtime::Runtime::new() {
            Ok(rt) => rt.block_on(task()),
            Err(e) => runtime_error(e.to_string()),
        };
        if let Err(e) = s.send(result) {
            // use println because log is not init
            println!("sender fail, {e}");
        }
    });
    r
}

fn get_config(
    config_manager: Arc<ConfigManager>,
) -> Receiver<Result<PingapConfig, pingap_config::Error>> {
    run_startup(
        move || async move {
            // Before the first read, and before anything can write: fold any
            // layout left over from a previous `ConfigMode` into the current
            // one. Failing here must not be fatal - a read-only config
            // directory holding a single old layout loads perfectly well, and
            // used to.
            migrate_config_layout(&config_manager).await;
            match config_manager.load_all().await {
                Ok(config) => config.to_pingap_config(true),
                Err(e) => Err(e),
            }
        },
        |message| Err(pingap_config::Error::Invalid { message }),
    )
}

fn sync_config(
    config_manager: Arc<ConfigManager>,
    path: String,
) -> Receiver<Result<(), pingap_config::Error>> {
    run_startup(
        move || async move {
            pingap_config::sync_to_path(config_manager, &path).await
        },
        |message| Err(pingap_config::Error::Invalid { message }),
    )
}

fn new_access_logger(
    path: &str,
) -> Receiver<
    Result<
        (tokio::sync::mpsc::Sender<BytesMut>, AsyncLoggerTask),
        pingap_core::Error,
    >,
> {
    let file = path.to_string();
    run_startup(
        move || async move { new_async_logger(&file).await },
        |message| Err(pingap_core::Error::Invalid { message }),
    )
}

fn run_admin_node(args: Args) -> Result<(), Box<dyn Error>> {
    pingap_logger::logger_try_init(pingap_logger::LoggerParams {
        ..Default::default()
    })?;
    // The admin plugin's constructor calls `get_config_manager()`, so the
    // manager must exist before any plugin is built; otherwise the plugin is
    // missing and the listener answers every request with 404.
    let config_manager =
        try_init_config_manager(&args.conf.clone().unwrap_or_default())?;
    tokio::runtime::Runtime::new()?
        .block_on(migrate_config_layout(&config_manager));

    let (admin_server_conf, admin_name, admin_plugin_conf) =
        plugin::parse_admin_plugin(&args.admin.unwrap_or_default())?;
    // No config is loaded in this mode: the plane is assembled from the
    // defaults, with the admin plugin as its only extra. `background_tasks`
    // is `None` because the control-panel node serves no data plane and has
    // never run the proxy loops.
    let mut assembled = data_plane::assemble(
        &PingapConfig::default(),
        config_manager,
        data_plane::DataPlaneOptions {
            daemon: args.daemon,
            upgrade: false,
            threads: None,
            admin_plugin: Some((admin_name, admin_plugin_conf)),
            background_tasks: None,
            admin_only: true,
        },
    )?;
    let error = assembled.plugins.errors.as_str();
    if !error.is_empty() {
        error!(error, "init plugins fail",);
    }
    let ps = Server::new(&admin_server_conf, assembled.app_context(None))?;
    let services = ps.run(assembled.server.configuration.clone())?;
    // See run(): bootstrap as a service, with the listener depending on it so
    // it waits for the inherited sockets instead of binding fresh ones.
    assembled
        .server
        .add_service(services.lb)
        .add_dependency(&assembled.bootstrap);
    info!(target: LOG_TARGET, "Admin node server is running");

    // TODO not process exit until pingora supports
    assembled.server.run_forever();
}

fn parse_arguments() -> Args {
    let get_from_env = |key: &str| -> String {
        let k = format!("PINGAP_{key}").to_uppercase();
        if let Ok(value) = std::env::var(k) {
            value
        } else {
            "".to_string()
        }
    };
    let mut arr = vec![];
    let mut exist_config_argument = false;
    for arg in std::env::args_os() {
        // `--upstream` builds the config from the command line, it conflicts
        // with `-c`, so the PINGAP_CONF fallback must not be applied either.
        for item in ["-c", "--conf", "--upstream"] {
            if arg == item
                || arg.to_string_lossy().starts_with(&format!("{item}="))
            {
                exist_config_argument = true;
            }
        }
        arr.push(arg);
    }
    if !exist_config_argument {
        let conf = get_from_env("conf");
        if !conf.is_empty() {
            arr.push(format!("-c={conf}").into());
        }
    }

    if arr.contains(&OsString::from_str("--template").unwrap_or_default()) {
        return Args {
            template: true,
            ..Default::default()
        };
    }
    let mut args = Args::parse_from(arr);

    if !args.daemon && !get_from_env("daemon").is_empty() {
        args.daemon = true;
    }
    if !args.upgrade && !get_from_env("upgrade").is_empty() {
        args.upgrade = true;
    }
    if args.log.is_none() {
        let log = get_from_env("log");
        if !log.is_empty() {
            args.log = Some(log);
        }
    }
    let mut addr = get_from_env("admin_addr");
    if args.admin.is_none() && !addr.is_empty() {
        let user = get_from_env("admin_user");
        let password = get_from_env("admin_password");
        if !user.is_empty() && !password.is_empty() {
            let data = format!("{user}:{password}");
            addr = format!("{}@{addr}", pingap_util::base64_encode(&data));
        }
        args.admin = Some(addr)
    }
    if !args.cp && !get_from_env("cp").is_empty() {
        args.cp = true;
    }

    if args.log.is_none() {
        let log = get_from_env("log");
        if !log.is_empty() {
            args.log = Some(log);
        }
    }

    if !args.autorestart && !get_from_env("autorestart").is_empty() {
        args.autorestart = true;
    }
    if !args.autoreload && !get_from_env("autoreload").is_empty() {
        args.autoreload = true;
    }

    args
}

/// Dry-runs each configured plugin through the factory so `--test` reports bad
/// plugin configs, which `PingapConfig::validate` cannot check (the factory
/// lives in a higher layer). A category this build does not know — e.g. a
/// feature-gated plugin that was compiled out — is only warned about, matching
/// runtime behaviour; any other construction error is treated as fatal.
fn validate_plugins(config: &PingapConfig) -> Result<(), Box<dyn Error>> {
    let factory = pingap_plugin::get_plugin_factory();
    for (name, conf) in config.plugins.iter() {
        match factory.create(conf) {
            Ok(_) => {},
            Err(pingap_plugin::Error::NotFound { category }) => {
                warn!(
                    target: LOG_TARGET,
                    name = %name,
                    category = %category,
                    "plugin category is unavailable in this build, skipping validation"
                );
            },
            Err(e) => {
                return Err(format!("plugin \"{name}\" is invalid: {e}").into());
            },
        }
    }
    Ok(())
}

fn run() -> Result<(), Box<dyn Error>> {
    let args = parse_arguments();

    // Handle template output request
    if args.template {
        println!("{TEMPLATE_CONFIG}");
        return Ok(());
    }

    // `--cp` is the admin-only control-panel mode; without an admin
    // listener it would silently run a full proxy instead.
    if args.cp && args.admin.is_none() {
        return Err("--cp requires --admin user:pass@host:port[/prefix]".into());
    }

    // Set up admin node if specified
    if args.cp {
        return run_admin_node(args);
    }

    let mut sys = System::new();
    sys.refresh_memory();
    pingap_cache::update_available_memory(sys.available_memory());

    // Initialize configuration. With `--upstream` the whole config is built
    // from the command line and kept in memory, so no config file is needed.
    let config_manager = if let Some(upstream) = &args.upstream {
        let mut config =
            quick_start::build_config(&quick_start::QuickStartParams {
                domains: args.domain.clone(),
                upstreams: upstream.clone(),
                cert: args.cert.clone(),
                key: args.key.clone(),
                addr: args.addr.clone(),
            })?;
        // Without a certificate the generated config asks let's encrypt for
        // one, and that has to survive a restart: issuing is rate limited.
        let acme_state_path = quick_start::acme_state_path(&config);
        if let Some(path) = &acme_state_path {
            let restored =
                quick_start::restore_acme_certificate(&mut config, path);
            // The logger is not initialized yet, but the operator needs to know
            // where the certificate is kept.
            println!(
                "acme state: {} ({})",
                path.to_string_lossy(),
                if restored {
                    "certificate restored"
                } else {
                    "no certificate yet, one will be requested"
                }
            );
        }
        try_init_memory_config_manager(
            &toml::to_string_pretty(&config)?,
            acme_state_path,
        )?
    } else {
        try_init_config_manager(&args.conf.clone().unwrap_or_default())?
    };

    let r = get_config(get_config_manager()?);
    // A broken config is fatal on its own, but not with `--admin`: the admin
    // server has to come up so the configuration can be repaired through it.
    // Starting on an empty config is indistinguishable from a healthy server
    // that simply has nothing configured, though, so the reason has to be
    // reported. This runs before the logger exists, hence stderr.
    let empty_config =
        |e: Box<dyn Error>| -> Result<PingapConfig, Box<dyn Error>> {
            if args.admin.is_none() {
                return Err(e);
            }
            eprintln!(
                "load config fail, starting with an empty config so it can be fixed through the admin server: {e}"
            );
            Ok(PingapConfig::default())
        };
    let config = match r.recv() {
        Ok(Ok(conf)) => conf,
        Ok(Err(e)) => empty_config(e.into())?,
        Err(e) => empty_config(e.into())?,
    };

    config_manager.set_current_config(config.clone());

    // Convert config to HCL and output
    if args.to_hcl {
        let toml_str = toml::to_string_pretty(&config)?;
        let hcl_str = pingap_config::hcl::convert_toml_to_hcl(&toml_str)?;
        println!("{hcl_str}");
        return Ok(());
    }

    // Convert config to KDL and output
    if args.to_kdl {
        let toml_str = toml::to_string_pretty(&config)?;
        let kdl_str = pingap_config::kdl::convert_toml_to_kdl(&toml_str)?;
        println!("{kdl_str}");
        return Ok(());
    }

    let mut application_log_paths = vec![];

    // Initialize logging system
    let (reload_handle, log_path) =
        pingap_logger::logger_try_init(pingap_logger::LoggerParams {
            capacity: config
                .basic
                .log_buffered_size
                .unwrap_or_default()
                .as_u64(),
            log: args.log.clone().unwrap_or_default(),
            level: config.basic.log_level.clone().unwrap_or_default(),
            json: config.basic.log_format_json.unwrap_or_default(),
        })?;
    if let Some(log_path) = log_path {
        application_log_paths.push(log_path);
    }

    config.validate()?;
    // Reject per-server TLS version/cipher settings the active backend cannot
    // apply (rustls fixes 1.2/1.3 + default suites). Must run for `--test` too.
    validate_servers_tls_for_backend(&config.servers)?;
    // The process provider (ring) is installed in main; this is a no-op
    // safeguard for library use and for the OpenSSL backend.
    install_default_crypto_provider();

    // sync config to other storage
    if let Some(sync_path) = args.sync {
        let r = sync_config(config_manager.clone(), sync_path);
        r.recv()??;
        info!(target: LOG_TARGET, "sync config success");
        return Ok(());
    }

    let basic_conf = &config.basic;

    webhook::set_webhook_notification_sender(basic_conf);

    // return if test mode
    if args.test {
        validate_plugins(&config)?;
        info!(target: LOG_TARGET, "Validate config success");
        return Ok(());
    }

    let auto_restart_check_interval = basic_conf
        .auto_restart_check_interval
        .unwrap_or(Duration::from_secs(90));

    #[cfg(feature = "perf")]
    info!(target: LOG_TARGET, "Enable feature perf");

    if let Ok(exec_path) = std::env::current_exe() {
        let mut cmd = process::RestartProcessCommand {
            exec_path,
            ..Default::default()
        };
        if let Ok(env) = std::env::var("RUST_LOG") {
            cmd.log_level = env;
        }
        let mut new_args = vec!["-d".to_string(), "-u".to_string()];
        if let Some(conf) = &args.conf {
            let conf_path = if conf.starts_with(ETCD_PROTOCOL) {
                conf.clone()
            } else {
                pingap_util::resolve_path(conf)
            };
            new_args.push(format!("-c={conf_path}"));
        }
        // The command line proxy has no config file to point the new process
        // at, so pass the arguments it was built from instead.
        for (name, value) in [
            ("upstream", &args.upstream),
            ("domain", &args.domain),
            ("cert", &args.cert),
            ("key", &args.key),
            ("addr", &args.addr),
        ] {
            if let Some(value) = value {
                new_args.push(format!("--{name}={value}"));
            }
        }
        if let Some(log) = &args.log {
            new_args.push(format!("--log={log}"));
        }
        if let Some(admin) = &args.admin {
            new_args.push(format!("--admin={admin}"));
        }
        // Only on the command line: it overrides `basic.threads`, so leaving it
        // out silently drops the replacement process back to the configured
        // value, or to one thread.
        if let Some(threads) = args.threads {
            new_args.push(format!("--threads={threads}"));
        }
        // `--autoreload` is deliberately not forwarded: it is implied by
        // `--autorestart`, which the restarted process gets below.
        if args.autorestart {
            new_args.push("--autorestart".to_string());
        }
        // The readiness channel for the hand-over: a unix socket next to the
        // upgrade socket, plus the pid file both generations share so that a
        // daemon dying before it reports is noticed.
        cmd.ready_sock = std::path::PathBuf::from(format!(
            "{}.ready",
            data_plane::upgrade_sock_path(&config.basic)
        ));
        cmd.ready_timeout = config
            .basic
            .restart_ready_timeout
            .unwrap_or(process::DEFAULT_RESTART_READY_TIMEOUT);
        cmd.pid_file = config.basic.get_pid_file();
        cmd.args = new_args;
        process::set_restart_process_command(cmd);
    }

    // Parse the admin listener once. The same plugin is registered in the
    // provider (through `assemble`) and describes the listener added below, so
    // `--admin` is not parsed twice and nothing depends on start-up order.
    let (admin_server_conf, admin_plugin) = match args
        .admin
        .as_deref()
        .map(plugin::parse_admin_plugin)
        .transpose()?
    {
        Some((server_conf, name, conf)) => {
            (Some(server_conf), Some((name, conf)))
        },
        None => (None, None),
    };

    let mut assembled = data_plane::assemble(
        &config,
        config_manager.clone(),
        data_plane::DataPlaneOptions {
            daemon: args.daemon,
            upgrade: args.upgrade,
            threads: args.threads,
            admin_plugin: admin_plugin.clone(),
            background_tasks: Some("simple_background_service"),
            admin_only: false,
        },
    )?;
    // Wire upstreams into Prometheus scrapes for per-backend gauges. Only this
    // entry point has ever done it: the setter is a process-wide `OnceLock`,
    // and the agent-hosted plane leaves the gauges unwired.
    #[cfg(feature = "tracing")]
    set_metrics_upstream_provider(new_upstream_provider());

    {
        let server_conf = assembled.server.configuration.as_ref();
        info!(
            target: LOG_TARGET,
            tls_backend = pingap_certificate::TLS_BACKEND,
            pid_file = server_conf.pid_file,
            error_log = server_conf.error_log,
            upgrade_sock = server_conf.upgrade_sock,
            user = server_conf.user,
            group = server_conf.group,
            threads = server_conf.threads,
            work_stealing = server_conf.work_stealing,
            grace_period_seconds = server_conf.grace_period_seconds,
            graceful_shutdown_timeout_seconds =
                server_conf.graceful_shutdown_timeout_seconds,
            upstream_keepalive_pool_size = server_conf.upstream_keepalive_pool_size,
            listener_tasks_per_fd = server_conf.listener_tasks_per_fd,
            "server configuration"
        );
    }
    #[cfg(feature = "full")]
    {
        let sentry_dsn = basic_conf.sentry.clone().unwrap_or_default();
        if !sentry_dsn.is_empty() {
            match pingap_sentry::new_sentry_options(&sentry_dsn) {
                Ok(opts) => {
                    assembled.server.set_sentry_config(opts);
                },
                Err(e) => {
                    error!(error = e.to_string(), "sentry init fail");
                },
            }
        }
    }
    // Bootstrap runs as a service rather than up front so that a restart's
    // readiness report (next) can be ordered *before* it: bootstrap is where
    // the new process asks the old one for the listening sockets, and the
    // old one only hands them over after that report. `assemble` already
    // added it; every listener below declares a dependency on this handle: a
    // listening service builds its sockets from the inherited fds when it
    // starts, and would bind fresh ones if it ran first.
    // Started by `--autorestart`? Report readiness to the process that
    // spawned us right before bootstrap asks it for the listening sockets;
    // that report is what lets it send itself SIGQUIT.
    if let Some(service) = process::new_ready_notify_service() {
        let notify_handle = assembled
            .server
            .add_service(background_service("ready_notify", service));
        assembled.bootstrap.add_dependency(&notify_handle);
    }

    #[cfg(feature = "pyro")]
    if let Some(url) = &config.basic.pyroscope {
        assembled.server.add_service(background_service(
            "pyro_agent",
            pingap_pyroscope::new_agent_service(url),
        ));
    }

    info!(
        target: LOG_TARGET,
        plugins = get_plugin_factory().supported_plugins().join(","),
        "plugins are registered"
    );
    let plugin_errors = assembled.plugins.errors.as_str();
    if !plugin_errors.is_empty() {
        error!(target: LOG_TARGET, error = plugin_errors, "init plugins fail",);
    }

    let mut server_conf_list: Vec<ServerConf> = parse_from_conf(config.clone());

    if let Some(server_conf) = admin_server_conf {
        let path = admin_plugin
            .as_ref()
            .and_then(|(_, plugin_conf)| plugin_conf.get("path"))
            .map(|path| path.to_string())
            .unwrap_or_default();
        info!(
            target: LOG_TARGET,
            admin_addr = server_conf.addr,
            path, "admin plugin is created"
        );
        if let Some(server) = server_conf_list
            .iter_mut()
            .find(|item| item.addr == server_conf.addr)
        {
            server.admin = true;
        } else {
            server_conf_list.push(server_conf);
        }
    }

    let mut exits_80_server = false;
    for serve_conf in server_conf_list.iter() {
        if serve_conf.addr.ends_with(":80") {
            exits_80_server = true;
        }
        #[cfg(feature = "full")]
        // add otlp service
        if let Some(otlp_exporter) = &serve_conf.otlp_exporter {
            assembled.server.add_service(background_service(
                &format!("otlp:{}", serve_conf.name),
                TracerService::new(&serve_conf.name, otlp_exporter),
            ));
        }
    }
    let certificate_provider = assembled.certificate_provider.clone();
    let mut simple_background_service = assembled
        .background_tasks
        .take()
        .expect("assemble builds the background tasks for a data plane");

    let enabled_http_challenge =
        config.certificates.iter().any(|(_, certificate)| {
            let acme = certificate.acme.clone().unwrap_or_default();
            let domains = certificate.domains.clone().unwrap_or_default();
            let dns_challenge = certificate.dns_challenge.unwrap_or_default();
            !acme.is_empty() && !domains.is_empty() && !dns_challenge
        });

    if std::env::var("PINGAP_DISABLE_ACME")
        .unwrap_or_default()
        .is_empty()
    {
        simple_background_service.add_task(
            "lets_encrypt",
            new_lets_encrypt_service(
                config_manager.clone(),
                certificate_provider.clone(),
                webhook::get_webhook_sender(),
            ),
        );
    }

    let certificate_update = &assembled.certificates;
    if !certificate_update.updated.is_empty() {
        info!(
            target: LOG_TARGET,
            updated_certificates = certificate_update.updated.join(","),
            "init certificates success"
        );
    }
    if !certificate_update.errors.is_empty() {
        error!(
            target: LOG_TARGET,
            error = certificate_update.errors.as_str(),
            "parse certificate fail"
        );
    }

    // no server listen 80 and lets encrypt domains is not empty
    if !exits_80_server && enabled_http_challenge {
        server_conf_list.push(ServerConf {
            name: "lets encrypt".to_string(),
            addr: "0.0.0.0:80".to_string(),
            ..Default::default()
        });
    }

    for server_conf in server_conf_list {
        let listen_80_port = server_conf.addr.ends_with(":80");
        let (_, log_path) =
            parse_access_log_directive(server_conf.access_log.as_ref());

        let access_logger = if let Some(log_path) = log_path {
            let r = new_access_logger(&log_path);
            let (tx, task) = r.recv()??;
            application_log_paths.push(task.get_dir());
            assembled
                .server
                .add_service(background_service("access_logger", task));
            Some(tx)
        } else {
            None
        };
        let mut ps =
            Server::new(&server_conf, assembled.app_context(access_logger))?;
        if enabled_http_challenge && listen_80_port {
            ps.enable_lets_encrypt();
        }
        if let Some(service) = ps.get_prometheus_push_service() {
            simple_background_service.add_task("prometheus_push", service);
        }
        let services = ps.run(assembled.server.configuration.clone())?;
        assembled
            .server
            .add_service(services.lb)
            .add_dependency(&assembled.bootstrap);
    }

    let basic_config = &config.basic;
    if !application_log_paths.is_empty()
        && basic_config.log_compress_algorithm.is_some()
    {
        let mut params = LogCompressParams::new(application_log_paths);
        params.set_compression(
            basic_config
                .log_compress_algorithm
                .clone()
                .unwrap_or_default(),
        );
        params.set_level(basic_config.log_compress_level.unwrap_or_default());
        params.set_days_ago(
            basic_config.log_compress_days_ago.unwrap_or_default(),
        );
        params.set_time_point_hour(
            basic_config
                .log_compress_time_point_hour
                .unwrap_or_default(),
        );

        simple_background_service
            .add_task("log_compress", new_log_compress_service(params));
    }
    // A buffered application log is otherwise only written when the buffer
    // fills; this bounds the delay to one tick.
    if let Some(task) = pingap_logger::new_log_flush_service() {
        simple_background_service.add_task("log_flush", task);
    }

    if args.autorestart || args.autoreload {
        let only_hot_reload = !args.autorestart;
        // The admin listener outlives every reload, so its plugin is passed to
        // each rebuild instead of being re-derived from a process-global.
        if config_manager.support_observer() {
            assembled.server.add_service(background_service(
                "observer",
                new_observer_service(
                    config_manager.clone(),
                    reload_handle,
                    auto_restart_check_interval,
                    only_hot_reload,
                    admin_plugin,
                ),
            ));
        } else {
            let auto_restart_task = new_auto_restart_service(
                config_manager.clone(),
                reload_handle,
                auto_restart_check_interval,
                only_hot_reload,
                admin_plugin,
            );
            let name = auto_restart_task.name().to_string();
            assembled
                .server
                .add_service(background_service(&name, auto_restart_task));
        }
    }

    let name = simple_background_service.name().to_string();

    assembled
        .server
        .add_service(background_service(&name, simple_background_service));

    let upstream_health_check_task = new_upstream_health_check_task(
        new_upstream_provider(),
        Duration::from_secs(10),
        webhook::get_webhook_sender(),
    );
    let name = upstream_health_check_task.name().to_string();
    assembled
        .server
        .add_service(background_service(&name, upstream_health_check_task));

    assembled.server.add_service(background_service(
        "webhook_flush",
        webhook::WebhookFlushService,
    ));

    info!(
        target: LOG_TARGET,
        daemon = args.daemon,
        upgrade = args.upgrade,
        auto_restart = args.autorestart,
        auto_reload = args.autoreload,
        control_plane = args.cp,
        "server is running"
    );

    // `run`, not `run_forever`: it returns once the runtimes have exited, and
    // a fast shutdown (SIGINT) takes them down without running the flush
    // service, so the webhook gets one more chance to post its last batch
    // before the process goes.
    assembled.server.run(server::RunArgs::default());
    webhook::flush_pending_before_exit();
    // `exit` runs no destructors, so a buffered application log would keep
    // its last lines.
    pingap_logger::flush_application_log();
    std::process::exit(0);
}

fn main() {
    // Record the process start before anything reads it: the lazy fallback in
    // `get_start_time` would report its first caller instead. Covers both the
    // platform mode and the plain proxy started below.
    init_start_time();
    // Explicit registration is the link edge for feature-gated plugins that
    // live outside `pingap-plugin` (and for its own `#[ctor]`s).
    plugin::register_builtin_plugins();

    // The graph pulls in two rustls crypto providers (ring + aws-lc-rs). Ring
    // is the process provider: install it before any TLS listener or client
    // initialises. `install_default_crypto_provider()` is the idempotent
    // library-side safeguard and must name the same provider.
    let _ = rustls::crypto::ring::default_provider().install_default();

    // Check if VarmanWAF mode is requested (via subcommand or VARMAN_MODE env)
    if cli::is_varman_mode() {
        varman::main();
        return;
    }

    if let Err(e) = run() {
        // stderr, and unbuffered: everything that can fail here can fail before
        // `logger_try_init`, in which case the `error!` below reaches nobody.
        eprintln!("{e}");
        error!(error = e.to_string());
        // Exit non-zero. Without this `pingap -t` reported success on a config
        // it had just refused to load, so `pingap -t && systemctl reload pingap`
        // reloaded anyway, and a supervisor could not tell a failed start from
        // a clean shutdown.
        std::process::exit(1);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_startup_bridge_returns_the_task_result() {
        let result = run_startup(|| async { 42 }, |_| 0);
        assert_eq!(42, result.recv().expect("bridge result"));
    }
}
