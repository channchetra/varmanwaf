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

//! PingWAF CLI subcommand definitions.
//!
//! These are additive to the existing pingap CLI and are detected before
//! the normal argument parsing runs.

use clap::{Parser, Subcommand};

/// PingWAF top-level CLI wrapper.
///
/// When the first positional argument is one of the PingWAF subcommand
/// names — the three run modes (`server`, `agent`, `all-in-one`) or a
/// maintenance command (`user`, `mode`, `security`) — the binary switches to
/// PingWAF mode.
#[derive(Parser, Debug)]
#[command(
    name = "pingwaf",
    about = "PingWAF — Web Application Firewall control plane and data plane",
    version
)]
pub struct PingWafCli {
    #[command(subcommand)]
    pub command: PingWafCommand,
}

#[derive(Subcommand, Debug)]
pub enum PingWafCommand {
    /// Run the control plane server only (REST API + gRPC + dashboard)
    Server(ServerOpts),
    /// Run the data plane agent only (connects to a remote control plane)
    Agent(AgentOpts),
    /// Run both control plane and data plane in a single process
    AllInOne(AllInOneOpts),
    /// Dashboard user administration
    User {
        #[command(subcommand)]
        command: UserSubcommand,
    },
    /// Observation mode: run every detection, enforce nothing
    Mode {
        #[command(subcommand)]
        command: ModeCommand,
    },
    /// Control plane (9080) self-protection switches
    Security {
        #[command(subcommand)]
        command: SecurityCommand,
    },
}

/// Options shared by all PingWAF modes.
#[derive(Parser, Debug, Clone)]
pub struct CommonOpts {
    /// PostgreSQL connection string
    #[arg(
        long,
        env = "PINGWAF_DB_URL",
        default_value = "postgres://pingwaf:pingwaf@localhost:5432/pingwaf"
    )]
    pub db_url: String,

    /// HTTP admin/API listen address
    #[arg(long, env = "PINGWAF_ADMIN_ADDR", default_value = "0.0.0.0:9080")]
    pub admin_addr: String,

    /// gRPC listen/connect address
    #[arg(long, env = "PINGWAF_GRPC_ADDR", default_value = "0.0.0.0:9090")]
    pub grpc_addr: String,

    /// Serve the admin dashboard and REST API over TLS. A self-signed
    /// certificate is generated on first boot; upload a real one from
    /// Settings → Control plane HTTPS. Set to false behind a reverse proxy
    /// that terminates TLS.
    #[arg(
        long,
        env = "PINGWAF_TLS_ENABLED",
        default_value = "true",
        num_args = 0..=1,
        default_missing_value = "true",
        action = clap::ArgAction::Set
    )]
    pub tls_enabled: bool,

    /// Subject alternative names of the generated self-signed certificate,
    /// comma separated (DNS names and IP addresses)
    #[arg(long, env = "PINGWAF_TLS_SANS", value_delimiter = ',')]
    pub tls_sans: Vec<String>,
}

/// Control plane server options.
#[derive(Parser, Debug, Clone)]
#[command(args_override_self = true)]
pub struct ServerOpts {
    #[command(flatten)]
    pub common: CommonOpts,

    /// TOML configuration file; its `[server]` and `[agent]` tables hold
    /// these same settings. Precedence is this file, then the `PINGWAF_*`
    /// environment variables, then the command line.
    #[arg(long, env = "PINGWAF_CONFIG")]
    pub config: Option<String>,

    /// JWT signing secret (must be at least 16 characters)
    #[arg(
        long,
        env = "PINGWAF_JWT_SECRET",
        default_value = "change-me-in-production"
    )]
    pub jwt_secret: String,

    /// Default admin email for initial seeding
    #[arg(
        long,
        env = "PINGWAF_ADMIN_EMAIL",
        default_value = "admin@pingwaf.local"
    )]
    pub admin_email: String,

    /// Default admin password for initial seeding
    #[arg(long, env = "PINGWAF_ADMIN_PASSWORD", default_value = "pingwaf123")]
    pub admin_password: String,

    /// Whether to serve the embedded frontend (SPA)
    #[arg(
        long,
        env = "PINGWAF_SERVE_FRONTEND",
        default_value = "true",
        num_args = 0..=1,
        default_missing_value = "true",
        action = clap::ArgAction::Set
    )]
    pub serve_frontend: bool,
}

/// Data plane agent options.
#[derive(Parser, Debug, Clone)]
#[command(args_override_self = true)]
pub struct AgentOpts {
    /// TOML configuration file; its `[server]` and `[agent]` tables hold
    /// these same settings. Precedence is this file, then the `PINGWAF_*`
    /// environment variables, then the command line.
    #[arg(long, env = "PINGWAF_CONFIG")]
    pub config: Option<String>,

    /// Control plane gRPC URL to connect to
    #[arg(
        long,
        env = "PINGWAF_SERVER_URL",
        default_value = "http://localhost:9090"
    )]
    pub server_url: String,

    /// API key for agent authentication
    #[arg(long, env = "PINGWAF_API_KEY", default_value = "")]
    pub api_key: String,

    /// Local rule cache directory
    #[arg(long, env = "PINGWAF_CACHE_DIR", default_value = "./data/cache")]
    pub cache_dir: String,

    /// Allow traffic when disconnected from control plane
    #[arg(
        long,
        env = "PINGWAF_FAIL_OPEN",
        default_value = "true",
        num_args = 0..=1,
        default_missing_value = "true",
        action = clap::ArgAction::Set
    )]
    pub fail_open: bool,

    /// Heartbeat interval in seconds
    #[arg(long, env = "PINGWAF_HEARTBEAT_INTERVAL", default_value = "30")]
    pub heartbeat_interval_secs: u64,

    /// Maximum log batch size before flush
    #[arg(long, default_value = "100")]
    pub log_batch_size: usize,

    /// Log flush interval in seconds
    #[arg(long, default_value = "5")]
    pub log_flush_interval_secs: u64,

    /// Maximum request body size to log (bytes)
    #[arg(long, default_value = "8192")]
    pub max_body_log_size: usize,

    /// Metrics shipping interval in seconds (0 disables metric shipping)
    #[arg(long, env = "PINGWAF_METRICS_SHIP_INTERVAL", default_value = "30")]
    pub metrics_ship_interval_secs: u64,
}

/// All-in-one mode options (server + agent in one process).
#[derive(Parser, Debug, Clone)]
#[command(args_override_self = true)]
pub struct AllInOneOpts {
    #[command(flatten)]
    pub common: CommonOpts,

    /// TOML configuration file; its `[server]` and `[agent]` tables hold
    /// these same settings. Precedence is this file, then the `PINGWAF_*`
    /// environment variables, then the command line.
    #[arg(long, env = "PINGWAF_CONFIG")]
    pub config: Option<String>,

    // ── Server ────────────────────────────────────────────────────────
    /// JWT signing secret (must be at least 16 characters)
    #[arg(
        long,
        env = "PINGWAF_JWT_SECRET",
        default_value = "change-me-in-production"
    )]
    pub jwt_secret: String,

    /// Default admin email for initial seeding
    #[arg(
        long,
        env = "PINGWAF_ADMIN_EMAIL",
        default_value = "admin@pingwaf.local"
    )]
    pub admin_email: String,

    /// Default admin password for initial seeding
    #[arg(long, env = "PINGWAF_ADMIN_PASSWORD", default_value = "pingwaf123")]
    pub admin_password: String,

    /// Whether to serve the embedded frontend (SPA)
    #[arg(
        long,
        env = "PINGWAF_SERVE_FRONTEND",
        default_value = "true",
        num_args = 0..=1,
        default_missing_value = "true",
        action = clap::ArgAction::Set
    )]
    pub serve_frontend: bool,

    // ── Agent ─────────────────────────────────────────────────────────
    /// API key for agent authentication (empty = auto-register via loopback)
    #[arg(long, env = "PINGWAF_API_KEY", default_value = "")]
    pub api_key: String,

    /// Local rule cache directory
    #[arg(long, env = "PINGWAF_CACHE_DIR", default_value = "./data/cache")]
    pub cache_dir: String,

    /// Allow traffic when disconnected from control plane
    #[arg(
        long,
        env = "PINGWAF_FAIL_OPEN",
        default_value = "true",
        num_args = 0..=1,
        default_missing_value = "true",
        action = clap::ArgAction::Set
    )]
    pub fail_open: bool,

    /// Heartbeat interval in seconds
    #[arg(long, env = "PINGWAF_HEARTBEAT_INTERVAL", default_value = "30")]
    pub heartbeat_interval_secs: u64,

    /// Maximum log batch size before flush
    #[arg(long, default_value = "100")]
    pub log_batch_size: usize,

    /// Log flush interval in seconds
    #[arg(long, default_value = "5")]
    pub log_flush_interval_secs: u64,

    /// Maximum request body size to log (bytes)
    #[arg(long, default_value = "8192")]
    pub max_body_log_size: usize,

    /// Metrics shipping interval in seconds (0 disables metric shipping)
    #[arg(long, env = "PINGWAF_METRICS_SHIP_INTERVAL", default_value = "30")]
    pub metrics_ship_interval_secs: u64,
}

/// Database connection options of the maintenance commands.
///
/// Those commands talk straight to PostgreSQL instead of the REST API, so
/// they keep working when the control plane is down or its IP allowlist has
/// locked the operator out. A running control plane notices their writes
/// within a few seconds.
#[derive(clap::Args, Debug, Clone)]
pub struct DbOpts {
    /// PostgreSQL connection string
    #[arg(
        long,
        env = "PINGWAF_DB_URL",
        default_value = "postgres://pingwaf:pingwaf@localhost:5432/pingwaf"
    )]
    pub db_url: String,
}

/// `user` — dashboard account administration.
#[derive(Subcommand, Debug)]
pub enum UserSubcommand {
    /// List dashboard accounts
    List(DbOpts),
    /// Create an administrator account
    AddAdmin(AddAdminOpts),
    /// Set a new password for an account
    ResetPassword(ResetPasswordOpts),
}

#[derive(clap::Args, Debug)]
pub struct AddAdminOpts {
    #[command(flatten)]
    pub db: DbOpts,

    /// E-mail address of the new administrator
    #[arg(long)]
    pub email: String,
    /// Display name
    #[arg(long)]
    pub name: Option<String>,
    /// Password; when omitted a random one is generated and printed
    #[arg(long)]
    pub password: Option<String>,
}

#[derive(clap::Args, Debug)]
pub struct ResetPasswordOpts {
    #[command(flatten)]
    pub db: DbOpts,

    /// E-mail address of the account
    #[arg(long)]
    pub email: String,
    /// New password; when omitted a random one is generated and printed
    #[arg(long)]
    pub password: Option<String>,
}

/// `mode` — the observation mode switch.
#[derive(Subcommand, Debug)]
pub enum ModeCommand {
    /// Turn observation mode on: detect everything, block nothing
    Observe(DbOpts),
    /// Turn observation mode off: protections enforce again
    Enforce(DbOpts),
    /// Print the current observation mode
    Status(DbOpts),
}

/// `security` — quick switches for the control plane's own protection.
#[derive(Subcommand, Debug)]
pub enum SecurityCommand {
    /// Print the 9080 protection settings and the effective allowlist
    Status(DbOpts),
    /// Turn the API IP allowlist on or off (the break-glass switch when the
    /// console is unreachable)
    Allowlist(AllowlistOpts),
}

#[derive(clap::Args, Debug)]
pub struct AllowlistOpts {
    #[command(flatten)]
    pub db: DbOpts,

    /// New state of the allowlist
    #[arg(value_enum)]
    pub state: OnOff,
    /// Enable even when the allowlist is empty (refuses every API caller)
    #[arg(long)]
    pub force: bool,
}

/// An `on` / `off` command line value.
#[derive(Clone, Copy, Debug, PartialEq, Eq, clap::ValueEnum)]
pub enum OnOff {
    On,
    Off,
}

/// The run modes: the subcommands that start a long-running process.
pub const RUN_MODES: [&str; 3] = ["server", "agent", "all-in-one"];

/// The maintenance commands: they run against the database and exit.
const MAINTENANCE_MODES: [&str; 3] = ["user", "mode", "security"];

/// Whether `value` names a PingWAF subcommand.
fn is_mode(value: &str) -> bool {
    RUN_MODES.contains(&value) || MAINTENANCE_MODES.contains(&value)
}

/// The mode named by `PINGWAF_MODE`, when it names one.
fn mode_from_env() -> Option<String> {
    let mode = std::env::var("PINGWAF_MODE").ok()?;
    let mode = mode.trim().to_lowercase();
    is_mode(&mode).then_some(mode)
}

/// Check whether the command line invokes a PingWAF subcommand.
///
/// Returns `true` if the first non-binary argument is one of the PingWAF
/// subcommand names, or if `PINGWAF_MODE` environment variable is set.
pub fn is_pingwaf_mode() -> bool {
    let from_argv = std::env::args().nth(1).is_some_and(|arg| is_mode(&arg));
    from_argv || mode_from_env().is_some()
}

/// The version banner shared with the pingap-mode `--version`.
fn version_banner() -> &'static str {
    crate::version_banner()
}

/// Print the version and exit. `--version` carries the long banner, `-V` the
/// bare number, matching how clap answers the two forms elsewhere.
///
/// clap serves `--version` from the top-level command, which an injected
/// subcommand hides, so the flag is answered here instead.
fn print_version(args: &[String]) -> ! {
    if args.iter().skip(1).any(|arg| arg == "--version") {
        println!("pingwaf {}", version_banner());
    } else {
        println!("pingwaf {}", env!("CARGO_PKG_VERSION"));
    }
    std::process::exit(0);
}

/// Whether the arguments ask for the version rather than a mode.
fn wants_version(args: &[String]) -> bool {
    args.iter()
        .skip(1)
        .any(|arg| arg == "--version" || arg == "-V")
}

/// Parse the PingWAF CLI from command line arguments.
///
/// If `PINGWAF_MODE` is set but no subcommand is given on the command line,
/// injects the mode as a subcommand so that env-only invocation works. The
/// settings of a `--config` file are added last, underneath the command line.
pub fn parse_pingwaf_cli() -> PingWafCli {
    let args: Vec<String> = std::env::args().collect();

    if wants_version(&args) {
        print_version(&args);
    }

    let mode = args
        .get(1)
        .filter(|arg| is_mode(arg))
        .cloned()
        .or_else(mode_from_env);
    let Some(mode) = mode else {
        eprintln!("error: no PingWAF subcommand or PINGWAF_MODE specified");
        std::process::exit(1);
    };

    let mut argv = if args.get(1).map(String::as_str) == Some(mode.as_str()) {
        args.clone()
    } else {
        let mut injected = args.clone();
        injected.insert(1, mode.clone());
        injected
    };

    // The file's arguments go next to the subcommand so that the command line,
    // parsed after them, still wins.
    match crate::config_file::injections(&mode, &argv) {
        Ok(extra) => {
            argv.splice(2..2, extra);
        },
        Err(err) => {
            eprintln!("pingwaf: {err}");
            std::process::exit(1);
        },
    }

    PingWafCli::parse_from(argv)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(args: &[&str]) -> PingWafCommand {
        PingWafCli::try_parse_from(args).unwrap().command
    }

    #[test]
    fn flags_that_default_to_true_can_be_turned_off() {
        // Bare flag and no flag both mean the default; only an explicit value
        // (or environment variable) turns it off.
        let PingWafCommand::Agent(opts) = parse(&["pingwaf", "agent"]) else {
            panic!("expected the agent mode");
        };
        assert!(opts.fail_open);
        assert!(opts.config.is_none());

        let PingWafCommand::Agent(opts) =
            parse(&["pingwaf", "agent", "--fail-open"])
        else {
            panic!("expected the agent mode");
        };
        assert!(opts.fail_open);

        let PingWafCommand::Agent(opts) =
            parse(&["pingwaf", "agent", "--fail-open=false"])
        else {
            panic!("expected the agent mode");
        };
        assert!(!opts.fail_open);
    }

    #[test]
    fn the_last_spelling_of_an_argument_wins() {
        // The configuration file is layered in as earlier arguments, so an
        // argument repeated on the command line has to override it.
        let PingWafCommand::Server(opts) = parse(&[
            "pingwaf",
            "server",
            "--config=/etc/pingwaf/pingwaf.toml",
            "--jwt-secret=from-file-16-chars",
            "--jwt-secret=from-cli-16-chars",
        ]) else {
            panic!("expected the server mode");
        };
        assert_eq!(opts.jwt_secret, "from-cli-16-chars");
        assert_eq!(opts.config.as_deref(), Some("/etc/pingwaf/pingwaf.toml"));

        let PingWafCommand::AllInOne(opts) = parse(&[
            "pingwaf",
            "all-in-one",
            "--serve-frontend=false",
            "--serve-frontend",
        ]) else {
            panic!("expected the all-in-one mode");
        };
        assert!(opts.serve_frontend);
    }

    #[test]
    fn every_run_mode_accepts_a_config_file() {
        for mode in RUN_MODES {
            let path = format!("--config=/{mode}.toml");
            let args = ["pingwaf", mode, path.as_str()];
            let cli = PingWafCli::try_parse_from(args).unwrap();
            let config = match cli.command {
                PingWafCommand::Server(opts) => opts.config,
                PingWafCommand::Agent(opts) => opts.config,
                PingWafCommand::AllInOne(opts) => opts.config,
                _ => panic!("{mode} is not a run mode"),
            };
            assert_eq!(
                config.as_deref(),
                Some(format!("/{mode}.toml").as_str())
            );
        }
    }

    #[test]
    fn maintenance_commands_parse_with_their_database_options() {
        let PingWafCommand::User { command } = parse(&[
            "pingwaf",
            "user",
            "add-admin",
            "--email=ops@example.com",
            "--db-url=postgres://other/db",
        ]) else {
            panic!("expected the user command");
        };
        let UserSubcommand::AddAdmin(opts) = command else {
            panic!("expected add-admin");
        };
        assert_eq!(opts.email, "ops@example.com");
        assert_eq!(opts.db.db_url, "postgres://other/db");
        assert!(opts.password.is_none());

        let PingWafCommand::Mode { command } =
            parse(&["pingwaf", "mode", "observe"])
        else {
            panic!("expected the mode command");
        };
        assert!(matches!(command, ModeCommand::Observe(_)));

        let PingWafCommand::Security { command } =
            parse(&["pingwaf", "security", "allowlist", "off"])
        else {
            panic!("expected the security command");
        };
        let SecurityCommand::Allowlist(opts) = command else {
            panic!("expected allowlist");
        };
        assert_eq!(opts.state, OnOff::Off);
        assert!(!opts.force);
    }

    #[test]
    fn maintenance_commands_are_recognised_as_pingwaf_invocations() {
        for mode in RUN_MODES.into_iter().chain(MAINTENANCE_MODES) {
            assert!(is_mode(mode), "{mode} must select PingWAF mode");
        }
        assert!(!is_mode("reset-password"));
        assert!(!is_mode(""));
    }

    #[test]
    fn the_version_flag_is_recognised_wherever_it_appears() {
        // With PINGWAF_MODE the mode is injected, so the flag must be caught
        // before the subcommand would reject it as an unknown argument.
        let argv = |args: &[&str]| {
            args.iter().map(|arg| arg.to_string()).collect::<Vec<_>>()
        };
        assert!(wants_version(&argv(&["pingwaf", "--version"])));
        assert!(wants_version(&argv(&["pingwaf", "-V"])));
        assert!(wants_version(&argv(&["pingwaf", "server", "--version"])));
        assert!(!wants_version(&argv(&["pingwaf", "server", "--config=x"])));
        assert!(!wants_version(&argv(&["pingwaf"])));
    }
}
