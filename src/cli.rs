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

//! VarmanWAF CLI subcommand definitions.
//!
//! These are additive to the existing pingap CLI and are detected before
//! the normal argument parsing runs.

use clap::{CommandFactory, Parser, Subcommand};

/// VarmanWAF top-level CLI wrapper.
///
/// When the first positional argument is one of the VarmanWAF subcommand
/// names — the three run modes (`server`, `agent`, `all-in-one`) or a
/// maintenance command (`user`, `mode`, `security`) — the binary switches to
/// VarmanWAF mode.
#[derive(Parser, Debug)]
#[command(
    name = "varman",
    about = "VarmanWAF — Web Application Firewall control plane and data plane",
    version
)]
pub struct VarmanCli {
    #[command(subcommand)]
    pub command: VarmanCommand,
}

#[derive(Subcommand, Debug)]
pub enum VarmanCommand {
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
    /// WAF configuration version history: list, inspect, roll back
    Config {
        #[command(subcommand)]
        command: ConfigCommand,
    },
}

impl VarmanCommand {
    /// Whether this command starts a long-running process: `server`, `agent`
    /// or `all-in-one`.
    ///
    /// The match is exhaustive on purpose: a new variant must be classified
    /// here, or the module stops compiling.
    pub const fn is_run_mode(&self) -> bool {
        match self {
            Self::Server(_) | Self::Agent(_) | Self::AllInOne(_) => true,
            Self::User { .. }
            | Self::Mode { .. }
            | Self::Security { .. }
            | Self::Config { .. } => false,
        }
    }

    /// Whether this command runs a maintenance task against PostgreSQL and
    /// exits: `user`, `mode`, `security` or `config`.
    ///
    /// Derived from [`Self::is_run_mode`], so the exhaustive match there is
    /// the one place a new variant has to be classified.
    pub const fn is_maintenance(&self) -> bool {
        !self.is_run_mode()
    }
}

/// Options shared by all VarmanWAF modes.
#[derive(Parser, Debug, Clone)]
pub struct CommonOpts {
    /// PostgreSQL connection string
    #[arg(
        long,
        env = "VARMAN_DB_URL",
        default_value = "postgres://varman:varman@localhost:5432/varman"
    )]
    pub db_url: String,

    /// HTTP admin/API listen address
    #[arg(long, env = "VARMAN_ADMIN_ADDR", default_value = "0.0.0.0:9080")]
    pub admin_addr: String,

    /// gRPC listen/connect address
    #[arg(long, env = "VARMAN_GRPC_ADDR", default_value = "0.0.0.0:9090")]
    pub grpc_addr: String,

    /// Optional TLS for the gRPC control plane: PEM certificate chain, used
    /// together with --grpc-tls-key. Agents then connect via `https://`.
    #[arg(long, env = "VARMAN_GRPC_TLS_CERT")]
    pub grpc_tls_cert: Option<String>,

    /// PEM private key for --grpc-tls-cert.
    #[arg(long, env = "VARMAN_GRPC_TLS_KEY")]
    pub grpc_tls_key: Option<String>,

    /// Transport security of the gRPC control plane: `tls` (the default)
    /// serves the configured certificate or, absent one, the self-signed
    /// control-plane certificate; `off` serves plaintext (degraded).
    #[arg(long, env = "VARMAN_GRPC_TLS_MODE", default_value = "tls")]
    pub grpc_tls_mode: varman_control::config::GrpcTlsMode,

    /// Serve the admin dashboard and REST API over TLS. A self-signed
    /// certificate is generated on first boot; upload a real one from
    /// Settings → Control plane HTTPS. Set to false behind a reverse proxy
    /// that terminates TLS.
    #[arg(
        long,
        env = "VARMAN_TLS_ENABLED",
        default_value = "true",
        num_args = 0..=1,
        default_missing_value = "true",
        action = clap::ArgAction::Set
    )]
    pub tls_enabled: bool,

    /// Subject alternative names of the generated self-signed certificate,
    /// comma separated (DNS names and IP addresses)
    #[arg(long, env = "VARMAN_TLS_SANS", value_delimiter = ',')]
    pub tls_sans: Vec<String>,

    /// Host the dashboard is reached under from the outside, optionally with
    /// a port. Pinned into the HTTP-to-HTTPS redirect target instead of the
    /// client's Host header.
    #[arg(long, env = "VARMAN_PUBLIC_HOST")]
    pub public_host: Option<String>,
}

/// Control plane settings shared by `server` and `all-in-one`.
#[derive(clap::Args, Debug, Clone)]
pub struct ServerSharedOpts {
    /// JWT signing secret (must be at least 16 characters)
    #[arg(
        long,
        env = "VARMAN_JWT_SECRET",
        default_value = "change-me-in-production"
    )]
    pub jwt_secret: String,

    /// Default admin email for initial seeding
    #[arg(
        long,
        env = "VARMAN_ADMIN_EMAIL",
        default_value = "admin@varman.local"
    )]
    pub admin_email: String,

    /// Default admin password for initial seeding
    #[arg(long, env = "VARMAN_ADMIN_PASSWORD", default_value = "varman123")]
    pub admin_password: String,

    /// Whether to serve the embedded frontend (SPA)
    #[arg(
        long,
        env = "VARMAN_SERVE_FRONTEND",
        default_value = "true",
        num_args = 0..=1,
        default_missing_value = "true",
        action = clap::ArgAction::Set
    )]
    pub serve_frontend: bool,
}

/// Data plane settings shared by `agent` and `all-in-one`.
#[derive(clap::Args, Debug, Clone)]
pub struct AgentSharedOpts {
    /// API key for agent authentication
    #[arg(long, env = "VARMAN_API_KEY", default_value = "")]
    pub api_key: String,

    /// Local rule cache directory
    #[arg(long, env = "VARMAN_CACHE_DIR", default_value = "./data/cache")]
    pub cache_dir: String,

    /// Fallback policy when disconnected with no synced rules for a host;
    /// per-site failover policies and the control-plane default win when
    /// they have been synced
    #[arg(
        long,
        env = "VARMAN_FAIL_OPEN",
        default_value = "true",
        num_args = 0..=1,
        default_missing_value = "true",
        action = clap::ArgAction::Set
    )]
    pub fail_open: bool,

    /// Heartbeat interval in seconds
    #[arg(long, env = "VARMAN_HEARTBEAT_INTERVAL", default_value = "30")]
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
    #[arg(long, env = "VARMAN_METRICS_SHIP_INTERVAL", default_value = "30")]
    pub metrics_ship_interval_secs: u64,
}

/// Control plane server options.
#[derive(Parser, Debug, Clone)]
#[command(args_override_self = true)]
pub struct ServerOpts {
    #[command(flatten)]
    pub common: CommonOpts,

    /// TOML configuration file; its `[server]` and `[agent]` tables hold
    /// these same settings. Precedence is this file, then the `VARMAN_*`
    /// environment variables, then the command line.
    #[arg(long, env = "VARMAN_CONFIG")]
    pub config: Option<String>,

    #[command(flatten)]
    pub server: ServerSharedOpts,
}

/// Data plane agent options.
#[derive(Parser, Debug, Clone)]
#[command(args_override_self = true)]
pub struct AgentOpts {
    /// TOML configuration file; its `[server]` and `[agent]` tables hold
    /// these same settings. Precedence is this file, then the `VARMAN_*`
    /// environment variables, then the command line.
    #[arg(long, env = "VARMAN_CONFIG")]
    pub config: Option<String>,

    /// Control plane gRPC URL to connect to
    #[arg(
        long,
        env = "VARMAN_SERVER_URL",
        default_value = "http://localhost:9090"
    )]
    pub server_url: String,

    /// Optional PEM file with the CA (or chain) that signed the control
    /// plane's gRPC certificate; defaults to the bundled webpki roots.
    #[arg(long, env = "VARMAN_SERVER_CA_CERT")]
    pub server_ca_cert: Option<String>,

    #[command(flatten)]
    pub agent: AgentSharedOpts,
}

/// All-in-one mode options (server + agent in one process).
#[derive(Parser, Debug, Clone)]
#[command(args_override_self = true)]
pub struct AllInOneOpts {
    #[command(flatten)]
    pub common: CommonOpts,

    /// TOML configuration file; its `[server]` and `[agent]` tables hold
    /// these same settings. Precedence is this file, then the `VARMAN_*`
    /// environment variables, then the command line.
    #[arg(long, env = "VARMAN_CONFIG")]
    pub config: Option<String>,

    #[command(flatten)]
    pub server: ServerSharedOpts,

    #[command(flatten)]
    pub agent: AgentSharedOpts,
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
        env = "VARMAN_DB_URL",
        default_value = "postgres://varman:varman@localhost:5432/varman"
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

/// `config` — the WAF configuration version history.
///
/// Like the other maintenance commands it talks straight to PostgreSQL, so
/// it keeps working when the control plane is down. Note that a *running*
/// control plane is not notified of a CLI rollback (unlike the console
/// rollback, which pushes to the agents immediately).
#[derive(Subcommand, Debug)]
pub enum ConfigCommand {
    /// List recorded configuration versions, newest first
    History(ConfigHistoryOpts),
    /// Print one version's metadata and snapshot summary
    Show(ConfigShowOpts),
    /// Restore a recorded configuration version
    Rollback(ConfigRollbackOpts),
}

#[derive(clap::Args, Debug)]
pub struct ConfigHistoryOpts {
    #[command(flatten)]
    pub db: DbOpts,

    /// Restrict the history to one site: its UUID, or `global` for the
    /// deployment-wide settings
    #[arg(long)]
    pub site: Option<String>,

    /// How many versions to print
    #[arg(long, default_value_t = 20)]
    pub limit: u32,
}

#[derive(clap::Args, Debug)]
pub struct ConfigShowOpts {
    #[command(flatten)]
    pub db: DbOpts,

    /// The version number to print
    pub version: i64,

    /// Print the full snapshot as JSON instead of a summary
    #[arg(long)]
    pub json: bool,
}

#[derive(clap::Args, Debug)]
pub struct ConfigRollbackOpts {
    #[command(flatten)]
    pub db: DbOpts,

    /// The version number to restore
    pub version: i64,

    /// Skip the confirmation prompt
    #[arg(long)]
    pub yes: bool,
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

/// Whether `program` (argv[0]) is an installed binary called `name`.
///
/// The file stem is compared, so a path (`/usr/local/bin/varman`) and a
/// versioned file name behave the same, while a test harness
/// (`varman-<hash>`) deliberately does not match.
pub(crate) fn invoked_as(program: &str, name: &str) -> bool {
    std::path::Path::new(program)
        .file_stem()
        .and_then(|stem| stem.to_str())
        .is_some_and(|stem| stem == name)
}

/// Legacy pingap options that never take a value. A subcommand may follow one
/// of these (`pingap -d server`); any other option ends the scan, because its
/// value cannot be told apart from a positional.
const LEGACY_BOOLEAN_FLAGS: [&str; 17] = [
    "-d",
    "--daemon",
    "-u",
    "--upgrade",
    "-t",
    "--test",
    "-a",
    "--autorestart",
    "--autoreload",
    "--cp",
    "--template",
    "--to-hcl",
    "--to-kdl",
    "-h",
    "--help",
    "-V",
    "--version",
];

/// Index of the first token that is neither an option nor an option's value.
///
/// The flat proxy invocation (`varman -c varman.toml`) has no positional at
/// all; `varman all-in-one` has one at index 1. Only the value-free legacy
/// options are skipped: anything else could be a value (a path named `server`,
/// for instance), so the scan gives up instead of guessing.
fn first_positional_index(argv: &[String]) -> Option<usize> {
    let mut after_terminator = false;
    for (index, arg) in argv.iter().enumerate().skip(1) {
        if after_terminator {
            return Some(index);
        }
        if arg == "--" {
            after_terminator = true;
            continue;
        }
        if arg.starts_with('-') {
            if LEGACY_BOOLEAN_FLAGS.contains(&arg.as_str()) {
                continue;
            }
            return None;
        }
        return Some(index);
    }
    None
}

/// The first positional token, when it names a VarmanWAF subcommand.
fn mode_token(argv: &[String]) -> Option<(usize, &str)> {
    let index = first_positional_index(argv)?;
    let value = argv[index].as_str();
    is_mode(value).then_some((index, value))
}

/// Whether `value` names a VarmanWAF subcommand.
///
/// The names come from the clap definition derived from [`VarmanCommand`],
/// so a new variant is recognised without a second table to keep in sync.
fn is_mode(value: &str) -> bool {
    VarmanCli::command()
        .get_subcommands()
        .any(|command| command.get_name() == value)
}

/// Trims and lower-cases a configured mode, keeping it only when it names a
/// subcommand.
fn normalize_mode(raw: &str) -> Option<String> {
    let mode = raw.trim().to_lowercase();
    is_mode(&mode).then_some(mode)
}

/// The mode named by `VARMAN_MODE`, when it names one.
fn mode_from_env() -> Option<String> {
    normalize_mode(&std::env::var("VARMAN_MODE").ok()?)
}

/// Whether an invocation selects VarmanWAF mode.
///
/// A subcommand anywhere in the positional position wins, whatever the binary
/// is called. Without one, the `varman` binary is VarmanWAF when the command
/// line is empty or asks only for help or the template (the flat proxy and the
/// maintenance flags stay on the legacy parser), and `VARMAN_MODE` selects it
/// for either binary. The first argument is matched as typed; the environment
/// value is trimmed and lower-cased.
fn selects_varman_mode(
    program: &str,
    argv: &[String],
    env_mode: Option<&str>,
) -> bool {
    let from_argv = mode_token(argv).is_some();
    let from_env = env_mode.and_then(normalize_mode).is_some();
    let varman_own_cli = invoked_as(program, "varman")
        && argv
            .iter()
            .skip(1)
            .all(|arg| matches!(arg.as_str(), "-h" | "--help" | "--template"));
    from_argv || from_env || varman_own_cli
}

/// Which product the invocation identifies as.
///
/// The binary name decides the brand, and a VarmanWAF subcommand or
/// `VARMAN_MODE` selects it for any binary. This is deliberately separate
/// from `selects_varman_mode`: an installed `varman` may still run the flat
/// legacy proxy parser, but it must not print a pingap-named template or
/// write its ACME state under the pingap directory.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Identity {
    Varman,
    Pingap,
}

fn identity_for(
    program: &str,
    argv: &[String],
    env_mode: Option<&str>,
) -> Identity {
    let pingap_binary = invoked_as(program, "pingap");
    if pingap_binary
        && mode_token(argv).is_none()
        && env_mode.and_then(normalize_mode).is_none()
    {
        Identity::Pingap
    } else {
        // The installed `varman` binary, any renamed build (including the
        // test harness), a VarmanWAF subcommand and VARMAN_MODE all brand
        // the output as VarmanWAF.
        Identity::Varman
    }
}

/// Resolves the product identity from the current process environment.
pub fn identity() -> Identity {
    let args: Vec<String> = std::env::args().collect();
    let program = args
        .first()
        .cloned()
        .unwrap_or_else(|| env!("CARGO_BIN_NAME").to_string());
    identity_for(
        &program,
        &args,
        std::env::var("VARMAN_MODE").ok().as_deref(),
    )
}

/// The starter configuration branded for the resolved identity.
pub fn template_config() -> String {
    match identity() {
        Identity::Varman => crate::TEMPLATE_CONFIG.replace("pingap", "varman"),
        Identity::Pingap => crate::TEMPLATE_CONFIG.to_string(),
    }
}

/// Check whether the command line invokes the VarmanWAF CLI.
///
/// Returns `true` when the first positional argument names a VarmanWAF
/// subcommand, when the executable is `varman` and the command line is empty,
/// help or the template, or when `VARMAN_MODE` names a mode.
pub fn is_varman_mode() -> bool {
    let args: Vec<String> = std::env::args().collect();
    let program = args
        .first()
        .cloned()
        .unwrap_or_else(|| env!("CARGO_BIN_NAME").to_string());
    selects_varman_mode(
        &program,
        &args,
        std::env::var("VARMAN_MODE").ok().as_deref(),
    )
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
        println!("varman {}", version_banner());
    } else {
        println!("varman {}", env!("CARGO_PKG_VERSION"));
    }
    std::process::exit(0);
}

/// Whether the arguments ask for the version rather than a mode.
fn wants_version(args: &[String]) -> bool {
    args.iter()
        .skip(1)
        .any(|arg| arg == "--version" || arg == "-V")
}

/// Whether the arguments ask for the starter configuration.
fn wants_template(args: &[String]) -> bool {
    args.iter().skip(1).any(|arg| arg == "--template")
}

/// Print the starter configuration and exit.
///
/// The schema and sample values are the legacy template, rebranded for the
/// binary that printed it: `varman --template` must not hand a new operator a
/// `pingap`-named file. `TEMPLATE_CONFIG` stays at the crate root so the flat
/// `pingap --template` output is unchanged.
fn print_template() -> ! {
    print!("{}", template_config());
    std::process::exit(0);
}

/// Print the VarmanWAF help and exit successfully.
fn print_help() -> ! {
    let mut command = VarmanCli::command();
    if command.print_help().is_err() {
        std::process::exit(1);
    }
    println!();
    std::process::exit(0);
}

/// Parse the VarmanWAF CLI from command line arguments.
///
/// If `VARMAN_MODE` is set but no subcommand is given on the command line,
/// injects the mode as a subcommand so that env-only invocation works. A
/// subcommand found after a flag is moved into clap's position. The settings
/// of a `--config` file are added last, underneath the command line.
pub fn parse_varman_cli() -> VarmanCli {
    let args: Vec<String> = std::env::args().collect();

    if wants_version(&args) {
        print_version(&args);
    }
    if wants_template(&args) {
        print_template();
    }

    let mut argv = args.clone();
    let mode = match mode_token(&args) {
        Some((1, value)) => value.to_string(),
        Some((index, value)) => {
            // A legacy flag preceded the subcommand: move the mode into
            // clap's position and let it report the stray option.
            argv.remove(index);
            argv.insert(1, value.to_string());
            value.to_string()
        },
        None => match mode_from_env() {
            Some(mode) => {
                argv.insert(1, mode.clone());
                mode
            },
            None if args
                .iter()
                .skip(1)
                .all(|arg| arg == "-h" || arg == "--help") =>
            {
                print_help();
            },
            None => {
                eprintln!(
                    "error: no VarmanWAF subcommand or VARMAN_MODE specified"
                );
                std::process::exit(1);
            },
        },
    };

    // The file's arguments go next to the subcommand so that the command line,
    // parsed after them, still wins.
    match crate::config_file::injections(&mode, &argv) {
        Ok(extra) => {
            argv.splice(2..2, extra);
        },
        Err(err) => {
            eprintln!("varman: {err}");
            std::process::exit(1);
        },
    }

    VarmanCli::parse_from(argv)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(args: &[&str]) -> VarmanCommand {
        VarmanCli::try_parse_from(args).unwrap().command
    }

    #[test]
    fn flags_that_default_to_true_can_be_turned_off() {
        // Bare flag and no flag both mean the default; only an explicit value
        // (or environment variable) turns it off.
        let VarmanCommand::Agent(opts) = parse(&["varman", "agent"]) else {
            panic!("expected the agent mode");
        };
        assert!(opts.agent.fail_open);
        assert!(opts.config.is_none());

        let VarmanCommand::Agent(opts) =
            parse(&["varman", "agent", "--fail-open"])
        else {
            panic!("expected the agent mode");
        };
        assert!(opts.agent.fail_open);

        let VarmanCommand::Agent(opts) =
            parse(&["varman", "agent", "--fail-open=false"])
        else {
            panic!("expected the agent mode");
        };
        assert!(!opts.agent.fail_open);
    }

    #[test]
    fn the_last_spelling_of_an_argument_wins() {
        // The configuration file is layered in as earlier arguments, so an
        // argument repeated on the command line has to override it.
        let VarmanCommand::Server(opts) = parse(&[
            "varman",
            "server",
            "--config=/etc/varman/varman.toml",
            "--jwt-secret=from-file-16-chars",
            "--jwt-secret=from-cli-16-chars",
        ]) else {
            panic!("expected the server mode");
        };
        assert_eq!(opts.server.jwt_secret, "from-cli-16-chars");
        assert_eq!(opts.config.as_deref(), Some("/etc/varman/varman.toml"));

        let VarmanCommand::AllInOne(opts) = parse(&[
            "varman",
            "all-in-one",
            "--serve-frontend=false",
            "--serve-frontend",
        ]) else {
            panic!("expected the all-in-one mode");
        };
        assert!(opts.server.serve_frontend);
    }

    #[test]
    fn shared_server_and_agent_flags_parse_in_every_mode_that_declares_them() {
        // The flags live in `ServerSharedOpts` / `AgentSharedOpts`; every
        // mode that flattens them must still accept the same spellings.
        let VarmanCommand::AllInOne(opts) = parse(&[
            "varman",
            "all-in-one",
            "--jwt-secret=shared-secret-16",
            "--admin-email=ops@example.com",
            "--serve-frontend=false",
            "--api-key=shared-key",
            "--cache-dir=/var/cache/varman",
            "--heartbeat-interval-secs=5",
        ]) else {
            panic!("expected the all-in-one mode");
        };
        assert_eq!("shared-secret-16", opts.server.jwt_secret);
        assert_eq!("ops@example.com", opts.server.admin_email);
        assert!(!opts.server.serve_frontend);
        assert_eq!("shared-key", opts.agent.api_key);
        assert_eq!("/var/cache/varman", opts.agent.cache_dir);
        assert_eq!(5, opts.agent.heartbeat_interval_secs);

        let VarmanCommand::Server(opts) = parse(&[
            "varman",
            "server",
            "--jwt-secret=shared-secret-16",
            "--admin-email=ops@example.com",
        ]) else {
            panic!("expected the server mode");
        };
        assert_eq!("shared-secret-16", opts.server.jwt_secret);
        assert_eq!("ops@example.com", opts.server.admin_email);

        let VarmanCommand::Agent(opts) =
            parse(&["varman", "agent", "--api-key=shared-key"])
        else {
            panic!("expected the agent mode");
        };
        assert_eq!("shared-key", opts.agent.api_key);
    }

    /// One minimal command line per [`VarmanCommand`] variant. The names are
    /// compared with the clap definition in
    /// `every_subcommand_is_classified_exactly_once`, so a new variant
    /// without an entry fails the test instead of drifting silently.
    const SUBCOMMAND_ARGV: [&[&str]; 7] = [
        &["varman", "server"],
        &["varman", "agent"],
        &["varman", "all-in-one"],
        &["varman", "user", "list"],
        &["varman", "mode", "status"],
        &["varman", "security", "status"],
        &["varman", "config", "history"],
    ];

    /// The subcommand names clap declares from [`VarmanCommand`].
    fn declared_subcommands() -> Vec<String> {
        VarmanCli::command()
            .get_subcommands()
            .map(|command| command.get_name().to_string())
            .collect()
    }

    #[test]
    fn every_subcommand_is_classified_exactly_once() {
        let mut covered = Vec::new();
        for argv in SUBCOMMAND_ARGV {
            let command = VarmanCli::try_parse_from(argv.iter().copied())
                .unwrap()
                .command;
            assert!(
                command.is_maintenance() ^ command.is_run_mode(),
                "{argv:?} must be exactly one of maintenance or run"
            );
            covered.push(argv[1].to_string());
        }
        assert_eq!(covered, declared_subcommands());
    }

    #[test]
    fn every_run_mode_accepts_a_config_file() {
        for argv in SUBCOMMAND_ARGV {
            let cli = VarmanCli::try_parse_from(argv.iter().copied())
                .unwrap_or_else(|err| panic!("{argv:?} does not parse: {err}"));
            if !cli.command.is_run_mode() {
                continue;
            }
            let mode = argv[1];
            let path = format!("--config=/{mode}.toml");
            let cli = VarmanCli::try_parse_from(
                argv.iter().copied().chain(std::iter::once(path.as_str())),
            )
            .unwrap();
            let config = match cli.command {
                VarmanCommand::Server(opts) => opts.config,
                VarmanCommand::Agent(opts) => opts.config,
                VarmanCommand::AllInOne(opts) => opts.config,
                other => panic!("{mode} is not a run mode: {other:?}"),
            };
            assert_eq!(
                config.as_deref(),
                Some(format!("/{mode}.toml").as_str())
            );
        }
    }

    #[test]
    fn maintenance_commands_parse_with_their_database_options() {
        let VarmanCommand::User { command } = parse(&[
            "varman",
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

        let VarmanCommand::Mode { command } =
            parse(&["varman", "mode", "observe"])
        else {
            panic!("expected the mode command");
        };
        assert!(matches!(command, ModeCommand::Observe(_)));

        let VarmanCommand::Security { command } =
            parse(&["varman", "security", "allowlist", "off"])
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
    fn config_commands_parse_with_their_filters() {
        let VarmanCommand::Config { command } = parse(&[
            "varman",
            "config",
            "history",
            "--site=global",
            "--limit=5",
            "--db-url=postgres://other/db",
        ]) else {
            panic!("expected the config command");
        };
        let ConfigCommand::History(opts) = command else {
            panic!("expected history");
        };
        assert_eq!(opts.site.as_deref(), Some("global"));
        assert_eq!(opts.limit, 5);
        assert_eq!(opts.db.db_url, "postgres://other/db");

        let VarmanCommand::Config { command } =
            parse(&["varman", "config", "show", "42", "--json"])
        else {
            panic!("expected the config command");
        };
        let ConfigCommand::Show(opts) = command else {
            panic!("expected show");
        };
        assert_eq!(opts.version, 42);
        assert!(opts.json);

        let VarmanCommand::Config { command } =
            parse(&["varman", "config", "rollback", "7", "--yes"])
        else {
            panic!("expected the config command");
        };
        let ConfigCommand::Rollback(opts) = command else {
            panic!("expected rollback");
        };
        assert_eq!(opts.version, 7);
        assert!(opts.yes);
    }

    #[test]
    fn every_subcommand_name_selects_varman_mode() {
        for name in declared_subcommands() {
            assert!(is_mode(&name), "{name} must select VarmanWAF mode");
        }
        assert!(!is_mode("reset-password"));
        assert!(!is_mode(""));
    }

    /// `argv` with `program` at index 0, the shape `std::env::args` produces.
    fn argv(program: &str, args: &[&str]) -> Vec<String> {
        std::iter::once(program.to_string())
            .chain(args.iter().map(|arg| arg.to_string()))
            .collect()
    }

    #[test]
    fn the_first_positional_and_env_var_select_the_expected_mode() {
        // A subcommand in the first positional selects VarmanWAF whichever
        // binary runs it.
        assert!(selects_varman_mode(
            "varman",
            &argv("varman", &["server"]),
            None
        ));
        assert!(selects_varman_mode(
            "pingap",
            &argv("pingap", &["config"]),
            None
        ));
        assert!(selects_varman_mode(
            "pingap",
            &argv("pingap", &["-d", "server"]),
            None
        ));
        // The value of a legacy option is not a positional.
        assert!(!selects_varman_mode(
            "varman",
            &argv("varman", &["-c", "server"]),
            None
        ));
        assert!(!selects_varman_mode(
            "pingap",
            &argv("pingap", &["--conf=server"]),
            None
        ));
        // Names are matched as typed, the token clap would parse.
        assert!(!selects_varman_mode(
            "varman",
            &argv("varman", &["SERVER"]),
            None
        ));
        assert!(!selects_varman_mode(
            "varman",
            &argv("varman", &["--version"]),
            None
        ));

        // Bare and help-only invocations of the varman binary show the
        // VarmanWAF parser; pingap keeps the legacy one. A legacy flag keeps
        // the flat proxy on the legacy parser.
        assert!(selects_varman_mode("varman", &argv("varman", &[]), None));
        assert!(selects_varman_mode(
            "varman",
            &argv("varman", &["--help"]),
            None
        ));
        assert!(selects_varman_mode(
            "varman",
            &argv("varman", &["-h"]),
            None
        ));
        assert!(selects_varman_mode(
            "varman",
            &argv("varman", &["--template"]),
            None
        ));
        // A legacy proxy flag keeps the template on the legacy parser too.
        assert!(!selects_varman_mode(
            "varman",
            &argv("varman", &["--template", "-c", "x"]),
            None
        ));
        assert!(!selects_varman_mode(
            "pingap",
            &argv("pingap", &["--template"]),
            None
        ));
        assert!(!selects_varman_mode("pingap", &argv("pingap", &[]), None));
        assert!(!selects_varman_mode(
            "pingap",
            &argv("pingap", &["--help"]),
            None
        ));
        assert!(!selects_varman_mode(
            "varman",
            &argv("varman", &["-c", "varman.toml"]),
            None
        ));

        // Environment: trimmed and lower-cased.
        assert!(selects_varman_mode(
            "pingap",
            &argv("pingap", &[]),
            Some("SERVER")
        ));
        assert!(selects_varman_mode(
            "pingap",
            &argv("pingap", &[]),
            Some(" mode ")
        ));
        assert!(!selects_varman_mode(
            "pingap",
            &argv("pingap", &[]),
            Some("reset-password")
        ));

        assert!(!selects_varman_mode(
            "pingap",
            &argv("pingap", &["--version"]),
            None
        ));
    }

    #[test]
    fn the_first_positional_skips_values_it_cannot_classify() {
        // A value-taking option ends the scan: the next token may be its value
        // (a config path named `server`), not a subcommand.
        assert_eq!(
            None,
            first_positional_index(&argv(
                "varman",
                &["-c", "varman.toml", "-d"]
            ))
        );
        assert_eq!(
            None,
            first_positional_index(&argv(
                "varman",
                &["--log", "/tmp/access.log", "server"]
            ))
        );
        // Value-free legacy options can precede the subcommand.
        assert_eq!(
            Some(2),
            first_positional_index(&argv("pingap", &["-d", "server"]))
        );
        // After `--` even a dashed token is positional.
        assert_eq!(
            Some(2),
            first_positional_index(&argv("varman", &["--", "server"]))
        );
        assert_eq!(
            Some(1),
            first_positional_index(&argv("varman", &["server"]))
        );
    }

    #[test]
    fn the_binary_identity_ignores_paths_and_test_harnesses() {
        assert!(invoked_as("/usr/local/bin/varman", "varman"));
        assert!(invoked_as("./varman", "varman"));
        assert!(!invoked_as("/usr/local/bin/varman-debug", "varman"));
        assert!(!invoked_as("/usr/local/bin/pingap", "varman"));
    }

    #[test]
    fn product_identity_is_decided_once() {
        assert_eq!(
            Identity::Varman,
            identity_for("varman", &argv("varman", &[]), None)
        );
        assert_eq!(
            Identity::Varman,
            identity_for("pingap", &argv("pingap", &["server"]), None)
        );
        assert_eq!(
            Identity::Varman,
            identity_for("pingap", &argv("pingap", &[]), Some("agent"))
        );
        assert_eq!(
            Identity::Pingap,
            identity_for("pingap", &argv("pingap", &[]), None)
        );
        // A renamed varman build, including the test harness, keeps the
        // VarmanWAF brand.
        assert_eq!(
            Identity::Varman,
            identity_for(
                "/tmp/varman-1234",
                &argv("/tmp/varman-1234", &[]),
                None
            )
        );
    }

    #[test]
    fn the_template_flag_is_recognised() {
        assert!(wants_template(&argv("varman", &["--template"])));
        assert!(wants_template(&argv("varman", &["server", "--template"])));
        assert!(!wants_template(&argv("varman", &["server"])));
    }

    #[test]
    fn the_version_flag_is_recognised_wherever_it_appears() {
        // With VARMAN_MODE the mode is injected, so the flag must be caught
        // before the subcommand would reject it as an unknown argument.
        let argv = |args: &[&str]| {
            args.iter().map(|arg| arg.to_string()).collect::<Vec<_>>()
        };
        assert!(wants_version(&argv(&["varman", "--version"])));
        assert!(wants_version(&argv(&["varman", "-V"])));
        assert!(wants_version(&argv(&["varman", "server", "--version"])));
        assert!(!wants_version(&argv(&["varman", "server", "--config=x"])));
        assert!(!wants_version(&argv(&["varman"])));
    }
}
