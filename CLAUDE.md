# CLAUDE.md

> **Current release:** [v1.5.0](docs/releases/v1.5.0.md). [HANDOFF.md](HANDOFF.md)
> is historical (v1.1.9); start from `docs/README.md`.

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project

VarmanWAF is a self-hosted WAF platform: the `varman` binary runs the control
plane (`varman-control`), the edge agent (`varman-agent`) and the Varman
detection engine (`varman-waf`), on top of the Pingap/Pingora foundation
crates (`pingap-*`). MSRV is `1.96.0`; the workspace package defaults to edition 2024, while several foundation crates still declare edition 2021. Pingora is `0.9.0` from crates.io; only the `lb`/`cache` features are enabled there, and the TLS backend feature (pingora's `openssl` or `rustls`) is added by pingap's own top-level `openssl` / `tls-rustls` features. The three `pingora*` entries in `[workspace.dependencies]` must always name the same version, or cargo resolves two copies of `pingora-core`.

**Build the pingora `Server` with `Server::new_with_opt_and_conf`, never `Server::new` followed by assigning `my_server.configuration`.** Since 0.8.1 the constructor snapshots the configuration into a private `Bootstrap`, and that snapshot — not `Server::configuration` — is what the receiving half of a hot upgrade reads `upgrade_sock` from. A later assignment silently leaves the two halves on different sockets.

### Versioning

Most crates inherit the workspace version `1.5.0` with `version.workspace = true`. Three internally published crates are the exception: `varman-waf`, `varman-challenge` and `varman-pprof` declare `version = "0.1.0"`, and `varman-pprof` is pinned at `0.1.0` in `[workspace.dependencies]`. A version bump must update those manifests and the `varman-pprof` requirement as well as `[workspace.package]` and the `pingap-*` dependency entries.

Editions are mixed by design: the workspace default is 2024, but `varman-agent`, `varman-protocol`, `varman-control` and most `pingap-*` foundation crates still declare 2021. MSRV is 1.96.0 for both. The internal `pingap-*` dependencies live in `[workspace.dependencies]`, so a member depends on a sibling with `{ workspace = true }`.

**Bumping the version means editing two places in the root `Cargo.toml`**: `workspace.package.version`, and the `version = "..."` on each `pingap-*` entry in `[workspace.dependencies]` — cargo has no way to inherit the package version into a dependency requirement. `publish.sh` then publishes the `pingap-*` foundation crates at the new version in dependency order; the Varman platform crates are path-only workspace members and are not published.

## Common commands

```bash
# Bacon-driven dev loop (uses --autoreload + data-plane admin API on :3018)
make dev                 # bacon run -- --features=full -- -c=... --admin=...

# Lint (CI gate — runs typos + clippy --features=full --all-targets -- -D warnings)
make lint

# Format
make fmt

# Full test suite (requires the `full` feature set)
make test                # cargo test --workspace --features=full
make test-rustls         # same suite built with the rustls TLS backend (also: make lint-rustls)

# One package / one test (use cargo directly, not make)
cargo test -p pingap-proxy
cargo test -p pingap-core util::tests::test_now_ms -- --nocapture

# Benchmarks (criterion)
make bench               # workspace-wide
make bench-all           # explicit list (pingap-core, pingap-logger, pingap-location)

# Release builds — see Makefile for the matrix
make release             # default features
make release-full        # tracing + imageoptim
make release-perf        # release-perf profile, includes pyroscope agent

# Web console assets (rust-embed'd from web/dist into varman-control)
make build-web           # cd web && npm install && npm run build

# Pre-commit hook (runs `make lint`)
make hooks               # cp hooks/* .git/hooks/
```

Bacon shortcuts: `bacon` (check), `bacon clippy-all`, `bacon test`, `bacon test -- some::path`, `bacon nextest`, `bacon doc-open`.

## Architecture

The workspace has two layers (the graph in `docs/modules.md` is generated
from every member's `Cargo.toml` by `src/bin/generate-mermaid.rs`):

- **Varman platform** — the root `varman` binary, `varman-control` (control
  plane, REST/gRPC, console), `varman-agent` (edge client), `varman-waf`
  (pipeline engine), `varman-plugin` (WAF, challenge, cache, rewrite, error-page,
  stream/processor/shadow/custom plugins), `varman-protocol`, `varman-challenge`, `varman-pprof`.
- **Pingap foundation** — `pingap-core`, `pingap-config`, `pingap-proxy`,
  `pingap-plugin`, `pingap-upstream`, `pingap-discovery`, `pingap-health`,
  `pingap-location`, `pingap-cache`, `pingap-certificate`, `pingap-acme`,
  `pingap-logger`, `pingap-performance`, `pingap-otel`/`sentry`/`pyroscope`,
  `pingap-webhook`, `pingap-imageoptim`, `pingap-util`.

- `pingap-core` — `HttpResponse`, `Ctx`, plugin traits, clock helpers (`now_sec`/`now_ms`), `BackgroundTaskService`. Every other crate depends on it.
- `pingap-config` — `PingapConfig` model plus storage backends (`file_storage.rs`, `etcd_storage.rs`) chosen at runtime by URL prefix (`file://`, `etcd://`). Supports TOML, HCL (`hcl.rs`), and KDL (`kdl.rs`) input formats.
- `pingap-proxy` — implements pingora's `ProxyHttp`. The request lifecycle in `pingap-proxy/src/server.rs` calls (in order) `early_request_filter` -> `request_filter` -> `proxy_upstream_filter` -> `upstream_request_filter` -> `upstream_response_filter` -> `logging`. Each step matches the `PluginStep` enum in `pingap-core/src/plugin.rs` (`EarlyRequest`, `Request`, `ProxyUpstream`, `UpstreamResponse`, `Response`); a plugin runs at most one step per request.
- `pingap-plugin` — generic Pingap plugins and the plugin factory. Add a generic plugin by implementing the `Plugin` trait from `pingap-core` and registering it via the plugin factory; Varman-specific plugins live in `varman-plugin`.
- `pingap-upstream` — pingora `Backends` + load-balancing wiring; gets its backend set from `pingap-discovery` (static / DNS / Docker labels / transparent) and `pingap-health` for active checks.
- `src/main.rs` — argument parsing, config bootstrap, daemonization, server assembly. `src/varman/` is the all-in-one platform mode, `src/cli.rs` the Varman CLI, `src/maintenance.rs` the PostgreSQL maintenance commands (`varman user|mode|security|config`), and `src/quick_start.rs` the starter config. `src/process/` and `src/plugin/` handle hot reload and the data-plane admin plugin.
- `--admin` is the **data-plane admin JSON/profiling API** (`PINGAP_ADMIN_*`) and serves no console; `--admin-addr` / `VARMAN_ADMIN_ADDR` is the **control-plane console + REST listener** (`varman server`, default `0.0.0.0:9080`). They are different features.
- `build.rs` — uses `vergen = "10.0.3"` + `vergen-git2 = "10.0.3"` to embed `VERGEN_GIT_SHA` into the binary's `--version`. **Both crates must stay on matching majors**; if you see `Add` trait-bound errors from `vergen_lib`, the lockfile has pulled mismatched versions — refresh it. The emitter runs with `default_on_error()`: vergen 10 otherwise leaves `VERGEN_GIT_SHA` unset when there is no `.git` (source export, crates.io tarball) and `env!()` stops compiling; with it the value is `VERGEN_IDEMPOTENT_OUTPUT`, which `git_hash()` in `src/main.rs` reports as `unknown`.
- `examples/` — working configs to copy from: `api-gateway`, `grpc-web`, `static-serve`, `transparent-proxy`, `web-socket`.

### Hot reload vs auto-restart

`src/main.rs` branches on `pingap_config::ConfigManager::support_observer()`. **etcd** returns `true` and pushes changes via a `WatchStream` (`pingap-config/src/etcd_storage.rs`) wired through `new_observer_service`. **File** storage returns `false` and is polled by `new_auto_restart_service` (`src/process/auto_restart.rs`) on a fixed interval. Both feed the same `reload_handle` — the difference is only the delivery mechanism. `--autoreload` keeps the process and swaps config in place; `--autorestart` performs a zero-downtime graceful restart for changes that need a fresh listener.

The restart hand-over (`src/process/common.rs::restart_now`) is readiness-driven, not timer-driven, and the channel is pingap's own. `restart_now` binds a unix socket at `<upgrade_sock>.ready`, spawns the replacement with `-d -u` and `PINGAP_READY_SOCK` in its environment, and waits: the new process runs `ReadyNotifyService` (added in `main.rs`, and made a dependency of the bootstrap service) which connects to that socket right before bootstrap asks the old process for the listening sockets. Only then does the old process send itself SIGQUIT; if the spawned process exits non-zero, the daemon it forked disappears (watched through the shared pid file), or `basic.restart_ready_timeout` passes, the restart is abandoned and the old process keeps serving. This cannot deadlock because the report precedes `load_fds`. It relies on `Server::bootstrap_as_a_service()`: every listening service is added with `.add_dependency(&bootstrap_handle)` so it builds its sockets from the inherited fds instead of binding fresh ones.

**Do not switch to pingora's `daemon_wait_for_ready`.** Its parent side waits on a tokio SIGUSR1 listener, and tokio's signal wake-up pipe is process-global. pingap creates a tokio runtime before the fork (config loading), so the daemon inherits that pipe (verified with `lsof`: parent and daemon hold the same unix socket pair), its runtimes drain the wake-up, and the parent never sees the signal: it waits the full timeout and exits 1 while the daemon runs fine. pingora's own `graceful_upgrade` example, which creates no runtime before the fork, works on the same machine.

### Daemonization and background threads

Pingora forks inside `Server::run()` (what `run_forever()` wraps) for daemon mode, **after** `bootstrap()` and **before** the service runtimes start. `fork()` only carries the calling thread, so **any `std::thread` started before that point does not exist in the daemon**, and any handle to it is a handle to nothing — joining one gives `EINVAL`. Long-lived threads must be started from a pingora `BackgroundService`, which runs post-fork, not from a `#[ctor]` or from `run()`.

This is why `now_sec()`/`now_ms()` read the system clock directly (`SystemTime::now()`, ~18ns) instead of caching it in a background-updated global. The coarse clock that used to back them saved ~17ns per call but needed a thread, and the only per-request caller left was `ttl_lru_limit`; the fork-safety machinery it required had already caused one real bug (admin auth reading an hours-stale timestamp in daemon mode).

`main.rs` runs the server with `Server::run(RunArgs::default())` rather than `run_forever()`: `run` returns once every runtime has exited, which is where `webhook::flush_pending_before_exit()` posts the webhook batch a fast shutdown (SIGINT, no shutdown broadcast) would otherwise drop, before `process::exit(0)`. Graceful shutdowns are covered earlier by `WebhookFlushService`, which flushes when the shutdown watch flips.

### Plugin step contract

`PluginStep` is matched to the pingora callback by `pingap-proxy/src/server.rs`. Plugins return `RequestPluginResult` (`Skipped` / `Continue` / `Respond(HttpResponse)`) or `ResponsePluginResult`. Respect the configured `step` value — running a request plugin at `Response` is silently a no-op.

A location resolves its plugin names once and caches the `Arc<[NamedPlugin]>` (`Location::plugins_for`), keyed on `PluginProvider::version()`; a request only bumps the reference count. Any `PluginProvider` whose plugins can change must return a new version after every replacement (the binary's provider bumps it in `store`), or locations keep serving the old instances.

### Config formats

The same configuration can be expressed in TOML (canonical, see `conf/*.toml`), HCL (`conf/test.hcl`), or KDL (`conf/test.kdl`). `--to-hcl` and `--to-kdl` round-trip the loaded config. The `--sync <url>` flag pushes the loaded config to a different backend (e.g. file -> etcd). `--template` prints a starter TOML and exits.

## Features and feature gates

The top-level `[features]` block in `Cargo.toml`:

- `default` = `openssl`.
- `openssl` / `tls-rustls` — the TLS backend, exactly one of them. Each forwards pingora's `openssl` or `rustls` feature plus the same-named feature of `pingap-acme`, `pingap-certificate`, `pingap-performance`, `pingap-proxy` and `pingap-upstream`; those five carry `default = ["openssl"]` themselves (so `cargo test -p <crate>` keeps working) and are depended on with `default-features = false` in `[workspace.dependencies]` so the root's choice wins. Only `pingap-certificate` (`LoadedCertificate`, `GlobalCertificate`) and `pingap-upstream` (`new_ca`) contain backend-specific code, and both `compile_error!` when neither or both features are on. Build the rustls variant with `cargo build --no-default-features --features tls-rustls[,full]`; `make lint-rustls` / `make test-rustls` are its CI gates. Under rustls the per-server `tls_min_version`, `tls_max_version`, `tls_cipher_list` and `tls_ciphersuites` are rejected by `validate_servers_tls_for_backend` at config validation (pingora's rustls listener fixes TLS 1.2/1.3 and rustls' default suites), `TlsAccept::certificate_callback` is never invoked (certificates come from `GlobalCertificate`'s `ResolvesServerCert` impl), and the rustls crypto provider is ring, installed explicitly in `main`; `install_default_crypto_provider()` is the idempotent library-side safeguard. `pingap_certificate::TLS_BACKEND` names the backend at runtime (`--version`, startup log, admin `/basic` features).
- `tracing` — turns on `pingap-otel` + `pingap-sentry`, and the `tracing` feature on `pingap-cache`, `pingap-core`, `pingap-performance`, `pingap-proxy`, and pingora's `sentry`. **`pingap-cache/tracing` also pulls in `prometheus`** — needed for any code touching cache metrics.
- `imageoptim` — `pingap-imageoptim` (png/jpeg/webp/avif).
- `full` = `tracing` + `imageoptim`. Required by `make test` and `make lint`.
- `pyro` — pyroscope agent.
- `perf` = `pyro` + `full`, paired with the `release-perf` profile (keeps debug info, no strip).

When adding a feature-gated module, mirror the wiring in both the workspace `Cargo.toml` and the consuming crate's `Cargo.toml`, and gate the `use`/registration with `#[cfg(feature = "...")]`.

## Configuration loading and env vars

`src/main.rs::parse_arguments()` overlays CLI args with `PINGAP_*` env vars. Anything not on the CLI falls back to env: `PINGAP_CONF`, `PINGAP_DAEMON`, `PINGAP_UPGRADE`, `PINGAP_LOG`, `PINGAP_ADMIN_ADDR`/`PINGAP_ADMIN_USER`/`PINGAP_ADMIN_PASSWORD` (these three combine into `--admin user:pass@addr` with base64-encoded creds). Other env vars used at runtime: `VARMAN_DISABLE_ACME` (legacy alias `PINGAP_DISABLE_ACME`), and `$ENV:...` interpolations inside HCL configs (e.g. `$ENV:PINGAP_DNS_SERVICE_URL`).

CLI flags worth knowing: `-c/--conf <url>`, `-d/--daemon`, `-u/--upgrade` (hot upgrade from a running instance), `-t/--test` (validate config and exit), `-a/--autorestart` (graceful restart on config change), `--autoreload` (hot reload only — preferred for containers), `--cp` (control-panel mode, admin only).

## Lint and code style notes

- `clippy.toml` denies unwrap outside tests, sets `cognitive-complexity-threshold = 10`, and pins `msrv = "1.96.0"`. The root `Cargo.toml` adds `unwrap_used = "deny"`.
- CI runs `cargo clippy --features=full --all-targets --all -- --deny=warnings` plus `typos`. Run `make lint` before pushing.
- The git pre-commit hook (installed via `make hooks`) just runs `make lint`.
- `typos.toml` excludes `*.md` and `*.toml` from the spell check — typos in those file types will not be caught by `make lint`.

## CI gates

CI is local: the GitHub Actions workflows were removed. Run the gates below
before committing; `hooks/pre-push` runs `make test`. The table maps each
historical CI step to its local command:

| CI step | Local equivalent |
|---|---|
| `cargo fmt --all -- --check` | `make fmt` (auto-fixes) or run the check directly |
| `make lint` (typos + clippy `--features=full -D warnings`) | `make lint` |
| `cargo machete` | `cargo install cargo-machete@0.9.1 && cargo machete` — `Cargo.toml` whitelists `humantime-serde`, `include-flate`, `hcl-rs`, `kdl` in `[package.metadata.cargo-machete]` |
| `make test` (`cargo test --workspace --features=full`) | `make test` |
| `make lint-rustls` + `make test-rustls` (rustls TLS backend; full suite on stable, `cargo check --features tls-rustls,full` on MSRV) | `make lint-rustls && make test-rustls` |
| `cargo msrv list` | `cargo install cargo-msrv --version 0.18.4 && cargo msrv list` |
| `cargo llvm-cov` | `make cov` |
| `make release-all` (builds both `pingap` and `pingap-full`) | `make release-all` |
| `make build-web` (web assets) | `make build-web` |

### Release toolchain vs MSRV

The MSRV (`rust-version` in `Cargo.toml`, `msrv` in `clippy.toml`) is a floor
proved by `cargo msrv list`. Release binaries use the **pinned recent stable**
in the `Dockerfile`, deliberately newer. `make release-all` builds the default
and `-full` binaries; `make release-rustls-full` builds `tls-rustls,full`
without OpenSSL. The published tarballs and Docker variants are produced from
these targets and the `Dockerfile`; the former workflow steps now run locally.

## Web admin

`web/` is the Vite/React console. After editing it, run `make build-web` so the compiled assets in `web/dist/` get embedded into `varman-control` via `rust-embed` at compile time. The console is served by the control plane (`varman server --admin-addr <addr>`, or `VARMAN_ADMIN_ADDR`; default `0.0.0.0:9080`) next to its `/api/v1` REST API. The data-plane admin plugin behind `--admin user:pass@host:port[/prefix]` is API only — `/configs`, `/config-history`, `/basic`, `/restart`, `/aes`, `/certificates`, `/pprof/*` — and serves no UI; `make dev` exposes that API on `127.0.0.1:3018`.

**Every config field the console edits must have a form item in `web/`.** The console is site-centric: a field added to a config struct that a site or the control plane exposes through `/api/v1` is not done until the operator can see and edit it. Add the field to the matching interface under `web/src/api/` (`sites.ts`, `ssl.ts`, `settings.ts`, `wafSettings.ts`, ...) and the control to the owning page or panel: `web/src/pages/sites/*` for per-site policy, `SettingsPage.tsx` for instance settings, `GlobalSslPage.tsx` for control-plane TLS. A plugin field belongs in the panel that owns that plugin (for example `ProtectionSettingsPanel.tsx`); there is no generic plugin builder any more. Each item needs its label, placeholder and help text in `web/src/i18n/locales/en/common.json` (the console ships one locale). Follow the existing control for the Rust type: a toggle for `Option<bool>`, a select with an explicit "unset" choice for enum-like `Option<String>`, a tag/text list for `Option<Vec<String>>`, a number input for integers, and text with duration/byte validation for durations and sizes.

Keep "unset" distinct from an explicit `false` or empty string when building the request payload, and send only the fields the form owns. Verify a new item end to end in the console (run `varman server` with `--admin-addr` after `make build-web`): the value renders, an edit is saved, and clearing it removes the key or restores the documented default.

## Documentation (English only)

VarmanWAF documentation is **English only**. The source of truth is `docs/`
(index: `docs/README.md`); the public site is generated from it by
`website/build.mjs` (`cd website && npm run build`). The inherited VitePress
toolchain (`website/.vitepress/`, `scripts/build-website.sh`) and the GitHub
Pages workflow have been removed. When a behaviour change touches a config
key, a default, a CLI flag or a plugin, update the matching file in `docs/`;
security-engine changes also update `docs/security-engine.md` and the status
in `docs/roadmap.md`.
