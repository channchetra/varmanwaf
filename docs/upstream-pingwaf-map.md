# Upstream PingWAF Map (Phase 0)

> Status: **complete for the imported baseline.** This document maps the upstream
> codebase that VarmanWAF is built on, records what was inspected, and fixes the
> retain/rename/redesign decisions that later phases execute. No major rewrite may
> start before this map exists (mandate §41).

## Provenance

| Item | Value |
|---|---|
| Upstream | https://github.com/shuaiZend/PingWAF |
| Imported commit | `c87ef671` — “docs(waf): add post20 rule-grading zero-regression verification results” |
| Imported version | `0.20.0` (`[workspace.package]` in root `Cargo.toml`) |
| License | Apache-2.0 (`LICENSE`), CLA in `CLA.md` |
| Import commit in VarmanWAF | `1489ca4` — “chore: import PingWAF v0.20.0 as the VarmanWAF foundation” |
| Pristine reference clone | `C:\Users\MPTC\Desktop\waf-dev\PingWAF` (kept untouched) |
| Local reference forks | `C:\Users\MPTC\Desktop\waf-dev\references\*` (see `docs/references.md`) |

How this map was produced: workspace manifest and crate inspection, entry-point and
lifecycle reading, gRPC protobuf review, SeaORM model/migration review, Docker and
frontend inspection, plus the upstream-internal review document
`docs/waf-engine-review.md`. File paths below are relative to the repository root.

---

## 1. Repository layout

VarmanWAF starts as PingWAF, which is itself an evolution of
[Pingap](https://github.com/vicanso/pingap): a Pingora-based reverse proxy.
PingWAF adds a control plane, an edge agent, and a WAF engine on top.

Workspace members (25 crates) fall into two families:

### 1.1 Proxy foundation — `pingap-*` (retained)

| Crate | Purpose | Varman decision |
|---|---|---|
| `pingap-core` | `Ctx`, `HttpResponse`, plugin traits, clock helpers, background services | Retain |
| `pingap-util` | Shared utilities incl. `IpRules` CIDR matcher | Retain |
| `pingap-config` | Config model + file/etcd storage, TOML/HCL/KDL | Retain |
| `pingap-cache` | HTTP cache plugin | Retain |
| `pingap-certificate` | Certificate loading/provider (openssl or rustls) | Retain |
| `pingap-discovery` | Static/DNS/Docker/transparent upstream discovery | Retain |
| `pingap-health` | Active upstream health checks | Retain |
| `pingap-location` | Location matching | Retain |
| `pingap-logger` | Access logging | Retain |
| `pingap-plugin` | All proxy plugins, including the security plugins (see §8) | Rename security plugins later; retain crate for now |
| `pingap-proxy` | Pingora `ProxyHttp` implementation, request lifecycle | Retain — **the data plane foundation** |
| `pingap-upstream` | Pingora `Backends` + load balancing | Retain |
| `pingap-acme` | ACME client (HTTP-01/DNS-01) | Retain |
| `pingap-performance` | Performance metrics helpers | Retain |
| `pingap-otel`, `pingap-sentry`, `pingap-pyroscope` | Telemetry exporters (feature-gated) | Retain |
| `pingap-imageoptim` | Image optimization plugin (feature-gated) | Retain, optional |
| `pingap-webhook` | Outbound webhook batching | Retain |

Rationale for keeping `pingap-*` names: they are internal identifiers, the mandate
requires user-facing branding removal first, and a mass crate rename is high-risk
churn. A later mechanical rename is possible once the platform stabilizes.

### 1.2 WAF platform — `pingwaf-*` (to be renamed `varman-*`)

| Crate | Purpose | Varman decision |
|---|---|---|
| `pingwaf-server` | Control plane: REST API, gRPC server, migrations, auth, dashboard hosting, self-protection, AI assistant, MCP server | Rename → `varman-control`; **retain architecture** |
| `pingwaf-agent` | Edge client: registration, heartbeat, config/rule cache, log/metric shipping, blocked-IP ledger | Rename → `varman-agent` |
| `pingwaf-waf` | Current detection engine: normalize + signatures + expression rules + anomaly score | Rename → `varman-waf`; **engine: redesign in Phase 2+** |
| `pingwaf-proto` | gRPC/protobuf definitions (`control_plane.proto`) | Rename → `varman-protocol` |
| `pingwaf-challenge` | JS challenge, clearance cookies, fingerprints, block/auth pages | Rename → `varman-challenge` |
| `pingwaf-pprof` | Profiling endpoint | Rename → `varman-pprof` |

### 1.3 Root binary and entry points

- `src/main.rs` — dual `[[bin]]`: `pingap` and `pingwaf`, both from the same source.
- `src/cli.rs` — `PingWafCli` subcommands: `server`, `agent`, `all-in-one`, `user`,
  `mode` (observation mode), `security` (control-plane self-protection).
- Without a subcommand the binary runs plain Pingap proxy mode (`-c config.toml`).
- `src/pingwaf.rs` — mode assembly: builds `ServerConfig`/`AgentConfig`, converts
  the agent rule cache into a live Pingap config (`cached_rules_to_pingap_config`,
  line ~298), wires ACME, starts proxy + agent in `all-in-one`.
- `src/plugin/admin.rs` — Pingap's own admin UI plugin (embeds `dist/`).

Runtime modes:

| Mode | Process contents | Control plane required at request time? |
|---|---|---|
| `server` | Control plane only | — |
| `agent` | Proxy + agent | No (cached rules; `fail_open`) |
| `all-in-one` | Control plane + proxy + agent in one process; agent dials loopback gRPC | No (same-process, is resilient to gRPC loss) |

---

## 2. Request lifecycle (data plane)

Pingora server → `pingap-proxy/src/server.rs` (`ProxyHttp` impl). Callback order
documented in `CLAUDE.md`:

```
early_request_filter → request_filter → proxy_upstream_filter
  → upstream_request_filter → upstream_response_filter → logging
```

Plugins bind to one `PluginStep` each (`EarlyRequest`, `Request`, `ProxyUpstream`,
`UpstreamResponse`, `Response`); a plugin runs at most one step per request.

Security plugin order for every site location (built in
`src/pingwaf.rs::cached_rules_to_pingap_config`):

```
waf → challenge → rewrite → error_page → (cache, when cache rules exist)
```

- `waf` runs at `EarlyRequest` and is the single enforcement point for:
  WAF rules, site-wide basic auth, IP access rules, rate limiting, geo rules,
  bot protection, access-log capture and security-event emission.
- `challenge` serves the JS challenge / block / paused / rate-limit / basic-auth
  pages and verifies the clearance cookie.

Locations and upstreams are generated per site (including alternate domains) from
the agent rule cache, then applied to the proxy through Pingap's config reload
mechanism (no proxy restart).

### 2.1 Lane mapping (current vs. target)

The current stack already has rough equivalents of parts of the Varman pipeline:
IP ACL + rate limiting + geo + bot run **inside one plugin**, WAF signatures run in
`pingwaf-waf`, and there is no semantic lane, no SecLang, and no response
inspection beyond the error-page/rewrite plugins. See §8 for engine internals.

---

## 3. Control plane (`pingwaf-server`)

Boot sequence (`pingwaf-server/src/lib.rs::start_server`): validate config →
connect PostgreSQL → run SeaORM migrations → seed admin + IP group defaults →
start optional Elasticsearch shipper → control-plane TLS → self-protection →
serve HTTP (axum) and gRPC concurrently.

### 3.1 REST API

Prefix: `/api/v1`. Route modules (`pingwaf-server/src/api/mod.rs`):

| Group | Modules |
|---|---|
| Identity | `auth`, `passkeys`, `keys` (API keys), `users` via `auth` |
| Sites | `sites`, `site_basic_auth`, `ssl`, `mtls`, `system_tls` |
| Rules & policy | `rules`, `waf_settings`, `rate_limiting`, `ip_rules`, `ip_groups`, `blocked_ips`, `geo`, `bot`, `challenge`, `rewrite`, `error_pages` |
| Agents | `agents`, `debug` |
| Observability | `logs`, `analytics`, `log_retention`, `cache` |
| Platform | `settings`, `defense`, `api_protection`, `ai`, `mcp` |
| Health | `/health`, `/version`, root `/healthz` |

Also: hosted MCP endpoint at `/mcp` (outside `/api/v1`) and the embedded React
dashboard. Middleware layers: tracing, CORS, gzip, auth, and the
self-protection stack (access log, IP allowlist, WAF) — the control plane runs its
own `WafEngine` instance against its own admin requests
(`api/self_protection.rs`).

### 3.2 gRPC protocol (`pingwaf-proto/proto/control_plane.proto`)

`service ControlPlane`:

| RPC | Shape | Purpose |
|---|---|---|
| `RegisterAgent` | unary | API key + host facts → `agent_id`, JWT `agent_token`, heartbeat interval, initial `SiteConfig` |
| `Heartbeat` | bidi stream | agent metrics/status/blocked-IPs up; `ServerCommand` down (rule update, config reload, block/unblock IP, purge cache, update site, restart) |
| `SyncRules` | server stream | pushes `RuleBundle` per site (delta via `config_hash`) |
| `GetSiteConfig` | unary | pulls full `SiteConfig` (all sites + bundles) |
| `ShipLogs` | client stream | access + security log entries, truncated bodies per config |
| `ShipCertEvents` | client stream | raw ACME/certificate lifecycle log lines |
| `ShipMetrics` | client stream | metric batches |

`RuleBundle` (per site) carries: WAF config + custom rules + overrides, rate-limit
rules, IP access rules, geo, cache rules, challenge config, rewrite rules, error
pages, SSL config, upstreams, routes, bot protection, basic auth, and
`observation_mode`.

### 3.3 Other control-plane subsystems

- `auth/` — JWT sessions, bcrypt passwords, WebAuthn passkeys.
- `es/` — optional Elasticsearch log shipping (PostgreSQL-only install must work).
- `ai/` — assistant provider + conversational agent (`ai_settings`, `ai_conversations`, `ai_messages`).
- `mcp/` — MCP server exposing tools/resources/prompts for AI clients.
- `grpc/` — `control_plane.rs` service impl, `registry.rs` (agent registry),
  `config.rs` (bundle assembly), `cache_status.rs` (per-agent cache status).
- `monitoring.rs` — background retention/cleanup of metrics/logs.

---

## 4. Edge agent (`pingwaf-agent`)

Modules: `client/` (gRPC lifecycle), `cache/` (local persistence), `heartbeat/`
(metrics collector), `config/`, `probe/` (host samples), `cert_status.rs`,
`cert_events.rs`.

Lifecycle:

```
start()
  ├─ RuleCache::new(cache_dir, agent_id)   ← loads persisted rules + blocked IPs
  ├─ MetricsCollector
  ├─ ControlPlaneClient
  ├─ register()  → agent_token, heartbeat interval, initial config
  └─ background tasks: connection loop, heartbeat, log shipper,
     cert-event shipper, metric shipper
```

- **Reconnect**: exponential backoff (`next_backoff`), server-provided heartbeat
  interval wins over local config.
- **Rule cache** (`cache/mod.rs`): `CachedRules { sites: HashMap<domain, SiteRules>, .. }`
  + per-site bundles converted from proto; blocked-IP ledger with expiry
  (`BlockedIpEntry::is_expired`); atomic JSON persistence to `cache_dir`;
  `config_hash()` for delta sync; quota accounting for site caches.
- **Autonomy**: agent serves from cache when the control plane is down
  (`fail_open` config). Blocked IPs are reconciled with the control plane on
  heartbeat.
- **Blocked-IP flow**: WAF verdict block → `agent.block_ip()` → local early-refusal
  ring → reported on next heartbeat → control plane persists to
  `agent_blocked_ips` → replayed as `BlockIpCommand` to other agents.

Types the agent exposes to the host: `SecurityEvent`, `AccessLogEntry`,
`get_rules_for_domain(host)`, `get_rules_for_site(site_id)`, `is_ip_blocked`.

---

## 5. Data model (PostgreSQL, SeaORM)

30 migrations (`pingwaf-server/src/migration/`), ~40 tables. Grouped:

| Domain | Tables |
|---|---|
| Identity | `users`, `api_keys`, `passkey_credentials`, `passkey_states` |
| Sites | `sites`, `site_ssl`, `site_upstreams`, `site_upstream_pools`, `site_routes`, `site_basic_auth`, `ip_group_sites` |
| Security policy | `rules`, `rule_groups`, `rate_limit_rules`, `cache_rules`, `ip_access_rules`, `ip_groups`, `geo_rules`, `bot_protection`, `challenge_settings`, `waf_settings`, `defense_settings`, `rewrite_rules`, `error_pages`, `api_protection_settings` |
| Agents | `agents`, `agent_metrics`, `host_samples`, `agent_blocked_ips` |
| Certificates | `site_certificates`, `mtls_cas`, `mtls_client_certificates`, `control_plane_certificates` |
| Logs & events | `access_logs`, `security_events`, `control_plane_access_logs`, `certificate_events`, `rate_limit_stats` |
| Retention/settings | `log_retention_settings` |
| AI | `ai_settings`, `ai_conversations`, `ai_messages` |

Observations relevant to the mandate: there is **no config-version / deployment
table** yet (sections §15–16 of the mandate): bundles are assembled per request
from live rows and identified by a content hash. Phase 2+ should add explicit
desired/active/last-good version tracking.

---

## 6. Certificate lifecycle

- **Site certificates**: `site_certificates` rows; selected per site via
  `SslConfig.certificate_id`; PEM pairs.
- **ACME**: edge-side issuance (`pingap-acme`) with HTTP-01/DNS-01; state file
  under the agent cache dir (`acme_state_path`); DNS provider config travels in
  `SslConfig`.
- **Status reporting**: the host registers a cert-status snapshot
  (`pingwaf_agent::cert_status`); heartbeats carry per-site
  `SiteStatus.ssl_status`/`ssl_expires_at`; `AcmeCaptureLayer` ships raw issuance
  logs via `ShipCertEvents` → `certificate_events`.
- **mTLS**: `mtls_cas` + `mtls_client_certificates`; the listener verifies the
  chain against the union of per-site CAs; the WAF plugin enforces per-site
  require/revocation/organization pinning.
- **Control-plane HTTPS**: `control_plane_certificates`; self-signed generated on
  first boot (dashboard is HTTPS by default; passkeys require a secure origin).

---

## 7. Deployment, build, frontend

### 7.1 Docker

- `docker-compose.yml`: `pingwaf` (all-in-one) + `postgres:16-alpine`; published
  ports 80/443/9080/9090; volumes `pingwaf-data` (`/var/lib/pingwaf`),
  `pingwaf-certs` (`/etc/pingwaf/certs`), `postgres-data`; healthcheck
  `GET /healthz`; env `PINGWAF_*` (`DB_URL`, `MODE`, `JWT_SECRET`, `ADMIN_ADDR`,
  `GRPC_ADDR`, `ADMIN_EMAIL`, `ADMIN_PASSWORD`, `TLS_ENABLED`,
  `HEARTBEAT_INTERVAL`, ...). Distributed mode = uncomment the `pingwaf-agent`
  service and switch `PINGWAF_MODE=server`.
- `Dockerfile`: 3 stages — node:22 build of `web/` → rust:1.98.1-bookworm builder
  (protobuf, cmake, clang, openssl, nasm; dependency warm-up layer; `--features
  full`) → debian:trixie-slim runtime, non-root `pingwaf` user, binary
  `/usr/local/bin/pingwaf`, config `/etc/pingwaf/pingwaf.toml`.
- `entrypoint.sh`: legacy arg dispatcher (prepends `pingap` for flag-style args).

### 7.2 Build commands

```bash
cargo build --release            # both binaries (openssl TLS default)
cargo build --no-default-features --features tls-rustls,full
docker build .                   # full image incl. frontend
make lint / make test            # CI gates: typos + clippy -D warnings + tests
```

Rust MSRV: 1.96 (edition 2024); release toolchain pinned to 1.98.1.
Pingora is Linux/Unix-oriented: builds and runtime target Linux (verified:
this Windows host builds via the `varman-dev` Docker container).

### 7.3 Frontend

`web/` is Vite 8 + React 19 + TypeScript + Tailwind 4 + React Router 7 +
TanStack Query 5 + Zustand + i18next (en/zh). Pages: `DashboardPage`,
`SitesListPage`, `SiteDetailPage` (incl. Web Protection), `GlobalTrafficPage`,
`GlobalSslPage`, `AgentsPage`, `LifecyclePage`, `LogsPage`, `RateLimitingPage`,
`IpGroupsPage`, `SettingsPage`, `AssistantPage`, `LoginPage`. Built to `web/dist/`
and embedded into the control-plane binary via `rust-embed`
(`pingwaf-server/src/frontend.rs`, folder `../web/dist/`). Pingap's separate admin
UI (`src/plugin/admin.rs`, embeds root `dist/`) also still exists.

CI workflows: `ci.yml`, `release.yml`, `audit.yml`, `mark-stale.yaml`.
Images: `ghcr.io/shuaizend/pingwaf:latest`.

---

## 8. Current WAF integration (what Phase 2 will replace)

### 8.1 Enforcement point

`pingap-plugin/src/waf.rs` (~4.4k lines, `EarlyRequest`). Per request:

1. Resolve host → `agent.get_rules_for_domain(host)` → build/refresh a per-domain
   `Arc<WafEngine>` keyed on the agent's config hash (`EngineChoice::Base |
   Site(engine) | Disabled`).
2. Site basic auth gate (before everything).
3. IP access rules → geo → bot → rate limit (all in this plugin).
4. `WafEngine::inspect(RequestData)` → `WafVerdict`.
5. Verdict mapping: Pass/Monitor continue; Block → 403 error page; Challenge →
   challenge subsystem; events (`SecurityEvent`) and (`AccessLogEntry`) queued to
   the agent (non-blocking).
6. mTLS policy enforcement; internal header hygiene.

### 8.2 Engine (`pingwaf-waf`) internals

```
RequestData
  → normalize_request(): percent multi-decode (≤ max layers), HTML entity decode,
    path collapse, query/cookie/header/body extraction; strict level also decodes
    \xHH/\uHHHH escapes → decoded_values (source + name + value)
  → Stage 1: Aho-Corasick (~113 needles, LeftmostLongest, case-insensitive) +
    libinjection-style detect_sqli/detect_xss + shape checks
  → fast path: critical hit → Block (no Stage 2)
  → Stage 2: up to 14 built-in managed rules (Cloudflare-like expression DSL) +
    control-plane custom rules (parse_expression → CompiledRule)
  → AnomalyScorer: severity/category points, threshold default 40, paranoia 1–4,
    strict level, per-site monitor categories/stacks downgrade (scored but not
    blocking), observation mode site-wide
  → WafVerdict { action, score, hits, ... }
```

The `WafLevel` (normal/strict) and `StackSet` (backend technology) already exist
as concepts — directly reusable by the mandate's Lane 0/2 filters and backend
technology awareness.

### 8.3 Upstream's own review findings

`docs/waf-engine-review.md` (Chinese) documents known gaps in this engine, e.g.:
body inspection is gated on agent presence (`agent.is_some() && (body_limit > 0 ||
inspect_body)`) so POST bodies can bypass detection; `+` is not decoded in the
query; `WAITFOR DELAY`-style SQL doesn't match without whitespace normalization.
These are direct inputs to the Varman engine roadmap (Phases 4–6).

---

## 9. Branding inventory (user-facing)

Case-insensitive count of `pingwaf` occurrences at import time:

| Area | Count |
|---|---|
| `docs/` | 473 |
| `src/` | 234 |
| `README.md` | 108 |
| `web/` | 89 |
| `install.sh` | 85 |
| `docker-compose.yml` | 57 |
| `Dockerfile` | 55 |
| `Cargo.toml` | 46 |
| `.github/` | 45 |
| `pingwaf.toml` | 22 |
| `pingwaf.service` | 15 |

Renames must be incremental and keep the tree buildable (mandate §2, §41).

---

## 10. Phase 1 rename plan (execution order)

1. **Repository identity** (this repo): README, LICENSE header note, `VarmanWAF.md`
   kept as the mandate document.
2. **CLI & runtime identity**: binary `pingwaf` → `varman`; clap names/version
   banner; subcommands unchanged; env prefix `PINGWAF_` → `VARMAN_`; default
   admin email/password/DB URL; cache/config path defaults
   (`/etc/varman`, `/var/lib/varman`).
3. **Deployment**: `Dockerfile` (binary name, paths, user), `docker-compose.yml`
   (service/container/volume names, env vars, image name), `pingwaf.toml` →
   `varman.toml`, `pingwaf.service` → `varman.service`, `install.sh`, `.github`
   workflows (artifacts keep working).
4. **Dashboard/UI**: page titles, i18n en/zh strings, logos, favicon; API paths
   stay `/api/v1` (not branded).
5. **Internal crate rename** (one mechanical commit, verified by
   `cargo check --workspace`): `pingwaf-server` → `varman-control`,
   `pingwaf-agent` → `varman-agent`, `pingwaf-waf` → `varman-waf`,
   `pingwaf-proto` → `varman-protocol`, `pingwaf-challenge` → `varman-challenge`,
   `pingwaf-pprof` → `varman-pprof`. `pingap-*` names stay for now (documented).
6. **Docs**: replace PingWAF branding in `docs/`, keep upstream provenance note.

> Execution status (2026-10-06): items 1–6 executed in commits `a31d7cd`
> (runtime identity, crates, deployment, dashboard) and its follow-ups; the
> fresh VarmanWAF `CHANGELOG.md` references the preserved upstream history in
> `CHANGELOG-upstream-pingwaf.md`. The canonical project location is
> `https://github.com/channchetra/varmanwaf`; images are published under
> `ghcr.io/channchetra/varmanwaf`.

Acceptance for Phase 1: `cargo build --release` passes and
`docker compose up -d` yields a usable VarmanWAF install (dashboard, sites,
agents, proxy, TLS) with unchanged behaviour.

---

## 11. Risks and watch-items

- **Two admin UIs**: Pingap's `dist/` admin and PingWAF's `web/dist/` console are
  both embedded. Decide later whether the Pingap admin stays; do not break it in
  Phase 1.
- **Config generation coupling**: `src/pingwaf.rs` builds Pingap configs from the
  agent cache on every change; the new security runtime must slot in without
  breaking this pipeline.
- **Hot reload semantics**: Pingap reloads via `--autoreload`/`--autorestart`;
  the mandate's atomic `RuntimeSnapshot` swap (ArcSwap) should replace per-request
  engine construction where it hurts the hot path.
- **`unwrap_used` is denied workspace-wide** and clippy threshold is 10:
  new code must follow (`expect` is allowed; prefer explicit error handling).
- **Tests**: upstream has extensive unit tests per crate and WAF corpus/results in
  `docs/waf-benchmark-report.md`; keep them green through every rename.
