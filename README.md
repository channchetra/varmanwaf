<div align="center">

# VarmanWAF (វរ្ម័ន)

**Self-hosted, distributed Web Application Firewall platform**

Central control plane · Lightweight edge agents · Pingora data plane · PostgreSQL · Rust end to end

[![License](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](./LICENSE)
[![Rust](https://img.shields.io/badge/rust-1.96%2B-orange.svg)](https://www.rust-lang.org/)
[![Docker](https://img.shields.io/badge/docker-compose%20ready-2496ED?logo=docker&logoColor=white)](./docker-compose.yml)
[![Release](https://img.shields.io/badge/release-v1.0.0-brightgreen.svg)](./docs/releases/v1.0.0.md)

**v1.0.0 - the first official release.** The native Varman engine enforces,
the console carries the full operator surface (policy tuning, access control
with ipverse data, API assets with learning and per-operation controls,
exclusion packages with upstream imports, alerts, reports, fleet), and the
whole program is verified by a 40-script end-to-end sweep. See
[release notes](./docs/releases/v1.0.0.md).

</div>

---

## What is VarmanWAF?

VarmanWAF is a **self-hosted Web Application Firewall platform** for real
public-facing websites, APIs and internal systems. It keeps the simple
deployment model of its platform foundation (control plane + PostgreSQL, or
all-in-one) while running a modern, multi-lane security engine written in
Rust.

```text
                 VarmanWAF Control Plane
                 ───────────────────────
                    Dashboard / REST API   :9080
                    gRPC control protocol  :9090
                    PostgreSQL             (authoritative store)
                          │
                          │ gRPC: registration, heartbeat, config sync,
                          │       log / metric / certificate events
              ┌───────────┴───────────┐
              │                       │
       Varman Edge Agent       Varman Edge Agent
              │                       │
              ▼                       ▼
        Pingora data plane      Pingora data plane     :80 / :443
              │                       │
           Origins                 Origins
```

- **The control plane is never in the request path.** If it goes down, every
  edge keeps serving traffic from its local, persisted configuration.
- **One minimal installation:** VarmanWAF + PostgreSQL. No Kafka, Redis or
  Elasticsearch required (Elasticsearch log shipping is optional).
- **Configuration is versioned** and pushed to agents as per-site bundles;
  runtime changes apply without a proxy restart.

## Security engine

| Engine | Status |
| --- | --- |
| Varman native engine (`engine_mode = varman`) | **Enforces** - the default posture on new sites |
| Imported signature engine (PingWAF lineage) | Available per site (`engine_mode = legacy`) |
| Shadow comparison | `engine_mode = shadow` runs both and records how the verdicts compare, never affecting responses |

The native engine includes:

- **Canonical request model** - one normalization (bounded percent decoding,
  path collapse, query/cookie parsing, authority handling) shared by every
  detector, so `/open/../admin` cannot mean different paths to different
  components.
- **Signature lane + managed rules** - an Aho-Corasick scanner with a tiered
  table (block-tier payload syntax vs log-tier ambiguous tokens) feeding
  anomaly scores, plus 13 managed rules (`VARMAN-1001..1061`) covering SQLi,
  XSS, RCE, scanners, dotfile probes, methods, admin paths and more.
- **Custom rules** - operator-written expressions (`http.request.uri.query
  contains "…"`, `cf.waf.score.sqli ge 30`, …) with per-rule modes.
- **SecLang layer** - virtual patches, a real OWASP **CRS 4.30.0** import
  (`crs_import` policy layer) and native `SecRuleUpdateTargetById` /
  `SecRuleRemoveById` support, including the `ctl:` controls the CRS plugins
  use.
- **Policy layers** - engine posture, CRS tuning, custom rules, rule
  overrides (disable / monitor / score / target exclusions), virtual
  patches, API schema, rate limits, IP access, bot posture, CRS import -
  shared through revisioned **policies** sites can follow.
- **Exclusion packages** - curated per-application exclusion sets (WordPress,
  Next.js static assets, Nextcloud WebDAV, rich-text editors) attached at a
  path prefix, plus **upstream imports**: a CRS rule-exclusion plugin is
  fetched, checked to parse as SecLang, stored with a report of what it
  contains, and compiled into the site's virtual patches on attach.
- **Geo and ASN enforcement from [ipverse](https://github.com/ipverse)** -
  country ranges (`rir-ip`) and ASN ranges (`as-ip-blocks`) are synced into
  `ip_datasets`; the edge matches them with the same range matcher the IP
  rules use. Unsynced keys are **not enforced and say so**.
- **Bounded work** - per-request finding caps, body inspection budgets,
  structured degradation instead of errors.
- **Immutable runtime snapshots** - per-site security runtimes behind an
  atomic `ArcSwap`; in-flight requests keep the snapshot they started on.

Detection quality is enforced by test corpora in `varman-waf/tests/corpus`:
every attack case must stay detected, and no benign case (WordPress, SQL and
JavaScript documentation, markdown, signed URLs, JWTs, API payloads) may ever
reach Monitor/Block. See [`docs/security-engine.md`](./docs/security-engine.md).

## The console, feature by feature

| Surface | What it does |
| --- | --- |
| **Dashboard** | Fleet health, traffic and interception summaries, coverage tiles |
| **Sites** | Site lifecycle, domains, origins/upstreams, failover, SSL/ACME, caching, routes/rewrite, traffic analytics |
| **Protection -> Policy tuning** | One surface per site: summary chips, **site posture** (engine mode, advanced mode, custom layers, monitor lists), **effective posture**, rule exceptions, **exclusion packages**, preview/apply, version history |
| **Protection -> Rules / CC** | Custom rule authoring with a tester, challenge/under-attack controls |
| **Access control** | IP rules and groups, **geo policy with ipverse data** (monitor action, per-country/ASN sync), **client IP analysis**, basic auth |
| **API assets** | Observed endpoint inventory vs the declared OpenAPI document, **bounded JSON learning** (requests and responses; structures and counts, never values), **OpenAPI draft export**, per-endpoint **Off / Observe / Enforce** controls |
| **Global policies** | Revisioned policy documents with a per-policy detail page (every layer editable in place, history, preview) |
| **Routing topology** | A live flow view (ReactFlow) of the real request path — drag to rearrange, drag palette items to add, click any node to edit it in place |
| **CRS** | Imported rulesets, categories, paranoia ceiling, rule catalogue |
| **Alerts & notifications** | Alert rules, silences, delivery channels (email, webhook, Telegram), login security, alert history - one merged page |
| **Reports** | Interception reports (filters, custom heading/footer, HTML attachment), schedules (daily/weekly/monthly), send-now |
| **Logs** | Security events and the full access log with filters, the "why" resolver and body views |
| **Fleet** | Agents, IP groups, blocked IPs, lifecycle, config history (versioned rollbacks) |
| **Settings** | Appearance, **display & data timezone**, account, dashboard users, passkeys, control-plane TLS, observation mode, API protection, AI assistant, MCP, Elasticsearch, log retention, custom error pages, API keys |

## Quick start (Docker)

```bash
docker compose up -d
```

- Dashboard + REST API: **https://localhost:9080** (self-signed certificate on
  first boot)
- Default credentials: **admin@varman.local / varman123**
- HTTP/HTTPS traffic: ports **80 / 443**
- gRPC control plane: port **9090**

The bundled image is published on Docker Hub as
[`sovichetra/varmanwaf:latest`](https://hub.docker.com/r/sovichetra/varmanwaf).
To build from source instead, uncomment the `build:` block in
[`docker-compose.yml`](./docker-compose.yml).

Useful environment variables (see [`varman.toml`](./varman.toml) for the full
set): `VARMAN_DB_URL`, `VARMAN_JWT_SECRET`, `VARMAN_ADMIN_EMAIL`,
`VARMAN_ADMIN_PASSWORD`, `VARMAN_TLS_ENABLED`, `VARMAN_WAF_SHADOW`.

## Build from source

Requires a Linux environment (Pingora does not target Windows) and Rust 1.96+:

```bash
cargo build --release            # OpenSSL TLS backend (default)
cargo build --release --no-default-features --features tls-rustls,full
docker build .                   # full image (frontend built inside)
```

Tests and lint (the CI gates):

```bash
cargo test --workspace --features full
cargo clippy --features full --all-targets -- -D warnings
cargo fmt --all -- --check
```

## Development notes

- **CI is local.** The GitHub Actions workflows were removed while the account
  is billing-locked; they can be restored from git history once that clears.
  The gate is the local one: the cargo commands above, `npm run build` in
  `web/`, and the E2E scripts in the `build-artifacts/` folder that sits next
  to this repository (it is tooling, not part of the tree).
- **The full sweep** (`build-artifacts/run-e2e-all.ps1`, next to this
  repository) runs every feature E2E script against the deployed stack and
  prints a pass/fail summary. It is **paced** (25s between scripts) because
  the control plane limits login attempts to 10 per minute per IP - the
  limiter is part of the product, not an obstacle.
- **Version bumps are line-scoped.** Bump the workspace version and the
  `pingap-*` path dependencies only; external crates that happen to share the
  version string must stay untouched. Known traps: `tor-geoip` sits at
  `0.46.0`, `sqlparser` at `0.63.0`.
- **Shadow mode:** run the data plane with `VARMAN_WAF_SHADOW=1` (or a site
  with `engine_mode = shadow`) to execute the Varman pipeline beside the
  legacy engine and record how the two verdicts compare (agree / pipeline
  stricter / pipeline weaker). Comparisons are logged and counted;
  enforcement never changes.
- **Dashboard assets:** `web/dist` is embedded into the binary at compile
  time. Run `npm run build` inside `web/` **before** rebuilding the Rust
  binary - never in parallel - or the binary embeds the previous bundle.
  Verify after deploying: the hash in the served `index.html` must match the
  newest `web/dist/assets/index-*.js`.
- **Adding a site in all-in-one mode:** create the site first, then restart
  the container once so the embedded agent re-registers and binds to it.

## Documentation

| Document | Contents |
| --- | --- |
| [`docs/features.md`](./docs/features.md) | The complete feature inventory: every surface, how it works, its API |
| [`docs/user-guide-km/index.html`](./docs/user-guide-km/index.html) | **ណែនាំអ្នកប្រើប្រាស់ (ភាសាខ្មែរ)** - the full Khmer user guide with screenshots of every feature |
| [`docs/usage.md`](./docs/usage.md) | How to use the console: sites, Web Protection, logs, API examples |
| [`docs/architecture.md`](./docs/architecture.md) | The actual current architecture and its invariants |
| [`docs/security-engine.md`](./docs/security-engine.md) | Pipeline, canonicalization, detectors, scoring, limits |
| [`docs/navigation-ia.md`](./docs/navigation-ia.md) | The console's information architecture and its decisions |
| [`docs/compatibility.md`](./docs/compatibility.md) | SecLang / OWASP CRS compatibility tracking |
| [`docs/deployment.md`](./docs/deployment.md) | Deployment, operations and the verification smoke test |
| [`docs/performance.md`](./docs/performance.md) | Lane-cost measurements, methodology and hardware |
| [`docs/benchmarks/v1.0.0.md`](./docs/benchmarks/v1.0.0.md) | The 1.0.0 performance benchmark report |
| [`docs/releases/`](./docs/releases) | Per-release notes (digests, E2E evidence) |
| [`docs/roadmap.md`](./docs/roadmap.md) | Phase-by-phase status |

## Project status

**v1.0.0 is the first official release.** The platform (control plane, edge
agent, proxy, TLS/ACME, dashboard, certificates, config sync) is complete;
the native security engine enforces with managed rules, custom rules, the
SecLang/CRS layer and policy layers; the operator surface covers policy
tuning, access control (ipverse geo/ASN), API assets with learning and
per-operation controls, exclusion packages with upstream imports, alerts,
reports and the fleet. Every round shipped with a live edge E2E; the full
sweep and the benchmark report are the release evidence. See
[`docs/roadmap.md`](./docs/roadmap.md) for what could come next.

## License and acknowledgements

Apache-2.0. VarmanWAF is built on the PingWAF platform (in turn based on
[Pingap](https://github.com/vicanso/pingap) and Cloudflare
[Pingora](https://github.com/cloudflare/pingora)); the security-engine design
draws on the open-source projects listed in
[`docs/references.md`](./docs/references.md), and the geo/ASN data comes from
[ipverse](https://github.com/ipverse). Upstream history is preserved in
[`CHANGELOG-upstream-pingwaf.md`](./CHANGELOG-upstream-pingwaf.md).
