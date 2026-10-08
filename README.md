<div align="center">

# VarmanWAF (វរ្ម័ន)

**Self-hosted, distributed Web Application Firewall platform**

Central control plane · Lightweight edge agents · Pingora data plane · PostgreSQL · Rust end to end

[![License](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](./LICENSE)
[![Rust](https://img.shields.io/badge/rust-1.96%2B-orange.svg)](https://www.rust-lang.org/)
[![Docker](https://img.shields.io/badge/docker-compose%20ready-2496ED?logo=docker&logoColor=white)](./docker-compose.yml)
[![Release](https://img.shields.io/badge/release-v0.21.0-brightgreen.svg)](./docs/releases/v0.21.0.md)

**v0.21.0 — first production rollout** (2026-10-08): see
[release notes](./docs/releases/v0.21.0.md) for highlights, verification and
known limitations.

</div>

---

## What is VarmanWAF?

VarmanWAF is a **self-hosted Web Application Firewall platform** for real
public-facing websites, APIs and internal systems. It keeps the simple
deployment model of its platform foundation (control plane + PostgreSQL, or
all-in-one) while growing a modern, multi-lane security engine written in
Rust.

The platform architecture:

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

## Security engine (current state, honestly)

The platform runs two engine generations side by side right now:

| Engine | Status |
| --- | --- |
| Imported signature + rule engine (PingWAF lineage) | **Enforces** all traffic today |
| Varman multi-lane pipeline | Runs beside it in **shadow mode** (`VARMAN_WAF_SHADOW=1`), never affecting responses yet |

The Varman pipeline already includes:

- **Canonical request model** — one normalization (bounded percent decoding,
  path collapse, query/cookie parsing, authority handling) shared by all
  detectors, so `/open/../admin` cannot mean different paths to different
  components.
- **Structured findings** — detector id, rule id, attack category,
  confidence, severity, score, evidence source, suggested action.
- **Monotonic actions** — `Pass < Log < Monitor < Challenge < Block`; a later
  weak detection can never downgrade an earlier strong one.
- **Lane 1 fast detectors** — protocol sanity checks (conflicting
  `Content-Length`, CL+TE smuggling shape, header injection material, framing
  violations), an Aho-Corasick signature scanner with a tiered table
  (Block-tier payload syntax vs Log-tier ambiguous tokens), and raw-path
  traversal evidence.
- **Bounded work** — per-request finding caps, body inspection budgets,
  structured degradation instead of errors.
- **Immutable runtime snapshots** — per-site security runtimes behind an
  atomic `ArcSwap`; in-flight requests keep the snapshot they started on.

Detection quality is enforced by test corpora in `varman-waf/tests/corpus`:
every attack case must stay detected, and no benign case (WordPress, SQL and
JavaScript documentation, markdown, signed URLs, JWTs, API payloads) may ever
reach Monitor/Block. See [`docs/security-engine.md`](./docs/security-engine.md).

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

- **Shadow mode:** run the data plane with `VARMAN_WAF_SHADOW=1` to execute
  the Varman pipeline beside the enforcing engine and record how the two
  verdicts compare (agree / pipeline stricter / pipeline weaker). Comparisons
  are logged and counted; enforcement never changes.
- **Dashboard assets:** `web/dist` is embedded into the binary at compile
  time. Run `npm run build` inside `web/` **before** rebuilding the Rust
  binary — never in parallel — or the binary embeds the previous bundle.
  Verify after deploying: the hash in the served `index.html` must match the
  newest `web/dist/assets/index-*.js`.
- **Adding a site in all-in-one mode:** create the site first, then restart
  the container once so the embedded agent re-registers and binds to it.

## Documentation

| Document | Contents |
| --- | --- |
| [`docs/usage.md`](./docs/usage.md) | How to use the console: sites, Web Protection, logs, API examples — with screenshots |
| [`docs/architecture.md`](./docs/architecture.md) | The actual current architecture and its invariants |
| [`docs/security-engine.md`](./docs/security-engine.md) | Pipeline, canonicalization, detectors, scoring, limits |
| [`docs/upstream-pingwaf-map.md`](./docs/upstream-pingwaf-map.md) | Phase 0 map of the imported platform and the rename decisions |
| [`docs/references.md`](./docs/references.md) | Upstream projects studied and the rules for reimplementation |
| [`docs/roadmap.md`](./docs/roadmap.md) | Phase-by-phase status (what is done, in progress, next) |
| [`docs/compatibility.md`](./docs/compatibility.md) | SecLang / OWASP CRS compatibility tracking |
| [`docs/deployment.md`](./docs/deployment.md) | Deployment, operations and the verification smoke test |
| [`docs/performance.md`](./docs/performance.md) | Lane-cost measurements, methodology and hardware |

## Project status

The platform (control plane, edge agent, proxy, TLS/ACME, dashboard,
certificates, config sync) is complete and verified end to end. The security
engine work is in progress: canonicalization, the detection pipeline, the
fast lane (protocol checks + signatures) and immutable runtime snapshots have
landed, with semantic detectors (SQL/iXSS/command), SecLang/CRS and advanced
security phases next. Details and exit criteria live in
[`docs/roadmap.md`](./docs/roadmap.md).

## License and acknowledgements

Apache-2.0. VarmanWAF is built on the PingWAF platform (in turn based on
[Pingap](https://github.com/vicanso/pingap) and Cloudflare
[Pingora](https://github.com/cloudflare/pingora)); the security-engine design
draws on the open-source projects listed in
[`docs/references.md`](./docs/references.md). Upstream history is preserved in
[`CHANGELOG-upstream-pingwaf.md`](./CHANGELOG-upstream-pingwaf.md).
