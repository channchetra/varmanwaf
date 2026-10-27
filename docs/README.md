# VarmanWAF Documentation

Welcome to the VarmanWAF documentation index. VarmanWAF is a distributed,
centrally-controlled Web Application Firewall built on
[`pingap`](https://github.com/vicanso/pingap) and Cloudflare
[`Pingora`](https://github.com/cloudflare/pingora).

> Project home: [`README.md`](../README.md)

**Release 1.2.4** — the current reference set. The public docs site (`/docs/`) adds a role-based entry point, deployment paths, search and screenshots on top of these source documents.

| Document | What you'll find |
| --- | --- |
| [roles/site-user.md](./roles/site-user.md) | Start here if you own a site: protection mode, origin, caching, TLS, logs |
| [roles/administrator.md](./roles/administrator.md) | Users, policies, CRS, IP intelligence, alerts, reports and the audit trail |
| [roles/developer.md](./roles/developer.md) | Build, test and ship the platform |
| [roles/system-administrator.md](./roles/system-administrator.md) | Hosts, PostgreSQL, edge fleets, HA, backup and upgrades |
| [deployment-paths.md](./deployment-paths.md) | Choose all-in-one, split control plane + edges, or an HA fleet |
| [features.md](./features.md) | The complete feature inventory: every console surface, how it works, its API, its honest limits |
| [user-guide-km/index.html](./user-guide-km/index.html) | **ណែនាំអ្នកប្រើប្រាស់ (ភាសាខ្មែរ)** — the full Khmer user guide with screenshots of every feature |
| [security-engine.md](./security-engine.md) | Pipeline, canonicalization, detectors, scoring, limits |
| [architecture.md](./architecture.md) | The actual system shape, request path, invariants and failure semantics |
| [sizing.md](./sizing.md) | Server requirements and measured capacity (from the benchmark) |
| [ha.md](./ha.md) | High availability: edge fleets, control-plane standby, DNS, node sync |
| [developer-guide.md](./developer-guide.md) | Build, test, release workflow, where to add what |
| [benchmarks/v1.0.0.md](./benchmarks/v1.0.0.md) | The 1.0.0 performance benchmark report |
| [releases/](./releases) | Per-release notes (digests, E2E evidence) |

## 🚀 Getting started

| Document | What you'll find |
| --- | --- |
| [quick-start.md](./quick-start.md) | From zero to your first protected site: prerequisites, install, first run |
| [deployment.md](./deployment.md) | Docker Compose, binary + systemd, distributed (server + agents), backup, upgrade |
| [ha.md](./ha.md) | Running an edge fleet, control-plane standby, database HA, domain/DNS and node sync |
| [sizing.md](./sizing.md) | How much server you need, what consumes resources, how to measure your own |
| [features.md](./features.md) | The per-surface inventory: every console page, API and limit |
| [user-guide.md](./user-guide.md) | English console walkthrough — sites, rules, policies, IP access, rate limiting |
| [http-lifecycle.md](./http-lifecycle.md) | Where every feature acts in the request pipeline — the WAF check order, caching, error pages |
| [api.md](./api.md) | REST API reference (base URL `https://<host>:9080/api/v1`) |
| [profiling.md](./profiling.md) | Built-in profiling: CPU profiles, flame graphs, memory snapshots |

## 🧭 Project & community

| Document | What you'll find |
| --- | --- |
| [CONTRIBUTING.md](../CONTRIBUTING.md) | How to contribute — setup, workflow, code style |
| [SECURITY.md](../SECURITY.md) | Vulnerability disclosure policy |
| [CODE_OF_CONDUCT.md](../CODE_OF_CONDUCT.md) | Community guidelines |
| [LICENSE](../LICENSE) | Apache License 2.0 |

## 🏗️ Architecture at a glance

```
Client ──HTTP/HTTPS──► Data-plane Agent (:80/:443)
                              │  gRPC bidi streams (rules / logs / metrics)
                              ▼
                    Control-plane Server
                    ├─ REST API + Dashboard (:9080, HTTPS)
                    ├─ gRPC ControlPlane    (:9090)
                    ├─ PostgreSQL (state)
                    └─ Elasticsearch (logs, optional)
```

Run everything in one process with `all-in-one`, or split the control plane
(`server`) from one or many edge agents (`agent`).

## 📦 Crate documentation

VarmanWAF adds six WAF-specific crates on top of the `pingap` proxy foundation.

**WAF crates:**

| Crate | What it does |
| --- | --- |
| [varman-protocol](../varman-protocol) | Control-plane gRPC protocol definitions (single source: `control_plane.proto`) |
| [varman-control](../varman-control) | Control plane: Axum REST + tonic gRPC + SeaORM/PostgreSQL + ES logs + embedded frontend + agent health monitoring |
| [varman-agent](../varman-agent) | Data-plane agent: connects to the control plane, caches rules with disk persistence, ships logs/metrics, receives commands |
| [varman-waf](../varman-waf) | Detection engine: normalize → signatures → expression → anomaly score |
| [varman-challenge](../varman-challenge) | Dynamic challenges: JS 5-second shield, interactive challenge, PoW, fingerprinting, HMAC clearance cookies |
| [varman-pprof](../varman-pprof) | Built-in profiling: `go tool pprof` CPU profiles, SVG flame graphs, memory snapshots (CPU sampling is Linux-only) |

**Proxy foundation (`pingap-*`) — each crate has its own README** describing what
it owns, how it is configured and where it sits in the dependency graph:

| Crate | What it does |
| --- | --- |
| [pingap-util](../pingap-util/README.md) | Crypto, IP rules, PEM/base64, path and formatting helpers |
| [pingap-core](../pingap-core/README.md) | `Ctx`, `HttpResponse`, the `Plugin` trait, background services, clock helpers |
| [pingap-config](../pingap-config/README.md) | Configuration model, storage backends, TOML/HCL/KDL |
| [pingap-discovery](../pingap-discovery/README.md) | Static / DNS / Docker / transparent backend discovery |
| [pingap-health](../pingap-health/README.md) | TCP, HTTP(S) and gRPC health checks |
| [pingap-upstream](../pingap-upstream/README.md) | Load balancing, circuit breaking, upstream connection options |
| [pingap-location](../pingap-location/README.md) | Host/path matching, rewriting, per-location limits |
| [pingap-certificate](../pingap-certificate/README.md) | SNI-based dynamic TLS certificate store |
| [pingap-acme](../pingap-acme/README.md) | Let's Encrypt HTTP-01 and DNS-01 automation |
| [pingap-cache](../pingap-cache/README.md) | Memory (TinyUFO) and file cache backends |
| [pingap-plugin](../pingap-plugin/README.md) | Built-in plugins — see the [plugin index](../pingap-plugin/README.md#plugin-index) |
| [pingap-imageoptim](../pingap-imageoptim/README.md) | PNG/JPEG → WebP/AVIF conversion |
| [pingap-logger](../pingap-logger/README.md) | Access logs, file/syslog writers, rotation and compression |
| [pingap-performance](../pingap-performance/README.md) | Prometheus metrics and process introspection |
| [pingap-otel](../pingap-otel/README.md) | OpenTelemetry distributed tracing |
| [pingap-sentry](../pingap-sentry/README.md) | Sentry error reporting |
| [pingap-pyroscope](../pingap-pyroscope/README.md) | Continuous CPU profiling |
| [pingap-webhook](../pingap-webhook/README.md) | Operational notifications to WeCom / DingTalk / HTTP |
| [pingap-proxy](../pingap-proxy/README.md) | The proxy engine: lifecycle, routing, server configuration |

## 🔌 Plugin documentation

Every plugin has a page covering its configuration keys, worked examples and the
caveats worth knowing before you deploy it:
[pingap-plugin/docs](../pingap-plugin/README.md#plugin-index).

## 🌐 Reference material

- [architecture.md](./architecture.md) — system shape, request path, invariants, failure semantics.
- [ha.md](./ha.md) — high availability, edge fleets, DNS and node synchronisation.
- [sizing.md](./sizing.md) — requirements and measured capacity.
- [modules.md](./modules.md) — the workspace module map (Varman crates + the `pingap-*` foundation).
- [developer-guide.md](./developer-guide.md) — build, test, release workflow.
- [acme_chart.md](./acme_chart.md) — ACME / Let's Encrypt issuance flow.
- [performance.md](./performance.md) — lane-cost measurements; [benchmarks/](./benchmarks) — the release benchmark reports.
- [shadow-report.md](./shadow-report.md) — the shadow-comparison report (engine rollout evidence).
- [upstream-pingwaf-map.md](./upstream-pingwaf-map.md) / [upstream-update-plan.md](./upstream-update-plan.md) — the fork's upstream baseline map and sync plan (historical record).
