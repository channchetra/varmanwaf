# Workspace Modules

VarmanWAF is one Cargo workspace with two layers: the **Varman** crates (the
WAF platform) and the **`pingap-*` foundation** (the proxy engine the fork is
built on). This page is the map; crate-level guidance lives in `docs/` and the module documentation in each crate.

## Varman crates

| Crate | What it owns |
| --- | --- |
| `varman-control` | Control plane: REST API (48 modules), gRPC server, SeaORM/PostgreSQL store + migrations, config-history versioning, the embedded console, self-protection |
| `varman-agent` | Edge agent: registration, heartbeats, bundle cache with disk persistence, blocked-IP ledger, log/metric/certificate shipping |
| `varman-waf` | The security engine: canonical model, signature lane, managed rules, custom-rule evaluator, SecLang/CRS, API-schema layer, exclusions, scoring, corpora |
| `varman-protocol` | gRPC protocol definitions (single source: `proto/control_plane.proto`) |
| `varman-challenge` | Challenge engine: JS shield, PoW, clearance cookies, fingerprints |
| `varman-pprof` | Built-in profiling (CPU profiles, flame graphs, memory snapshots) |
| `varman` (root) | The binary: `all-in-one` / `server` / `agent` assembly, CLI, admin plugin |

## Proxy foundation (`pingap-*`)

| Crate | What it owns |
| --- | --- |
| `pingap-proxy` | The proxy engine: lifecycle, routing, server configuration |
| `pingap-core` | `Ctx`, `HttpResponse`, the `Plugin` trait, background services |
| `pingap-config` | Configuration model, storage backends, TOML/HCL/KDL |
| `pingap-plugin` | Generic Pingap plugins: compression, auth, headers, redirects, limits, bot DNS, geo restriction |
| `varman-plugin` | VarmanWAF plugins: WAF (engine, stream, shadow, processor, custom layers, ATO), challenge, cache, rewrite, error pages |
| `pingap-upstream` | Load balancing, circuit breaking, upstream connection options |
| `pingap-location` | Host/path matching, rewriting, per-location limits |
| `pingap-certificate` | SNI-based dynamic TLS certificate store |
| `pingap-acme` | Let's Encrypt HTTP-01 / DNS-01 automation |
| `pingap-cache` | Memory and file cache backends |
| `pingap-discovery` | Static / DNS / Docker / transparent backend discovery |
| `pingap-health` | TCP, HTTP(S) and gRPC health checks |
| `pingap-logger` | Access logs, writers, rotation, compression |
| `pingap-performance` | Prometheus metrics and process introspection |
| `pingap-otel` / `pingap-sentry` / `pingap-pyroscope` | Tracing, error reporting, continuous profiling |
| `pingap-webhook` | Operational notifications (WeCom / DingTalk / HTTP) |
| `pingap-imageoptim` | PNG/JPEG → WebP/AVIF conversion |
| `pingap-util` | Crypto, IP rules, PEM/base64, path and formatting helpers |

## Dependency shape

```mermaid
graph TD
    challenge["challenge"]
    core["core"]
    otel["otel"]
    pprof["pprof"]
    protocol["protocol"]
    pyroscope["pyroscope"]
    sentry["sentry"]
    util["util"]
    waf["waf"]
    acme --> certificate
    acme --> config
    acme --> core

    agent --> cache
    agent --> core
    agent --> protocol

    cache --> core

    certificate --> config
    certificate --> core
    certificate --> util


    config --> core
    config --> discovery
    config --> util

    control --> pprof
    control --> protocol
    control --> waf


    discovery --> core

    health --> util

    imageoptim --> config
    imageoptim --> core
    imageoptim --> plugin

    location --> config
    location --> core

    logger --> core
    logger --> util


    performance --> cache
    performance --> core
    performance --> location
    performance --> upstream

    plugin --> config
    plugin --> core
    plugin --> util



    proxy --> acme
    proxy --> certificate
    proxy --> config
    proxy --> core
    proxy --> location
    proxy --> logger
    proxy --> otel
    proxy --> performance
    proxy --> upstream
    proxy --> util


    root --> acme
    root --> agent
    root --> cache
    root --> certificate
    root --> config
    root --> control
    root --> core
    root --> imageoptim
    root --> location
    root --> logger
    root --> otel
    root --> performance
    root --> plugin
    root --> pprof
    root --> proxy
    root --> pyroscope
    root --> sentry
    root --> upstream
    root --> util
    root --> varman-plugin
    root --> webhook


    upstream --> config
    upstream --> core
    upstream --> discovery
    upstream --> health
    upstream --> util


    varman-plugin --> agent
    varman-plugin --> cache
    varman-plugin --> challenge
    varman-plugin --> config
    varman-plugin --> core
    varman-plugin --> plugin
    varman-plugin --> util
    varman-plugin --> waf


    webhook --> core
```

Request flow, invariants and failure semantics live in
[`architecture.md`](./architecture.md); the engine itself in
[`security-engine.md`](./security-engine.md).
