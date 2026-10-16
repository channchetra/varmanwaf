# VarmanWAF Architecture

> **Truthfulness rule**: this document describes what is actually implemented
> in this repository, not planned marketing features. It is updated in the
> same change as any behavioural change.
>
> Current state: **v1.1.0** - the native engine enforces, the console carries
> the full operator surface, and the platform is verified by the full E2E
> sweep and the benchmark report ([`benchmarks/v1.0.0.md`](./benchmarks/v1.0.0.md)).

## 1. System shape

```text
        Visitors / attackers / APIs
                  │
                  ▼
   ┌─────────────────────────────────────────────┐
   │  Varman Edge (Pingora + Varman engine)      │   :80 / :443
   │  canonicalise → evaluate → decide → proxy   │
   └───────────────┬─────────────────────────────┘
                   │ (allowed requests only)
                   ▼
        Origin pools → your servers

   ┌─────────────────────────────────────────────┐
   │  VarmanWAF Control Plane                    │
   │  REST API + console            :9080 (TLS)  │
   │  gRPC control protocol         :9090        │
   │  PostgreSQL (authoritative store)           │
   └─────────────────────────────────────────────┘
             ▲ gRPC: registration, heartbeat,
             │       config sync, log/metric/
             │       certificate shipping
             └────────── Edge agents (one per node)
```

Deployment modes:

- **all-in-one** (default Compose): control plane, proxy and agent in one
  process.
- **server + agent(s)**: control plane process plus one data-plane process per
  node; agents may run behind a load balancer or on separate machines.
- The minimum installation is **VarmanWAF + PostgreSQL**. No Kafka, Redis or
  Elasticsearch required (Elasticsearch log shipping is optional).

## 2. Hard invariants

1. **The control plane is never in the request path.** User traffic is served
   by the edge from local, persisted configuration. Losing the control plane
   does not stop traffic.
2. **Edge autonomy.** The agent persists site bundles, blocked IPs and config
   hashes to disk and restarts from them; it reconnects with backoff.
3. **PostgreSQL is the single authoritative store** for control-plane state.
4. **Configuration reaches the data plane as versioned bundles** (per site,
   identified by `config_hash`), applied without a proxy restart.
5. **Secrets never enter logs** (access-log body capture is bounded and
   configurable).
6. **No per-request database access** on the edge.
7. **Policy surfaces never lie.** A setting the operator saved is either
   applied (and pushed) or reported as not applied - never silently dropped.

## 3. Data plane: the request path

Every request walks the same path; the WAF decides, the proxy delivers:

```text
   request (HTTP/HTTPS, site resolved by Host)
     │
     ▼
   1. Canonicalisation        one normalization shared by every detector:
                              bounded percent decoding, HTML entities, path
                              collapse, query/cookie parsing, authority handling
     │
     ▼
   2. IP / blocked-IP gate    IP rules and groups; auto-block refusal window
                              (600s after a block verdict, before the engine)
     │
     ▼
   3. WAF engine (varman)     ┌ signature lane (Aho-Corasick: block-tier payload
      [or legacy / shadow]    │ syntax, log-tier ambiguous tokens)
                              ├ managed rules (13 families, anomaly scoring)
                              ├ custom rules (operator expressions)
                              ├ SecLang virtual patches + imported CRS 4.30.0
                              ├ API schema validation (per-operation Off/
                              │   Observe/Enforce)
                              ├ exclusions (path-scoped target exclusions,
                              │   curated packages, imported SecLang packages)
                              └ rate limits, geo/ASN (ipverse ranges), bot
                                posture, challenges
     │
     ▼
   4. Verdict                 Allow → proxy   Monitor → proxy + record
                              Block → 403 block page (+ auto-block)
                              Challenge → 503 challenge page
     │
     ▼
   5. Delivery                rewrite / cache / compression → origin pool →
                              target; access log + security events shipped
```

The engine runs from an **immutable per-site runtime snapshot** behind an
atomic `ArcSwap`: in-flight requests keep the snapshot they started on, so a
push never exposes a half-applied configuration. Work is bounded (finding
caps, body inspection budgets) and degrades in a structured way instead of
erroring.

Details: [`security-engine.md`](./security-engine.md).

## 4. Security engine (`varman-waf`)

| Layer | What it does |
| --- | --- |
| Canonical model | One normalization truth for every detector |
| Signature lane | Aho-Corasick tiers + SQLi/XSS shape checks |
| Managed rules | 13 families (`VARMAN-1001..1061`) with anomaly scores and per-rule modes |
| Custom rules | Operator expressions (`http.request.uri.query contains "…"`, `cf.waf.score.sqli ge 30`), modes and score actions |
| SecLang / CRS | Virtual patches, CRS 4.30.0 import, `SecRuleUpdateTargetById` / `SecRuleRemoveById` incl. the `ctl:` controls plugins use |
| API schema | OpenAPI request validation with per-operation Off / Observe / Enforce |
| Access | IP rules/groups, geo & ASN from **ipverse** (`rir-ip`, `as-ip-blocks`) |
| Bots / CC | Bot posture, verified bots (reverse DNS), challenges, under-attack |
| Exclusions | Path-scoped named-member target exclusions, curated per-application packages, upstream SecLang imports with an import report |

Engine mode per site: `varman` (native, enforcing), `legacy` (imported
signature engine), `shadow` (both run, verdicts compared, enforcement
unchanged).

## 5. Control plane

- **HTTP REST** (`/api/v1`, axum): 48 route modules - auth/passkeys/users/keys,
  sites/upstreams/pools/routes/rewrite/cache/SSL/TLS, protection (rules,
  policies, CRS, exclusions, challenge, bot, rate limits, IP rules/groups/geo/
  ipverse datasets, API assets), observability (logs, analytics, alerts,
  notifications, reports, blocked IPs, retention), integrations (AI, MCP),
  system (self-protection, debug).
- **gRPC** (`:9090`, tonic): `RegisterAgent`, bidi `Heartbeat` (+ server
  commands), `SyncRules`, `GetSiteConfig`, `ShipLogs`, `ShipCertEvents`,
  `ShipMetrics`.
- **Console**: React SPA embedded in the binary at build time, served over
  HTTPS (self-signed on first boot; replaceable from Settings). The
  **routing topology** page renders the site's real flow and edits it in
  place.
- **Migrations**: SeaORM, applied automatically at boot.
- **Self-protection**: the control plane guards its own admin surface with an
  in-process engine instance, an IP allowlist and its own access log.
- **Login protection**: 10 attempts/minute/IP on login, 5/hour on
  registration, 30/min refresh, 10/min password change.

## 6. Edge agent

- Registers with the control plane (API key, host facts) and receives a JWT;
  registration can be closed and agents can be pinned with mutual TLS.
- Maintains a persisted `RuleCache`: sites keyed by domain with their full
  bundle, the blocked-IP ledger with expiry, and the `config_hash` for delta
  sync.
- Ships heartbeats (health, metrics, host samples, site status incl. cache
  and certificate state, blocked IPs), batched logs, certificate events and
  metrics.
- Exposes a lock-light read API to the proxy plugins:
  `get_rules_for_domain`, `is_ip_blocked`, `block_ip`, `log_security_event`,
  `log_access`.

## 7. Data and configuration flow

```text
Console/API edit ──► PostgreSQL (authoritative)
                          │
                 bundle compilation (per site, versioned)
                          │
      SyncRules stream / GetSiteConfig ◄─────────────┐
                          │                          │
                          ▼                          │
                 agent RuleCache (disk)              │
                          │                          │
             Pingap config assembly                  │
                          │                          │
                 hot reload (no restart)             │
                          │                          │
      proxy serves from the local bundle             │
                          │                          │
   security events + access logs + metrics ──────────┘
```

Every change that produces a bundle is recorded in **config history** with a
diff summary, actor and time; a version can be previewed and rolled back,
which re-pushes it to the affected agents.

## 8. Failure semantics

| Failure | Behaviour |
| --- | --- |
| Control plane unreachable | Edge serves from cached bundles; reconnect with backoff |
| Agent registration fails at boot | Agent keeps cached rules; the site keeps serving |
| Bundle compilation fails on the edge | Invalid bundle rejected; last-good cache kept |
| Log shipping unavailable | Bounded channel; bounded loss, never blocks requests |
| Elasticsearch down | Log shipping degrades; PostgreSQL-only operation unaffected |
| Certificate expired | Reported via heartbeat; the edge keeps serving (clients see the TLS error) |
| Origin pool fully down | Failover policy: secondary pool or a static response |
| Auto-block misfire | Unblock from Blocked IPs (or the API) revokes it immediately |

## 9. Repository layout

```text
VarmanWAF/
├── Cargo.toml                  # workspace, dual root binary (pingap + varman)
├── src/                        # root binary: cli, varman mode assembly, admin plugin
├── varman-control/             # control plane (REST + gRPC + migrations + embedded console)
├── varman-agent/               # edge agent (cache, sync, shipping)
├── varman-waf/                 # the security engine (pipeline, detectors, seclang, corpora)
├── varman-protocol/            # gRPC protocol definitions (single source: .proto)
├── varman-challenge/           # challenge engine (JS shield, PoW, clearance cookies)
├── varman-pprof/               # profiling
├── pingap-*/                   # proxy foundation crates (Pingora proxy, plugins, cache, …)
├── web/                        # console (Vite/React), embedded at build time
├── docs/                       # this documentation set
└── docker-compose.yml, Dockerfile, Dockerfile.runtime, varman.toml, varman.service
```

## 10. Build and run

```bash
# Build (Linux; Pingora does not target Windows)
cargo build --release                          # default: openssl TLS
cargo build --no-default-features --features tls-rustls,full

# Run a full local stack
docker compose up -d                           # console: https://localhost:9080

# The local gate (CI is local in this fork)
cargo fmt --all -- --check
cargo test --workspace --features full
cargo clippy --features full --all-targets -- -D warnings
cd web && npx tsc -b && npx eslint . && npx vitest run && npx vite build
```

Development on Windows hosts is supported through a Linux environment (WSL2
or the provided Docker dev container); the produced artifacts are Linux
binaries. The E2E sweep (`build-artifacts/run-e2e-all.ps1` next to the
repository) verifies a deployed stack.

## 11. Capacity and scale

Measured numbers, methodology and caveats live in
[`benchmarks/v1.0.0.md`](./benchmarks/v1.0.0.md); server sizing guidance in
[`sizing.md`](./sizing.md); high availability in [`ha.md`](./ha.md). Headline
figures on a development desktop (single all-in-one container): ~5.8k req/s
pass-through at 25 connections, ~1 ms engine block verdicts, ~9.8k req/s on
the auto-block refusal lane.

## 12. Where to look next

| Question | Document |
| --- | --- |
| What does every console surface do? | [`features.md`](./features.md) |
| How does the engine decide? | [`security-engine.md`](./security-engine.md) |
| Where in the request path does a feature act? | [`http-lifecycle.md`](./http-lifecycle.md) |
| How do I deploy, back up, upgrade? | [`deployment.md`](./deployment.md) |
| How big should the server be? | [`sizing.md`](./sizing.md) |
| How do I run this highly available? | [`ha.md`](./ha.md) |
| How do I build, test and ship changes? | [`developer-guide.md`](./developer-guide.md) |
