# VarmanWAF Architecture

> **Truthfulness rule**: this document describes what is actually implemented in
> this repository at the referenced state, not planned marketing features. It is
> updated in the same change as any behavioural change (mandate §36).
>
> Current state: **imported PingWAF v0.20.0 baseline** (see
> `docs/upstream-pingwaf-map.md` for the source map). The Varman security engine
> described in the mandate is not implemented yet; this document describes the
> inherited platform, which remains the foundation.

## 1. System shape

VarmanWAF is a self-hosted distributed WAF platform with the same architecture as
the imported PingWAF base:

```text
                 VarmanWAF Control Plane
                 ───────────────────────
                    Dashboard / API          :9080   (axum, HTTPS by default)
                    PostgreSQL                       (SeaORM, authoritative store)
                    gRPC control protocol    :9090
                          │
                          │ gRPC (registration, heartbeat, config/rule sync,
                          │       log/metric/cert-event shipping)
              ┌───────────┴───────────┐
              │                       │
       Varman Edge Agent       Varman Edge Agent
              │                       │
              ▼                       ▼
          Pingora Edge            Pingora Edge       :80 / :443
              │                       │
         Varman WAF Core          Varman WAF Core
              │                       │
              ▼                       ▼
           Origins                 Origins
```

Deployment modes:

- **all-in-one** (default Compose): control plane, proxy and agent in one process.
- **server + agent(s)**: control plane process plus remote data-plane processes.
- The minimum installation is **VarmanWAF + PostgreSQL** (no Kafka/Redis/ES/etc.;
  Elasticsearch log shipping is optional and disabled by default).

## 2. Hard invariants (inherited and enforced)

1. **The control plane is never in the request path.** User traffic is served by
   the edge proxy from local configuration and cache. Losing the control plane
   does not stop traffic.
2. **Edge autonomy.** The agent persists site bundles, blocked IPs and config
   hashes to disk (default `./data/cache`) and restarts from them; it reconnects
   with exponential backoff.
3. **PostgreSQL is the single authoritative store** for control-plane state.
4. **Configuration reaches the data plane as versioned bundles** (`RuleBundle`
   per site, identified by `config_hash`), applied without a proxy restart.
5. **Secrets never enter logs** (access-log body capture is bounded and
   configurable).
6. **No per-request database access** on the edge.

## 3. Data plane (Pingora proxy)

- Engine: Cloudflare **Pingora** (crates.io `0.9.0`, features `lb`, `cache`;
  TLS via `openssl` or `rustls` build features).
- Lifecycle (`pingap-proxy/src/server.rs`): `early_request_filter → request_filter
  → proxy_upstream_filter → upstream_request_filter → upstream_response_filter →
  logging`.
- Plugins attach to one step; the security-relevant chain per location is:

```text
[host/path routing, ~ form: host + location match]
   │
   ▼
WAF plugin (EarlyRequest)  ← single security enforcement point today
   ├─ site basic auth
   ├─ IP access rules (CIDR, actions incl. block/challenge/allow/basic-auth)
   ├─ geo rules (country/ASN, tor-geoip embedded DB)
   ├─ bot protection (UA classification + whitelist)
   ├─ rate limiting (per-rule characteristics: ip, ip-nat, host, path,
   │   header, cookie, query, asn, country, ja3; in-process counters)
   ├─ mTLS policy per site (require cert, org pinning, revocations)
   ├─ WAF engine verdict (see §4)
   └─ emits access logs + security events (non-blocking, batched)
   │
   ▼
challenge plugin  → JS challenge / clearance cookie / block pages
rewrite / error_page / cache plugins
   │
   ▼
upstream (per-site pools; round-robin / hash / least-conn / random)
```

- Runtime configuration is generated from the agent rule cache
  (`src/varman.rs::cached_rules_to_pingap_config`): sites → locations, origin
  pools → upstreams, SSL config → certificates, security plugins. Pingap applies
  it through `--autoreload` (hot) or `--autorestart` (fresh listeners) semantics.

## 4. Current detection engine (`varman-waf`)

A single-crate, signature-first engine with anomaly scoring:

```text
RequestData
  │
  ▼ normalize_request: URL percent multi-decode (bounded layers),
  │   HTML entity decode, path collapse, query/cookie parsing;
  │   strict mode adds \xHH / \uHHHH escape decoding
  ▼
Stage 1: Aho-Corasick signatures (~113 needles) + libinjection-style
         SQLi/XSS + shape checks per decoded value
  │
  ├─ critical hit → early Block (fast path)
  ▼
Stage 2: compiled expression rules (built-in managed ruleset + custom rules
         from the control plane; Cloudflare-like field/operator/value DSL)
  │
  ▼
Anomaly scoring (severity/category points; threshold default 40;
  paranoia 1–4; Normal/Strict levels; per-site monitor categories and
  backend stacks downgrade to non-blocking; site-wide observation mode)
  │
  ▼
Verdict: Pass | Monitor | Block | Challenge   (Off / Monitor / Block modes)
```

Known limitations are documented by upstream's own review
(`docs/waf-engine-review.md`) and drive the Varman engine roadmap: no semantic
lane, no SecLang/CRS, limited body handling, no response inspection. The mandate's
target architecture (Lanes 0–3 + semantic detectors + SecLang) is planned in
`docs/roadmap.md`, executed **behind shadow mode** so the existing engine keeps
serving until parity is proven.

## 5. Control plane

- **HTTP REST** (`/api/v1`, axum): auth (JWT, passkeys), sites/domains, SSL/mTLS,
  agents, rules & policies (WAF settings, rate limits, IP groups/rules, geo,
  bot, challenge, rewrite, error pages), logs/analytics, settings, self-protection,
  AI assistant, MCP endpoint `/mcp`.
- **gRPC** (`:9090`, tonic): `RegisterAgent`, bidi `Heartbeat` (+ server
  commands), `SyncRules`, `GetSiteConfig`, `ShipLogs`, `ShipCertEvents`,
  `ShipMetrics`.
- **Dashboard**: React SPA embedded in the binary (rust-embed), served over HTTPS
  (self-signed on first boot; replaceable from Settings).
- **Migrations**: SeaORM, applied automatically at boot.
- **Self-protection**: the control plane guards its own admin surface with an
  in-process `WafEngine` instance, an IP allowlist and its own access log.
- **Optional**: Elasticsearch log shipping, AI assistant (LLM provider), webhooks.

## 6. Edge agent

- Registers with the control plane (API key, host facts) and receives a JWT.
- Maintains a persisted `RuleCache`: sites keyed by domain, each with its full
  `RuleBundle`; blocked-IP ledger with expiry; `config_hash` for delta sync.
- Ships heartbeats (health, metrics, host samples, site status incl. cache and
  certificate state, blocked IPs), batched logs, cert events and metrics.
- Exposes a fast read API to the proxy plugins:
  `get_rules_for_domain`, `is_ip_blocked`, `block_ip`, `log_security_event`,
  `log_access` — all lock-light and non-blocking on the request path.

## 7. Data and configuration flow

```text
Dashboard/API edit ──► PostgreSQL (authoritative)
                            │
                   config/rule assembly (per-site RuleBundle)
                            │
        SyncRules stream / GetSiteConfig ◄─────────────┐
                            │                          │
                            ▼                          │
                   agent RuleCache (disk)              │
                            │                          │
        cached_rules_to_pingap_config()                │
                            │                          │
                  Pingap hot reload                    │
                            │                          │
        proxy serves traffic from immutable-ish config │
                            │                          │
      security events + access logs + metrics ─────────┘
```

## 8. Failure semantics (inherited; to be hardened per mandate §38)

| Failure | Current behaviour |
|---|---|
| Control plane unreachable | Edge serves from cached bundles; reconnect with backoff |
| Agent registration fails at boot | Agent keeps cached rules; `fail_open` config decides traffic handling |
| Config/rule compilation fails on edge | Invalid bundle is rejected; previous cache is kept (persisted last-good) |
| Log shipping unavailable | Entries accumulate in a bounded channel; bounded loss, never blocks requests |
| Elasticsearch down | Log shipping degrades; PostgreSQL-only operation unaffected |
| Certificate expired | Reported via heartbeat; edge keeps serving (clients see TLS error) |

## 9. Repository layout (current)

```text
VarmanWAF/
├── Cargo.toml                  # workspace, dual root binary (pingap + varman)
├── src/                        # root binary: cli, varman mode assembly, admin plugin
├── pingap-*/                   # proxy foundation crates (names retained for now)
├── varman-control/             # control plane (renamed from pingwaf-server)
├── varman-agent/               # edge agent (renamed from pingwaf-agent)
├── varman-waf/                 # current engine (renamed from pingwaf-waf)
├── varman-protocol/            # gRPC protocol (renamed from pingwaf-proto)
├── varman-challenge/           # challenges (renamed from pingwaf-challenge)
├── varman-pprof/               # profiling (renamed from pingwaf-pprof)
├── web/                        # console (Vite/React), embedded at build time
├── migrations/                 # (SeaORM migrations live in varman-control/src/migration)
├── tests/                      # (added by Varman phases; see roadmap)
├── docs/                       # this documentation set
└── docker-compose.yml, Dockerfile, varman.toml, varman.service, ...
```

## 10. Build and run

```bash
# Build (Linux; Pingora does not target Windows)
cargo build --release                          # default: openssl TLS
cargo build --no-default-features --features tls-rustls,full

# Run a full local stack
docker compose up -d                           # dashboard: https://localhost:9080

# Tests and lint (CI gates)
make lint && make test
```

Development on Windows hosts is supported through any Linux environment (WSL2 or
the provided Docker dev container); the produced artifacts are Linux binaries.

## 11. What the Varman evolution changes

The following are **planned, not implemented** (see `docs/roadmap.md`):

- Canonical request model shared by every detector (one normalization truth).
- Multi-lane security pipeline (fast signatures → structured extraction →
  semantic detectors → SecLang/CRS) with shadow-mode rollout.
- Immutable per-site security runtime behind an atomic snapshot swap.
- Streaming, bounded body inspection; response inspection.
- Config versioning with desired/active/last-good tracking and acknowledgements.
- Independent test corpora (benign/attack/bypass), CRS conformance, fuzzing.

Until those land, the platform’s runtime behaviour is exactly the imported
baseline described above.
