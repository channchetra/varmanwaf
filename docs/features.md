# VarmanWAF Feature Inventory

The complete operator-facing feature set: every console surface, how it works,
where it lives, and the API behind it. This document is the reference for the
[Khmer user guide](./user-guide-km/index.html), the benchmark report and
release verification.

Conventions used below:

- **Where** — the console route. All routes are served by the control plane
  (`https://<host>:9080`).
- **API** — the REST modules under `/api/v1/...` that the surface calls. The
  full route table is generated from `varman-control/src/api/`.
- **Honest limits** — anything the surface does *not* do is stated. The
  console never shows success for work that was not applied.

---

## 1. Platform foundation

### 1.1 Login and sessions

- **Where** — `/login`.
- **API** — `auth.rs` (`/auth/login`, `/auth/refresh`, `/auth/logout`,
  `/auth/me`), `passkeys.rs` (WebAuthn), `login_security.rs`.
- **How it works** — Email + password issues a short-lived JWT access token
  and a refresh token; the browser keeps them in `localStorage`
  (`varman.token`, `varman.refreshToken`, `varman.user`) and the API client
  refreshes on 401. Passkeys are an optional second sign-in method.
- **Login security** — failed attempts and sign-in history are tracked
  (`/alerts` → Login security). The login endpoint is rate limited to
  **10 attempts per minute per IP**; register 5/hour, refresh 30/min,
  password change 10/min. Exceeding a limit returns
  `429 too_many_requests` with `Retry-After`.

### 1.2 Dashboard

- **Where** — `/dashboard`.
- **API** — `analytics.rs`, `agents.rs`.
- **How it works** — Fleet health (agents online/offline), traffic and
  interception summaries for the selected window, coverage tiles for sites
  and rules, and the world map fed by request geography. Counters come from
  the events the edges ship; the dashboard **summarises**, it never generates
  the full report (that is `/reports`, on demand).

### 1.3 Fleet / agents

- **Where** — `/agents`.
- **API** — `agents.rs`, `mtls.rs`.
- **How it works** — Agents register over gRPC (:9090), then heartbeat with
  load metrics; the control plane pushes per-site config bundles and tracks
  what each agent has applied. Agent identity can be pinned with mutual TLS.
  Registration can be closed (`registration_open: false` in
  `/api/v1/version`) so unknown agents cannot enrol.

### 1.4 Config history

- **Where** — `/config-history`.
- **API** — `config_versions.rs`.
- **How it works** — Every change that produces a new bundle is versioned.
  The page lists versions with their diff summary, actor and time; a version
  can be previewed and rolled back, which re-pushes the bundle to the
  affected agents.

### 1.5 Lifecycle

- **Where** — `/lifecycle`.
- **How it works** — The site lifecycle view: creation → configured →
  receiving traffic → protected, with what is missing at each stage. It is a
  checklist surface, not a separate configuration store.

---

## 2. Sites

### 2.1 Sites list

- **Where** — `/sites`.
- **API** — `sites.rs`.
- **How it works** — Create a site (name, domains), see its status, engine
  mode, agent binding and quick metrics; open a site to enter its detail
  workspace. Deleting a site removes its bundles from every agent.

### 2.2 Site detail — Origin

- **Where** — `/sites/:siteId/origin`.
- **API** — `sites.rs`, `site_failover.rs`.
- **How it works** — Upstream definition: address, TLS to origin, SNI, Host
  header rewriting, health checks. Multiple upstreams form a load-balanced
  pool; failover rules decide what happens when the pool is unhealthy
  (secondary pool, static response). The edge resolves origins from its local
  bundle — the control plane is never in the request path.

### 2.3 Site settings

- **Where** — `/sites/:siteId/settings`.
- **How it works** — Per-site identity and behaviour that is not security or
  routing: display name, domains, engine mode (`varman` / `legacy` /
  `shadow`), advanced mode, custom-layer toggles, monitor lists, log options.

---

## 3. Protection (per site)

### 3.1 Web Protection — the single security surface

- **Where** — `/sites/:siteId/security/protection`.
- **Legacy links** — `/security/waf` → Rules tab, `/security/cc` → CC tab,
  `/security/policy` → Policy tuning, `?rule=` and `?block=` deep links are
  preserved.
- **Tabs** — **Overview** (posture summary and what is active), **Rules**
  (managed + custom rules, rule tester), **CC** (challenge / under-attack),
  **Policy tuning** (see 3.2).

#### Managed rules

- **How it works** — 13 managed rule families (`VARMAN-1001..1061`) ship in
  the engine: SQLi, XSS, RCE, path traversal, scanners, dotfile probes,
  dangerous methods, admin paths, protocol anomalies, oversized payloads,
  upload abuse, SSRF and generic payload syntax. Each rule has a severity,
  an anomaly score contribution and a mode (off / monitor / block). Rules
  are grouped by family; disabling a rule records an override that survives
  bundle pushes.

#### Custom rules

- **How it works** — Operator-written expressions in the engine's rule
  language, e.g. `http.request.uri.query contains "union select"` or
  `cf.waf.score.sqli ge 30`, with a name, mode and score action. A rule
  tester evaluates an expression against a synthetic request and shows which
  conditions matched — the same evaluator the edge runs.

#### CC (challenge / under attack)

- **API** — `challenge.rs`, `defense.rs`.
- **How it works** — Challenge posture for bots and bursts: JS challenge,
  managed challenge, or under-attack mode (heightened thresholds). Verdicts
  are recorded as events with the reason.

### 3.2 Policy tuning

- **Where** — `/sites/:siteId/security/protection?tab=tuning` (legacy
  `?tab=settings|policy|exclusions` resolve here).
- **API** — `policies.rs`, `exclusions.rs`, `waf_settings.rs`.
- **Sections (rail)** —
  - **Policy summary** — chips for every layer with its state.
  - **Site posture** — engine mode, advanced mode, custom layers, monitor
    lists: what this site runs.
  - **Effective posture** — the merged result after policy inheritance:
    which layer wins where, so "published" and "applied" are visibly
    distinct.
  - **Rule exceptions** — per-rule overrides: disable, monitor-only, score
    adjustment, and **target exclusions** (path-scoped, with named members
    such as `query:q`, `body:content`, `cookie:x`, `header:x`).
  - **Exclusion packages** — see 3.3.
  - **Preview and apply** — compiles the candidate bundle and shows the
    diff; apply pushes it.
  - **Version history** — the site's bundle versions with rollback.

### 3.3 Exclusion packages

- **API** — `exclusions.rs`.
- **Two kinds** —
  1. **entries** — curated per-application exclusion sets (WordPress,
     Next.js static assets, Nextcloud WebDAV, rich-text editors, …). Each
     entry is path-scoped and can name a specific argument target
     (`query:q`), addressing both managed and custom rule ids.
  2. **seclang** — an upstream SecLang file (e.g. a CRS exclusion plugin)
     fetched by URL, checked to parse, stored **with a report of what it
     contains** (counts by directive, never invented), and compiled into the
     site's virtual patches when attached. SecLang packages act on the CRS
     rules carried in the site's virtual patches; root-prefix only,
     site-wide.
- **Honest limits** — managed rules that consume `cf.waf.score.*` are not
  suppressible by target exclusions (Stage-1 pipeline); the UI says so
  instead of pretending.

### 3.4 Access control

- **Where** — `/sites/:siteId/security/access` (tabs IP / Geo; legacy
  `/security/ip-rules` and `/security/geo` redirect here).
- **API** — `ip_rules.rs`, `ip_groups.rs`, `ip_lists.rs`, `geo.rs`,
  `ip_datasets.rs`, `ip_analysis.rs`, `site_basic_auth.rs`.
- **IP rules** — allow/deny lists at site level, evaluated before the
  security pipeline; lists can reference **IP groups** (named sets shared
  across sites).
- **Geo policy** — country and ASN policy with **ipverse** data only:
  - country ranges come from `ipverse/rir-ip` files, ASN ranges from
    `ipverse/as-ip-blocks`;
  - the sync endpoint downloads, parses and stores ranges in `ip_datasets`;
    **sync = applied** (the bundle carries the ranges the edge matches);
  - actions per country/ASN: off / monitor / block;
  - unsynced keys are shown as **not enforced** (`missing_keys`), never as
    active.
- **Client IP analysis** — paste an IP, get what the edge would decide:
  which dataset matched (country/ASN), which rule would fire, using the same
  loaders the edge uses.
- **Basic auth** — HTTP basic credentials for the site, per path.

### 3.5 Rate limiting

- **Where** — `/sites/:siteId/security/rate-limiting`.
- **API** — `rate_limiting.rs`.
- **How it works** — Named limiters (key: IP / header / cookie / path;
  window; burst; action). Attached to routes or site-wide; the edge enforces
  from the local bundle and reports hits as events.

### 3.6 Bot protection

- **Where** — `/sites/:siteId/security/bot`.
- **API** — `bot.rs`.
- **How it works** — Bot posture (off / monitor / challenge / block),
  verified-bot lists (known good crawlers by reverse DNS), user-agent
  heuristics and reputation signals feeding the CC layer.

### 2.4 Routing topology (the flow view)

- **Where** — `/topology` (fleet-wide, with a site selector) and
  `/sites/:siteId/topology` (site-scoped; also a tab in the site workspace).
- **API** — composes existing endpoints (site detail, WAF settings, routes,
  pools, upstreams, rate limits, IP rules, cache rules, basic auth, bot, geo,
  SSL, rewrites, custom rules, exclusion bindings); edits go through the same
  endpoints the feature pages use.
- **How it works** — a live ReactFlow graph of the real request path:
  **Internet → Site → Web Protection → Security layers → Routing → Origin
  pools → Targets**. Every link is animated; security layers are grouped in
  one box and each origin pool groups its targets. Nodes are draggable and
  the arrangement is remembered per site; `Auto layout` restores the computed
  layout.
- **Editing in place** — clicking a node opens an editor: site identity,
  WAF posture (enabled/mode/engine/paranoia), rate limits, IP rules, cache
  rules, basic auth credentials, bot posture, geo policy, routes, pools and
  upstreams. Components whose editors are pages of their own (rule authoring,
  API schema, exclusions, SSL issuance) open from the panel.
- **Drag to add** — palette items (Upstream, Origin pool, Route, Rate limit,
  IP rule, Cache rule) are dragged onto the canvas; the create form opens and
  **nothing is written until it is saved**.
- **Honest by construction** — the graph is built from configuration, never
  hand-drawn; empty sections render explicit placeholder nodes ("No origin
  pool yet"), so a site with nothing configured still shows the complete flow
  instead of a single lonely node.

### 3.7 API assets
- **Where** — `/sites/:siteId/security/api-assets`.
- **API** — `api_assets.rs`, `api_protection.rs`.
- **How it works** —
  - **Inventory** — observed endpoints from real traffic (methods ×
    templated paths, e.g. `/orders/42` → `/orders/{id}`), with counts;
  - **Declared spec** — the OpenAPI document for the site; the page diffs
    observed vs declared;
  - **Bounded learning** — learns request and response **structures and
    counts, never values** (types, key sets, required-ness observations per
    status class), and can export an **OpenAPI draft** (no `required`
    fields, no values);
  - **Per-operation controls** — every operation gets Off / Observe /
    Enforce, gating the OpenAPI validation layer only. Templates collapse
    (`/orders/42` → `/orders/{id}`), and when several operations match, the
    most restrictive mode wins. Every mode change pushes the bundle.

### 3.8 Caching

- **Where** — `/sites/:siteId/caching`.
- **API** — `cache.rs`, `cache_settings.rs`.
- **How it works** — Cache rules by path/extension with TTL and key
  composition; purge by path or tag; hit/miss stats per site. The WAF never
  caches responses it blocked or personalised.

### 3.9 SSL / ACME

- **Where** — `/sites/:siteId/ssl`; global view at `/ssl`.
- **API** — `ssl.rs`, `system_tls.rs`.
- **How it works** — Per-site certificates: manual PEM upload, or ACME
  (Let's Encrypt) issuance/renewal with HTTP-01 or DNS-01; renewal status
  and expiry are shown. The global page lists every certificate in the
  fleet with expiry warnings.

### 3.10 Traffic analytics

- **Where** — `/sites/:siteId/traffic`; global view at `/traffic`.
- **API** — `analytics.rs`.
- **How it works** — Requests, status classes, bandwidth, top paths,
  cache-hit ratio, geography, over the selected window; sourced from the
  access-log pipeline with daily buckets in the configured timezone.

### 3.11 Rewrite / routes

- **Where** — `/sites/:siteId/rules/rewrite`.
- **API** — `rewrite.rs`.
- **How it works** — Routing rules (match host/path → action: proxy to
  upstream, redirect, static response) and URL rewrites (regex
  replace/redirect) evaluated in order; preview shows the effect for a
  sample URL.

### 3.12 Logs

- **Where** — `/logs` (global), per-site logs inside the site workspace.
- **API** — `logs.rs`, `log_retention.rs`.
- **How it works** — Two streams: **security events** (each with the
  canonical request, the matched rules, the verdict and the "why" resolver)
  and the **access log** (every request the edge answered, including WAF
  answers). Filters: site, status, verdict, rule id, path, IP, time window.
  Body views show the inspected payload. Pass-through 5xx responses are not
  access-logged; WAF-answered requests are. Retention is configurable
  (Settings → Log retention); Elasticsearch shipping is optional.

---

## 4. Global surfaces

### 4.1 Policies

- **Where** — `/policies`, detail at `/policies/:policyId`.
- **API** — `policies.rs` (17 routes).
- **How it works** — A policy is a revisioned document of **layers**
  (engine posture, CRS tuning, custom rules, rule overrides, virtual
  patches, API schema, rate limits, IP access, bot posture, CRS import,
  …). Sites **follow** a policy; the effective posture merges policy layers
  with site-local layers (most restrictive wins where both speak). The
  detail page shows per-layer sections, add-layer, version history and a
  preview of the compiled result.

### 4.2 CRS

- **Where** — `/crs`.
- **API** — `crs.rs`.
- **How it works** — Import OWASP CRS rulesets (4.30.0 imported: 693
  rules), browse categories, set the paranoia ceiling per policy, inspect
  the rule catalogue, and see which rules are active where. Imported rules
  live as virtual patches in the site's bundle; the compatibility tracker is
  in [`compatibility.md`](./compatibility.md).

### 4.3 Alerts and notifications

- **Where** — `/alerts` (legacy `/notifications` redirects).
- **API** — `alerts.rs`, `notifications.rs`, `login_security.rs`.
- **How it works** — **Alert rules** (condition → severity), **silences**
  (mute a rule for a window), **delivery channels** (email SMTP, webhook,
  Telegram bot), **login security** (failed attempts, sign-in history) and
  **alert history**. Channels are tested from the UI; a test that fails
  says so.

### 4.4 Reports

- **Where** — `/reports`.
- **API** — `reports.rs`.
- **How it works** — The dashboard summarises; the full **interception
  report** is generated on demand: choose filters (site, date range within
  92 days, verdicts), an optional custom heading/footer, preview the
  summary, then generate and download a self-contained HTML report (no
  scripts, attachment disposition). **Schedules** (daily/weekly/monthly)
  email the report; "send now" triggers one immediately. Date-only bounds
  and daily buckets follow the configured timezone.

### 4.5 Blocked IPs

- **Where** — `/blocked-ips`.
- **API** — `blocked_ips.rs`.
- **How it works** — Every auto-block (reputation/CC escalation) and manual
  block, with reason, scope, expiry and hit count; unblock from the list.
  Auto-blocks expire on their TTL.

### 4.6 IP groups

- **Where** — `/ip-groups`.
- **API** — `ip_groups.rs`, `ip_lists.rs`.
- **How it works** — Named, reusable sets of IPs/CIDRs shared by IP rules
  and rate limits across sites; editing a group re-pushes every bundle that
  references it.

### 4.7 AI assistant

- **Where** — `/assistant`.
- **API** — `ai.rs`, `mcp.rs`.
- **How it works** — Optional AI assistant for operators (explain an event,
  draft a rule). Provider/keys configured in Settings → AI assistant; the
  MCP endpoint exposes the console's read tools to external agents. Off by
  default; nothing is sent anywhere unless configured.

### 4.8 Settings

- **Where** — `/settings`.
- **API** — `settings.rs`, `display.rs`, `users.rs`, `passkeys.rs`,
  `system_tls.rs`, `keys.rs`, `error_pages.rs`, `log_retention.rs`.
- **Sections** —
  - **Appearance** — theme, brand colour, console language.
  - **Display & data timezone** — the zone used for display and for report
    bounds/buckets (`chrono-tz`).
  - **Account** — profile, password, sessions; **Dashboard users** — create
    operators with roles, enable/disable, force password change.
  - **Passkeys** — WebAuthn registration per user.
  - **Control-plane TLS** — certificate for the console itself.
  - **Observation mode** — global WAF observation (record, don't block).
  - **API protection** — default posture for the OpenAPI layer.
  - **AI assistant / MCP** — assistant provider and the MCP server toggle.
  - **Elasticsearch** — optional log shipping.
  - **Log retention** — how long events and access logs are kept.
  - **Custom error pages** — branded block/challenge pages.
  - **API keys** — machine credentials for the REST API.

---

## 5. Security engine (behind the surfaces)

Full detail in [`security-engine.md`](./security-engine.md). Summary:

| Layer | What it does |
| --- | --- |
| Canonicalisation | One normalization for every detector (bounded percent decoding, path collapse, query/cookie parsing) |
| Signature lane | Aho-Corasick scan: block-tier payload syntax, log-tier ambiguous tokens |
| Managed rules | 13 families with anomaly scores and per-rule modes |
| Custom rules | Operator expressions with modes and score actions |
| SecLang / CRS | Virtual patches, CRS 4.30.0 import, `SecRuleUpdateTargetById` / `SecRuleRemoveById` incl. the `ctl:` controls plugins use |
| API schema layer | OpenAPI validation with per-operation Off / Observe / Enforce |
| Rate limiting | Named limiters enforced at the edge |
| IP / geo | IP rules, groups, ipverse country/ASN ranges |
| Bots / CC | Bot posture, verified bots, challenges, under-attack |
| Exclusions | Path-scoped target exclusions (named members) + curated packages + upstream imports |
| Work bounds | Per-request finding caps, body budgets, structured degradation |
| Runtime | Immutable per-site snapshots behind `ArcSwap` |

Engine mode per site: `varman` (native, enforcing), `legacy` (imported
signature engine), `shadow` (both run, verdicts compared, enforcement
unchanged).

---

## 6. REST API surface

48 route modules under `/api/v1`, 189 route declarations. Groups:

| Group | Modules |
| --- | --- |
| Auth & users | `auth`, `passkeys`, `users`, `keys`, `login_security` |
| Fleet | `agents`, `mtls` |
| Sites & config | `sites`, `site_failover`, `site_basic_auth`, `rewrite`, `cache`, `cache_settings`, `config_versions`, `settings`, `display`, `error_pages`, `system_tls`, `ssl` |
| Protection | `rules`, `waf_settings`, `policies`, `crs`, `exclusions`, `challenge`, `defense`, `bot`, `rate_limiting`, `ip_rules`, `ip_groups`, `ip_lists`, `geo`, `ip_datasets`, `ip_analysis`, `api_assets`, `api_protection` |
| Observability | `logs`, `analytics`, `alerts`, `notifications`, `reports`, `blocked_ips`, `log_retention` |
| Integrations | `ai`, `mcp` |
| System | `debug`, `mod`, `rate_limit`, `self-protection` |

API conventions: Bearer JWT; JSON errors as
`{"error": {"code": "...", "message": "..."}}`; rate limits return 429 with
`Retry-After`; list endpoints accept window/pagination filters.

---

## 7. External data and integrations

| Source | Used for | Rules |
| --- | --- | --- |
| [ipverse](https://github.com/ipverse) `rir-ip` | Country ranges (geo policy) | **Only** source of geo/ASN enforcement data |
| ipverse `as-ip-blocks` | ASN ranges | Same |
| OWASP CRS 4.30.0 | Imported ruleset (Apache-2.0) | Imported with a report of what was imported |
| Telegram Bot API | Alert delivery | Token configured in Alerts |
| SMTP | Alert + report email | Configured in Alerts / Reports |
| Webhooks | Alert delivery | JSON POST to operator URL |
| Elasticsearch | Optional log shipping | Off by default |
| MCP | Assistant tool access | Off by default |

The embedded tor-geoip database is used for **display labels only** (country
names on maps); enforcement uses ipverse ranges exclusively.
