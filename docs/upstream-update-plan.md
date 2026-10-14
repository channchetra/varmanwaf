# Upstream PingWAF update plan

> Status: **batch 1 landed (foundation), batches 2-5 planned.** This document
> tracks the work of pulling the latest PingWAF upstream into VarmanWAF after
> the initial import (`c87ef671`, v0.20.0). It is the reference for every
> update round: the delta, the crate mapping, the batch order, and the rules
> that keep the fork mergeable.

## 1. Upstream baseline and delta

| Item | Value |
|---|---|
| Upstream | https://github.com/shuaiZend/PingWAF |
| Imported baseline | `c87ef671` ("docs(waf): add post20 rule-grading zero-regression verification results"), v0.20.0 |
| Latest upstream main | `aa597371` ("chore(release): bump version to 0.25.10"), v0.25.10 |
| History | `main` was force-pushed upstream: `c87ef671` is **not** an ancestor of `aa597371`; the net tree diff is the integration basis, not a merge |
| Net delta | **249 files, +33,562 / −5,758** (`git diff c87ef671 aa597371`) |
| Extra branches | `feature/config-versioning-and-notifications`, `feature/per-site-failover` (not in main's delta yet) |
| Local reference clone | `C:\Users\MPTC\Desktop\waf-dev\PingWAF` (pristine, used to generate patches) |

### Delta by area

| Area | Files | Crate mapping | Notes |
|---|---:|---|---|
| `pingwaf-server` | 97 | → `varman-control` | Control plane: cache settings, logs UI APIs, API keys/passkeys, config versioning, per-site failover, notifications |
| `web` | 82 | → `web` | Dashboard: cache pages, logs autocomplete, profile/account pages, world map, WAF pages, nav splits |
| `pingap-plugin` | 9 | retained | WAF body staging model, challenge pages, error pages, verified-bots DNS plugin, cache enrichment |
| `pingwaf-agent` | 6 | → `varman-agent` | Config push fields: trusted ranges, verified bots, engine switch, cache settings, timestamps |
| `pingap-acme` | 6 | retained | Ready orders, cert reload, DNS providers |
| `src` | 5 | retained | Binary: admin/certificates/CLI, start-up features |
| `pingwaf-waf` | 5 | → `varman-waf` | Engine posture (site mode/paranoia), rule grading |
| `pingap-core` | 5 | retained | Host normalization, client-IP trust model, new plugin hooks |
| `pingap-proxy`, `pingap-config`, `pingap-upstream`, `pingwaf-challenge`, `pingwaf-proto`, remaining | ~30 | mixed | Server wiring, config, multi-node upstream fixes, challenge, protocol |

## 2. Integration mechanism

Because the upstream rewrote history and this fork renames crates, updates are
applied as **area-scoped 3-way patches**, never as a git merge:

```bash
# in the pristine clone
git diff <baseline> <upstream-target> -- <paths> > batch.patch
# in VarmanWAF (clean index for the touched files)
git apply --3way batch.patch
# resolve conflicts, then: fmt, check --workspace, tests, clippy, build, E2E
```

Rules:

- `--3way` works because the imported tree still carries the baseline blobs;
  files we never touched apply cleanly.
- Renamed crates need path renames in the patch (`pingwaf-server` →
  `varman-control`, `pingwaf-agent` → `varman-agent`, `pingwaf-waf` →
  `varman-waf`, `pingwaf-challenge` → `varman-challenge`, `pingwaf-proto` →
  `varman-protocol`).
- A batch must compile and pass the full suite **as a whole**; a batch that
  pulls in APIs from a later area is deferred, not stubbed.
- Our divergences stay authoritative where they are deliberate: the WAF
  plugin pipeline, engine modes, custom layers, stream inspection, the
  dashboard's Varman pages. Upstream work is integrated *around* them.

## 3. Batch plan

| Batch | Scope | Status |
|---|---|---|
| 1 | Foundation crates: `pingap-acme`, `pingap-config`, `pingap-core`, `pingap-proxy`, `pingap-upstream` | **Landed** (v0.22.0) |
| 2a | Protocol + agent model: proto fields, `varman-agent` cache/client/config, run-mode boxing | **Landed** (v0.22.1) |
| 2b | Control plane (110 files) + `src` start-up | **Landed** (v0.22.2 / v0.23.0) |
| 3a | Verified bots: `bot_dns.rs` (DNS reverse+forward confirmation), verified-bot IP ranges honoured by the plugin, Bot Protection UI | **Landed** (v0.35.1; v0.35.0 failed its E2E on a manual IP-group insert bug and was superseded) |
| 3b | WAF plugin body staging: staged request bodies with limits, upstream hook model around our pipeline | **Landed** (v0.37.0) |
| 3c | Challenge + error pages: branded edge pages, provenance headers, storable clearance on HTTP, redirect guard | **Landed** (v0.38.0) |
| 4 | Dashboard: `web` (82 files) — merge upstream pages/features into the rebranded dashboard, keep the Varman pages | **Split 4a/4b/4c** (below) |
| 4a | Account & identity: `AccountPage`, `ProfilePage`, `account/*` cards (API keys, passkeys, users admin), `ForceChangePasswordDialog`, `users` + `loginSecurity` APIs | **Landed** (v0.39.1; v0.39.0 failed its E2E on the missing first-sign-in flag and empty login history, and was superseded) |
| 4b | Ops surfaces: `BlockedIpsPage`, `NotificationsPage`, `WorldMapChart`, `wafLinkage`, per-site `FailoverPanel` | **Landed** (v0.40.0; channels stay on the Alerts page - one owner - and the failover panel replaces the site-settings stub) |
| 4c | Assistant widgets (`components/assistant/*`, widget store/hook) evaluated against our AssistantPage; upstream's site-page restructure (`basic/*`, panel renames) is skipped — our structure is authoritative | **Landed** (v0.41.0; the page keeps our admin gate, the widget mounts for administrators; first assistant unit tests added) |
| 5 | Feature branches (`config-versioning-and-notifications`, `per-site-failover`) once main is synced | Next (batch 4 complete) |

### Batch 1 detail (landed)

- `pingap-core/src/http_header.rs`: host normalization (`normalize_host`,
  `get_host` now returns a normalized owned `String`) and the client-IP trust
  model (`set_trusted_proxies`, `resolve_client_ip_with_trust`,
  spoof-resistant `get_client_ip`: public peers always resolve to their TCP
  address, forwarded headers are honoured only from loopback/private peers or
  configured proxies).
- `pingap-core/src/plugin.rs`: the upstream `handle_request_body` plugin hook
  (mutable body + `Result<Option<HttpResponse>>` answer path). VarmanWAF's own
  request-body/upgraded-body hooks were reconciled onto it: the WAF tail scan
  now answers with the standard block page, tunnel findings still abort the
  connection.
- `pingap-config`: trusted-proxy config field, manager reload wiring, common
  helpers.
- `pingap-upstream`: multi-node upstream fixes and lenient origin
  verification on snapshot restore.
- `pingap-acme`: Ready-order handling, certificate reload fixes, DNS provider
  touch-ups.
- `pingap-proxy`: error templates, request-body plugin hook call, error page
  HTML.

Two adaptations were needed where our code met renamed upstream APIs:
`pingap-plugin/src/cache.rs` (owned-host borrows) and the WAF plugin's hook
signature.

## 4. Verification protocol per batch

1. `cargo fmt --all`, `cargo check --workspace --all-targets`.
2. Full test sweep: engine (485+), plugin, control-plane, agent, corpus,
   robustness, budgets, lane cost, shadow report.
3. `cargo clippy --workspace --all-targets -- -D warnings`.
4. Release build, deploy to the live stack, E2E smoke (benign 200, attack
   probes 403, client IP unchanged in events, engine telemetry present),
   then publish.
5. Record the batch in this document and in the release notes.

## Batch 3b detail (landed, v0.37.0)

Upstream model extracted from `aa597371` (all in
`pingap-plugin/src/waf.rs`); our fork lacks it (our `waf_stream.rs` covers
*upgraded* protocol frames, not HTTP body staging):

1. **`stage_chunk(cap, inspect, &mut passthrough, &mut buffer, chunk) ->
   StageAction { Withhold | Flush(Bytes) | PassThrough }`** - the pure
   state machine. Withhold = the chunk is buffered and the caller replaces
   the outgoing chunk with an **empty chunk** (never `None`: that would end
   the upstream body). Past the cap: `Flush` inspects the prefix once, then
   passthrough.
2. **`DeferredBody` entries** keyed by request id (DashMap): withheld
   `BytesMut`, `passthrough`, `inspect` (false for log-capture-only),
   `log_prefix`, the deferred-verdict snapshot, `created_at`.
3. **Completion-time verdict**: the request-body filter withholds until the
   client finishes; the engine then runs once on the complete body (or the
   staged prefix past the cap) before any byte reaches the upstream - block
   answers with the block page, otherwise the staged bytes are handed over.
4. **Log capture**: `LogBodyPrefix` with `MAX_LOG_BODY_LIMIT = 64 KiB`
   (request `max_body_size` default 64 KiB), independent of inspection.
5. **Stale sweep**: entries whose exchange never completes are dropped on
   the periodic task's TTL (client vanished mid-body / upstream answered
   early).
6. **Tests to port/extend**: upstream's
   `request_body_staging_withholds_until_the_cap` and
   `request_body_staging_is_skipped_for_log_only_entries`, plus ours: a
   fragmented attack split across chunks still reaches a block verdict; an
   over-cap body is prefix-inspected and streams on.
7. **E2E**: chunked request-body attack blocked; large benign body passes;
   access log keeps the body prefix.

## Batch 3a detail (landed, v0.35.1)

- `pingap-plugin/src/bot_dns.rs` (new, upstream): reverse + forward DNS
  confirmation of known crawler user agents, verdict cache keyed by
  (IP, family) with tiered TTLs, resolver-outage degradation.
- `pingap-plugin/src/waf.rs` `BotPolicy`: verified-bot IP ranges
  (`ipnet`) and the DNS check, evaluated before the user-agent whitelist;
  the request path passes the parsed client IP. `contains_ignore_case` is
  now `pub(crate)` for the module.
- Control plane and proto needed **no** changes: `verified_bot_ranges`,
  `ip_verification_enabled` and `dns_verification_enabled` already flow
  from the site row (or a policy bot layer) through the bundle (batch 2).
- Dashboard: the Bot Protection page exposes all three switches + the
  verified-bot list picker.

Deferred within batch 3 (recorded, not stubbed): 3b body staging, 3c
challenge/error pages. The upstream engine posture/grading and managed-rule
catalogue deltas were already present in this fork (integrated in P2/P3),
so nothing was ported for them.

## Batch 2b-2 WIP state (branch `upstream-batch2b2-wip`)
The applied 86 files are committed on the WIP branch. The remaining work is
the interconnected core, in dependency order:

1. **`varman-control/Cargo.toml`** - add `hmac`, `ring`, `maxminddb`,
   `lettre` (workspace entries needed for the last three), `sysinfo`
   (workspace), `rustls-pemfile = { workspace = true }`, `axum` `multipart`
   feature, `version.workspace = true`.
2. **`src/config/mod.rs`** - new settings (notification channels/secret key,
   gRPC TLS, cache ceilings, failover defaults, login security) + JWT-secret
   pinning.
3. **`src/lib.rs`** - `pub mod config_history; pub mod notify;`, the
   `resolve_jwt_secret` call, notification init/reload/self-monitor, gRPC TLS
   builder.
4. **`src/grpc/mod.rs`** - per-agent visibility (`agent_visible_site_ids`,
   `update_payload_for_agent`), config-version recording, actor-aware
   `notify_config_changed`/`notify_all_config_changed`.
5. **`src/grpc/config.rs`** - map the new schema (mode/paranoia, waf_enabled,
   monitor_managed_rules, proxy trust, cache settings, failover policies,
   event types) into the proto, keeping our engine fields.
6. **`src/api/waf_settings.rs`** - add the upstream fields beside our
   engine_mode/virtual_patches/openapi_spec.
7. **`src/{admin,cli,main,varman}.rs`** - config CLI (`pingwaf config`),
   startup services, new flags.

Then: full sweep, deploy, smoke, release. The 229 compile errors on the WIP
branch are all attributable to these seven files.