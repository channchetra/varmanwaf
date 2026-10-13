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
| 2b | Control plane (110 files) + `src` start-up | Next |

| 3 | WAF engine + plugin: `pingap-plugin/src/waf.rs` upstream evolution (body staging, posture), `varman-waf` engine posture/grading, `varman-challenge`, verified-bots wiring | Planned |
| 4 | Dashboard: `web` (82 files) — merge upstream pages/features into the rebranded dashboard, keep the Varman pages | Planned |
| 5 | Feature branches (`config-versioning-and-notifications`, `per-site-failover`) once main is synced | Planned |

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
