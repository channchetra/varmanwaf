# Desloppify continuation state (2026-11-27)

> Internal. Read this before continuing the code-health work.

## Goal

Maximise the **strict score** honestly with the desloppify harness.
Target: **85.0**. Current: **81.1** (queue 121).

```bash
export PATH="$HOME/.local/bin:$HOME/.cargo/bin:$PATH"
desloppify status
desloppify next
```

The harness lives in `.desloppify/` (gitignored). Skill: `desloppify` (v7),
installed project-locally under `.claude/skills/desloppify`.

## Ground rules

- Branch: `desloppify/code-health`. **Nothing has been pushed or deployed.**
- Production runs **1.4.5**; the edge uses the real 1.4.5 image.
- Every step ends with:
  `cargo test --workspace --features=full`,
  `cargo clippy --workspace --all-targets --features=full -- -D warnings`,
  `cargo fmt --all -- --check`, `cargo machete`.
- Console/feature changes also get a visual smoke (local Postgres + all-in-one
  on Kiri, browser login/dashboard).
- ACME: do not trigger orders before **2026-12-04 03:53 UTC** (rate-limit
  window; see `docs/private/incident-2026-11-20-telemetry-outage.md`).

## Committed on this branch

| Commit | Change |
|---|---|
| `91e5031`..`4aa6289` | 1.4.3–1.4.5: gRPC TLS rotation, renewal watchdog, NUL ingest, stream policy |
| `2fe547b`, `9f30198` | stream policy + failed-reload guard/atomic registries |
| `5dd99f8` | one category taxonomy; dead processor trait removed |
| `58fe5c6`, `f972bad` | docs regenerated from the tree; placement rule |
| `daa1c8e` | single console embed; startup/admin dedupe |
| `3a40e4e` | `waf.rs` 7,525 → `waf/` modules |
| `8d80277` | data-plane drifts + `--cp` init order (200 verified) |
| `8200531` | `varman.rs` 2,885 → `varman/mod.rs` + `data_plane.rs` |
| `032f75e` | rule tester reports skipped exclusions/threshold truthfully |
| `8769a8a` | `admin.rs` → `maintenance.rs`; root map + flag distinction |

## Current high-elegance findings (all open unless noted)

1. `console_contract_mismatch` — `--admin` embeds the console but implements
   `/configs`, `/pprof`, `/basic`, not `/api/v1`. **Decision needed:** either
   stop embedding the console in `src/plugin/admin.rs` (breaks `make dev`'s
   :3018 UI) or implement a matching contract. Not changed deliberately.
2. `data_plane_assembled_three_ways` — `run()`, `run_admin_node()` and
   `start_data_plane()` still have three assembly paths (behaviour aligned in
   `8d80277`). Suggested: one `src/data_plane.rs::assemble(config, extras)`.
3. `engine_config_mapping_ownerless` — `WafEngineConfig` mapping is mirrored in
   `pingap-plugin/src/waf/mod.rs` (`build_site_engine`), the rule tester
   (`varman-control/src/policy_test.rs`) and `api/self_protection.rs`.
   Suggested: a shared constructor in `varman-waf`; the tester must keep
   listing what it cannot resolve (done in `032f75e`).
4. `control_plane_transport_modules_own_services` — move `defense::load`,
   `self_protection::load_settings/effective_allowlist` and the four `start_*`
   schedulers out of `api/`, re-exporting for routes.
5. `varman_mode_god_module` — `varman/mod.rs` is 1,651 lines after the data
   plane split; `run`/CLI/bootstrap remain.
6. `waf_policy_split_across_foundation_and_agent` — the rule model still lives
   in `varman-agent::cache` while enforcement lives in `pingap-plugin`.

## Test strategy (67)

- `control_plane_handler_coverage_gap` — 23 handler modules untested. Options:
  a disposable Postgres harness (real handlers) or a focused MockDatabase for
  the authz guard.
- `proxy_data_plane_integration_gap` — no `pingap-proxy/tests/` lifecycle test.
- The pre-push gate, shadow-report output and flaky window test are fixed.

## Recommended next steps

1. Decide the console contract (item 1) — it is the only workflow-breaking
   choice; everything else is a refactor.
2. `src/data_plane.rs::assemble` extraction (item 2), then re-review high/mid.
3. Move the control-plane services (item 4); then the engine mapping owner.
4. Add the API authz + proxy lifecycle suites; re-review test strategy.
5. When the queue is clear: `desloppify scan --path .` and check strict.

## Notes

- The first blind review was lenient (83.2); later re-reviews were stricter and
  the score settled at 81.1. Small fixes do not move it; the structural items
  above are what the reviewers weigh.
- `--cp` now returns 200 for the console shell, but its API calls still hit
  missing `/api/v1` routes (see item 1).
- Local stacks used for visual tests were torn down; no containers remain.
