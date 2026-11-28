# Desloppify continuation state (2026-11-28)

> Internal. Read this before continuing the code-health work.

## Current score

Strict **84.9 / 85.0** (plan start 22.1, +62.8). Queue **112**.
The branch was merged to `main` and released as **1.5.0** on 2026-11-28;
production `proxy-1` is verified on 1.5.0. The remaining architecture work is
planned in [`next-release-1.6-plan.md`](./next-release-1.6-plan.md).

The remaining gap is concentrated in three dimensions:

| Dimension | Score | Anchor findings |
|---|---|---|
| Cross-module architecture | 78 | `foundation_plugin_depends_on_platform` (pingap-plugin → varman-waf/-agent/-challenge), `rule_vocabulary_duplicated_across_crates`, `plugin_reads_agent_process_global` (16 sites), `shared_types_create_module_cycles` |
| Initialization coupling | 80 | `provider_registries_are_process_globals` (five `LazyLock` registries) |
| Test strategy | 80 | `maintenance_writes_untested` (needs a disposable PostgreSQL), remaining handler-module coverage |

Everything else is at or above 85 (elegance, design, API, naming, authorization, error consistency, contracts, AI debt).

## Gates (green at this commit)

```bash
export PATH="$HOME/.local/bin:$HOME/.cargo/bin:$PATH"
cargo fmt --all -- --check
cargo test --workspace --features=full      # 64 suites, 0 failed
cargo clippy --workspace --all-targets --features=full -- -D warnings
cargo machete
```

Feature checks used: `--cp --admin` (401 unauth, 200 auth), file-config proxy on
a loopback port, all-in-one boot against a temporary PostgreSQL, `make build-web`,
and admin `/configs` auth/prefix tests.

## What this pass changed (highlights)

- **Security**: the `--admin` `/configs/*.js` auth bypass is closed; empty/malformed
  admin credentials fail closed; the CSRF key and admin credentials are redacted
  from logs; `--admin` decodes both credential halves; **every mutating control-plane
  handler now enforces the forced-password-change flag** (57 handlers, with
  self-service flag-only paths and the password-change exemption); IP-group
  mutations are admin-only; `key_allows_agent` fails closed; MCP tools are
  tenant-scoped (17 tests); auditors get documented read-all.
- **Structure**: typed plugin params everywhere (unknown keys/wrong types fail
  `pingap -t`); one `src/data_plane.rs::assemble` for all three roots; one
  `src/config_apply.rs` apply engine; `varman/data_plane.rs` split into
  bundle/acme/assembly; `WafEngine::inspect` 862→52 lines and
  `WafPlugin::handle_request` 900→45; one `ProviderUpdate` shape; root
  `app_state`/`error`/`bundle`/`key_auth`/`certificate_status`/`api_util`/`time_util`.
- **Tests**: boot smoke, server-location ordering, a real-origin proxy lifecycle
  (including `$variable` upstream), 16 authz tests, 17 MCP-scope tests, admin
  mutation/auth/import tests, secret redaction, last-admin guard, env fallbacks.
- **Operations**: `varman` help/template identity, Debian varman unit, ring as the
  documented rustls provider, strict readiness pid, `--cp` requires `--admin`,
  replaceable restart command, memory budget set once in `main`, pprof flake
  retried.

## Next: 1.6.0

The detailed plan is in [`next-release-1.6-plan.md`](./next-release-1.6-plan.md).
The short version is the foundation inversion as a new crate
(`varman-plugin`/`varman-edge`) in two stages:

1. Move the WAF modules (`waf/`, `waf_custom`, `waf_processor`, `waf_shadow`,
   `waf_stream`) into the new crate; keep `pingap-plugin` for generic plugins.
2. Move `challenge`, `cache`, `rewrite`, `error_page`; drop the `varman-*`
   dependencies from `pingap-plugin`.

Then inject the five provider registries (init 80) instead of `LazyLock`
singletons, and add a disposable-PostgreSQL maintenance test harness
(`tests/` with a container or a CI service) for test strategy.

Each stage ends with the four gates above; re-review only the dimension changed
and import with `--allow-partial`. The blind reviewers are anti-gaming: resolve
findings only after the code change.

## ACME / production safety

- Do **not** order or renew certificates before **2026-12-04 03:53 UTC** (rate-limit
  window). The current certificate expires **2026-12-03 20:58 UTC**; the 12-01
  renewal is the fifth and must succeed.
- 1.5.0 is deployed and verified; the certificate row count/fingerprint is
  unchanged. Future restarts must keep that invariant.

## Useful commands

```bash
desloppify status
desloppify next
desloppify review --run-batches --dry-run --dimensions <dim>
desloppify review --import-run <run-dir> --scan-after-import --manual-override --allow-partial --attest "..."
```

Recent re-review runs and the current issue IDs live in `.desloppify/`.
