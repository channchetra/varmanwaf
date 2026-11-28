# 1.6.0 plan — finish the code-health architecture work

> Internal. Written after the 1.5.0 production release (2026-11-28).
> Current strict score: 84.9/85. The three below-target dimensions are
> cross-module architecture (78), initialization coupling (80) and test
> strategy (80).

## Goal

Move the Varman-specific plugins out of the Pingap foundation, make the five
provider registries injectable, and add the missing database-backed tests —
without changing runtime behavior. Target: strict **85.0**, then 1.6.0.

## Phase 1 — create `varman-plugin`, move the WAF surface

1. Branch from `main` (1.5.0) as `refactor/varman-plugin`.
2. Create `varman-plugin/Cargo.toml`:
   - depends on `pingap-core`, `pingap-config`, `pingap-plugin` (factory +
     helpers), `varman-waf`, `varman-agent`, `varman-challenge`, `pingora`,
     `async-trait`, `serde`, `toml`, `tracing`;
   - `register_plugin!` registrations for the moved categories;
   - mirror the `geo`/`tracing` feature gates from `pingap-plugin`.
3. Move with `git mv` from `pingap-plugin/src`:
   - `waf/` (mod, access, bot, rate_limit, state, request, request_body,
     inspect, tests),
   - `waf_custom.rs`, `waf_processor.rs`, `waf_shadow.rs`, `waf_stream.rs`.
4. Update imports: `crate::` helpers become `pingap_plugin::`; keep the
   category names (`waf`, `waf_custom`, `waf_processor`, `waf_shadow`)
   unchanged so existing configs keep working.
5. Root `Cargo.toml`: add `varman-plugin`; root `src/main.rs` registration
   entry point calls its `register()`; remove the moved modules from
   `pingap-plugin`.
6. Gate: `cargo test -p varman-plugin`, `-p pingap-plugin`, full workspace,
   clippy, fmt, container e2e (WAF still blocks).

## Phase 2 — move the remaining Varman plugins

Move `challenge.rs`, `cache.rs`, `rewrite.rs`, `error_page.rs` into
`varman-plugin`; drop `varman-waf`, `varman-agent` and `varman-challenge`
from `pingap-plugin/Cargo.toml`. Update `docs/modules.md` (regenerate),
`CLAUDE.md` and the plugin index. Keep `pingap-plugin` for generic proxy
plugins only.

Residual `varman_agent::cache` model types used by the moved plugins should
move to `varman-waf`/`varman-protocol` (or a small `varman-edge-model` crate)
so `pingap-plugin` no longer imports the agent at all.

## Phase 3 — inject the provider registries

Replace the five `LazyLock<Arc<Provider>>` statics with a `ProviderSet` owned
by the composition root:

```rust
pub struct ProviderSet {
    pub upstreams: Arc<dyn UpstreamProvider>,
    pub locations: Arc<dyn LocationProvider>,
    pub server_locations: Arc<dyn ServerLocationsProvider>,
    pub certificates: Arc<dyn CertificateProvider>,
    pub plugins: Arc<dyn PluginProvider>,
}
```

- `assemble` builds one set and passes it to `AppContext` and the background
  tasks; tests construct local sets.
- Keep a thin process-global only for the legacy `--admin`/pprof paths if they
  cannot be converted in the same release; document it.
- Add a test that two independently constructed sets do not share state.
- Remove `plugin_reads_agent_process_global` by passing the agent handle/context
  into the WAF plugin instead of `VarmanAgent::instance()` (16 sites).

## Phase 4 — test strategy

1. Add a disposable-PostgreSQL harness:
   - `TEST_DATABASE_URL` (or a `docker compose` test service);
   - migrations + a per-test schema/transaction;
   - skip explicitly when unavailable (no silent pass).
2. Cover the maintenance writes: `add-admin`, `reset-password`, `set-allowlist`,
   `config-rollback`.
3. Cover the remaining control-plane handler modules with the authz matrix
   (owner/admin/auditor/viewer; flagged admin; 404-not-403 for foreign sites).
4. Add a check that every non-GET route's handler contains `require_write`,
   `require_password_changed`, `load_site_write`, or is on the documented
   exemption list.

## Acceptance

- Strict **85.0** from a fresh blind review of the changed dimensions.
- `cargo test --workspace --features=full`, `make lint-rustls`,
  `make test-rustls`, clippy `-D warnings`, fmt, cargo-machete.
- Container e2e: all-in-one + Postgres + origin; control plane, console,
  forced-password gate, site creation, HTTP proxy, WAF block, agent online.
- Production deploy: certificate row count/fingerprint unchanged; no ACME
  order before the 2026-12-04 window.

## Risks / notes

- `register_plugin!` uses `#[ctor]`; keep the explicit `register()` entry point
  from 1.5.0 so the link anchor cannot regress.
- The WAF tests share process-global state; keep the existing locks and run
  the new crate's tests serially if needed.
- Do not trigger ACME orders while staging; the 2026-12-01 renewal is the
  fifth slot and must succeed.
- Production rollback image: `sovichetra/varmanwaf:1.4.5`
  (`sha256:98b8935c…`); current: `1.5.0` (`sha256:875daafd…`).
