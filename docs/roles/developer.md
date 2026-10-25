# For developers

> **Who this is for:** engineers changing VarmanWAF itself — the Rust crates,
> the React console, the rule engine, the API, or the docs. You build on Linux
> (or a Linux container), run the local gate, and ship the console bundle
> before the binary.

The repository follows one non-negotiable rule: **the documentation that
describes a behaviour changes in the same commit as the behaviour**. The docs
site is generated from the same markdown, so drift is a build failure waiting
to happen.

## The shape you are working in

VarmanWAF is a control plane plus edge agents:

- **`varman-control`** — Axum REST, tonic gRPC, SeaORM/PostgreSQL, logs,
  policies, agent health, embedded console.
- **`varman-agent`** — the Pingora data plane; pulls configuration, persists a
  last-good bundle, ships logs and metrics, receives commands.
- **`varman-waf`** — normalize → signatures → expression → anomaly score.
- **`varman-challenge`** — JS shield, interactive challenge, PoW, fingerprints,
  clearance cookies.
- **`pingap-*`** — the proxy foundation: routing, cache, TLS, ACME, plugins.
- **`web/`** — React/Vite/TypeScript console, built into `web/dist/` and
  embedded into the binary at compile time.

The deep version is in [Architecture](../architecture.md) and
[Workspace modules](../modules.md).

## Step 1 — Prepare the host

- Linux build host (Pingora does not target Windows). On Windows, use WSL2 or
  the project's Docker dev container; the artifacts are Linux binaries.
- Rust 1.96+ and Node 20+ (Node 22 is what the image uses).
- PostgreSQL for a local run: `docker compose up -d varman-postgres`.

```bash
git clone https://github.com/channchetra/varmanwaf.git
cd varmanwaf
docker compose up -d varman-postgres
```

## Step 2 — Know where a change belongs

| You are adding… | It goes in |
|---|---|
| A REST endpoint | `varman-control/src/api/<area>.rs` + route registration |
| A table or column | `varman-control/src/migration/` (SeaORM migration + `mod.rs`) |
| An engine detector | `varman-waf/src/` pipeline stage + corpus cases |
| A SecLang feature | `varman-waf/src/seclang/` + `docs/compatibility.md` |
| A policy layer | policy API, bundle compiler, console editor |
| A console page | `web/src/pages/`, router, sidebar, API module, i18n |
| A topology node | `web/src/components/topology/` (graph, nodes, panel) |
| A release check | the E2E harness next to the repository |

## Step 3 — Build the console first

The Rust build embeds `web/dist/`. If you build Rust first, you ship the old
console.

```bash
cd web
npm ci
npx tsc -b
npm run lint
npx vitest run
npm run build

cd ..
cargo build --release --bin varman --features full
```

The served `index.html` must point at the newest `web/dist/assets/index-*.js`.
This is the most common "my change did not deploy" failure.

## Step 4 — Run the local gate

CI is local in this fork. A change is not ready until all of it passes:

```bash
cargo fmt --all -- --check
cargo test --workspace --features full
cargo clippy --features full --all-targets -- -D warnings
cargo machete
typos

cd web
npx tsc -b
npm run lint          # 0 errors
npx vitest run
npm run build
```

For a deployed stack, run the functional suite, the route-surface sweep, and
the cache suite. The release notes record the exact counts.

## Step 5 — Verify the decision, not just the endpoint

The console has a **Request lifecycle** page that renders the real order of
WAF checks, cache, rewrites, and error pages. Use it when a feature "works" in
isolation but acts in the wrong place in the pipeline.

![Request lifecycle showing the real order of WAF checks](images/console/lifecycle.webp)

The topology is the other debugging surface: **Internet → Site → Protection →
Security layers → Routing → Origin pool**. A missing edge usually means a
group frame lost its handle, not that the data is absent.

![Full-screen topology of a real request path](images/console/topology-fullscreen.webp)

## Step 6 — Add tests with the right evidence

- **Engine corpora** — every attack case stays detected; every benign case
  (docs, signed URLs, JWTs, API payloads) stays allowed. Add a benign case with
  every false-positive fix.
- **Control-plane tests** — API behaviour, policy compilation, migrations.
- **Console tests** — pure logic (graph builders, formatters) plus component
  smoke tests.
- **E2E** — a new feature adds a script; the sweep checks every method/path
  still returns a deliberate status, not a 405 or 500.

Never fake a success. If a surface cannot apply a setting, it must say so.

## Step 7 — Release in one line of intent

1. Bump the workspace `version` and the internal `pingap-*` path versions only;
   never bump unrelated external crates that share the string.
2. Write `docs/releases/v<version>.md` with verification evidence.
3. Build web → Rust → runtime image; tag `:<version>` and `:latest`.
4. Deploy, then verify `/healthz`, `/api/v1/version`, and the bundle hash.
5. Run the feature check, then the full sweep; benchmark when performance
   changed.
6. Push both tags, record the digest in the release note, tag the commit.

The detailed workflow, including the macOS/Windows boundary and the known
traps, is in the [Developer guide](../developer-guide.md).

## Step 8 — Change the docs with the code

Every behavioural change updates, in the same commit:

1. `docs/releases/v<version>.md`;
2. the surface document (`docs/features.md`, `security-engine.md`,
   `compatibility.md`, or `architecture.md`);
3. the Khmer guide when an operator-facing flow changes;
4. the README feature table when a new surface appears.

The docs site reads `docs/` directly. Add a page to the catalogue in
`website/build.mjs`; releases are discovered automatically.

## Related

- [Architecture](../architecture.md) — system shape, invariants, failure semantics.
- [REST API reference](../api.md) — every endpoint and its permissions.
- [Security engine](../security-engine.md) — pipeline, detectors, scoring.
- [Profiling](../profiling.md) — CPU profiles, flame graphs, memory snapshots.
- [For system administrators](./system-administrator.md) — deploy and run it.
