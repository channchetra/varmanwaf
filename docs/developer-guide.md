# Developer Guide

How to build, test, change and ship VarmanWAF - including the rule this
project actually follows: **every change updates the documentation that
describes it, in the same commit**.

## 1. Environment

- Linux build host required (Pingora does not target Windows). On Windows,
  use the Docker dev container (`varman-dev`) or WSL2; artifacts are Linux
  binaries.
- Rust 1.96+ (workspace pinned in `rust-toolchain` if present), Node 20+ for
  the console.
- PostgreSQL for local runs (`docker compose up -d varman-postgres`).

## 2. Repository map (where to put things)

| You are adding… | Where it goes |
| --- | --- |
| A REST endpoint | `varman-control/src/api/<area>.rs` + route registration in that module; a migration if it stores state |
| A database table/column | `varman-control/src/migration/` (SeaORM migration + `mod.rs` entry) |
| An engine detector or rule family | `varman-waf/src/` (pipeline stage), with corpora in `varman-waf/tests/corpus` |
| A SecLang feature | `varman-waf/src/seclang/` (+ compatibility notes in `docs/compatibility.md`) |
| A policy layer | `varman-control/src/api/policies.rs` (kind + config), bundle compiler in `varman-control/src/grpc/config.rs`, console editor in `web/src/pages/` |
| A console page | `web/src/pages/`, route in `web/src/router/index.tsx`, nav in `web/src/components/ui/Sidebar.tsx`, API module in `web/src/api/`, i18n keys in `web/src/i18n/locales/en/common.json` |
| A graph/node type in the topology | `web/src/components/topology/` (graph builder + nodes + panel) |
| An E2E check | `build-artifacts/run-e2e-<feature>.ps1` (next to the repository) |

### Documentation rule

Any behavioural change updates, in the same commit:

1. `docs/releases/v<version>.md` (what the round brings + verification),
2. the surface's document: `docs/features.md` for console/API behaviour,
   `docs/security-engine.md` for detection, `docs/compatibility.md` for
   SecLang/CRS, `docs/architecture.md` for structure,
3. `docs/user-guide-km/index.html` when an operator-facing flow changes,
4. the README feature table when a new surface appears.

## 3. The local gate (CI is local in this fork)

```bash
cargo fmt --all -- --check
cargo test --workspace --features full          # control / engine / plugin / agent
cargo clippy --features full --all-targets -- -D warnings

cd web
npx tsc -b
npx eslint .                                     # 0 errors
npx vitest run                                   # unit tests
npx vite build                                   # must run BEFORE the Rust build
```

The console bundle is embedded into the binary at compile time: **build
`web/dist` first**, then the Rust binary, or the old bundle ships. Verify
after deploying that the served `index.html` asset hash matches the newest
`web/dist/assets/index-*.js`.

## 4. Tests that matter

- **Engine corpora** (`varman-waf/tests/corpus`): every attack case must stay
  detected; no benign case (documentation, signed URLs, JWTs, API payloads)
  may reach Monitor/Block. Add a benign case with every false-positive fix.
- **Control-plane tests**: API behaviour, policy compilation, migrations.
- **Console tests** (`npx vitest run`): pure logic (graph builders, formatters)
  plus component smoke tests.
- **E2E sweep** (`build-artifacts/run-e2e-all.ps1`): 40+ scripts against a
  deployed stack, paced for the login limiter (10 attempts/min/IP - the
  limiter is part of the product). A new feature round adds one script.

## 5. The website

`website/` publishes the public site: a landing page plus **every document in
`docs/`**, rendered at build time from the same markdown, so the website can
never drift from the repository.

```bash
cd website
npm install            # marked + mermaid (build-time only)
npm run build          # docs/ -> website/dist (landing, docs, releases, khmer)

docker build -f website/Dockerfile -t varmanwaf-website website/
docker run --rm -p 8080:8080 varmanwaf-website     # http://localhost:8080
```

- The image is `scratch` + a static musl binary + the site files (a few MB);
  the server (`website/server/server.rs`) is standard library only - no
  crates, no shell in the image. **It is built locally and never published to
  Docker Hub.**
- New documents must be added to the catalogue in `website/build.mjs`
  (`GROUPS`); releases are discovered automatically from `docs/releases/`.
- Mermaid fences in the docs render as live diagrams (the runtime is bundled
  into `dist/assets/`).

## 6. Release workflow
1. **Bump the version line-scoped**: the workspace `version =` and the
   `pingap-*` path dependencies only (20 internal entries). External crates
   that share the string must stay untouched - known traps: `tor-geoip`
   0.46.0, `sqlparser` 0.63.0. Count the occurrences before and after.
2. **Write the release notes** (`docs/releases/v<version>.md`) with the
   verification evidence.
3. **Build**: `web` bundle → Rust release binary → runtime image
   (`Dockerfile.runtime`, tags `:<version>` and `:latest`).
4. **Deploy**: recreate the container, verify `/healthz`, `/api/v1/version`,
   and the served bundle hash.
5. **Verify**: run the new feature's E2E script, then the full sweep; run the
   benchmark when performance-relevant.
6. **Publish**: push both tags, record the digest in the release notes.
7. **Commit/tag/push**: one feature commit per round (plus doc commits),
   annotated tag, then update `docs/roadmap.md`.

## 7. Debugging

| Symptom | Where to look |
| --- | --- |
| Why was a request blocked? | Logs → security events → **why resolver** (rules, scores, exclusions) |
| A setting "did not apply" | The surface shows published vs applied; check the bundle push and Effective posture |
| Agent offline | Agents page, gRPC connectivity (:9090), registration state |
| Engine disagreement | Run the site in `shadow` mode and read the comparison events |
| Slow requests | `docs/profiling.md` (built-in profiling), analytics latency tiles |
| ACME order stuck pending/failed | The SSL page shows the reason; the Application log tab has the raw ACME transcript; check DNS and port 80 for HTTP-01 |
| CVE response / virtual patch | `docs/virtual-patches.md`; built-in templates via `GET /api/v1/virtual-patch-templates`; hits carry the rule id and the `php2shell` tag in security events |
| Config history | `/config-history` - every bundle with diff and rollback |

## 8. Working agreements

- Never fake a success: if a surface cannot apply something, it says so.
- Never invent shapes or values: learning reads structures and counts.
- Prefer the smallest honest fix; document limits instead of hiding them.
- Keep the benchmark and E2E tooling next to the repository
  (`build-artifacts/`) so verification is reproducible.
