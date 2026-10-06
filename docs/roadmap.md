# VarmanWAF Roadmap

> Honest status tracking for the implementation phases defined in the mandate
> (§34, §35). Update this file in the same change that advances a phase.

## Status board

| Phase | Scope | Status |
|---|---|---|
| 0 | Repository understanding | ✅ Complete (2026-10-06) |
| 1 | VarmanWAF bootstrap (rename, keep behaviour) | 🚧 In progress |
| 2 | New WAF engine skeleton (canonical model, pipeline, shadow) | 🚧 In progress — types + pipeline landed, shadow wiring pending |
| 3 | Canonicalization (stable normalization + bypass tests) | ⏳ Planned |
| 4 | Fast lane (Aho-Corasick, protocol checks, high-confidence sigs) | ⏳ Planned |
| 5 | Streaming body engine (bounded windows, limits) | ⏳ Planned |
| 6 | Semantic lane (SQL structural/AST, HTML5 XSS, shell, …) | ⏳ Planned |
| 7 | Native SecLang core + OWASP CRS conformance | ⏳ Planned |
| 8 | Advanced security (API, JWT, bot, ATO, TI, DLP, virtual patching) | ⏳ Planned |
| 9 | Optional External Processor API | ⏳ Planned |

---

## Phase 0 — Repository understanding (complete)

Delivered:

- `docs/upstream-pingwaf-map.md` — full module map, request flow, agent sync,
  control plane, schema, deployment, certificate lifecycle, current WAF
  integration, branding inventory, retain/rename/redesign decisions.
- `docs/architecture.md` — actual current architecture and invariants.
- `docs/references.md` — all studied/queued upstream projects, licenses, and the
  reimplementation rules of engagement.
- `docs/roadmap.md` — this file.
- VarmanWAF repository initialized from PingWAF v0.20.0 (commit `c87ef671`) as
  commit `1489ca4`; pristine upstream kept at `..\PingWAF`; all reference repos
  cloned under `..\references\`.
- Build environment established: `varman-dev` Docker image
  (`rust:1.98.1-bookworm` + protobuf/cmake/clang/openssl/nasm) with cached
  cargo registry and target volume (`CARGO_TARGET_DIR=/target`).

Exit criteria: met — no major rewrite has started; the map exists.

## Phase 1 — VarmanWAF bootstrap (in progress)

Goal: a user can clone VarmanWAF, build it, launch it with PingWAF-level
simplicity, open the Varman management interface, provision an edge node,
configure a site + upstream, and proxy traffic — with the existing engine still
working.

Task list:

- [x] Import PingWAF, keep pristine reference, baseline build environment.
- [x] Build `web/dist` (console embedding prerequisite) — workspace check green.
- [x] User-facing identity: binary `varman`, clap name/version, env prefix
      `VARMAN_*`, default admin email (`admin@varman.local`) / DB defaults,
      path defaults (`/etc/varman`, `/var/lib/varman`).
- [x] Deployment: `Dockerfile`, `docker-compose.yml`, `varman.toml`,
      `varman.service`, `install.sh`, `.github` workflows (image namespace
      `ghcr.io/varmanwaf/varmanwaf` is a placeholder until the registry is
      confirmed).
- [x] Dashboard: titles, i18n (en/zh), favicon.
- [x] Internal rename commit: `pingwaf-*` → `varman-*` crates
      (`varman-control`, `varman-agent`, `varman-waf`, `varman-protocol`,
      `varman-challenge`, `varman-pprof`). `pingap-*` names stay for now
      (documented in the map).
- [x] Docs branding sweep; provenance kept in the map/references docs and the
      upstream changelog file.
- [x] Verification: `cargo check --workspace --features full --all-targets`
      green ✅; full `cargo test --workspace --features full` green ✅
      (exit 0, no failures); `cargo build --release --bin varman --features
      full` green ✅ (7m42s, 55 MB binary); Docker Compose end-to-end ✅
      (runtime image built from the release binary; stack healthy on
      80/443/9080/9090; a real request proxied to a test origin returned 200;
      a SQLi-shaped request was recorded as a monitor-mode security event —
      `libinjection-sqli`, score 5). Procedure in `docs/deployment.md`.
- [x] Known behaviour recorded: in all-in-one the embedded agent registers
      before the first site exists, so one restart after creating the first
      site is needed to bind it (upstream-inherited; documented).
- [ ] First VarmanWAF release notes + version marker.

Exit criteria: `cargo build --release` passes and `docker compose up -d` serves
a working VarmanWAF with unchanged behaviour.

---

## Phase 2 — New WAF engine skeleton

- [x] `CanonicalRequest` model (provisional types; normalization Phase 3).
- [x] `Finding`, `AttackCategory`, `Confidence`, `Severity`, `EvidenceSource`,
      `DetectorId`.
- [x] `Action` with monotonic escalation (`Pass < Log < Monitor < Challenge <
      Block`), terminal `Block`.
- [x] `Detector` trait, `DetectionContext`, bounded `InspectionBudget`,
      structured `Degradation`.
- [x] `SecurityPipeline` with deterministic detector order, saturating score
      sum, optional stop-on-block.
- [x] `shadow::compare` — agree / stricter / **weaker** classification against
      the legacy `WafVerdict` (downgrades are the alertable class).
- [ ] Wire shadow execution into `pingap-plugin/src/waf.rs` (feature-flagged,
      metrics + structured logs; no enforcement change).
- [ ] Immutable per-site `SecuritySnapshot` behind ArcSwap; config version ack.
- [ ] Benchmarks: pipeline overhead vs legacy on the request corpus.

Exit: both engines run side by side; shadow results measurable; no behaviour
change in enforcement.

## Phase 3 — Canonicalization

- One canonical representation used by router, WAF, cache, upstream forwarding
  (`/open/../admin` cannot diverge between consumers).
- Exhaustive bypass tests: encoding, double-encoding, case, whitespace,
  comments, Unicode, multipart, JSON variants.
- Exit: normalization stable under corpus; detectors no longer decode
  independently.

## Phase 4 — Fast lane

- Aho-Corasick scanner, protocol/HTTP sanity checks (smuggling indicators,
  Host/authority issues), path traversal, CRLF, Log4Shell, high-confidence
  fingerprints, lightweight SQLi/XSS signals.
- Off/Monitor/Block modes, structured findings, metrics.
- Exit: fast lane alone detects the high-confidence attack corpus with zero
  benign-corpus blocks; benchmarked cost documented.

## Phase 5 — Streaming body engine

- Bounded windowed inspection for request bodies; decoders per content type;
  frame timeouts; slow-upload and trickling defenses; explicit size policies
  for formats that require full buffering.
- Exit: large-upload peak memory bounded; bypass corpus green; fuzz-clean
  decoders.

## Phase 6 — Semantic lane

- Detectors in order: SQL structural + SQL AST, HTML5/DOM XSS, shell/command,
  then SSRF, XXE, SSTI, NoSQL, LDAP/XPath, deserialization, prototype
  pollution, GraphQL abuse, API patterns.
- Every detector ships: attack corpus, benign corpus, bypass corpus, fuzz
  target, budget limits, degradation metrics.
- Exit: per-detector acceptance + performance budget; shadow-mode comparison
  report against the existing engine.

## Phase 7 — Native SecLang core

- Incremental per mandate §21: abstractions → request variables → operators →
  transformations → control semantics → OWASP CRS conformance runs.
- Unsupported directives stay observable; `docs/compatibility.md` tracks
  Supported/Partial/Unsupported/Planned with evidence.
- Exit: official CRS regression suites run in CI; differential tests vs.
  ModSecurity/Coraza triaged.

## Phase 8 — Advanced security

- API security/OpenAPI validation, JWT analysis, bot detection, ATO, threat
  intelligence, DLP, virtual patching, WebSocket inspection.
- Exit: each feature has corpora + FP controls + monitoring; security events
  explain what fired.

## Phase 9 — Optional External Processor API

- Zentinel-inspired UDS/gRPC external processors, capability negotiation,
  timeout/failure policies (`fail_open`/`fail_closed`/`monitor_only`).
- Exit: processors cannot destabilize the core; native engine remains the
  authority.

---

## v0.1 Core milestone checklist (mandate §35)

| Item | Phase |
|---|---|
| Pingora proxy (inherited) | 0 ✅ |
| Central control plane + PostgreSQL (inherited) | 0 ✅ |
| Edge agent + offline local config (inherited) | 0 ✅ |
| Sites/domains, upstreams, TLS/certificates (inherited) | 0 ✅ |
| Versioned config deployment | 2 |
| Canonical request representation | 2–3 |
| IP ACL, rate limiter (inherited, re-homed under Lane 0) | 2–4 |
| Fast lane scanner (SQLi/XSS/traversal/RCE/SSRF/Log4Shell/CRLF basics) | 4 |
| Monitor/Block modes | 4 (inherited modes re-exposed) |
| Streaming body size enforcement | 5 |
| Structured security events | 2 (extended) |
| Hot runtime swap (ArcSwap) | 2 |
| Docker Compose deployment (inherited) | 1 ✅/🚧 |

Explicitly **not** blocking v0.1: full CRS, DLP, ML, advanced bot management,
API discovery, enterprise clustering (mandate §35).

---

## Working agreements

- Keep the repository buildable at every step (`cargo check` gate in the dev
  container; `cargo build --release` and `docker compose up -d` for phase exits).
- Every significant task: read code → read reference → engineering note →
  smallest vertical change → tests → fmt/lint/test → docs (mandate §40).
- Security claims only from measurements (`docs/security-engine.md` once the
  Varman engine exists; benchmarks only with methodology).
- Never silently ignore configuration, unsupported SecLang, or malformed rules.
