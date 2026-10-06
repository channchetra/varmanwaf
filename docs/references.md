# References and Upstream Inspiration

> Rule of engagement (mandate §3): PingWAF is the only *implementation
> foundation*. Every other project below is a **research reference**: we study
> source, understand the idea, then design a Varman-native abstraction and
> implement it independently in Rust. We do **not** add submodules, runtime
> dependencies, embedded binaries, copied packages, or verbatim large files, and
> nothing here may become an operational dependency of VarmanWAF.

When an implementation idea is derived significantly from a project, add a row to
that project's table with the upstream URL, what was learned, and how the Varman
implementation differs.

All reference repositories are cloned locally (shallow) under
`C:\Users\MPTC\Desktop\waf-dev\references\` for deep source study; GuardianWAF is
at `C:\Users\MPTC\Desktop\waf-dev\GuardianWAF`.

| Reference | URL | License | Local checkout |
|---|---|---|---|
| PingWAF | https://github.com/shuaiZend/PingWAF | Apache-2.0 | `..\PingWAF` (full clone, pristine) |
| GuardianWAF | https://github.com/GuardianWAF/GuardianWAF | see upstream `LICENSE` | `..\GuardianWAF` |
| PRX-WAF | https://github.com/openprx/prx-waf | MIT OR Apache-2.0 | `..\references\prx-waf` |
| Zentinel | https://github.com/zentinelproxy/zentinel | MIT OR Apache-2.0 | `..\references\zentinel` |
| zentinel-modsec | https://github.com/zentinelproxy/zentinel-modsec | Apache-2.0 | `..\references\zentinel-modsec` |
| Zentinel WAF Agent | https://github.com/zentinelproxy/zentinel-agent-waf | Apache-2.0 | `..\references\zentinel-agent-waf` |
| Zion | https://github.com/fabriziosalmi/zion | Apache-2.0 | `..\references\zion` |
| Lorica | https://github.com/Rwx-G/Lorica | Apache-2.0 | `..\references\Lorica` |
| OWASP Core Rule Set | https://github.com/coreruleset/coreruleset | Apache-2.0 | `..\references\coreruleset` |
| Coraza | https://github.com/corazawaf/coraza | Apache-2.0 | `..\references\coraza` |
| ModSecurity | https://github.com/owasp-modsecurity/ModSecurity | Apache-2.0 | `..\references\ModSecurity` |

Status legend: **Studied** (deep source study done for the adopting phase),
**Inspected** (structure/README/entry points reviewed), **Queued** (cloned,
deep study starts with its phase).

---

## PingWAF — platform foundation (Studied)

- URL: https://github.com/shuaiZend/PingWAF (Apache-2.0)
- Area studied: whole platform — see `docs/upstream-pingwaf-map.md` for the
  full module map.
- Ideas adopted: everything structural: control-plane/edge split, gRPC control
  protocol, local rule cache and edge autonomy, per-site RuleBundle model,
  Pingora data plane, plugin steps, Docker simplicity, embedded React console,
  blocked-IP reconciliation, certificate/ACME lifecycle, observation mode.
- How Varman differs: branding, security engine (multi-lane, canonical model,
  semantic detectors, SecLang, response inspection), config versioning,
  independent test corpora. The platform architecture is intentionally
  recognizable (mandate §1).

---

## GuardianWAF — security breadth (Queued)

- URL: https://github.com/GuardianWAF/GuardianWAF
- Areas to study: `internal/engine`, `internal/layers`, `internal/proxy`,
  `internal/cluster`, `internal/runtime`.
- Target ideas: ordered security pipeline, monotonic action escalation
  (PASS < LOG < MONITOR < CHALLENGE < BLOCK), native detectors, sanitizer,
  threat intelligence, virtual patching, API validation, ATO protection, DLP,
  bot detection, WebSocket frame inspection, response security, cluster
  behaviour, panic/failure handling, fuzz/regression strategy.
- Varman difference: reimplemented idiomatically in Rust inside a unified
  pipeline; Go implementation is not ported line-by-line; no runtime coupling.

*(Rows added when a phase adopts a specific mechanism.)*

---

## PRX-WAF — two-lane security engine (Queued)

- URL: https://github.com/openprx/prx-waf
- Areas to study: `crates/waf-engine`, `crates/gateway`, `crates/waf-common`,
  `tests/lane2`, `tests/ftw`, `fuzz`.
- Target ideas: Lane 1 (Aho-Corasick/libinjection/regex screening) vs Lane 2
  (semantic): `StructuralSqlDetector`, `AstSqlDetector` (sqlparser),
  `XssDomDetector` (scraper/html5ever), `RceStructuralDetector`/`RceAstDetector`
  (brush-parser), structured body extraction (JSON/XML/GraphQL/multipart),
  windowed body/response inspection, semantic budgets and degradation, Lane 2
  shadow rollout, CRS/semantic regression corpora, parser fuzzing.
- Varman difference: detectors are Varman-native modules behind one canonical
  request model; no dependency on PRX-WAF crates; integration into the single
  Varman pipeline with unified `Finding`/scoring semantics.

*(Rows added when a phase adopts a specific mechanism.)*

---

## Zentinel — external processor architecture (Queued)

- URL: https://github.com/zentinelproxy/zentinel
- Areas to study: `crates/agent-protocol`, `crates/proxy/src/agents`.
- Target ideas for the **optional future** External Processor API: bidirectional
  protocol events (RequestHeaders, RequestBodyChunk, ResponseHeaders,
  ResponseBodyChunk, WebSocketFrame), decisions/cancellation/flow control,
  UDS + gRPC transports, binary body transport, correlation affinity,
  capability negotiation, health reporting, timeout/failure policies
  (fail_open / fail_closed / monitor_only).
- Varman difference (hard constraint): the primary engine stays in-process and
  native; external processors are opt-in extensions, never the enforcement core.

*(Rows added when Phase 9 adopts a specific mechanism.)*

---

## zentinel-modsec — native SecLang/CRS engine (Queued)

- URL: https://github.com/zentinelproxy/zentinel-modsec
- Areas to study: `src/engine`, `src/parser`, `src/operators`,
  `src/transformations`, `src/variables`, `src/actions`, `src/libinjection`,
  `tests/crs_conformance.rs`.
- Target ideas: pure-Rust SecLang parsing/execution model, TX variables,
  chains, skip/skipAfter/ctl/setvar, SecDefaultAction/SecMarker,
  SecRuleRemoveById/SecRuleUpdateTargetById, phase 1/2 semantics, JSON/XML/
  multipart processors, transformation/operator catalogs, anomaly scoring,
  `@detectSQLi`/`@detectXSS` equivalents, CRS conformance harness approach.
- Varman difference: independent implementation; conformance is measured
  against official OWASP CRS regression cases, and unsupported directives are
  observable (never silently ignored). See `docs/compatibility.md`.

*(Rows added when Phase 7 adopts a specific mechanism.)*

---

## Zentinel WAF Agent — advanced WAF capabilities (Queued)

- URL: https://github.com/zentinelproxy/zentinel-agent-waf
- Areas to study: API security, OpenAPI validation, GraphQL, JWT analysis,
  authentication abuse, credential attacks, bot detection, threat intelligence,
  sensitive-data detection, virtual patching, supply-chain checks, anomaly
  scoring, ML signals, streaming inspection.
- Varman difference: features land as native `varman-waf` subsystems in Phase 8,
  with independent corpora; no dependency on this agent.

*(Rows added when a phase adopts a specific mechanism.)*

---

## Zion — hot-path discipline (Queued)

- URL: https://github.com/fabriziosalmi/zion
- Areas to study: `src/waf.rs`, `src/dispatch.rs`, `src/dispatch/gates.rs`,
  `src/uri_norm.rs`, `src/security.rs`, `src/tls_fp.rs`, `src/waf_ml.rs`,
  `benchmarks/waf-corpus`, `.github/workflows/waf-corpus.yml`.
- Target ideas: zero-regex fast path, request canonicalization and iterative
  decoding, URI normalization before routing, streaming scanner, body frame
  timeouts / slow-upload defenses, cheap-rejection-first ordering, rate-limit
  placement, shadow mode, false-positive corpus and recall ratchet, JA4/TLS
  fingerprinting, spoofed internal-header stripping, advisory ML scoring,
  bounded tarpit behavior, allocation discipline.
- Varman difference: Zion is **not** the proxy foundation; Pingora (via Pingap)
  remains the data plane. Only hot-path and testing ideas are adopted.

*(Rows added when a phase adopts a specific mechanism.)*

---

## Lorica — proxy/ops patterns (Queued)

- URL: https://github.com/Rwx-G/Lorica
- Areas to study: Rust proxy architecture, Pingora-derived operational ideas,
  IP blocklists, rule compilation, body content-type decisions, fuzzing,
  deployment/release patterns, configuration design.
- Varman difference: Lorica's WAF engine is not adopted as the primary engine;
  the PingWAF-derived platform remains.

*(Rows added when a phase adopts a specific mechanism.)*

---

## OWASP CRS + Coraza + ModSecurity — compatibility references (Queued)

- OWASP CRS: https://github.com/coreruleset/coreruleset — official rule set and
  its regression tests; the conformance target for Phase 7.
- Coraza: https://github.com/corazawaf/coraza — Go reference engine used for
  differential testing of SecLang semantics.
- ModSecurity: https://github.com/owasp-modsecurity/ModSecurity — original
  engine; behavioural reference for ambiguous semantics.
- Varman difference: these are **test oracles**, not dependencies. CRS rules are
  consumed as data by the Varman SecLang engine; differences in behaviour are
  investigated, never resolved by copying another engine's code.

*(Conformance results recorded in `docs/compatibility.md` as Phase 7 lands.)*
