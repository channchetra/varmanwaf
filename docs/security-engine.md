# Varman Security Engine

> **Truthfulness rule** (mandate §36): this document describes what exists, what
> is enforced, and what is planned. Today the **legacy engine enforces**; the
> Varman pipeline is a skeleton running beside it (Phase 2). No claim here is
> valid for enforcement until the corresponding phase lands and tests pass.

## 1. Current state (Phase 2)

| Component | Status | Serves traffic? |
|---|---|---|
| Legacy engine (`varman-waf/src/{engine,normalize,rules,score}`) | Imported baseline; signature + expression rules + anomaly scoring | **Yes** |
| Canonical model (`varman-waf/src/canonical`) | Canonicalizer landed (Phase 3 first slice): bounded decode layers, path collapse, query/cookie/header policy + bypass tests | No |
| Pipeline (`varman-waf/src/pipeline`) | Skeleton landed: detector contract, findings, monotonic actions, bounded context, shadow comparison; first fast detector (raw-path traversal evidence) | No |
| Shadow wiring + engine switch (`pingap-plugin/src/waf_shadow.rs`) | Landed: `VARMAN_WAF_ENGINE=legacy|shadow|varman`; shadow compares pipeline vs legacy per request and records counters; `varman` enforces the pipeline verdict escalated with the legacy verdict | Yes (`varman` mode) |
| Lane 1 fast detectors | Started: protocol checks + Aho-Corasick signature scanner (starter table, tiered) + raw-path traversal evidence; corpora in `varman-waf/tests/corpus` | No (shadow only) |
| Streaming body engine | Pending (Phase 5) | No |
| Lane 2 semantic detectors | SQL, HTML/XSS, shell/command, SSRF, NoSQL, SSTI, XXE, deserialization, prototype-pollution, LDAP/XPath, GraphQL, JWT, DLP, JSON body-shape, threat-intelligence, WebSocket-handshake (Phase 5/8) structural detectors; covered by the corpora | No (shadow only) |
| SecLang / OWASP CRS (Lane 3) | Pending (Phase 7); tracked in `docs/compatibility.md` | No |

The pipeline is wired into the proxy through `pingap-plugin/src/waf_shadow.rs`.
The default mode is still the legacy engine; `VARMAN_WAF_ENGINE=shadow` compares
both engines per request, and `VARMAN_WAF_ENGINE=varman` enforces the pipeline
verdict **escalated with** the legacy verdict (the stronger action wins), so
dashboard-configured custom rules stay effective and the new engine can only
add protection. The switch's evidence trail is the comparison counters.

## 2. Target architecture (mandate §6)

```text
Request
  │
  ▼ Lane 0 — pre-security: real client IP, IP ACL, geo/ASN, JA4, bans,
  │          reputation, connection safeguards, rate limiting
  ▼ Canonical normalization (one representation for every consumer)
  ▼ Lane 1 — fast detection: Aho-Corasick signatures, protocol violations,
  │          smuggling indicators, known exploits, lightweight SQLi/XSS signals
  ▼ Structured body extraction: JSON, XML, form, multipart, GraphQL
  ▼ Lane 2 — semantic detection: SQL structural/AST, DOM XSS, shell AST,
  │          SSRF, XXE, SSTI, NoSQL, LDAP/XPath, deserialization,
  │          prototype pollution, GraphQL abuse, API patterns
  ▼ Lane 3 — SecLang / OWASP CRS: variables, operators, transformations,
  │          control flow, anomaly scoring, rule exclusions
  ▼ Advanced security: API validation, JWT, bot, ATO, DLP, virtual patching
  ▼ Decision engine
Pass < Log < Monitor < Challenge < Block    (monotonic escalation)
```

## 3. Pipeline types (implemented skeleton)

- **`canonical::CanonicalRequest`** — method, authority, raw + canonical path,
  raw query, decoded query pairs, headers (wire order, duplicates preserved),
  cookies, body, verified `ClientIdentity`. Everything downstream reads this;
  detectors must not re-decode or re-parse raw input.
- **`canonical::Canonicalizer`** (Phase 3) — the one component allowed to
  decode: bounded percent layers (`Normal` 2 / `Strict` 3, byte-wise with
  overlong-UTF-8 restoration), fragment drop, dot-segment resolution,
  `+`-as-space query decoding, cookie parsing/unquoting, header lowercasing,
  authority normalization (trim/lowercase/trailing dot; ports preserved).
  HTML entities and deeper layers are *inspection* transformations applied
  uniformly from the canonical form, not canonicalization: the origin routes
  on the percent-decoded bytes, and an entity-decoded path would route
  differently from the wire. Canonical output is idempotent under
  re-canonicalization (tested).
- **`pipeline::snapshot`** (Phase 2) — immutable `SecuritySnapshot`
  (revision + per-domain `SiteRuntime` holding the compiled pipeline) behind
  an `arc_swap::ArcSwap` in `SecurityRuntime`. `replace()` is atomic and
  returns the previous snapshot; requests keep the snapshot they started
  with, so no request ever sees a half-applied configuration (mandate §13).
  The desired/active/last-good version handshake with the agent builds on
  this.
- **`pipeline::semantic::CommandInjectionDetector`** (Phase 6) — shell
  structure: literal attack shapes (`/bin/sh`, `nc -e`, `${IFS}`, `cmd.exe`),
  sub-shell substitution containing a command (`$(id)`, backticks),
  metacharacter-before-command (`;cat`, `|whoami`, `&& wget`), plus a weak
  Log-tier context signal. Ambiguous words (`id`, `ps`, `rm`, …) only count
  inside sub-shells or the weak tier, so markdown tables (`| id |`) and query
  parameters (`&_fields=id`) stay clean — proven by the benign corpus.
- **`pipeline::semantic::HtmlXssDetector`** (Phase 6) — applies HTML
  entity decoding (the inspection transformation the canonical model
  deliberately excludes) and reasons structurally: entity-obfuscated
  dangerous tags (`&lt;script&gt;`), iframes with script/data URIs,
  event-handler attributes that call a function, `javascript:`/`vbscript:`
  URIs that call, and dangerous tags followed by calls. Bare `<script`
  snippets and prose about `javascript:` stay at Log tier.
- **`pipeline::semantic::SqlStructuralDetector`** (Phase 6, first semantic
  detector) — normalizes values the way an SQL engine would (comments
  stripped, whitespace collapsed) and reasons about structure:
  comment-obfuscated keywords (`un/**/ion`), stacked statements (`;drop`),
  dangerous functions (`into outfile`, `xp_cmdshell`, `load_file(`),
  attack-shaped UNION phrases, time-based shapes (`sleep(5)`,
  `waitfor delay`), boolean tautologies with quote breaks, quote-context
  breaks plus keywords (Monitor), and bare keywords (Log). Documentation
  prose that merely mentions SQL keywords stays at Log tier — the benign
  corpus asserts it never reaches Monitor/Block. Values above the semantic
  budget degrade instead of being partially parsed.
- **`pipeline::semantic::JwtDetector`** (Phase 8, first advanced-security
  detector) — finds JWT-shaped tokens (`eyJ…` base64url runs) in headers,
  cookies, query values and bodies, decodes the header and flags the
  verification-bypass family: `alg: none` and non-`none` algorithms with an
  empty signature **Block** (`CredentialAbuse`); `jku`/`x5u` external key
  URLs, embedded `jwk` keys and `kid` path separators/traversal **Monitor**;
  a JWT-shaped token without a signature segment stays **Log**. Missing
  `exp`, opaque bearer tokens and JWTs whose payload is not JSON stay clean —
  the benign corpus carries real-world samples of all three.
- **`pipeline::semantic::DlpDetector`** (Phase 8, DLP) — request-side secret
  exposure: PEM private-key blocks **Block** (`sem.dlp.private_key`);
  URLs/connection strings with embedded credentials (`scheme://user:pass@`)
  and provider tokens (GitHub, Slack, Stripe live, Google, npm, SendGrid) in
  query/cookie/body **Monitor**. Headers are exempt from provider-token
  checks (clients authenticate there with `Authorization: Bearer ghp_…`,
  `X-Api-Key: AIza…`, SigV4), AWS access-key ids are never flagged
  (presigned URLs carry them by design), and public keys, test-mode keys and
  credential-free connection strings stay clean — all locked in by the benign
  corpus.
- **`pipeline::semantic::BodyShapeDetector`** (Phase 5/8, API security) —
  reasons about the *shape* of a JSON request body with a byte-wise scanner
  (no document tree, so hostile nesting cannot exhaust the stack): nesting
  depth ≥ 24 **Monitors** (`sem.body.deep_nesting`) and a single array with
  ≥ 4096 elements **Monitors** (`sem.body.large_array`). Nothing blocks by
  default — bulk APIs legitimately send large arrays — and the benign body
  corpus locks ordinary payloads clean. Body payloads get their own corpus
  harness (`tests/corpus/attacks_body`, `benign_body`).
- **`pipeline::semantic::TiDetector`** (Phase 8, threat intelligence) —
  matches requests against a feed of attack-tool user agents, client
  IPs/CIDRs, hostnames and path prefixes (all **Block**:
  `ti.ua`/`ti.ip`/`ti.domain`/`ti.path`, category `ThreatIntelligence`). The
  bundled starter feed carries scanner/exploitation **user agents only**
  (sqlmap, nikto, nmap NSE, masscan, nuclei, wpscan, …); operators replace it
  with `VARMAN_WAF_TI_FILE` (same documented line format, `off` disables).
  Malformed feeds are observable errors — the plugin logs and falls back to
  the starter. UA and body payloads get dedicated corpus harness loops.
- **`pipeline::semantic::WebSocketDetector`** (Phase 8, WebSocket inspection
  first slice) — inspects the handshake (an ordinary HTTP request): an
  `Origin` whose host/port differs from the requested host (including `null`)
  **Monitors** as `ws.cross_origin` (cross-origin WebSocket hijacking), and a
  handshake declaring a body **Monitors** as `ws.handshake_with_body`
  (RFC 6455 forbids one). Same-origin handshakes and clients without
  `Origin` (CLIs, bots) stay clean; the `*_ws` corpus modes lock both
  directions in.

  **Frame-level inspection (v0.21.1):** after a 101 the raw tunnel bytes reach
  read-only plugin hooks in both directions (`Plugin::handle_request_body` for
  client-to-server frames, `Plugin::handle_upgraded_body` for server-to-client
  frames; the response-body hooks stay skipped so rewriting plugins cannot
  corrupt the tunnel, #114). `pingap-plugin/src/waf_stream.rs` decodes RFC 6455
  frames streaming, assembles fragmented messages under hard caps, handles
  control frames and fails the connection on malformed frames; complete
  message payloads are scanned with the injection detectors. Findings abort the
  connection and record `ws.*` events; a 101 that is not a WebSocket upgrade is
  never decoded. `ws_inspection = false` disables it. Compressed
  (permessage-deflate) frames are not decompressed.
- **`processor`** (Phase 9) - the optional external-processor contract:
  out-of-process components inspect a request and *add* findings. The native
  engine stays the authority: merging is monotonic (a processor can escalate,
  never weaken), contributions are bounded (16 findings, 40/finding, 60 per
  processor) and a timed-out or failed call resolves through an explicit
  `FailurePolicy` (`fail_open` / `monitor_only` / `fail_closed`) — never
  silently. The transport (`pingap-plugin/src/waf_processor.rs`) speaks
  newline-delimited JSON over a Unix domain socket or TCP with a per-call
  timeout and a 64 KiB response cap; `examples/processor/mock_processor.py`
  is a runnable reference implementation and `docker compose --profile
  processor up -d processor` starts it beside the stack. **Capability
  negotiation:** a response may carry a `processor` object (`name`,
  `version`, `max_findings`); the WAF namespaces findings with the declared
  name (when it is a safe token), clamps its caps to the declared limits,
  and logs the identity once per change.
- **Per-site custom layers (`pingap-plugin/src/waf_custom.rs`)** (Phase 8) —
  compiled once per site context from the dashboard's WAF settings and
  evaluated per request (escalate-only):
  * **SecLang virtual patches** — a rule source in the OWASP CRS dialect
    evaluated by the native engine; rules carrying `block`/`deny`/`drop`
    block matching requests (`virtual-patch:<ids>`). The control plane
    compiles the source at upload time, so an invalid patch is rejected by
    the API, never shipped.
  * **OpenAPI validation** — a JSON OpenAPI document; requests under the
    spec's base prefix are checked against the declared operations:
    undeclared path (`api.unknown_operation`, Monitor), undeclared method
    (`api.method_not_allowed`), missing required query parameter
    (`api.missing_required_param`). Out-of-scope paths are untouched.
    **JSON request-body schemas (v0.21.1):** `requestBody` schemas are
    enforced - `$ref` into `components.schemas`, `type`, `nullable`, `enum`,
    `required`, `properties`, `additionalProperties: false`, `items`,
    `minItems`/`maxItems`, `minLength`/`maxLength`, `pattern`, numeric bounds
    and `allOf`/`anyOf`/`oneOf` - recording `api.schema_violation` (Monitor)
    with a JSON-pointer detail; a truncated capture is skipped, never
    misreported. Non-JSON bodies and remote `$ref`s are not resolved.
- **Account-takeover defense (`pingap-plugin/src/waf_ato.rs`)** (Phase 8) -
  repeated upstream authentication failures (401/403) on state-changing
  requests (POST/PUT/PATCH/DELETE) from one client open a failure window;
  crossing the threshold (`ato_failed_auth_threshold`, default 20 per
  `ato_window_secs` = 300) blocks that `(site, client)` for
  `ato_block_secs` = 300 with a 403 + `Retry-After`. Expired-token polling
  is GET traffic, so ordinary SPAs cannot trip it; `0` disables the tracker.
- **Body size policy and tail inspection** (Phase 5) - `body_policy = "reject"`
  answers 413 once a request body exceeds `max_body_size` (itself clamped to
  the 64 KiB replay limit with a warning); the default `process_partial` keeps
  the head window. The read pass runs under `body_read_timeout_ms` (default
  10 s), so a trickling upload is refused with 408. **Tail inspection
  (v0.21.1):** the chunks the early read pass did not consume flow through the
  read-only `handle_request_body` hook and are scanned with a 256-byte sliding
  window (`pingap-plugin/src/waf_stream.rs`), so a payload split across chunk
  boundaries is still seen; a confirmed payload aborts the request and records
  an event (`tail_inspection = false` disables the scan). A tail payload is
  stopped as its chunks arrive - the upstream has already received the header
  and head, so no clean 403 is possible mid-stream.
- **`pipeline::semantic::SqlAstDetector`** (Phase 6, the second SQL tier;
  v0.21.1) - dialect-aware SQL parsing (`sqlparser`, generic/MySQL/PostgreSQL/
  SQLite). Full statements parse directly; fragments are wrapped into
  statement templates, which is what lets real constructs surface. Blocks
  stacked statements (`ast.stacked_statements`), UNION/EXCEPT/INTERSECT
  queries (`ast.set_operation`), tautological literal comparisons
  (`ast.tautology`) and DML/DDL (`ast.dml_statement`); a clean raw query is
  recorded at log level (`ast.raw_query`). Values that do not parse are
  ignored - the tier adds precision, it never guesses.
- **Coverage-guided fuzz targets** (Phase 6; `fuzz/`, cargo-fuzz, nightly) -
  `detectors` (no panic, no unbounded findings on arbitrary targets/bodies)
  and `canonicalizer` (no panic and convergence: a target that exhausts the
  decode budget resolves further escapes on a second pass and is stable from
  then on - the exact counterexample `/%2525e25e` is locked in the
  canonicalizer unit tests). Smoke campaigns at release: detectors 34,660
  runs / 30 s and canonicalizer 162,093 runs / 30 s, both clean; see
  `fuzz/README.md`.
- **`pipeline::fast::ProtocolDetector`** (Phase 4) — framing and header
  sanity: conflicting duplicate `Content-Length`, `Content-Length` +
  `Transfer-Encoding` together, unsupported transfer codings (RFC 9112
  rejection), duplicate TE headers, invalid/absurd content lengths, CR/LF or
  NUL bytes in header values, NUL in the target, invalid token bytes in
  header names/method, and a header-count ceiling. Smuggling/injection shapes
  are `Block`-tier `HttpSmuggling`/`CrlfInjection` findings; malformed but
  non-exploitable shapes are `Monitor`/`Log` `ProtocolViolation` findings.
- **`pipeline::fast::SignatureDetector`** (Phase 4) — Aho-Corasick scan
  (ASCII case-insensitive, **overlapping** matches so `../` cannot hide
  `/etc/passwd` behind it) over canonical path, query names/values, cookies
  (parsed pairs *and* the raw `Cookie` header, whose parsing can split a
  payload apart) and UTF-8 bodies within the body budget. One finding per
  signature per request; signatures are tiered:
  - **Block tier** — payload syntax (e.g. `union select null`,
    `<script>alert`, `/bin/sh`, `${jndi:`, `/etc/passwd`, `php://filter`,
    `rO0AB`, `169.254.169.254`, `\r\nset-cookie:`);
  - **Log tier** — ambiguous tokens that occur in documentation and normal
    traffic (`<script`, `union select`, `information_schema.tables`, `sleep(`,
    `javascript:`, `../`, `%0d%0a`); weak signals may feed scoring but never
    block on their own (mandate §9).
  The starter table ships with `varman-waf/tests/corpus` (attacks by category,
  realistic benign traffic) and CI asserts both ratchets: every attack case
  stays detected, no benign case reaches `Monitor`/`Block`.
- **`pipeline::fast::RawPathTraversalDetector`** (Phase 4) — dot-segment
  evidence in the decoded raw path; `Log` tier, medium severity when a `..`
  segment tries to climb above the root.
- **Robustness**: all detectors slice attacker strings through
  `pipeline::safe_window`, which never cuts a UTF-8 character; a
  deterministic soak test drives 5,000 random byte sequences plus hostile
  shapes through the full pipeline and asserts no panic, bounded findings and
  a generous time budget. Malformed input must never crash the edge.
- **`pipeline::Detector`** — `id()` + `inspect(&CanonicalRequest, &mut
  DetectionContext) -> DetectorResult`. `Send + Sync`, no I/O, no panics on
  attacker input.
- **`pipeline::Finding`** — `detector`, `rule_id`, `category` (24-value Varman
  taxonomy), `confidence`, `severity`, `score`, `source` + `field`, optional
  `detail`, and `action_hint`.
- **`pipeline::Action`** — `Pass < Log < Monitor < Challenge < Block` by
  declaration order; `escalate()` is monotonic; `Block` is terminal for normal
  inspection (response hardening still runs).
- **`pipeline::SecurityPipeline`** — ordered detectors; runs all of them
  (shadow mode) or stops at `Block` when `stop_on_block` is set; sums scores
  saturating; collects degradations.
- **`pipeline::DetectionContext` / `InspectionBudget`** — bounded findings per
  request (default 256) and a body inspection budget (default 1 MiB);
  exhaustion truncates and records a **degradation**, never an error or an
  unbounded allocation.
- **`pipeline::shadow::compare`** — compares a legacy `WafVerdict` with a
  `PipelineVerdict`: `Agree` / `PipelineStricter` / `PipelineWeaker`
  (downgrades are the alertable class) plus a score delta.

## 4. Scoring and decisions (target)

- Findings carry their own score and action hint; the platform's anomaly
  scoring (thresholds, paranoia levels, monitor-by-category/stack) moves from
  the legacy scorer to policy applied over structured findings — detectors do
  not decide for themselves.
- Escalation is monotonic; policy may downgrade to monitor per category,
  rule, site, path or backend stack (mandate §19), and such downgrades are
  recorded, not silent.
- Modes: `Off`, `Monitor`, `Block` today; `Challenge` exists in the action
  ladder and is produced by the challenge subsystem.

## 5. Limits and failure behaviour (mandate §8 / §38)

- Every semantic detector must declare: input length budget, parse depth and
  node limits, and re-use the shared `InspectionBudget`.
- A detector reaching its budget marks itself degraded; remaining layers still
  run; metrics count the degradation.
- Parser failures are findings-free degradation, never a request-path panic;
  panics are caught at the outer boundary and fail per explicit policy.
- Unsupported inputs must not silently pass a *claimed* protection: the
  `docs/compatibility.md` rules apply.

## 6. Relationship to the legacy engine

During the transition both engines can process the same request:

```text
pingap-plugin/src/waf.rs
  ├─ legacy WafEngine::inspect  → legacy verdict
  └─ waf_shadow::analyze        → runs in shadow/varman modes
       ├─ Canonicalizer          (the one decoding policy)
       ├─ SecurityPipeline       (fast lane first; detectors appended over time)
       ├─ shadow::compare(legacy, pipeline)
       │    → Agree / PipelineStricter / PipelineWeaker counters
       └─ effective_verdict(legacy, pipeline)   [varman mode only]
            → the stronger action wins; ties keep the legacy verdict
```

`VARMAN_WAF_ENGINE` selects the mode: `legacy` (default), `shadow`
(`VARMAN_WAF_SHADOW=1` also works) and `varman`. Unknown values are logged at
`error` and fall back to `legacy`. Each site can override the process default
from the dashboard (**Settings → Protection → Detection engine**,
`waf_settings.engine_mode`): `inherit` follows the process mode, the other
values override it, and an invalid per-site value logs and falls back to the
process mode. `waf_shadow::stats()` exposes checked/agree/stricter/weaker
counters for metrics, and every comparison is logged at `debug` with the
canonical path. In `shadow` mode no response is ever influenced; in `varman`
mode the pipeline can only escalate, never weaken. A site's monitor-only
category list (`waf_settings.monitor_categories`) is applied to the pipeline
verdict as well (`pipeline::policy::downgrade_monitored`), so a family the
dashboard marks monitor-only records without blocking in either engine.
Engine telemetry ships with the heartbeat: shadow-comparison classes
(`varman_waf_shadow_total{agreement=…}`) and processor outcomes
(`varman_waf_processor_calls_total{outcome=…}`) land in `agent_metrics` and
render in the dashboard's agent detail (**Engine telemetry**).

Replacement requires corpus evidence: zero `PipelineWeaker` results on the
attack corpus and zero new blocks on the benign corpus, with performance
within budget (`docs/roadmap.md` Phases 2–6).

## 7. Testing requirements for every detector (mandate §23)

Each detector ships with: attack corpus, benign corpus, bypass corpus
(encoded / double-encoded / case / whitespace / comments / Unicode / multipart
/ JSON variants as relevant), fuzz target for any parser it embeds, a
performance budget, and metrics for degradation. A detector without its
corpora is not done.
