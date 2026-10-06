# VarmanWAF Roadmap

> Honest status tracking for the implementation phases defined in the mandate
> (§34, §35). Update this file in the same change that advances a phase.

## Status board

| Phase | Scope | Status |
|---|---|---|
| 0 | Repository understanding | ✅ Complete (2026-10-06) |
| 1 | VarmanWAF bootstrap (rename, keep behaviour) | 🚧 In progress |
| 2 | New WAF engine skeleton (canonical model, pipeline, shadow) | 🚧 In progress — types, pipeline and shadow wiring landed and verified E2E; snapshot/benchmarks pending |
| 3 | Canonicalization (stable normalization + bypass tests) | 🚧 In progress — canonicalizer core landed (authority, profiles, idempotence); plugin wiring pending |
| 4 | Fast lane (Aho-Corasick, protocol checks, high-confidence sigs) | 🚧 In progress — signature scanner + corpora landed and verified live in shadow mode; protocol checks pending |
| 5 | Streaming body engine (bounded windows, limits) | ⏳ Planned |
| 6 | Semantic lane (SQL structural/AST, HTML5 XSS, shell, …) | 🚧 In progress — SQL structural, HTML/XSS structural and shell/command detectors landed, corpus-covered and live-verified in shadow; AST, SSRF, XXE, SSTI, NoSQL, deserialization, GraphQL pending |
| 7 | Native SecLang core + OWASP CRS conformance | 🚧 In progress — SecRule parser landed (structured AST, unsupported directives observable); execution engine next |
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
      `varman.service`, `install.sh`, `.github` workflows (canonical location
      `github.com/channchetra/varmanwaf`, images published on Docker Hub as
      `sovichetra/varmanwaf`).
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
- [x] Published the production image to Docker Hub:
      `sovichetra/varmanwaf:latest` and `:0.20.0` (built with the official
      multi-stage `Dockerfile`; GitHub Actions is blocked on account billing,
      so publication is manual for now).
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
- [x] Wire shadow execution into `pingap-plugin/src/waf.rs`: opt-in with
      `VARMAN_WAF_SHADOW=1`, counters + debug logs, no enforcement change.
      Verified end-to-end (2026-10-06): the stack was recreated with the flag
      and raw/encoded traversal probes produced `[shadow]` comparisons
      (`legacy=monitor`, `pipeline=log`, `PipelineWeaker`, `score_delta=1`,
      one finding each) while response behaviour stayed with the legacy
      engine. The 307 responses on literal `..` paths came from the test
      origin (Go `ServeMux` path cleaning), not from VarmanWAF.
- [x] Immutable per-site `SecuritySnapshot` behind ArcSwap
      (`pipeline::snapshot`): atomic replace, in-flight pinning, revision
      tracking. Wiring per-site compiled pipelines from the agent rule cache
      is the next step, together with the desired/active/last-good version
      handshake.
- [ ] Benchmarks: pipeline overhead vs legacy on the request corpus.

Exit: both engines run side by side; shadow results measurable; no behaviour
change in enforcement.

## Phase 3 — Canonicalization

- [x] `Canonicalizer` + `RequestParts`: fragment drop, target split, bounded
      byte-wise percent decoding (overlong-UTF-8 restoration reused from the
      legacy decoder), path dot-segment resolution, `+`-as-space query
      decoding, cookie parsing/unquoting, header normalization.
- [x] Bypass tests: `/open/../admin`, encoded and double-encoded traversal,
      single-layer budget behavior, invalid escapes preserved, fragment
      handling, duplicate query parameters, cookie quoting.
- [x] Authority canonicalization (trim, lowercase, FQDN trailing dot; ports
      preserved) and profile layer policy (`Normal` 2 / `Strict` 3).
- [x] Idempotence tests: canonical output re-canonicalizes unchanged.
- [ ] Wire the canonicalizer into `pingap-plugin/src/waf.rs` so the legacy
      engine and detectors read the same canonical request.
- [ ] Property tests: canonicalize is idempotent on its own output.

Exit: normalization stable under corpus; detectors no longer decode
independently.

## Phase 4 — Fast lane

- [x] Aho-Corasick signature scanner (`pipeline::fast::signatures`) with a
      tiered starter table (Block = payload syntax; Log = ambiguous tokens)
      over canonical path, query, cookies and bounded UTF-8 bodies.
      Overlapping matches fix the `../`-hides-`/etc/passwd` class.
- [x] Raw-path traversal evidence detector.
- [x] Attack corpus (11 categories) + benign corpus (WordPress, SQL/JS docs,
      markdown, signed URLs, JWTs, API payloads) with CI ratchets:
      attacks must stay detected, benign must never reach `Monitor`/`Block`.
- [x] Live shadow verification (2026-10-06): SQLi, XSS, traversal and
      Log4Shell probes produced `PipelineStricter` comparisons
      (pipeline=`block` vs legacy=`monitor`; score deltas 15–41, one to two
      findings each) with enforcement unchanged. The only `PipelineWeaker`
      outcome was in-tree `/a/../b` (Log-tier traversal evidence — policy
      tuning backlog, not a detection gap).
- [x] HTTP protocol checks (`pipeline::fast::protocol`): conflicting/duplicate
      `Content-Length`, CL+TE conflicts, unsupported transfer codings,
      invalid content lengths, CR/LF and NUL in header values, NUL in the
      target, invalid header-name/method token bytes, header-count ceiling.
      Structured `HttpSmuggling`/`CrlfInjection`/`ProtocolViolation` findings.
- [ ] Expand signatures with per-pattern bypass cases and FP tuning.
- [ ] Fast-lane benchmarks vs the legacy engine (lane-cost report).

Exit: fast lane alone detects the high-confidence attack corpus with zero
benign-corpus blocks; benchmarked cost documented.

## Phase 5 — Streaming body engine

- Bounded windowed inspection for request bodies; decoders per content type;
  frame timeouts; slow-upload and trickling defenses; explicit size policies
  for formats that require full buffering.
- Exit: large-upload peak memory bounded; bypass corpus green; fuzz-clean
  decoders.

## Phase 6 — Semantic lane

- [x] `SqlStructuralDetector` — comment-stripping and whitespace-collapsing
      normalization, then structural tiers: comment obfuscation, stacked
      statements, dangerous functions, attack-shaped UNION, time-based
      shapes, boolean tautologies, quote-break + keywords (Monitor), bare
      keywords (Log). Corpus-covered by the attack/benign suites; benign SQL
      documentation never reaches Monitor.
- [x] HTML/XSS structural detector (`semantic::xss`) — entity decoding plus
      structure: entity-obfuscated tags, iframes with script URIs,
      event-handler calls, `javascript:`/`vbscript:` calls, tag+call
      combinations; documentation stays Log-tier. Entity-encoded payloads are
      covered by the attack corpus.
- [x] Shell/command structural detector (`semantic::command`) — literal
      shapes, sub-shells, metachar-before-command, `${IFS}` evasion; strong vs
      weak command tiers keep markdown tables and query parameters clean.
- [x] SSRF structural detector (`semantic::ssrf`) — dangerous schemes
      (gopher/dict/file/tftp/smb/jar/netdoc), URLs targeting loopback/private
      hosts (127/10/172.16-31/192.168/169.254), decimal/hex-obfuscated IPv4,
      and a weak Log tier for prose mentions. Corpus-covered.
- [x] NoSQL injection structural detector (`semantic::nosql`) — `$where`
      with JavaScript (`this.`/`return`/`sleep(`) and server-side JS operators
      (`$func`/`$accumulator`) block; bracket operator injection in parameter
      names (`user[$ne]`) and driver syntax (`db.users.find(`) monitor;
      legitimate operator payloads (`{"price":{"$gt":10}}`) stay at Log.
      Corpus-covered (attacks + a benign Mongo-style API payload).
- [x] SSTI structural detector (`semantic::ssti`) — delimiter-aware
      (`{{}}`, `${}`, `<%= %>`, `{% %}`, `#{}`, `*{}`, `@{}`): runtime/class
      access (`__class__`, `Runtime`, `system(`) and evaluation probes
      (`7*7`) block; any other expression monitors; `${jndi:…}` only
      monitors (Log4Shell's own detector owns that family). Corpus-covered.
- [x] XXE structural detector (`semantic::xxe`) — DOCTYPE/entity with
      external `SYSTEM` (or `PUBLIC` alongside an entity), entity-expansion
      bombs (3+ declarations) block; a lone `<!ENTITY` stays Log; plain HTML5
      and HTML4 `PUBLIC` doctypes stay clean. Corpus-covered.
- [x] Deserialization structural detector (`semantic::deser`) — PHP
      serialized shapes (`O:8:"…"`, `a:2:{…`) and .NET
      ViewState/LosFormatter base64 prefixes block; PHP magic-method
      mentions (`__wakeup`, `__destruct`) stay Log. Java markers remain
      owned by the signature table. Corpus-covered.
- [x] Prototype pollution structural detector (`semantic::proto`) —
      mutation shapes (`"__proto__":`, `__proto__[`, `[__proto__]`,
      `__proto__.`, `__proto__=`, `constructor[prototype]`) block; bare
      `__proto__` / `constructor.prototype` mentions (documentation) stay
      Log. Corpus-covered.
- [x] LDAP / XPath injection structural detector (`semantic::ldap_xpath`) —
      LDAP filter-break shapes (`)(|`, `)(cn=`, `*)(`) block, bare filter
      fragments log; XPath expression shapes (`' or count(`, `descendant-or-self::`,
      `']|`) block, bare `//*` logs. Two new attack corpus files.
- [x] GraphQL abuse detector (`semantic::graphql`) — introspection probes
      (`__schema`, `__type(`, `IntrospectionQuery`), nesting depth ≥ 12 and
      batched documents (≥ 8 operations) monitor; `__typename`/`__type`
      references log. Nothing blocks by default: introspection and batching
      are per-API policy decisions. Corpus-covered.
- [x] Robustness soak (`varman-waf/tests/robustness.rs`): 5,000 deterministic
      pseudo-random byte sequences + targeted hostile shapes (invalid UTF-8,
      NUL, huge nesting, lone delimiters) through the full 14-detector
      pipeline. It immediately caught **three real UTF-8 boundary panics**
      (byte-window slicing in the shell/SSRF/XSS detectors) — all detectors
      now slice through `pipeline::safe_window`, and malformed input can no
      longer crash the edge.
- [ ] SQL AST detector (dialect-aware) as the second SQL tier.
- [ ] Remaining Phase 6 exit work: per-detector fuzz targets; shadow-mode
      comparison report.
- [ ] Per-detector fuzz targets and performance budgets.

Exit: per-detector acceptance + performance budget; shadow-mode comparison
report against the existing engine.

## Phase 7 — Native SecLang core

- [x] Parser skeleton (`varman-waf/src/seclang`): `SecRule VARIABLES "OPERATOR"
      "ACTIONS"` → structured AST. Variables `|`-separated; operators `@rx`,
      `@pm`, `@contains`, `@streq`, `@beginsWith`, `@endsWith`,
      `@detectSQLi`, `@detectXSS`, `@ipMatch`, bare pattern = `@rx`; actions
      split on commas outside quotes, order preserved; comments/blanks
      ignored. **Unsupported directives/operators return observable errors**
      — never silent no-ops (mandate §37).
- [x] Transaction + execution slice (`seclang::transaction`): variables
      `ARGS`, `ARGS_NAMES`, `REQUEST_HEADERS[:name]` (case-insensitive),
      `REQUEST_METHOD`, `REQUEST_URI`, `QUERY_STRING`, `REQUEST_BODY`,
      `REMOTE_ADDR`, `TX` (set/get); operators pre-compiled once (`@rx`
      regex, `@ipMatch` CIDR) and evaluated with bounded resolution
      (≤256 values, ≤8 KiB per value); `@detectSQLi`/`@detectXSS` reuse the
      existing detectors.
- [x] Transformation execution (`t:` actions, applied in order before the
      operator): `lowercase`, `trim`, `compressWhitespace`, `removeNulls`,
      `urlDecode`/`urlDecodeUni` (one bounded layer), `htmlEntityDecode`,
      `base64Decode` (failed decoding leaves the value unchanged, mirroring
      ModSecurity). **Unknown transformations are observable compile errors.**
- [x] `chain` groups (`SecRuleGroup`): consecutive rules joined by the `chain`
      action fire only when **every** member matches; a chain that reaches
      the end of input without a final rule is an observable error. `ARGS`
      now merges form-urlencoded body parameters (ModSecurity semantics),
      including bounded percent decoding.
- [x] Rule-set runner (`seclang::ruleset`): `SecRuleSet::from_source` parses +
      validates a whole source; `evaluate` runs groups in order, records
      `RuleHit`s, and executes **`setvar:tx.<name>=<value>`** (assignment,
      `+n`, `-n`) so later rules see updated `TX`. **Strict action
      validation**: any action this engine does not implement is a compile
      error, never a silent no-op (mandate §37); non-TX `setvar` targets error.
- [x] `SecRuleRemoveById <ids…>` inline tuning: removed before compilation;
      unknown ids are a documented no-op (CRS removes rules that may not exist
      at the current paranoia level); a chain member removal degrades the
      remaining head to a singleton; missing/non-numeric ids error observably.
- [x] `SecRuleUpdateTargetById <id> <vars>`: replaces a rule's variable
      list before compilation; unknown ids are a no-op; missing/non-numeric
      ids and `!VAR` exclusions error observably (exclusions are a later
      slice). Covered by tests against header-targeted retargeting.
- [x] `skip:N` and `skipAfter:NAME` with `SecMarker`: markers are recorded
      in the rule stream and resolved to group positions at compile time —
      unknown targets, non-numeric counts, empty marker names and
      backward-pointing skips are **observable compile errors** (a backward
      jump would loop). Runner verified by tests to jump over rules and to
      land after the marker.
- [x] `capture` + `TX:0…9`: a chained member carrying `capture` writes its
      regex groups (TX:0 whole match, TX:1..9 groups) into the transaction
      before the next member resolves variables; non-regex operators capture
      nothing (ModSecurity behaviour). Tests prove a chain where the second
      member matches on `TX:2`, and that without `capture` the chain fails.
- [x] `SecDefaultAction "…"`: defaults apply to every rule that follows;
      explicit rule actions win **within their category** (phase,
      disposition, audit, capture), other categories fill in. Missing actions
      error observably.
- [x] `ctl:ruleEngine` (`On` / `DetectionOnly` / `Off`): detection-only
      strips disruptive dispositions (`block`/`deny`/`drop`) from recorded
      hits while keeping the match; `Off` stops evaluation after the
      matching rule; unknown values error observably. With this, **SecLang
      control flow is feature-complete for CRS-style rules.**
- [x] **CRS conformance harness** landed:
      `varman-waf/tests/crs_conformance.rs` loads every
      `references/coreruleset/rules/*.conf` and prints per-file results
      (`cargo test -p varman-waf --test crs_conformance -- --nocapture`).
      First measurement: **1/27 files load, 0 rules**; blockers are tracked
      honestly in `docs/compatibility.md`. Every slice from here ratchets the
      load count up.
- [x] Second CRS slice: `@pmFromFile` data-file loading (base-dir aware
      `from_source_with_base`), macro collections (`MATCHED_VAR`,
      `MATCHED_VAR_NAME`, `remote_addr`, `request_line`, `request_headers.*`,
      `args.*`), `setvar` target macros, `REQUEST_LINE` + HTTP version
      plumbing, case-insensitive TX, `noauditlog`. **CRS load: 17/27 files,
      253 rules** (ratcheted in the harness).
- [ ] Next CRS blockers: `t:normalizePath`, `t:replaceComments` (small) →
      byte-preserving value plumbing (unblocks `@validateUtf8Encoding` and
      `t:utf8toUnicode`, 4 files) → `t:sha1`/`t:hexEncode` + `initcol`
      collections (901) → cross-file `skipAfter` resolution and a full-set
      (non-per-file) conformance run.
- [ ] OWASP CRS conformance harness against official regression tests
      (recorded in `docs/compatibility.md`).

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

## Dashboard "Coming soon" backlog (implement these next)

Investigation results (2026-10-06):
- `asn` / `country` rate-limit characteristics are **already implemented and
  enforced** by the edge (`RateChar::Asn` / `RateChar::Country` in
  `pingap-plugin/src/waf.rs`, geo resolution included) — they are not in the
  pending list.
- `ja3` **is** legitimately pending: Pingora 0.9's `SslDigest`
  (`pingora-core/src/protocols/tls/digest.rs`) exposes only
  cipher/version/peer-certificate data — **no JA3**. Keying on JA3 therefore
  requires capturing the TLS ClientHello (custom accept callback / rustls
  extension) and plumbing the fingerprint into the plugin context; it is a
  deliberate TLS-layer feature, not a lookup.
- The three bot-protection flags (`js_detection`, `tls_fingerprint`,
  `behavioral_analysis`) exist in the database model and REST API but **do not
  reach the edge yet**: `BotProtectionConfig` in
  `varman-protocol/proto/control_plane.proto` carries only
  `enabled`/`action`/`known_bots_whitelist`, and the agent cache mirrors the
  proto. Full implementation order per flag:
  1. proto fields + `varman-control/src/grpc/config.rs` conversion
  2. `varman-agent/src/cache` conversion + `pingap-plugin` config struct
  3. detection logic in the plugin's bot check (`pingap-plugin/src/waf.rs`)
  4. dashboard: remove `comingSoon`/`disabled` on the toggle
  5. tests + benign/attack corpus updates, live shadow verification

4. **`ja3` rate-limit characteristic — TLS-subsystem feature (recon done
   2026-10-06).** The repository has **no existing ClientHello/TLS hook**
   (grep for `client_hello|TlsAccept|SslDigestExtension` in `pingap-*` /
   `varman-*` / `src` is empty). The building blocks that do exist:
   - `pingora-core` `listeners/mod.rs` `trait TlsAccept` — the per-connection
     accept hook;
   - `pingora-core` `protocols/tls/digest.rs` `SslDigestExtension` with a
     typed `get<T>()`/`set<T>()` slot — the correct place to stash a computed
     fingerprint for later reads from `session.digest()`;
   - the raw ClientHello itself is only accessible per TLS backend:
     *rustls* passes a `ClientHello` (cipher suites, extensions, curves) to
     the certificate resolver, which is the clean JA3/JA4 extraction point —
     meaning this feature pairs naturally with the `tls-rustls` build;
     *OpenSSL* needs an FFI `SSL_CTX_set_client_hello_cb` callback (not in the
     safe `openssl` crate API) to see the same bytes.
   Implementation order when picked up: pin the TLS backend path (rustls
   resolver preferred), parse ClientHello → JA3, store in
   `SslDigestExtension`, read in the plugin, add the `RateChar::Ja3` key
   extraction (enum + `counter_key` + `build`), remove `ja3` from
   `RATE_LIMIT_CHARACTERISTICS_PENDING`, tests + a TLS handshake test fixture.
   This is a deliberate multi-session subsystem; do not half-wire it.

Each item lands only when the whole chain above is complete — no
half-wired toggles that pretend to work.

Status (2026-10-06): **all three bot toggles are implemented end-to-end** —
`js_detection` (proto 4), `tls_fingerprint` (proto 5, TLS session read from
`session.digest().ssl_digest`, never a client header) and
`behavioral_analysis` (proto 6, bounded edge-local per-IP burst tracker:
60 s window, 120-request threshold, 65 536-entry cap with expiry sweep).
`ClientSignals { browser_hints, tls_verified, burst }` drives enforcement;
whitelisted verified bots pass first; dashboard toggles enabled; plugin
tests cover every signal. Only `ja3` remains, waiting for TLS ClientHello
capture (Pingora exposes no JA3).

## Working agreements

- Keep the repository buildable at every step (`cargo check` gate in the dev
  container; `cargo build --release` and `docker compose up -d` for phase exits).
- Every significant task: read code → read reference → engineering note →
  smallest vertical change → tests → fmt/lint/test → docs (mandate §40).
- Security claims only from measurements (`docs/security-engine.md` once the
  Varman engine exists; benchmarks only with methodology).
- Never silently ignore configuration, unsupported SecLang, or malformed rules.
