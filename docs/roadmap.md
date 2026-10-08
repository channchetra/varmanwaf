# VarmanWAF Roadmap

> Honest status tracking for the implementation phases defined in the mandate
> (§34, §35). Update this file in the same change that advances a phase.

## Status board

| Phase | Scope | Status |
|---|---|---|
| 0 | Repository understanding | ✅ Complete (2026-10-06) |
| 1 | VarmanWAF bootstrap (rename, keep behaviour) | 🚧 In progress |
| 2 | New WAF engine skeleton (canonical model, pipeline, shadow) | 🚧 In progress — types, pipeline, shadow wiring and the `legacy|shadow|varman` engine switch landed and verified E2E; snapshot/benchmarks pending |
| 3 | Canonicalization (stable normalization + bypass tests) | 🚧 In progress — canonicalizer core landed (authority, profiles, idempotence); plugin wiring pending |
| 4 | Fast lane (Aho-Corasick, protocol checks, high-confidence sigs) | 🚧 In progress — signature scanner + corpora landed and verified live in shadow mode; protocol checks pending |
| 5 | Streaming body engine (bounded windows, limits) | 🚧 In progress - JSON body-shape detector + body corpora landed; windowed inspection, timeouts and size policies pending |
| 6 | Semantic lane (SQL structural/AST, HTML5 XSS, shell, …) | 🚧 In progress — SQL structural, HTML/XSS structural and shell/command detectors landed, corpus-covered and live-verified in shadow; AST, SSRF, XXE, SSTI, NoSQL, deserialization, GraphQL pending |
| 7 | Native SecLang core + OWASP CRS conformance | 🚧 In progress — SecRule parser landed (structured AST, unsupported directives observable); execution engine next |
| 8 | Advanced security (API, JWT, bot, ATO, TI, DLP, virtual patching) | 🚧 In progress — JWT analysis and DLP detectors landed with corpora; API security, ATO, TI and virtual patching pending |
| 9 | Optional External Processor API | 🚧 In progress — processor contract (trait, DTOs, failure policies, bounded monotonic merge) landed; UDS/gRPC transport and plugin wiring pending |

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
- [x] **Engine switch (shadow→enforce)**: `VARMAN_WAF_ENGINE=legacy|shadow|varman`
      (`VARMAN_WAF_SHADOW=1` still selects shadow; unknown values error-log and
      fall back to legacy). In `varman` mode the pipeline verdict escalates
      with the legacy verdict — the stronger action wins, ties keep the legacy
      verdict — so dashboard-configured custom rules stay effective and the
      new engine can only add protection. `PipelineVerdict::to_waf_verdict`
      maps the pipeline outcome onto the proxy verdict shape (action,
      saturating score, per-category breakdown, matched rule ids). Verified
      end-to-end: SQLi/XSS/traversal probes blocked in `varman` mode while
      benign traffic passes.
- [x] **Per-site engine selection**: `waf_settings.engine_mode`
      (`inherit|legacy|shadow|varman`, dashboard **Settings → Protection →
      Detection engine**) overrides the process-wide `VARMAN_WAF_ENGINE` per
      site. Full chain: migration `000031` → settings API (validated) →
      gRPC `WafConfig.engine_mode` → agent cache → plugin `resolve_mode`;
      an explicit mode also opts the site into inspection. Invalid values are
      rejected by the API; stale caches default to `inherit`. **Verified
      end-to-end**: with the process default `shadow` the SQLi probe passed
      (200); switching the site to `varman` blocked it (403) while the process
      default stayed shadow; back to `inherit` with the process default
      `varman` the probe blocked again with `legacy=monitor pipeline=block`
      in the logs and `sig.sqli.tautology` (`varman-pipeline: 2 finding(s)`)
      in the security event.
- [x] **Per-site monitor downgrades in the pipeline**: the site's
      `waf_settings.monitor_categories` now applies to the Varman pipeline
      (`pipeline::policy::downgrade_monitored`) before the verdict is compared
      and enforced, so an attack family a site marked monitor-only never
      blocks in either engine. The score is kept for the event, weaker hints
      are never escalated, and categories outside the dashboard list
      (credential abuse, DLP, bot activity) cannot be downgraded. **Verified
      live**: with `["sqli"]` the SQLi probe returned 200 with a monitor event
      and the log showed `legacy=monitor pipeline=monitor agreement=Agree`
      (previously `pipeline=block`); a JWT `alg:none` probe still blocked
      (`legacy=pass pipeline=block`); clearing the list restored the 403.
- [x] **Engine telemetry to the control plane**: `MetricsCollector` carries
      shadow-comparison classes (`varman_waf_shadow_total{agreement=…}` +
      `varman_waf_shadow_checked_total`) and processor outcomes
      (`varman_waf_processor_calls_total{outcome=…}`); the plugin records them
      per inspected request and the metric shipper (30s cadence) stores them
      in `agent_metrics`. Surfaced in the dashboard's agent detail as an
      **Engine telemetry** panel via `GET /agents/{id}/metrics`.
- [x] Benchmarks: pipeline overhead vs legacy on the request corpus.
      `varman-waf/tests/lane_cost.rs` measures both engines over the attack +
      benign corpora (2,640 requests/lane) and prints the lane-cost table;
      methodology and numbers in `docs/performance.md`. **Measured
      2026-10-07: full pipeline 88.23 µs/request vs legacy 445.69 µs
      (ratio 0.20, ~5x faster); fast lane 2.51 µs; canonicalize 4.80 µs.**
      Loose sanity bounds asserted (10x+ headroom) so CI cannot flake.

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
- [x] Fast-lane benchmarks vs the legacy engine (lane-cost report):
      `docs/performance.md` — fast lane 2.51 µs/request, full pipeline
      88.23 µs, legacy 445.69 µs (ratio 0.20).

Exit: fast lane alone detects the high-confidence attack corpus with zero
benign-corpus blocks; benchmarked cost documented.

## Phase 5 — Streaming body engine

- [x] JSON body-shape detector (`semantic::body_shape`, Phase 5/8 first slice):
      a byte-wise, allocation-free scanner over JSON bodies reports nesting
      depth ≥ 24 (`sem.body.deep_nesting`, Monitor 20) and arrays with ≥ 4096
      elements (`sem.body.large_array`, Monitor 15) — API-abuse / parser-DoS
      shapes with no default blocking. Body corpora
      (`tests/corpus/{attacks_body,benign_body}`) and a dedicated harness
      loop cover it.
- [ ] Bounded windowed inspection beyond the head window; frame timeouts and
      slow-upload/trickling defenses; explicit size policies for formats that
      require full buffering.
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
- [x] Fifth CRS slice: `t:sha1` (in-tree RFC 3174 implementation),
      `t:hexEncode`, `initcol` collection registry (per-transaction,
      documented), case-insensitive action dispatch. **CRS load: 24/27 files,
      538 rules** (ratcheted in the harness).
- [x] **Seventh CRS slice — the CRS milestone is reached: the full OWASP Core
      Rule Set compiles.** Byte-preserving decode (`multi_decode_bytes`) with
      `invalid_utf8` flags on resolved values (body, args, filename),
      `@validateUtf8Encoding`, `@validateUrlEncoding`, `t:length`, and the
      documented `REQUEST_FILENAME` variable. **Full-set: OK, 693 rule
      statements across 27 files**; per-file 26/27 (950 is a standalone-compile
      artifact). Environment note: Windows Defender locks
      `web-shells-php.data`; use `CRS_DIR=/opt/crs-conformance` (container
      clone) or add an exclusion.
- [x] Eighth slice — **behavioural conformance harness** landed:
      `varman-waf/tests/crs_regression.rs` runs the go-ftw corpus in-process,
      at each expected rule's declared paranoia level. Score: **3317/5155
      checked expectations pass**. Engine fixes found by it: `&VAR` instance
      counts (CRS 901 defaults), corrected `@validateByteRange` semantics.
- [x] Twenty-ninth slice: **one-layer parse decoding** (Model A′: `%XX`
      decoded once at parse with `+`→space; the transform handles the
      second layer) — resolves the 941350-vs-932200 contradiction.
      Regression: **5135/5155** (99.6%).
- [x] Thirtieth slice: **phase-ordered response evaluation** (phase 3
      before 4/5 with per-phase `skipAfter`), **`ARGS_COMBINED_SIZE` /
      `FILES_COMBINED_SIZE` / `FILES_SIZES`** variables, `t:cmdLine`
      backslash→slash with `;` preserved, XSS guillemet normalization and
      quote-prefixed event handlers, Apache semantics in the harness
      (Transfer-Encoding unsets Content-Length, bodiless requests without
      Content-Length/Transfer-Encoding, versionless request lines =
      HTTP/0.9). Regression: **5144/5155** (99.8%).
- [x] Thirty-second slice: **`union all` signature** (libinjection flags the
      bare `UNION ALL` phrase; CRS 942101 t9). Regression: **5150/5155**
      (99.90%).
- [ ] Final residual (5, all genuine engine divergences):
      `934100` t5 (`removeWhitespace` erases the space the pattern needs),
      `934160` t4 + `942500` t3/t4 (`%2B`-derived `+` handling — our model
      is required by seven `932200` tests), `942100` t13 (libinjection's
      internal `sos` fingerprint pass — verified with the reference C
      library). Documented in `docs/compatibility.md`.
- [ ] OWASP CRS conformance harness against official regression tests
      (recorded in `docs/compatibility.md`).

## Phase 8 - Advanced security

- [x] JWT analysis detector (`semantic::jwt`, Phase 8 first slice) — finds
      JWT-shaped tokens in headers, cookies, query values and bodies;
      `alg: none` / empty-signature tokens **Block** (`CredentialAbuse`),
      `jku`/`x5u` external key URLs, embedded `jwk` and `kid`
      separators/traversal **Monitor**, signature-less shapes **Log**.
      Missing `exp`, opaque tokens and non-JSON payloads stay clean
      (benign-corpus guard). Attack corpus `credential_abuse.txt` (8 payloads,
      ratcheted to ≥ Monitor) + benign JWT samples. **Verified live**: valid
      JWT → 200, `kid` traversal → 200 + `sem.jwt.kid_traversal` Monitor
      event, `alg: none` → 403 with `sem.jwt.alg_none` (`varman-pipeline: 1
      finding(s), score 40`).
- [x] DLP / sensitive-data-exposure detector (`semantic::dlp`, Phase 8) —
      PEM private keys **Block**; credentialed URLs/connection strings and
      provider tokens (GitHub/Slack/Stripe-live/Google/npm/SendGrid) in
      query/cookie/body **Monitor**. Headers exempt from token checks
      (clients authenticate there), AWS access-key ids never flagged
      (presigned URLs). Attack corpus `sensitive_data_exposure.txt`
      (10 payloads, ratcheted to ≥ Monitor) + benign `dlp.txt` guards.
      **Verified live**: credentialed connection string → 200 +
      `sem.dlp.credentialed_url` Monitor event; PEM private key → 403 with
      `sem.dlp.private_key` (`varman-pipeline: 1 finding(s), score 40`).
      Corpus files use `${…}` placeholders expanded at read time so the
      repository never contains token-shaped literals (GitHub push
      protection).
- [ ] API security/OpenAPI validation, ATO, threat intelligence,
      virtual patching, WebSocket inspection.
- Exit: each feature has corpora + FP controls + monitoring; security events
  explain what fired.

## Phase 9 - Optional External Processor API

- [x] Processor contract first slice (`varman-waf/src/processor.rs`) — the
      Zentinel-inspired external-processor API: `ExternalProcessor` trait,
      `ProcessorRequest`/`ProcessorResponse` DTOs (owned, transport-ready),
      explicit `FailurePolicy` (`fail_open` / `monitor_only` / `fail_closed`),
      bounded contribution (16 findings, 40/finding, 60/processor) and a
      monotonic merge that can only escalate the native verdict. The transport
      (UDS/gRPC client) stays a thin adapter over the trait; the caller owns
      the async timeout.
- [x] Transport + plugin wiring: `pingap-plugin/src/waf_processor.rs` speaks
      newline-delimited JSON over UDS (`unix:`) or TCP (`tcp:`/`host:port`)
      with a 50 ms default timeout (1–5000 ms), a 64 KiB response cap and
      explicit failure policies; configured with `VARMAN_WAF_PROCESSOR_*` and
      wired after the pipeline merge (escalate-only). Reference processor in
      `examples/processor/mock_processor.py` + a `processor` compose profile.
      **Verified live**: with the mock running, `GET /fraud/claim` → 403 with
      `ext.processor.fraud_path | block | 35` (processor-driven enforcement);
      with the mock stopped, the same traffic returned 200 with
      `ext.processor.unavailable | monitor | 10` (the `monitor_only` failure
      policy); restarting the mock restored the block.
- [ ] Capability negotiation, UDS client pooling.
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
