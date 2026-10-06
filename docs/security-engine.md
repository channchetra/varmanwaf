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
| Shadow wiring (`pingap-plugin/src/waf_shadow.rs`) | Landed: opt-in with `VARMAN_WAF_SHADOW=1`; compares pipeline vs legacy per request, records counters, never changes enforcement | Observational only |
| Lane 1 fast detectors | Started: protocol checks + Aho-Corasick signature scanner (starter table, tiered) + raw-path traversal evidence; corpora in `varman-waf/tests/corpus` | No (shadow only) |
| Streaming body engine | Pending (Phase 5) | No |
| Lane 2 semantic detectors | SQL, HTML/XSS, shell/command, SSRF, NoSQL, SSTI, XXE structural detectors; covered by the corpora | No (shadow only) |
| SecLang / OWASP CRS (Lane 3) | Pending (Phase 7); tracked in `docs/compatibility.md` | No |

The pipeline is deliberately **not wired into the proxy**: `pingap-plugin/src/waf.rs`
still calls the legacy `WafEngine::inspect`. Phase 2's exit criterion is shadow
comparison evidence, not enforcement.

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
  ├─ legacy WafEngine::inspect  → enforced verdict (unchanged)
  └─ waf_shadow::observe        → runs only when VARMAN_WAF_SHADOW=1
       ├─ Canonicalizer          (the one decoding policy)
       ├─ SecurityPipeline       (fast lane first; detectors appended over time)
       └─ shadow::compare(legacy, pipeline)
            → Agree / PipelineStricter / PipelineWeaker counters
```

`VARMAN_WAF_SHADOW=1` (or `=true`) enables shadow execution; unset means the
only cost is one cached boolean read. `waf_shadow::stats()` exposes
checked/agree/stricter/weaker counters for metrics, and every comparison is
logged at `debug` with the canonical path. No response is ever influenced.

Replacement requires corpus evidence: zero `PipelineWeaker` results on the
attack corpus and zero new blocks on the benign corpus, with performance
within budget (`docs/roadmap.md` Phases 2–6).

## 7. Testing requirements for every detector (mandate §23)

Each detector ships with: attack corpus, benign corpus, bypass corpus
(encoded / double-encoded / case / whitespace / comments / Unicode / multipart
/ JSON variants as relevant), fuzz target for any parser it embeds, a
performance budget, and metrics for degradation. A detector without its
corpora is not done.
