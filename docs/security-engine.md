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
| Pipeline (`varman-waf/src/pipeline`) | Skeleton landed: detector contract, findings, monotonic actions, bounded context, shadow comparison | No |
| Lane 1 fast detectors | Pending (Phase 4) | No |
| Streaming body engine | Pending (Phase 5) | No |
| Lane 2 semantic detectors | Pending (Phase 6) | No |
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
  └─ SecurityPipeline::inspect  → shadow PipelineVerdict (recorded)
       └─ shadow::compare(legacy, pipeline) → agreement / downgrade metric
```

Replacement requires corpus evidence: zero `PipelineWeaker` results on the
attack corpus and zero new blocks on the benign corpus, with performance
within budget (`docs/roadmap.md` Phases 2–6).

## 7. Testing requirements for every detector (mandate §23)

Each detector ships with: attack corpus, benign corpus, bypass corpus
(encoded / double-encoded / case / whitespace / comments / Unicode / multipart
/ JSON variants as relevant), fuzz target for any parser it embeds, a
performance budget, and metrics for degradation. A detector without its
corpora is not done.
