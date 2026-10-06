# Compatibility Tracking

> Honest status of ModSecurity SecLang / OWASP CRS compatibility. The VarmanWAF
> native SecLang engine is implemented (Phase 7 in `docs/roadmap.md`) and
> hardening continues against the upstream CRS rule files; the CRS conformance
> harness (`varman-waf/tests/crs_conformance.rs`) records load results per run.
> No compatibility may be claimed before tests prove it (mandate §36, §37).

## Status legend

- **Supported** — implemented and verified against upstream regression tests;
  evidence linked.
- **Partial** — implemented with known deviations; deviations listed and tested.
- **Unsupported** — accepted by the parser but not executed, or rejected;
  behaviour is observable (never silently ignored).
- **Planned** — not implemented.

## Current state (inherited baseline)

The imported PingWAF engine is **not** a SecLang engine. It has its own rule
dialect (a Cloudflare-like field/operator/value expression DSL) with an anomaly
scorer. Therefore:

| Area | Status | Notes |
|---|---|---|
| SecLang parser (`SecRule` lines → AST) | Partial | Variables list, 19 operators (`@rx`, `@pm`, `@pmFromFile`, `@contains`, `@streq`, `@beginsWith`, `@endsWith`, `@detectSQLi`, `@detectXSS`, `@ipMatch`, `@eq`, `@ne`, `@lt`, `@le`, `@gt`, `@ge`, `@within`, `@validateByteRange`, `@unconditionalMatch`), operator negation (`!@…`), `\` line continuations, quoted action lists, comments, `SecAction`, `SecComponentSignature`; unsupported directives/operators error observably |
| SecLang execution (variables, operators) | Partial | `ARGS`, `ARGS_NAMES`, `REQUEST_HEADERS[:name]`, `REQUEST_METHOD`, `REQUEST_URI`, `QUERY_STRING`, `REQUEST_BODY`, `REMOTE_ADDR`, `TX`; `@rx` pre-compiled, `@ipMatch` CIDR + single addresses; bounded resolution |
| `%{tx.*}` macro expansion | Supported (tx.*, and MATCHED_VAR, MATCHED_VAR_NAME, remote_addr, request_line, request_headers.*, args.*) | Operator arguments and `setvar` values/targets; unset variables expand to empty; TX names are case-insensitive |
| Transformations (`urlDecode`, `htmlEntityDecode`, …) | Partial | 19 transforms implemented and applied in order (all ports of ModSecurity's C++); **known deviation:** `t:sha1` emits a lowercase hex digest, while ModSecurity emits raw digest bytes (string-valued engine); `t:none` accepted as a no-op; unknown transforms error observably |
| Collections (`initcol`, `ip.`/`global.`) | Partial | `initcol` creates per-transaction collection instances with expanded keys; cross-request (shared-memory) persistence is not implemented and `setvar` outside `tx.*` errors observably — no stock CRS rule reads collection values, so stock behaviour is exact |
| Control flow (chain, skip, skipAfter, ctl, setvar) | Supported (execution layer) | `chain` (+`TX:0…9` capture), `setvar:tx.*`, `RemoveById`, `UpdateTargetById`, `skip`/`skipAfter`+`SecMarker`, `SecDefaultAction`, `ctl:ruleEngine=On/DetectionOnly/Off` — all covered by tests |
| OWASP CRS stock ruleset execution | In progress | Harness loads `references/coreruleset/rules/*.conf` and reports per-file results. **Latest measurement (2026-10-07): 24/27 files load, 538 rules** (first: 1/27, 0) — remaining blockers: `@validateUtf8Encoding` (920; deliberately an error until byte-preserving value plumbing exists), cross-file `skipAfter` targets when files load standalone (950 → marker lives in 959; full-set loading is a planned harness mode), and Windows Defender quarantining `web-shells-php.data` (host environment, blocks 955). Each construct errors observably; none is silently ignored |
| Anomaly scoring compatible with CRS PL1–4 | Planned | Phase 7 |

## Rules for future entries

1. Compatibility entries land **with** the test that proves them: official CRS
   regression cases (https://github.com/coreruleset/coreruleset), differential
   runs against ModSecurity/Coraza, or both.
2. Unsupported directives must produce an observable diagnostic (startup warning
   + metrics), never silent no-ops.
3. When VarmanWAF intentionally differs from ModSecurity behaviour, record the
   difference here with the rationale — do not change behaviour to match without
   investigating which side is correct.
4. Parsing a rule file successfully is not evidence of behavioural
   compatibility; only execution against the regression corpus is.
