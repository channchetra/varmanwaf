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
| SecLang parser (`SecRule` lines → AST) | Partial | Variables list, 21 operators (`@rx`, `@pm`, `@pmFromFile`, `@contains`, `@streq`, `@beginsWith`, `@endsWith`, `@detectSQLi`, `@detectXSS`, `@ipMatch`, `@eq`, `@ne`, `@lt`, `@le`, `@gt`, `@ge`, `@within`, `@validateByteRange`, `@validateUtf8Encoding`, `@validateUrlEncoding`, `@unconditionalMatch`), operator negation (`!@…`), `\` line continuations, quoted action lists, comments, `SecAction`, `SecComponentSignature`; unsupported directives/operators error observably |
| SecLang execution (variables, operators) | Partial | `ARGS`, `ARGS_NAMES`, `REQUEST_HEADERS[:name]`, `REQUEST_METHOD`, `REQUEST_URI`, `QUERY_STRING`, `REQUEST_BODY`, `REMOTE_ADDR`, `TX`; `@rx` pre-compiled, `@ipMatch` CIDR + single addresses; bounded resolution |
| `%{tx.*}` macro expansion | Supported (tx.*, and MATCHED_VAR, MATCHED_VAR_NAME, remote_addr, request_line, request_headers.*, args.*) | Operator arguments and `setvar` values/targets; unset variables expand to empty; TX names are case-insensitive |
| Transformations (`urlDecode`, `htmlEntityDecode`, …) | Partial | 20 transforms implemented and applied in order (all ports of ModSecurity's C++); **known deviations:** `t:sha1` emits a lowercase hex digest (string-valued engine) and `t:cmdLine` preserves backslashes (CRS's traversal corpus requires `..\` to remain matchable); `t:none` accepted as a no-op; unknown transforms error observably |
| Collections (`initcol`, `ip.`/`global.`) | Partial | `initcol` creates per-transaction collection instances with expanded keys; cross-request (shared-memory) persistence is not implemented and `setvar` outside `tx.*` errors observably — no stock CRS rule reads collection values, so stock behaviour is exact |
| Control flow (chain, skip, skipAfter, ctl, setvar) | Supported (execution layer) | `chain` (+`TX:0…9` capture), `setvar:tx.*`, `RemoveById`, `UpdateTargetById`, `skip`/`skipAfter`+`SecMarker`, `SecDefaultAction`, `ctl:ruleEngine=On/DetectionOnly/Off` — all covered by tests |
| OWASP CRS stock ruleset execution | **Full set loads** | Harness loads `references/coreruleset/rules/*.conf` per file and as one concatenated configuration (the way CRS actually loads). **Latest measurement (2026-10-07): full-set OK — 693 rule statements across all 27 files**; per-file 26/27 (950 alone cannot resolve its cross-file `skipAfter` marker when compiled standalone — the full-set pass is the correct model). With the host's Windows Defender quarantine active, per-file reads of `web-shells-php.data` fail (`EINVAL`); a container-local clone via `CRS_DIR=/opt/crs-conformance` works around it (25/643 floor ratcheted for the default path, 26/678 with a clean clone) |
| OWASP CRS regression corpus (behavioural) | In progress | `varman-waf/tests/crs_regression.rs` runs the official go-ftw corpus in-process against the full rule set at each rule's declared paranoia level, with the **official test configuration from `tests/regression/README.md`** applied (arg-length limits, UTF-8 validation, blocking PL4). **Latest measurement (2026-10-07): 5100/5155 checked expectations pass** (first: 3238; 99.0%). Remaining failures: a flat tail (≤2 per class). **Documented platform divergence:** `t:urlDecodeUni`'s `+` handling differs across ModSecurity v2.9/v3/Coraza; our model (parse decodes `%XX` and `+`; the transform also converts `+`) is the corpus-optimal one (tested three alternatives against the full corpus) and leaves the two `942500` tests as a known conflict. Known harness scope: `status` expectations reported but not asserted, `encoded_request` and multi-stage tests skipped, one unparsable YAML (920539) |
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
