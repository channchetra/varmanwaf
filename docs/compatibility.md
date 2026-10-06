# Compatibility Tracking

> Honest status of ModSecurity SecLang / OWASP CRS compatibility. The VarmanWAF
> native SecLang engine is **not implemented yet** (Phase 7 in
> `docs/roadmap.md`). Until then this file records the plan and the rules for
> claiming compatibility; no compatibility may be claimed before tests prove it
> (mandate §36, §37).

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
| SecLang parser (`SecRule` lines → AST) | Partial | Variables list, 9 operators, quoted action lists, comments; unsupported directives/operators error observably |
| SecLang execution (variables, operators) | Partial | `ARGS`, `ARGS_NAMES`, `REQUEST_HEADERS[:name]`, `REQUEST_METHOD`, `REQUEST_URI`, `QUERY_STRING`, `REQUEST_BODY`, `REMOTE_ADDR`, `TX`; `@rx` pre-compiled, `@ipMatch` CIDR; bounded resolution |
| Transformations (`urlDecode`, `htmlEntityDecode`, …) | Partial | 7 transforms implemented and applied in order; unknown transforms error observably |
| Control flow (chain, skip, skipAfter, ctl, setvar) | Planned | Phase 7 |
| OWASP CRS stock ruleset execution | Planned | Phase 7 + CRS regression harness |
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
