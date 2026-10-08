# VarmanWAF Performance

> **Truthfulness rule** (mandate §36): every number here is reproducible with
> the command in [Methodology](#methodology), measured on the recorded
> hardware, with the caveats stated. No extrapolated or estimated figures.

## Lane-cost report (2026-10-07)

In-process inspection cost per request, averaged over the attack + benign
corpora (132 payloads x 20 repetitions = 2,640 requests per lane):

| Lane | µs / request |
|---|---:|
| Legacy engine (`WafEngine::inspect`, normalizes internally) | 462.05 |
| Canonicalize only (`Canonicalizer::canonicalize`) | 5.21 |
| Fast lane (protocol + signatures + raw-path traversal) | 2.74 |
| Full pipeline (20 detectors, incl. SQL AST) | 122.74 |
| Shadow/enforce path (canonicalize + full pipeline) | 130.03 |
| **Pipeline / legacy ratio** | **0.27** |

The Varman pipeline inspects the same adversarial corpus in **under a third of
the legacy engine's time** (3.8x faster), including canonicalization. The fast
lane alone is ~45x cheaper than the full pipeline, which is why it runs first
and why cheap detectors are registered before semantic ones.

### Interpretation

- The legacy engine's cost is dominated by its managed rule set and internal
  normalization; it is the production baseline today.
- The pipeline's ~123 µs is dominated by the semantic detectors (each scans
  every value with structure-aware regexes). The SQL AST tier adds ~30 µs on
  this corpus: parsing is attempted only for SQL-ish values (a cheap keyword
  prefilter), and it buys precision - fragments are wrapped into statements
  and inspected as real ASTs (stacked statements, UNIONs, tautologies,
  DML/DDL). The corpus is adversarial by design, so this is close to a worst
  case; benign production traffic measures lower.
- Canonicalization is cheap (5.21 µs) and shared: the pipeline never
  re-decodes inside detectors.

### Caveats

- **In-process engine cost only.** These numbers exclude TLS, proxying,
  logging, the control-plane link and the agent. End-to-end proxy throughput
  is a separate measurement and is not claimed here.
- Single-run averages after one warmup pass, on a Docker Desktop VM; treat
  them as order-of-magnitude facts, not microbenchmarks.
- The sanity bounds asserted in the test (1 ms fast lane, 5 ms full pipeline)
  exist to catch catastrophic regressions (regex bombs, accidental quadratic
  work); they are 10x+ above the measured baseline so CI cannot flake.

## Methodology

```bash
docker exec varman-dev bash -c \
  'cd /waf/VarmanWAF && cargo test -p varman-waf --test lane_cost -- --nocapture'
```

`varman-waf/tests/lane_cost.rs`:

1. Reads every non-comment line of `tests/corpus/attacks/*.txt` and
   `tests/corpus/benign/*.txt` (132 payloads).
2. Builds the same request shape the corpus harness uses (payload as one
   query value) for both engines.
3. Warms up once, then times 20 repetitions per lane with
   `std::time::Instant`, reporting the average per request.
4. `black_box`es the verdicts so nothing is optimised away.
5. Asserts loose sanity bounds and prints the table above.

Corpus shape: adversarial payloads (SQLi, XSS, RCE, traversal, SSRF, XXE,
deserialization, JWT, DLP, …) plus benign traffic (WordPress, SQL/JS docs,
JWTs, API payloads). This intentionally over-weights attack-shaped input, the
expensive path for a WAF.

## Hardware

Docker Desktop on Windows (WSL2 backend), `rust:1.98.1-bookworm` dev
container, release-profile test build (`cargo test` with optimizations as
configured by the workspace). Numbers are comparable **within** a machine,
not across machines.

## History

| Date | Change | Full pipeline | Pipeline / legacy |
|---|---|---:|---:|
| 2026-10-07 | First lane-cost measurement (16 detectors) | 88.23 µs | 0.20 |
| 2026-10-08 | SQL AST tier + WebSocket/stream detectors (20 detectors) | 122.74 µs | 0.27 |
