# Fuzz targets

Coverage-guided fuzz targets for the Varman engine, built with
[`cargo-fuzz`](https://github.com/rust-fuzz/cargo-fuzz) (nightly).

The fixed-corpus harnesses (`tests/robustness.rs`,
`tests/detector_budgets.rs`) assert the same contracts on the committed
corpus and run in CI on stable; these targets explore beyond it.

| Target | Contract |
|---|---|
| `detectors` | No detector panics, hangs or produces unbounded findings on arbitrary request targets and bodies. |
| `canonicalizer` | Canonicalization never panics and is idempotent on its own output. |

## Running

```bash
rustup toolchain install nightly --profile minimal
cargo install cargo-fuzz
cd VarmanWAF/fuzz
cargo +nightly fuzz run detectors -- -max_total_time=300
cargo +nightly fuzz run canonicalizer -- -max_total_time=300
```

A short smoke campaign is part of the release routine:

```bash
cargo +nightly fuzz run detectors -- -max_total_time=30 -rss_limit_mb=2048
```

Findings (if any) land in `fuzz/artifacts/<target>/` and are reproduced with
`cargo +nightly fuzz run <target> <artifact>`. The last smoke result is
recorded in `docs/security-engine.md`.
