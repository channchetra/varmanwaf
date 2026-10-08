//! Lane-cost benchmark: the Varman pipeline vs the legacy engine
//! (Phase 2/4 exit work). Methodology in `docs/performance.md`.
//!
//! Run with:
//!
//! ```text
//! cargo test -p varman-waf --test lane_cost -- --nocapture
//! ```
//!
//! The test prints a per-request cost table for the attack + benign corpora
//! and asserts only loose sanity bounds (10x+ headroom over the measured
//! baseline) so a slow CI machine cannot flake. Ratcheting the bounds down is
//! a deliberate change with a recorded measurement.

use std::fs;
use std::path::{Path, PathBuf};
use std::time::Instant;

use varman_waf::canonical::{Canonicalizer, RequestParts};
use varman_waf::engine::{RequestData, WafEngine, WafEngineConfig};
use varman_waf::pipeline::fast::{
    ProtocolDetector, RawPathTraversalDetector, SignatureDetector,
};
use varman_waf::pipeline::SecurityPipeline;

/// Corpus repetitions; the harness reports an average, not a single shot.
const REPEATS: usize = 20;

fn corpus_dir(kind: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/corpus")
        .join(kind)
}

fn corpus_lines() -> Vec<String> {
    let mut lines = Vec::new();
    for kind in ["attacks", "benign"] {
        let dir = corpus_dir(kind);
        let mut files: Vec<PathBuf> = fs::read_dir(&dir)
            .unwrap_or_else(|e| panic!("cannot list {}: {e}", dir.display()))
            .filter_map(|entry| entry.ok())
            .map(|entry| entry.path())
            .filter(|path| path.extension().is_some_and(|ext| ext == "txt"))
            .collect();
        files.sort();
        for file in files {
            let text = fs::read_to_string(&file).unwrap_or_else(|e| {
                panic!("cannot read {}: {e}", file.display())
            });
            for line in text.lines() {
                let line = line.trim();
                if line.is_empty() || line.starts_with('#') {
                    continue;
                }
                lines.push(line.to_string());
            }
        }
    }
    assert!(lines.len() >= 100, "corpus shrank unexpectedly");
    lines
}

/// Same request shape the corpus harness uses: the payload as one query value.
fn request_parts(line: &str) -> RequestParts {
    let encoded = line
        .replace('%', "%25")
        .replace('&', "%26")
        .replace('#', "%23")
        .replace('=', "%3D")
        .replace('\r', "%0D")
        .replace('\n', "%0A")
        .replace(' ', "%20");
    RequestParts::new("GET", "example.com", format!("/?p={encoded}"))
        .with_header("Host", "example.com")
        .with_header("User-Agent", "benchmark-agent/1.0")
}

fn legacy_data(line: &str) -> RequestData {
    let encoded = line
        .replace('%', "%25")
        .replace('&', "%26")
        .replace('#', "%23")
        .replace('=', "%3D")
        .replace('\r', "%0D")
        .replace('\n', "%0A")
        .replace(' ', "%20");
    RequestData {
        method: "GET".into(),
        path: "/".into(),
        query: format!("p={encoded}"),
        headers: vec![
            ("Host".into(), "example.com".into()),
            ("User-Agent".into(), "benchmark-agent/1.0".into()),
        ],
        body: None,
        client_ip: "203.0.113.9".into(),
        country_code: None,
        scheme: "https".into(),
        protocol: "HTTP/1.1".into(),
    }
}

fn fast_lane() -> SecurityPipeline {
    SecurityPipeline::new(vec![
        Box::new(ProtocolDetector::new()),
        Box::new(SignatureDetector::new()),
        Box::new(RawPathTraversalDetector::new()),
    ])
}

fn full_pipeline() -> SecurityPipeline {
    SecurityPipeline::new(varman_waf::pipeline::default_detectors())
}

/// Microseconds per request for one `run` invocation, after a warmup pass.
fn time_per_request(requests: usize, mut run: impl FnMut()) -> f64 {
    run();
    let start = Instant::now();
    run();
    start.elapsed().as_secs_f64() * 1_000_000.0 / requests as f64
}

#[test]
fn lane_cost_report() {
    let lines = corpus_lines();
    let requests = lines.len() * REPEATS;

    let legacy = WafEngine::new(&WafEngineConfig::default());
    let fast = fast_lane();
    let full = full_pipeline();
    let canonicalizer = Canonicalizer::default();

    let legacy_inputs: Vec<RequestData> =
        lines.iter().map(|line| legacy_data(line)).collect();
    let canonical: Vec<_> = lines
        .iter()
        .map(|line| canonicalizer.canonicalize(request_parts(line)))
        .collect();

    let legacy_us = time_per_request(requests, || {
        for _ in 0..REPEATS {
            for request in &legacy_inputs {
                let verdict = legacy.inspect(request);
                std::hint::black_box(verdict.action);
            }
        }
    });
    let canonicalize_us = time_per_request(requests, || {
        for _ in 0..REPEATS {
            for line in &lines {
                let request = canonicalizer.canonicalize(request_parts(line));
                std::hint::black_box(request.path());
            }
        }
    });
    let fast_us = time_per_request(requests, || {
        for _ in 0..REPEATS {
            for request in &canonical {
                let verdict = fast.inspect(request);
                std::hint::black_box(verdict.action);
            }
        }
    });
    let full_us = time_per_request(requests, || {
        for _ in 0..REPEATS {
            for request in &canonical {
                let verdict = full.inspect(request);
                std::hint::black_box(verdict.action);
            }
        }
    });
    let shadow_us = time_per_request(requests, || {
        for _ in 0..REPEATS {
            for line in &lines {
                let request = canonicalizer.canonicalize(request_parts(line));
                let verdict = full.inspect(&request);
                std::hint::black_box(verdict.action);
            }
        }
    });

    println!(
        "\n=== Varman lane-cost report ({} requests x {} corpus lines) ===",
        requests,
        lines.len()
    );
    println!("{:<42} {:>12}", "lane", "us/request");
    println!("{:-<42} {:->12}", "", "");
    println!(
        "{:<42} {:>12.2}",
        "legacy engine (normalized internally)", legacy_us
    );
    println!("{:<42} {:>12.2}", "canonicalize only", canonicalize_us);
    println!(
        "{:<42} {:>12.2}",
        "fast lane (protocol+signatures+traversal)", fast_us
    );
    println!(
        "{:<42} {:>12.2}",
        format!(
            "full pipeline ({} detectors)",
            varman_waf::pipeline::default_detectors().len()
        ),
        full_us
    );
    println!(
        "{:<42} {:>12.2}",
        "shadow/enforce path (canonicalize+full)", shadow_us
    );
    println!(
        "{:<42} {:>12.2}",
        "pipeline / legacy ratio",
        full_us / legacy_us
    );

    // Loose sanity bounds only: catch catastrophic regressions (regex bombs,
    // accidental quadratic work), never flake on a slow machine. The measured
    // baseline on the dev container is an order of magnitude below these.
    assert!(
        fast_us < 1000.0,
        "fast lane regressed: {fast_us:.2} us/request"
    );
    assert!(
        full_us < 5000.0,
        "full pipeline regressed: {full_us:.2} us/request"
    );
    assert!(
        shadow_us < 6000.0,
        "shadow path regressed: {shadow_us:.2} us/request"
    );
}
