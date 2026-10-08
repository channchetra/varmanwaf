#![no_main]
//! Coverage-guided fuzz target for the full detector set.
//!
//! Input format: one target on the first line, the rest is the body:
//!
//! ```text
//! /?q=<payload>
//! {"json":"body"}
//! ```
//!
//! The detectors must never panic, hang or grow findings without bound on
//! arbitrary input; `robustness.rs` and `detector_budgets.rs` assert the same
//! properties on a fixed corpus, this target explores beyond it.

use std::sync::LazyLock;

use libfuzzer_sys::fuzz_target;
use varman_waf::canonical::{Canonicalizer, RequestParts};
use varman_waf::pipeline::{DetectionContext, Detector, default_detectors};

/// The detector set the edge runs, built once for the whole campaign.
static DETECTORS: LazyLock<Vec<Box<dyn Detector>>> =
    LazyLock::new(default_detectors);

fuzz_target!(|data: &[u8]| {
    let text = String::from_utf8_lossy(data);
    let (target, body) = text
        .split_once('\n')
        .map_or((text.as_ref(), ""), |(target, body)| (target, body));
    let request = Canonicalizer::default().canonicalize(
        RequestParts::new("POST", "example.com", target.to_string())
            .with_header("Content-Type", "application/octet-stream")
            .with_body(body.as_bytes().to_vec()),
    );
    for detector in DETECTORS.iter() {
        let mut ctx = DetectionContext::new();
        let result = detector.inspect(&request, &mut ctx);
        // The pipeline's contract: bounded findings per input.
        assert!(
            result.findings.len() <= 128,
            "{} produced {} findings",
            detector.id().as_str(),
            result.findings.len()
        );
    }
});
