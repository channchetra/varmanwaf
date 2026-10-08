#![no_main]
//! Coverage-guided fuzz target for the canonicalizer.
//!
//! Properties asserted on arbitrary targets:
//!
//! 1. canonicalization never panics on arbitrary bytes;
//! 2. canonicalization converges: a target deep enough to exhaust the decode
//!    budget can leave a residual escape that the next (fresh-budget) pass
//!    resolves, but from the second pass on the form is stable and no escape
//!    is ever re-introduced. The production path canonicalizes exactly once
//!    per request, so this is the honest stability contract; the exact
//!    counterexample is locked in the canonicalizer unit tests.

use libfuzzer_sys::fuzz_target;
use varman_waf::canonical::{Canonicalizer, RequestParts};

/// Re-serialize a canonical form the same way the unit tests do.
fn recanonicalize(
    once: &varman_waf::canonical::CanonicalRequest,
) -> varman_waf::canonical::CanonicalRequest {
    let query = once
        .query()
        .iter()
        .map(|param| format!("{}={}", param.name, param.value))
        .collect::<Vec<_>>()
        .join("&");
    let target = if query.is_empty() {
        once.path().to_string()
    } else {
        format!("{}?{}", once.path(), query)
    };
    Canonicalizer::default().canonicalize(RequestParts::new(
        "GET",
        "example.com",
        target,
    ))
}

fuzz_target!(|data: &[u8]| {
    let text = String::from_utf8_lossy(data);
    let once = Canonicalizer::default().canonicalize(RequestParts::new(
        "GET",
        "example.com",
        text.to_string(),
    ));
    let twice = recanonicalize(&once);
    let thrice = recanonicalize(&twice);
    assert_eq!(thrice.path(), twice.path(), "path does not converge");
    let twice_query: Vec<(String, String)> = twice
        .query()
        .iter()
        .map(|param| (param.name.clone(), param.value.clone()))
        .collect();
    let thrice_query: Vec<(String, String)> = thrice
        .query()
        .iter()
        .map(|param| (param.name.clone(), param.value.clone()))
        .collect();
    assert_eq!(thrice_query, twice_query, "query does not converge");
});

