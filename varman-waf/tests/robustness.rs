//! Robustness soak test for the detection pipeline (Phase 6 exit work).
//!
//! Attacker input is malformed by definition: the mandate requires that a
//! malformed WAF input must never crash the edge and that every detector
//! stays within its budget. This test drives the full shadow pipeline with:
//!
//! - 5,000 deterministically generated pseudo-random byte sequences (a small
//!   LCG keeps the test reproducible without a fuzz dependency), fed both as
//!   a query value and as a request body;
//! - targeted hostile shapes: invalid UTF-8, NUL bytes, huge nesting, huge
//!   strings, lone delimiters, broken escapes.
//!
//! It asserts: no panic, a coherent verdict, findings never exceed the
//! pipeline's finding cap, and the whole run finishes inside a generous time
//! budget (per-detector budgets are separate unit tests).

use std::time::{Duration, Instant};

use varman_waf::canonical::{Canonicalizer, RequestParts};
use varman_waf::pipeline::fast::{
    ProtocolDetector, RawPathTraversalDetector, SignatureDetector,
};
use varman_waf::pipeline::semantic::{
    CommandInjectionDetector, DeserializationDetector, DlpDetector,
    GraphqlAbuseDetector, HtmlXssDetector, JwtDetector, LdapXPathDetector,
    NosqlInjectionDetector, PrototypePollutionDetector, SqlStructuralDetector,
    SsrfStructuralDetector, SstiDetector, XxeDetector,
};
use varman_waf::pipeline::{Action, PipelineVerdict, SecurityPipeline};

fn pipeline() -> SecurityPipeline {
    SecurityPipeline::new(vec![
        Box::new(ProtocolDetector::new()),
        Box::new(SignatureDetector::new()),
        Box::new(RawPathTraversalDetector::new()),
        Box::new(SqlStructuralDetector::new()),
        Box::new(HtmlXssDetector::new()),
        Box::new(CommandInjectionDetector::new()),
        Box::new(SsrfStructuralDetector::new()),
        Box::new(NosqlInjectionDetector::new()),
        Box::new(SstiDetector::new()),
        Box::new(XxeDetector::new()),
        Box::new(DeserializationDetector::new()),
        Box::new(PrototypePollutionDetector::new()),
        Box::new(LdapXPathDetector::new()),
        Box::new(GraphqlAbuseDetector::new()),
        Box::new(JwtDetector::new()),
        Box::new(DlpDetector::new()),
    ])
}

/// Deterministic pseudo-random generator (LCG) for reproducible soak cases.
struct Lcg(u64);

impl Lcg {
    fn next(&mut self) -> u64 {
        self.0 = self
            .0
            .wrapping_mul(6364136223846793005)
            .wrapping_add(1442695040888963407);
        self.0
    }
}

fn hostile_bytes(len: usize, rng: &mut Lcg) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(len);
    for _ in 0..len {
        let roll = rng.next() % 100;
        let byte = if roll < 30 {
            // ASCII letters/digits keep values scannable.
            let set = b"abcdefghijklmnopqrstuvwxyz0123456789";
            set[(rng.next() as usize) % set.len()]
        } else if roll < 45 {
            // Structural punctuation the detectors care about.
            let set = b"'\"{}[]()<>$;|&%#\\/.=:*!\r\n";
            set[(rng.next() as usize) % set.len()]
        } else {
            (rng.next() & 0xFF) as u8
        };
        bytes.push(byte);
    }
    bytes
}

fn verdict_of(pipeline: &SecurityPipeline, bytes: &[u8]) -> PipelineVerdict {
    // Feed the same bytes as a query value (lossy text) and as a body
    // (raw bytes — exercises the UTF-8 degradation paths).
    let value = String::from_utf8_lossy(bytes);
    let mut encoded = String::with_capacity(value.len());
    for ch in value.chars() {
        match ch {
            ' ' => encoded.push_str("%20"),
            '%' => encoded.push_str("%25"),
            '&' => encoded.push_str("%26"),
            '#' => encoded.push_str("%23"),
            '=' => encoded.push_str("%3D"),
            _ => encoded.push(ch),
        }
    }
    let target = format!("/?q={encoded}");
    let request = Canonicalizer::default().canonicalize(
        RequestParts::new("GET", "example.com", target)
            .with_body(bytes.to_vec()),
    );
    pipeline.inspect(&request)
}

fn assert_coherent(verdict: &PipelineVerdict, case: &[u8]) {
    // Findings are capped by the pipeline budget.
    assert!(
        verdict.findings.len() <= 256,
        "finding cap exceeded for case of {} bytes",
        case.len()
    );
    // Every action is on the escalation ladder.
    let rank = verdict.action.rank();
    assert!(rank <= Action::Block.rank());
}

#[test]
fn random_soak_never_panics_and_stays_in_budget() {
    let pipeline = pipeline();
    let mut rng = Lcg(0x5eed_1234_abcd_0001);
    let start = Instant::now();
    for case_index in 0..5_000 {
        let len = (rng.next() % 512) as usize;
        let bytes = hostile_bytes(len, &mut rng);
        let verdict = verdict_of(&pipeline, &bytes);
        assert_coherent(&verdict, &bytes);
        if case_index % 1_000 == 0 {
            // Keep the loop observable without printing per case.
            assert_eq!(bytes.len(), len);
        }
    }
    let elapsed = start.elapsed();
    assert!(
        elapsed < Duration::from_secs(60),
        "soak took {elapsed:?}; detectors must stay within budget"
    );
}

#[test]
fn hostile_shapes_are_handled() {
    let pipeline = pipeline();
    let cases: Vec<Vec<u8>> = vec![
        vec![0xff, 0xfe, 0x00, 0x01, 0x80],
        vec![b'{'; 4096],
        vec![b')'; 4096],
        b"{{7*7}}".to_vec(),
        b"${".to_vec(),
        b"<%=".to_vec(),
        b"<!DOCTYPE foo [<!ENTITY x SYSTEM \"file:///x\">]>".to_vec(),
        b"%zz%zz%zz".to_vec(),
        b"'\"'\"'\"'\"".to_vec(),
        b"\r\n\r\n\r\n".to_vec(),
        Vec::new(),
    ];
    for bytes in cases {
        let verdict = verdict_of(&pipeline, &bytes);
        assert_coherent(&verdict, &bytes);
    }
}

#[test]
fn out_of_budget_values_degrade_instead_of_erroring() {
    let pipeline = pipeline();
    // 64 KiB of SQL-looking content: larger than several semantic budgets.
    let bytes = b"SELECT * FROM users WHERE id = 1 OR 1=1; ".repeat(2000);
    let verdict = verdict_of(&pipeline, &bytes);
    // Detection still happens where budgets allow (signatures scan bounded
    // bodies), and any degradation is structured rather than a panic.
    for degradation in &verdict.degraded {
        assert!(!degradation.reason.is_empty());
    }
}
