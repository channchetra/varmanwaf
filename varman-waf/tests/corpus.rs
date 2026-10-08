//! Corpus regression tests for the Varman pipeline (mandate §23).
//!
//! - `tests/corpus/attacks/<category>.txt` — one payload per line; every
//!   payload must produce at least one finding of that category, and the
//!   categories listed in [`MUST_REACH_MONITOR`] must reach at least
//!   `Monitor` (removing a detection fails CI — the baseline is a ratchet).
//! - `tests/corpus/benign/<source>.txt` — realistic traffic (WordPress,
//!   documentation, signed URLs, JWTs, API payloads, markdown). It may
//!   produce weak `Log` signals, but must **never** reach `Monitor`/`Block`:
//!   a previously accepted benign case becoming blocked fails CI.
//!
//! Lines starting with `#` and blank lines are ignored.

use std::fs;
use std::path::{Path, PathBuf};

use varman_waf::canonical::{Canonicalizer, RequestParts};
use varman_waf::pipeline::fast::{RawPathTraversalDetector, SignatureDetector};
use varman_waf::pipeline::semantic::{
    BodyShapeDetector, CommandInjectionDetector, DeserializationDetector,
    DlpDetector, GraphqlAbuseDetector, HtmlXssDetector, JwtDetector,
    LdapXPathDetector, NosqlInjectionDetector, PrototypePollutionDetector,
    SqlStructuralDetector, SsrfStructuralDetector, SstiDetector, XxeDetector,
};
use varman_waf::pipeline::{
    Action, AttackCategory, PipelineVerdict, SecurityPipeline,
};

/// Categories whose corpus payloads must reach at least `Monitor`. The rest
/// (`ssti`, `prototype_pollution`) are deliberately weak-signal families for
/// now; their corpus only ratchets detection existence.
const MUST_REACH_MONITOR: &[&str] = &[
    "sql_injection",
    "xss",
    "command_injection",
    "path_traversal",
    "log4shell",
    "ssrf",
    "xxe",
    "crlf_injection",
    "deserialization",
    "lfi_rfi",
    "credential_abuse",
    "sensitive_data_exposure",
];

fn corpus_dir(kind: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/corpus")
        .join(kind)
}

/// The detector set under corpus test: fast lane + semantic detectors.
fn pipeline() -> SecurityPipeline {
    SecurityPipeline::new(vec![
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
        Box::new(BodyShapeDetector::new()),
    ])
}

/// Encode characters that cannot appear raw in a query value the way a
/// client would; everything else is sent verbatim (so payloads keep their
/// realistic `%xx` sequences, which the canonicalizer then decodes).
fn encode_value(raw: &str) -> String {
    let mut out = String::with_capacity(raw.len());
    for ch in raw.chars() {
        match ch {
            ' ' => out.push_str("%20"),
            '%' => out.push_str("%25"),
            '#' => out.push_str("%23"),
            '&' => out.push_str("%26"),
            '=' => out.push_str("%3D"),
            '\r' => out.push_str("%0D"),
            '\n' => out.push_str("%0A"),
            _ => out.push(ch),
        }
    }
    out
}

fn verdict_for(pipeline: &SecurityPipeline, payload: &str) -> PipelineVerdict {
    let target = format!("/?p={}", encode_value(payload));
    let request = Canonicalizer::default().canonicalize(RequestParts::new(
        "GET",
        "example.com",
        target,
    ));
    pipeline.inspect(&request)
}

/// POST with a JSON body (the body-shape corpus in `attacks_body`/`benign_body`).
fn verdict_for_body(
    pipeline: &SecurityPipeline,
    payload: &str,
) -> PipelineVerdict {
    let request = Canonicalizer::default().canonicalize(
        RequestParts::new("POST", "example.com", "/api/v1/items")
            .with_header("Content-Type", "application/json")
            .with_body(payload.as_bytes().to_vec()),
    );
    pipeline.inspect(&request)
}

fn read_cases(path: &Path) -> Vec<(usize, String)> {
    let text = fs::read_to_string(path)
        .unwrap_or_else(|e| panic!("cannot read {}: {e}", path.display()));
    text.lines()
        .enumerate()
        .map(|(i, line)| (i + 1, expand_placeholders(line.trim())))
        .filter(|(_, line)| !line.is_empty() && !line.starts_with('#'))
        .collect()
}

/// Corpus files must never contain literal provider tokens (GitHub push
/// protection flags them as secrets). Placeholders expand at read time into
/// values that match the detectors' patterns.
fn expand_placeholders(line: &str) -> String {
    let mut out = line.to_string();
    for (name, value) in [
        ("${GH_TOKEN}", format!("ghp_{}", "A".repeat(36))),
        (
            "${SLACK_TOKEN}",
            format!("xoxb-{}-{}", "1".repeat(12), "a".repeat(16)),
        ),
        ("${STRIPE_LIVE_KEY}", format!("sk_live_{}", "S".repeat(24))),
        ("${STRIPE_TEST_KEY}", format!("sk_test_{}", "T".repeat(24))),
        ("${GOOGLE_KEY}", format!("AIza{}", "B".repeat(35))),
    ] {
        out = out.replace(name, &value);
    }
    out
}

fn category_files(dir: &Path) -> Vec<PathBuf> {
    let mut files: Vec<PathBuf> = fs::read_dir(dir)
        .unwrap_or_else(|e| panic!("cannot list {}: {e}", dir.display()))
        .filter_map(|entry| entry.ok())
        .map(|entry| entry.path())
        .filter(|path| path.extension().is_some_and(|ext| ext == "txt"))
        .collect();
    files.sort();
    assert!(!files.is_empty(), "no corpus files in {}", dir.display());
    files
}

#[test]
fn attack_corpus_is_detected() {
    let pipeline = pipeline();
    let dir = corpus_dir("attacks");
    let mut failures: Vec<String> = Vec::new();
    let mut payload_count = 0usize;

    for file in category_files(&dir) {
        let stem = file
            .file_stem()
            .and_then(|s| s.to_str())
            .unwrap_or_default()
            .to_string();
        let Some(expected) = AttackCategory::parse(&stem) else {
            failures.push(format!(
                "corpus file {stem}.txt names no known category"
            ));
            continue;
        };
        let must_monitor = MUST_REACH_MONITOR.contains(&stem.as_str());

        for (line, payload) in read_cases(&file) {
            payload_count += 1;
            let verdict = verdict_for(&pipeline, &payload);
            if !verdict.findings.iter().any(|f| f.category == expected) {
                failures.push(format!(
                    "{stem}:{line}: no {expected} finding for {payload:?}"
                ));
                continue;
            }
            if !verdict.findings.is_empty() && verdict.action < Action::Log {
                failures.push(format!(
                    "{stem}:{line}: findings did not reach Log for {payload:?}"
                ));
            }
            if must_monitor && verdict.action < Action::Monitor {
                failures.push(format!(
                    "{stem}:{line}: expected >= monitor, got {} for {payload:?}",
                    verdict.action
                ));
            }
        }
    }

    assert!(
        failures.is_empty(),
        "attack corpus failures:\n{}",
        failures.join("\n")
    );
    assert!(payload_count >= 30, "attack corpus shrank unexpectedly");
}

#[test]
fn benign_corpus_is_never_monitored_or_blocked() {
    let pipeline = pipeline();
    let dir = corpus_dir("benign");
    let mut failures: Vec<String> = Vec::new();
    let mut case_count = 0usize;

    for file in category_files(&dir) {
        let name = file
            .file_name()
            .and_then(|s| s.to_str())
            .unwrap_or_default()
            .to_string();
        for (line, payload) in read_cases(&file) {
            case_count += 1;
            let verdict = verdict_for(&pipeline, &payload);
            if verdict.action >= Action::Monitor {
                let details: Vec<String> = verdict
                    .findings
                    .iter()
                    .map(|f| format!("{} ({})", f.rule_id, f.action_hint))
                    .collect();
                failures.push(format!(
                    "{name}:{line}: {} blocked/monitored benign case {payload:?} via {:?}",
                    verdict.action, details
                ));
            }
        }
    }

    assert!(
        failures.is_empty(),
        "benign corpus failures:\n{}",
        failures.join("\n")
    );
    assert!(case_count >= 20, "benign corpus shrank unexpectedly");
}

#[test]
fn body_attack_corpus_is_detected() {
    let pipeline = pipeline();
    let dir = corpus_dir("attacks_body");
    let mut failures: Vec<String> = Vec::new();
    let mut payload_count = 0usize;

    for file in category_files(&dir) {
        let stem = file
            .file_stem()
            .and_then(|s| s.to_str())
            .unwrap_or_default()
            .to_string();
        let Some(expected) = AttackCategory::parse(&stem) else {
            failures.push(format!(
                "corpus file {stem}.txt names no known category"
            ));
            continue;
        };
        let must_monitor = MUST_REACH_MONITOR.contains(&stem.as_str());

        for (line, payload) in read_cases(&file) {
            payload_count += 1;
            let verdict = verdict_for_body(&pipeline, &payload);
            if !verdict.findings.iter().any(|f| f.category == expected) {
                failures.push(format!(
                    "{stem}(body):{line}: no {expected} finding"
                ));
                continue;
            }
            if must_monitor && verdict.action < Action::Monitor {
                failures.push(format!(
                    "{stem}(body):{line}: expected >= monitor, got {}",
                    verdict.action
                ));
            }
        }
    }

    assert!(
        failures.is_empty(),
        "body attack corpus failures:\n{}",
        failures.join("\n")
    );
    assert!(payload_count >= 2, "body attack corpus shrank unexpectedly");
}

#[test]
fn body_benign_corpus_is_never_monitored_or_blocked() {
    let pipeline = pipeline();
    let dir = corpus_dir("benign_body");
    let mut failures: Vec<String> = Vec::new();
    let mut case_count = 0usize;

    for file in category_files(&dir) {
        let name = file
            .file_name()
            .and_then(|s| s.to_str())
            .unwrap_or_default()
            .to_string();
        for (line, payload) in read_cases(&file) {
            case_count += 1;
            let verdict = verdict_for_body(&pipeline, &payload);
            if verdict.action >= Action::Monitor {
                let details: Vec<String> = verdict
                    .findings
                    .iter()
                    .map(|f| format!("{} ({})", f.rule_id, f.action_hint))
                    .collect();
                failures.push(format!(
                    "{name}:{line}: {} blocked/monitored benign body via {:?}",
                    verdict.action, details
                ));
            }
        }
    }

    assert!(
        failures.is_empty(),
        "body benign corpus failures:\n{}",
        failures.join("\n")
    );
    assert!(case_count >= 2, "body benign corpus shrank unexpectedly");
}
