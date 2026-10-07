//! OWASP CRS behavioural regression harness.
//!
//! Reads the official go-ftw regression corpus from a local CRS clone, runs
//! each request through the full CRS rule set with the Varman SecLang engine
//! (in-process, no HTTP server), and checks the rule IDs the tests expect to
//! fire — or to stay silent.
//!
//! What is asserted: `log_contains`, `log.expect_ids`, and
//! `log.no_expect_ids` expectations. What is only counted/reported:
//! `status` expectations (the engine returns matched rules; mapping them to
//! HTTP statuses is the enforcement layer's job), multi-stage tests and
//! `encoded_request` tests (raw wire bytes, no persistence across stages).
//!
//! CRS location: `CRS_DIR` env var, else `../../references/coreruleset`.
//! When no clone is present the test skips, so builds without the reference
//! checkout stay green.

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Path, PathBuf};

use serde::Deserialize;
use varman_waf::canonical::{Canonicalizer, RequestParts};
use varman_waf::seclang::ruleset::SecRuleSet;
use varman_waf::seclang::transaction::SecLangTransaction;

#[derive(Debug, Deserialize)]
struct TestFile {
    tests: Vec<TestCase>,
}

#[derive(Debug, Deserialize)]
struct TestCase {
    #[serde(default)]
    test_id: Option<serde_yaml::Value>,
    #[serde(default)]
    #[allow(dead_code)]
    desc: Option<String>,
    stages: Vec<Stage>,
}

#[derive(Debug, Deserialize)]
struct Stage {
    input: Input,
    #[serde(default)]
    output: Output,
}

#[derive(Debug, Deserialize, Default)]
struct Input {
    #[serde(default)]
    method: Option<String>,
    #[serde(default)]
    uri: Option<String>,
    #[serde(default)]
    headers: Option<BTreeMap<String, serde_yaml::Value>>,
    #[serde(default)]
    data: Option<String>,
    #[serde(default)]
    encoded_request: Option<String>,
}

#[derive(Debug, Deserialize, Default)]
struct Output {
    #[serde(default)]
    log: Option<LogExpect>,
    #[serde(default)]
    log_contains: Option<String>,
    #[serde(default)]
    status: Option<u16>,
}

#[derive(Debug, Deserialize, Default)]
struct LogExpect {
    #[serde(default)]
    expect_ids: Option<Vec<u64>>,
    #[serde(default)]
    no_expect_ids: Option<Vec<u64>>,
}

fn crs_root() -> Option<PathBuf> {
    let candidates: Vec<PathBuf> = match std::env::var_os("CRS_DIR") {
        Some(dir) => vec![PathBuf::from(dir)],
        None => {
            let manifest = Path::new(env!("CARGO_MANIFEST_DIR"));
            vec![manifest.join("../../references/coreruleset")]
        },
    };
    candidates.into_iter().find(|root| {
        root.join("rules").is_dir()
            && root.join("tests/regression/tests").is_dir()
    })
}

fn scalar(value: &serde_yaml::Value) -> String {
    match value {
        serde_yaml::Value::String(text) => text.clone(),
        serde_yaml::Value::Number(number) => number.to_string(),
        serde_yaml::Value::Bool(flag) => flag.to_string(),
        serde_yaml::Value::Null => String::new(),
        other => format!("{other:?}"),
    }
}

fn extract_id(text: &str) -> Option<u64> {
    let start = text.find("id \"")? + 4;
    let rest = &text[start..];
    let end = rest.find('"')?;
    rest[..end].trim().parse().ok()
}

/// Concatenate all CRS rule files in include order.
fn combined_source(rules_dir: &Path) -> String {
    let mut files: Vec<PathBuf> = fs::read_dir(rules_dir)
        .expect("read CRS rules directory")
        .filter_map(|entry| entry.ok().map(|entry| entry.path()))
        .filter(|path| {
            let name = path.file_name().and_then(|n| n.to_str()).unwrap_or("");
            name.ends_with(".conf") && !name.ends_with(".example")
        })
        .collect();
    files.sort();
    let mut combined = String::new();
    for path in &files {
        let bytes = fs::read(path)
            .unwrap_or_else(|error| panic!("read {}: {error}", path.display()));
        combined.push_str(&String::from_utf8_lossy(&bytes));
        combined.push('\n');
    }
    combined
}

/// Compile the full CRS rule set (all files concatenated in include order).
fn compile_full_set(rules_dir: &Path) -> SecRuleSet {
    let combined = combined_source(rules_dir);
    SecRuleSet::from_source_with_base(&combined, Some(rules_dir))
        .unwrap_or_else(|error| {
            panic!("full CRS rule set failed to compile: {}", error.reason)
        })
}

/// Map rule ids to their declared `paranoia-level/N` tag (default 1).
fn paranoia_levels(source: &str) -> BTreeMap<u64, u8> {
    let mut levels = BTreeMap::new();
    let mut rest = source;
    while let Some(at) = rest.find("id:") {
        let after = &rest[at + 3..];
        let digits: String =
            after.chars().take_while(|c| c.is_ascii_digit()).collect();
        if digits.is_empty() {
            rest = after;
            continue;
        }
        let id: u64 = digits.parse().unwrap_or(0);
        // Stay inside this rule's quoted action list: the first `"` closes it.
        let window = &after[..after.len().min(1000)];
        let limit = match window.find('"') {
            Some(position) => &window[..position],
            None => window,
        };
        if let Some(tag_at) = limit.find("paranoia-level/") {
            let tail = &limit[tag_at + "paranoia-level/".len()..];
            let number: String =
                tail.chars().take_while(|c| c.is_ascii_digit()).collect();
            if let Ok(level) = number.parse::<u8>() {
                levels.insert(id, level);
            }
        }
        rest = after;
    }
    levels
}

/// Run one test stage's request through the engine; returns fired rule IDs.
fn fired_ids(
    engine: &SecRuleSet,
    input: &Input,
    paranoia_level: u8,
) -> BTreeSet<u64> {
    let method = input.method.clone().unwrap_or_else(|| "GET".into());
    let uri = input.uri.clone().unwrap_or_else(|| "/".into());
    let mut parts = RequestParts::new(method, "localhost", uri);
    if let Some(headers) = &input.headers {
        for (name, value) in headers {
            parts = parts.with_header(name.clone(), scalar(value));
        }
    }
    if let Some(data) = &input.data {
        parts = parts.with_body(data.clone().into_bytes());
    }
    let request = Canonicalizer::default().canonicalize(parts);
    let mut txn = SecLangTransaction::from_request(&request);
    // Run at the paranoia level the expected rule declares, mirroring CRS's
    // per-level CI runs; 901's default-setting rules skip pre-set values.
    let level = paranoia_level.to_string();
    txn.tx_set("detection_paranoia_level", level.clone());
    txn.tx_set("executing_paranoia_level", level.clone());
    txn.tx_set("paranoia_level", level);
    engine
        .evaluate(&mut txn)
        .into_iter()
        .flat_map(|hit| hit.rule_ids)
        .flatten()
        .collect()
}

#[test]
fn targeted_944300_fires() {
    let Some(root) = crs_root() else {
        eprintln!(
            "crs_regression: no CRS clone found; skipping targeted check"
        );
        return;
    };
    let engine = compile_full_set(&root.join("rules"));
    let mut headers = BTreeMap::new();
    headers.insert(
        "Host".to_string(),
        serde_yaml::Value::String("localhost".to_string()),
    );
    headers.insert(
        "User-Agent".to_string(),
        serde_yaml::Value::String("OWASP CRS test agent".to_string()),
    );
    headers.insert(
        "Content-Type".to_string(),
        serde_yaml::Value::String(
            "application/x-www-form-urlencoded".to_string(),
        ),
    );
    let input = Input {
        method: Some("POST".to_string()),
        uri: Some("/post".to_string()),
        headers: Some(headers),
        data: Some("test=cnVudGltZQ".to_string()),
        encoded_request: None,
    };
    // 944300 is tagged `paranoia-level/3`.
    let fired = fired_ids(&engine, &input, 3);
    assert!(
        fired.contains(&944300),
        "944300 did not fire at PL3; got {fired:?}"
    );
}

#[test]
fn crs_regression_corpus() {
    let Some(root) = crs_root() else {
        eprintln!(
            "crs_regression: no CRS clone found; skipping (set CRS_DIR to run)"
        );
        return;
    };
    let rules_dir = root.join("rules");
    let tests_root = root.join("tests/regression/tests");
    let engine = compile_full_set(&rules_dir);
    let combined = combined_source(&rules_dir);
    let levels = paranoia_levels(&combined);

    let mut yaml_files: Vec<PathBuf> = Vec::new();
    for group in fs::read_dir(&tests_root).expect("read regression tests") {
        let group = group.expect("dir entry").path();
        if !group.is_dir() {
            continue;
        }
        for entry in fs::read_dir(&group).expect("read test group") {
            let path = entry.expect("entry").path();
            if path.extension().is_some_and(|ext| ext == "yaml") {
                yaml_files.push(path);
            }
        }
    }
    yaml_files.sort();

    let mut total = 0usize;
    let mut checked = 0usize;
    let mut passed = 0usize;
    let mut failed: Vec<String> = Vec::new();
    let mut failed_by_expect: BTreeMap<String, usize> = BTreeMap::new();
    let mut skipped_raw = 0usize;
    let mut skipped_multistage = 0usize;
    let mut status_only = 0usize;
    let mut unchecked = 0usize;

    for file in &yaml_files {
        let name = file
            .file_name()
            .map(|n| n.to_string_lossy().to_string())
            .unwrap_or_default();
        let Ok(source) = fs::read_to_string(file) else {
            continue;
        };
        let Ok(parsed) = serde_yaml::from_str::<TestFile>(&source) else {
            eprintln!("crs_regression: unparsable {name}");
            continue;
        };
        for case in parsed.tests {
            total += 1;
            if case.stages.len() != 1 {
                skipped_multistage += 1;
                continue;
            }
            let stage = &case.stages[0];
            if stage.input.encoded_request.is_some() {
                skipped_raw += 1;
                continue;
            }

            let expected: Vec<u64> = stage
                .output
                .log
                .as_ref()
                .and_then(|log| log.expect_ids.clone())
                .unwrap_or_default();
            let forbidden: Vec<u64> = stage
                .output
                .log
                .as_ref()
                .and_then(|log| log.no_expect_ids.clone())
                .unwrap_or_default();
            let contains: Vec<u64> = stage
                .output
                .log_contains
                .as_deref()
                .and_then(extract_id)
                .into_iter()
                .collect();

            // Expected rules carry their paranoia level; run at that level.
            let level = expected
                .iter()
                .chain(contains.iter())
                .filter_map(|id| levels.get(id).copied())
                .max()
                .unwrap_or(1);
            let fired = fired_ids(&engine, &stage.input, level);

            if expected.is_empty()
                && forbidden.is_empty()
                && contains.is_empty()
            {
                if stage.output.status.is_some() {
                    status_only += 1;
                } else {
                    unchecked += 1;
                }
                continue;
            }
            checked += 1;
            let mut ok = true;
            for id in expected.iter().chain(contains.iter()) {
                if !fired.contains(id) {
                    ok = false;
                }
            }
            for id in &forbidden {
                if fired.contains(id) {
                    ok = false;
                }
            }
            if ok {
                passed += 1;
            } else {
                let test_id = case
                    .test_id
                    .as_ref()
                    .map(scalar)
                    .unwrap_or_else(|| "?".to_string());
                let expected_key = if !expected.is_empty() {
                    format!("expect {expected:?}")
                } else if !contains.is_empty() {
                    format!("contains {contains:?}")
                } else {
                    format!("forbid {forbidden:?}")
                };
                *failed_by_expect.entry(expected_key).or_default() += 1;
                let fired_sorted: Vec<u64> = fired.iter().copied().collect();
                failed.push(format!(
                    "{name} test {test_id}: expected={expected:?} contains={contains:?} forbidden={forbidden:?} fired={fired_sorted:?}"
                ));
            }
        }
    }

    eprintln!("=== CRS behavioural regression (full set, in-process) ===");
    let mut histogram: Vec<(String, usize)> =
        failed_by_expect.into_iter().collect();
    histogram.sort_by(|a, b| b.1.cmp(&a.1));
    for (key, count) in histogram.iter().take(15) {
        eprintln!("  fails {count:5}  {key}");
    }
    for line in failed.iter().take(10) {
        eprintln!("  FAIL {line}");
    }
    eprintln!(
        "regression: files={} tests={total} checked={checked} passed={passed} failed={} skipped_raw={skipped_raw} skipped_multistage={skipped_multistage} status_only={status_only} unchecked={unchecked}",
        yaml_files.len(),
        failed.len()
    );

    // Ratchet: raise only when the baseline genuinely improves.
    assert!(
        passed >= 3317,
        "CRS regression regressed: {passed} passed (baseline 3317)"
    );
}
