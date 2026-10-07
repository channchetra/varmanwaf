//! OWASP CRS conformance harness.
//!
//! Loads the official Core Rule Set from a local clone and records, per file,
//! how many `SecRule`s compile with the Varman SecLang engine. Results are
//! printed with `-- --nocapture` and ratcheted in `docs/compatibility.md`.
//!
//! The harness looks for the clone at `CRS_DIR` (or the default sibling path
//! `../../references/coreruleset`). When no clone is present the test skips,
//! so builds without the reference checkout stay green.

use std::fs;
use std::path::{Path, PathBuf};

fn crs_rules_dir() -> Option<PathBuf> {
    let candidates: Vec<PathBuf> = match std::env::var_os("CRS_DIR") {
        Some(dir) => vec![PathBuf::from(dir)],
        None => {
            let manifest = Path::new(env!("CARGO_MANIFEST_DIR"));
            vec![manifest.join("../../references/coreruleset")]
        },
    };
    candidates.into_iter().find_map(|root| {
        let rules = root.join("rules");
        rules.is_dir().then_some(rules)
    })
}

/// Count rule statements (`SecRule …`) in a CRS file, skipping comments and
/// the `SecRuleRemoveById`/`SecRuleUpdateTargetById` directives.
fn count_secrules(source: &str) -> usize {
    source
        .lines()
        .filter_map(|line| line.trim_start().strip_prefix("SecRule"))
        .filter(|rest| rest.starts_with(char::is_whitespace))
        .count()
}

#[test]
fn crs_rulesets_load_and_report() {
    let Some(rules_dir) = crs_rules_dir() else {
        eprintln!("crs_conformance: no CRS clone found; skipping (set CRS_DIR to run)");
        return;
    };

    let mut files: Vec<PathBuf> = fs::read_dir(&rules_dir)
        .expect("read CRS rules directory")
        .filter_map(|entry| entry.ok().map(|entry| entry.path()))
        .filter(|path| {
            let name = path.file_name().and_then(|n| n.to_str()).unwrap_or("");
            name.ends_with(".conf") && !name.ends_with(".example")
        })
        .collect();
    files.sort();

    let mut ok_files: Vec<(String, usize)> = Vec::new();
    let mut failures: Vec<(String, String)> = Vec::new();
    let mut rules_loaded = 0usize;

    for path in &files {
        let name = path
            .file_name()
            .map(|n| n.to_string_lossy().to_string())
            .unwrap_or_default();
        let source = fs::read_to_string(path).expect("read CRS rule file");
        let expected = count_secrules(&source);
        match varman_waf::seclang::ruleset::SecRuleSet::from_source_with_base(
            &source,
            Some(&rules_dir),
        ) {
            Ok(_) => {
                rules_loaded += expected;
                ok_files.push((name, expected));
            },
            Err(error) => failures.push((name, error.reason)),
        }
    }

    eprintln!("=== CRS conformance: ruleset load ===");
    for (name, rules) in &ok_files {
        eprintln!("  OK   {name}: {rules} rules");
    }
    for (name, reason) in &failures {
        eprintln!("  FAIL {name}: {reason}");
    }
    eprintln!(
        "summary: files_ok={} files_err={} rules_loaded={} total_files={}",
        ok_files.len(),
        failures.len(),
        rules_loaded,
        files.len()
    );

    // Full-set pass: CRS is normally loaded as one configuration, so
    // cross-file `skipAfter` markers (e.g. 950 → 959) can only resolve here.
    let mut combined = String::new();
    for path in &files {
        match fs::read(path) {
            Ok(bytes) => {
                combined.push_str(&String::from_utf8_lossy(&bytes));
                combined.push('\n');
            },
            Err(error) => {
                eprintln!(
                    "full-set: could not read {}: {error}",
                    path.display()
                );
                return;
            },
        }
    }
    let combined_rules = count_secrules(&combined);
    match varman_waf::seclang::ruleset::SecRuleSet::from_source_with_base(
        &combined,
        Some(&rules_dir),
    ) {
        Ok(_) => eprintln!(
            "full-set: OK ({combined_rules} rule statements across {} files)",
            files.len()
        ),
        Err(error) => eprintln!(
            "full-set: FAIL ({combined_rules} rule statements): {}",
            error.reason
        ),
    }

    assert!(
        !files.is_empty(),
        "CRS clone at {} has no rule files",
        rules_dir.display()
    );
    // Ratchet: never regress below the recorded baseline
    // (`docs/compatibility.md`, 2026-10-07: 26 files / 678 rules with a clean
    // clone via `CRS_DIR`; 25 / 643 when the Windows host has quarantined
    // `web-shells-php.data`). The conservative floor passes on both.
    assert!(
        ok_files.len() >= 25,
        "CRS load regressed: {} files (baseline 25)",
        ok_files.len()
    );
    assert!(
        rules_loaded >= 643,
        "CRS load regressed: {rules_loaded} rules (baseline 643)"
    );
}
