//! SQL structural detector (Phase 6, first semantic detector).
//!
//! Signature scanning misses trivially obfuscated SQL: `un/**/ion
//! sel/**/ect` or `union%0aselect` have no literal needle to match. This
//! detector normalizes the value the way an SQL engine would see it —
//! comments stripped, whitespace collapsed — and then reasons about
//! *structure*:
//!
//! | Evidence | Tier |
//! | --- | --- |
//! | comment-obfuscated keywords (`un/**/ion`) | Block |
//! | stacked statements (`;drop`, `;exec`) | Block |
//! | dangerous functions (`into outfile`, `xp_cmdshell`, `load_file(`) | Block |
//! | attack-shaped `union select null/1/'…` | Block |
//! | time-based (`sleep(5)`, `pg_sleep(2)`, `waitfor delay '0:0:5'`) | Block |
//! | boolean tautology with quote break (`' or 1=1`) | Block |
//! | quote-context break plus any SQL keyword | Monitor |
//! | bare keywords (documentation, search phrases) | Log |
//!
//! False-positive control is explicit: plain prose that merely *mentions*
//! SQL keywords (`UNION SELECT combines the result sets…`, `SLEEP()` in a
//! manual) stays at Log tier — it can never reach Monitor/Block.

use super::super::{
    Action, AttackCategory, Confidence, Detector, DetectorId, DetectorResult,
    EvidenceSource, Finding, Severity,
};

use crate::canonical::CanonicalRequest;

/// Default maximum value length considered by the structural analysis.
pub const DEFAULT_MAX_VALUE_LEN: usize = 8 * 1024;

/// Keywords that alone mean nothing, but matter in combination.
const KEYWORDS: &[&str] = &[
    "union",
    "select",
    "insert",
    "update",
    "delete",
    "drop",
    "alter",
    "exec",
    "execute",
    "truncate",
    "sleep",
    "pg_sleep",
    "benchmark",
    "waitfor",
    "xp_cmdshell",
    "information_schema",
    "load_file",
];

/// DML/DDL keywords that turn a `;` into a stacked statement.
const STACKED_KEYWORDS: &[&str] = &[
    "select", "insert", "update", "delete", "drop", "alter", "exec", "execute",
    "truncate",
];

/// Attack-shaped UNION phrases (a bare `union select` is prose).
const UNION_ATTACKS: &[&str] = &[
    "union select null",
    "union all select null",
    "union select 1",
    "union all select 1",
    "union select '",
    "union select (",
    "union select @",
    "union select version(",
    "union select @@",
];

const DANGEROUS_FUNCTIONS: &[&str] =
    &["into outfile", "into dumpfile", "load_file(", "xp_cmdshell"];

/// Structural SQL injection detector.
#[derive(Debug, Clone, Copy)]
pub struct SqlStructuralDetector {
    max_value_len: usize,
}

impl SqlStructuralDetector {
    pub const fn new() -> Self {
        Self {
            max_value_len: DEFAULT_MAX_VALUE_LEN,
        }
    }

    pub const fn with_max_value_len(max_value_len: usize) -> Self {
        Self { max_value_len }
    }
}

impl Default for SqlStructuralDetector {
    fn default() -> Self {
        Self::new()
    }
}

/// Strip SQL comments and collapse whitespace; `true` when a comment was
/// present (`--`, `#` at a plausible comment position, `/* … */`).
fn strip_sql_comments(input: &str) -> (String, bool) {
    let bytes = input.as_bytes();
    let mut out = String::with_capacity(input.len());
    let mut had_comment = false;
    let mut i = 0;
    let mut last: Option<u8> = None;
    while i < bytes.len() {
        let b = bytes[i];
        // /* … */
        if b == b'/' && bytes.get(i + 1) == Some(&b'*') {
            had_comment = true;
            i += 2;
            while i + 1 < bytes.len()
                && !(bytes[i] == b'*' && bytes[i + 1] == b'/')
            {
                i += 1;
            }
            i = (i + 2).min(bytes.len());
            continue;
        }
        // -- to end of line
        if b == b'-' && bytes.get(i + 1) == Some(&b'-') {
            had_comment = true;
            while i < bytes.len() && bytes[i] != b'\n' {
                i += 1;
            }
            continue;
        }
        // # comment when at start / after space / digit / quote (MySQL)
        let hash_comment = b == b'#'
            && (matches!(
                last,
                None | Some(b' ') | Some(b'\t') | Some(b'\'') | Some(b'"')
            ) || last.is_some_and(|l| l.is_ascii_digit()));
        if hash_comment {
            had_comment = true;
            while i < bytes.len() && bytes[i] != b'\n' {
                i += 1;
            }
            continue;
        }
        if b.is_ascii_whitespace() {
            out.push(' ');
        } else {
            out.push(b as char);
        }
        last = Some(b);
        i += 1;
    }
    (out, had_comment)
}

/// Collapse runs of spaces into one (post-comment stripping).
fn collapse_spaces(input: &str) -> String {
    let mut out = String::with_capacity(input.len());
    let mut prev_space = false;
    for ch in input.chars() {
        if ch == ' ' {
            if !prev_space {
                out.push(' ');
            }
            prev_space = true;
        } else {
            out.push(ch);
            prev_space = false;
        }
    }
    out
}

/// Word-boundary `contains` (no regex dependency here on purpose).
fn contains_word(haystack: &str, word: &str) -> bool {
    let mut start = 0;
    while let Some(pos) = haystack[start..].find(word) {
        let absolute = start + pos;
        let before_ok = absolute == 0
            || !haystack.as_bytes()[absolute - 1].is_ascii_alphanumeric();
        let after = absolute + word.len();
        let after_ok = after >= haystack.len()
            || !haystack.as_bytes()[after].is_ascii_alphanumeric();
        if before_ok && after_ok {
            return true;
        }
        start = absolute + word.len().max(1);
    }
    false
}

/// `true` when a stacked statement follows a `;`.
fn has_stacked_statement(low: &str) -> bool {
    let Some(semicolon) = low.find(';') else {
        return false;
    };
    let tail = &low[semicolon + 1..];
    STACKED_KEYWORDS.iter().any(|kw| contains_word(tail, kw))
}

/// Number of unescaped single/double quotes (odd = unbalanced context).
fn unbalanced_quotes(value: &str) -> bool {
    let mut single = 0usize;
    let mut double = 0usize;
    let mut escaped = false;
    for b in value.bytes() {
        if escaped {
            escaped = false;
            continue;
        }
        match b {
            b'\\' => escaped = true,
            b'\'' => single += 1,
            b'"' => double += 1,
            _ => {},
        }
    }
    single % 2 == 1 || double % 2 == 1
}

/// `sleep(`, `pg_sleep(` or `benchmark(` followed by a digit before the
/// closing parenthesis; or `waitfor delay` with a time literal.
fn time_based(low: &str) -> bool {
    for func in ["sleep(", "pg_sleep(", "benchmark("] {
        let mut start = 0;
        while let Some(pos) = low[start..].find(func) {
            let after = start + pos + func.len();
            let window = &low[after..low.len().min(after + 16)];
            let digit = window
                .chars()
                .take_while(|c| *c != ')')
                .any(|c| c.is_ascii_digit() || c == '\'' || c == '"');
            if digit {
                return true;
            }
            start = after;
        }
    }
    contains_word(low, "waitfor")
        && (low.contains("delay") || low.contains("time"))
}

/// Boolean tautology with a quote break: `' or 1=1`, `" or '1'='1'`, ….
fn boolean_tautology(low: &str) -> bool {
    let shapes = [
        "' or 1=1",
        "\" or 1=1",
        "' or '1'='1",
        "\" or \"1\"=\"1",
        "or true--",
        "' or true",
    ];
    shapes.iter().any(|shape| low.contains(shape))
}

/// One evidence tier; the first matching tier wins.
struct Evidence {
    rule: &'static str,
    severity: Severity,
    action: Action,
    score: u32,
    detail: String,
}

fn analyze(value: &str) -> Option<Evidence> {
    let (stripped, had_comment) = strip_sql_comments(value);
    let low = collapse_spaces(&stripped).to_ascii_lowercase();
    let keywords: Vec<&str> = KEYWORDS
        .iter()
        .copied()
        .filter(|kw| contains_word(&low, kw))
        .collect();

    // Comment-split keywords: the marker of deliberate obfuscation.
    if had_comment
        && !keywords.is_empty()
        && value.to_ascii_lowercase().contains("/*")
    {
        return Some(Evidence {
            rule: "sem.sql.comment_obfuscation",
            severity: Severity::High,
            action: Action::Block,
            score: 30,
            detail: format!(
                "SQL keywords reconstructed after comment removal: {keywords:?}"
            ),
        });
    }
    if has_stacked_statement(&low) {
        return Some(Evidence {
            rule: "sem.sql.stacked_statement",
            severity: Severity::Critical,
            action: Action::Block,
            score: 40,
            detail: "stacked statement after `;`".to_string(),
        });
    }
    if DANGEROUS_FUNCTIONS.iter().any(|f| low.contains(f)) {
        return Some(Evidence {
            rule: "sem.sql.dangerous_function",
            severity: Severity::High,
            action: Action::Block,
            score: 40,
            detail: "file/command SQL function in value".to_string(),
        });
    }
    if UNION_ATTACKS.iter().any(|phrase| low.contains(phrase)) {
        return Some(Evidence {
            rule: "sem.sql.union_attack",
            severity: Severity::High,
            action: Action::Block,
            score: 30,
            detail: "attack-shaped UNION SELECT".to_string(),
        });
    }
    if time_based(&low) {
        return Some(Evidence {
            rule: "sem.sql.time_based",
            severity: Severity::High,
            action: Action::Block,
            score: 30,
            detail: "time-based function with a literal argument".to_string(),
        });
    }
    if boolean_tautology(&low) {
        return Some(Evidence {
            rule: "sem.sql.boolean_tautology",
            severity: Severity::High,
            action: Action::Block,
            score: 30,
            detail: "boolean tautology with quote break".to_string(),
        });
    }
    if unbalanced_quotes(value) && !keywords.is_empty() {
        return Some(Evidence {
            rule: "sem.sql.quote_break",
            severity: Severity::Medium,
            action: Action::Monitor,
            score: 15,
            detail: format!("unbalanced quote with SQL keywords {keywords:?}"),
        });
    }
    if !keywords.is_empty() {
        return Some(Evidence {
            rule: "sem.sql.keywords",
            severity: Severity::Low,
            action: Action::Log,
            score: 5,
            detail: format!("SQL keywords in value: {keywords:?}"),
        });
    }
    None
}

impl Detector for SqlStructuralDetector {
    fn id(&self) -> DetectorId {
        DetectorId("semantic.sql.structural")
    }

    fn inspect(
        &self,
        request: &CanonicalRequest,
        ctx: &mut super::super::DetectionContext,
    ) -> DetectorResult {
        let mut findings: Vec<Finding> = Vec::new();
        let mut degraded = None;

        let scan = |value: &str,
                    source: EvidenceSource,
                    field: Option<&str>,
                    findings: &mut Vec<Finding>,
                    degraded: &mut Option<&'static str>| {
            if value.len() > self.max_value_len {
                if degraded.is_none() {
                    *degraded = Some("value exceeds semantic budget");
                }
                return;
            }
            let Some(evidence) = analyze(value) else {
                return;
            };
            let mut finding = Finding::new(
                DetectorId("semantic.sql.structural"),
                evidence.rule,
                AttackCategory::SqlInjection,
            )
            .confidence(match evidence.action {
                Action::Block => Confidence::High,
                Action::Monitor => Confidence::Medium,
                _ => Confidence::Low,
            })
            .severity(evidence.severity)
            .score(evidence.score)
            .action(evidence.action)
            .source(source)
            .detail(evidence.detail);
            if let Some(field) = field {
                finding = finding.field(field.to_string());
            }
            findings.push(finding);
        };

        for param in request.query() {
            scan(
                &param.value,
                EvidenceSource::Query,
                Some(&param.name),
                &mut findings,
                &mut degraded,
            );
        }
        for (name, value) in request.cookies() {
            scan(
                value,
                EvidenceSource::Cookie,
                Some(name),
                &mut findings,
                &mut degraded,
            );
        }
        if let Some(body) = request.body() {
            let limit = ctx.budget().max_body_bytes.min(body.len());
            match std::str::from_utf8(&body[..limit]) {
                Ok(text) => {
                    scan(
                        text,
                        EvidenceSource::Body,
                        None,
                        &mut findings,
                        &mut degraded,
                    );
                    if body.len() > limit && degraded.is_none() {
                        degraded = Some("body scan truncated at budget");
                    }
                },
                Err(_) => {
                    if degraded.is_none() {
                        degraded = Some("body is not valid utf-8");
                    }
                },
            }
        }

        DetectorResult { findings, degraded }
    }
}

#[cfg(test)]
mod tests {
    use super::SqlStructuralDetector;
    use crate::canonical::{Canonicalizer, RequestParts};
    use crate::pipeline::{Action, AttackCategory, DetectionContext, Detector};

    fn query(value: &str) -> crate::pipeline::DetectorResult {
        let target = format!("/?q={value}");
        let request = Canonicalizer::default().canonicalize(RequestParts::new(
            "GET",
            "example.com",
            target,
        ));
        let detector = SqlStructuralDetector::new();
        let mut ctx = DetectionContext::new();
        detector.inspect(&request, &mut ctx)
    }

    fn tier(value: &str) -> Option<(String, Action)> {
        let result = query(value);
        result
            .findings
            .first()
            .map(|f| (f.rule_id.to_string(), f.action_hint))
    }

    #[test]
    fn comment_split_keywords_block_as_obfuscation() {
        let (rule, action) =
            tier("1 un/**/ion sel/**/ect null").expect("finding");
        assert_eq!(rule, "sem.sql.comment_obfuscation");
        assert_eq!(action, Action::Block);
    }

    #[test]
    fn newline_split_keywords_are_still_structured() {
        // The signature scanner cannot match `union\nselect`; the structural
        // detector collapses whitespace first.
        let (rule, action) = tier("1 union\nselect\nnull").expect("finding");
        assert_eq!(rule, "sem.sql.union_attack");
        assert_eq!(action, Action::Block);
    }

    #[test]
    fn stacked_statement_blocks() {
        let (rule, action) = tier("1;drop table users").expect("finding");
        assert_eq!(rule, "sem.sql.stacked_statement");
        assert_eq!(action, Action::Block);
    }

    #[test]
    fn dangerous_functions_block() {
        for payload in ["1 into outfile '/tmp/x'", "1;xp_cmdshell('id')"] {
            let (_, action) = tier(payload).expect("finding");
            assert_eq!(action, Action::Block, "{payload}");
        }
    }

    #[test]
    fn time_based_shapes_block() {
        for payload in [
            "1 and sleep(5)",
            "1 or pg_sleep(2)",
            "1;waitfor delay '0:0:5'--",
        ] {
            let (_, action) = tier(payload).expect("finding");
            assert_eq!(action, Action::Block, "{payload}");
        }
    }

    #[test]
    fn boolean_tautology_blocks() {
        let (rule, action) = tier("1' or 1=1--").expect("finding");
        assert_eq!(rule, "sem.sql.boolean_tautology");
        assert_eq!(action, Action::Block);
    }

    #[test]
    fn quote_break_with_keyword_monitors() {
        let (rule, action) = tier("name' and select").expect("finding");
        assert_eq!(rule, "sem.sql.quote_break");
        assert_eq!(action, Action::Monitor);
    }

    #[test]
    fn prose_stays_weak() {
        // Documentation and search phrases must never reach Monitor.
        let cases = [
            "UNION SELECT combines the result sets of two queries.",
            "UNION SELECT merges the result sets; duplicates are removed.",
            "The SLEEP() function pauses execution for the given seconds.",
            "SELECT id, name FROM users WHERE active = 1 ORDER BY name;",
            "How do I SELECT multiple columns in SQL?",
        ];
        for case in cases {
            match tier(case) {
                Some((_, action)) => {
                    assert!(
                        action < Action::Monitor,
                        "{case:?} reached {action}"
                    );
                },
                None => {},
            }
        }
    }

    #[test]
    fn category_is_sql_injection() {
        let result = query("1 un/**/ion sel/**/ect null");
        assert_eq!(result.findings[0].category, AttackCategory::SqlInjection);
    }

    #[test]
    fn oversized_values_degrade() {
        let detector = SqlStructuralDetector::with_max_value_len(16);
        let target = format!("/?q={}", "select ".repeat(10));
        let request = Canonicalizer::default().canonicalize(RequestParts::new(
            "GET",
            "example.com",
            target,
        ));
        let mut ctx = DetectionContext::new();
        let result = detector.inspect(&request, &mut ctx);
        assert!(result.findings.is_empty());
        assert_eq!(result.degraded, Some("value exceeds semantic budget"));
    }

    #[test]
    fn clean_values_produce_nothing() {
        for value in ["hello world", "id=42", "price=19.99", "café au lait"] {
            assert!(tier(value).is_none(), "{value}");
        }
    }
}
