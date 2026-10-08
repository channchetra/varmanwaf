//! Dialect-aware SQL AST detector: the second SQL tier.
//!
//! The structural tier (`sql.rs`) is lexical: it scores shapes and keywords
//! without understanding them. This tier parses candidate values with a real
//! SQL parser (`sqlparser`) and flags constructs that only make sense as an
//! injection:
//!
//! - **stacked statements** — more than one statement in a single value;
//! - **set operations** — `UNION`/`EXCEPT`/`INTERSECT` queries;
//! - **tautologies** — literal comparisons that are trivially true
//!   (`1 = 1`, `'a' = 'a'`) inside a boolean expression;
//! - **DML/DDL** — `INSERT`/`UPDATE`/`DELETE`/`DROP`/`ALTER`/`CREATE`/
//!   `TRUNCATE` statements;
//! - **raw queries** — a value that parses cleanly as a `SELECT` is recorded
//!   at log level (documentation and admin tooling send complete queries as
//!   input, so it is evidence, never an alert on its own).
//!
//! Values that do not parse as SQL are ignored: this tier adds precision, it
//! never guesses. Parsing is attempted only for values that look SQL-ish,
//! across a small dialect set (generic, MySQL, PostgreSQL, SQLite), under
//! the pipeline's per-value budget.

use sqlparser::ast::{BinaryOperator, Expr, SetExpr, Statement, Value};
use sqlparser::dialect::{
    Dialect, GenericDialect, MySqlDialect, PostgreSqlDialect, SQLiteDialect,
};
use sqlparser::parser::Parser;

use super::super::{
    Action, AttackCategory, Confidence, Detector, DetectorId, DetectorResult,
    EvidenceSource, Finding, Severity,
};

/// Only values that mention a SQL keyword are parsed at all.
const SQL_HINTS: &[&str] = &[
    "select",
    "union",
    "insert",
    "update",
    "delete",
    "drop",
    "alter",
    "create",
    "truncate",
    "exec",
    "where",
    "from",
    " or ",
    " and ",
    "information_schema",
    "1=1",
    "'='",
];

/// A parsed-and-dangerous construct.
struct AstEvidence {
    rule: &'static str,
    score: u32,
    action: Action,
    severity: Severity,
    detail: String,
}

/// Dialect-aware SQL AST detector.
pub struct SqlAstDetector {
    /// Values longer than this are not parsed.
    max_value_len: usize,
}

impl Default for SqlAstDetector {
    fn default() -> Self {
        Self::new()
    }
}

impl SqlAstDetector {
    pub fn new() -> Self {
        Self {
            max_value_len: 4096,
        }
    }
}

impl Detector for SqlAstDetector {
    fn id(&self) -> DetectorId {
        DetectorId("semantic.sql.ast")
    }

    fn inspect(
        &self,
        request: &super::super::super::canonical::CanonicalRequest,
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
                    *degraded = Some("value exceeds AST parse budget");
                }
                return;
            }
            let Some(evidence) = analyze(value) else {
                return;
            };
            let mut finding = Finding::new(
                DetectorId("semantic.sql.ast"),
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

/// Parse `value` across the dialect set and return the first dangerous
/// construct found. `None` when it does not parse as SQL or parses cleanly.
fn analyze(value: &str) -> Option<AstEvidence> {
    if value.len() < 8 {
        return None;
    }
    let lower = value.to_ascii_lowercase();
    if !SQL_HINTS.iter().any(|hint| lower.contains(hint)) {
        return None;
    }
    // 1. The value may be a complete statement (`DELETE FROM ...`).
    if let Some(evidence) = parse_across_dialects(value, true) {
        return Some(evidence);
    }
    // 2. Otherwise treat it as a clause fragment: an injection is a fragment
    //    of the application's query, so wrapping it into a statement is what
    //    lets real SQL constructs surface. The unquoted templates catch
    //    expressions and stacked statements, the quoted one balances
    //    fragments that carry a trailing quote (`1' OR '1'='1`). A clean
    //    fragment produces nothing - only raw statements may report
    //    `ast.raw_query`.
    for template in [
        "SELECT 1 WHERE {value}",
        "SELECT 1 WHERE id = {value}",
        "SELECT 1 WHERE id = '{value}'",
    ] {
        let wrapped = template.replace("{value}", value);
        if let Some(evidence) = parse_across_dialects(&wrapped, false) {
            return Some(evidence);
        }
    }
    None
}

/// Try every dialect; the first one that parses decides, because a value that
/// is valid SQL in any dialect is SQL.
fn parse_across_dialects(source: &str, raw: bool) -> Option<AstEvidence> {
    let dialects: [&dyn Dialect; 4] = [
        &GenericDialect {},
        &MySqlDialect {},
        &PostgreSqlDialect {},
        &SQLiteDialect {},
    ];
    for dialect in dialects {
        let Ok(statements) = Parser::parse_sql(dialect, source) else {
            continue;
        };
        if statements.is_empty() {
            continue;
        }
        return inspect_statements(&statements, raw);
    }
    None
}

fn evidence(
    rule: &'static str,
    score: u32,
    action: Action,
    severity: Severity,
    detail: impl Into<String>,
) -> AstEvidence {
    AstEvidence {
        rule,
        score,
        action,
        severity,
        detail: detail.into(),
    }
}

fn inspect_statements(
    statements: &[Statement],
    raw: bool,
) -> Option<AstEvidence> {
    if statements.len() > 1 {
        return Some(evidence(
            "ast.stacked_statements",
            40,
            Action::Block,
            Severity::Critical,
            format!("value contains {} SQL statements", statements.len()),
        ));
    }
    match statements.first()? {
        Statement::Query(query) => {
            if let Some(evidence) = inspect_set(&query.body) {
                return Some(evidence);
            }
            // Only a value that parses as a statement on its own is worth a
            // `raw_query` note; inside a template every value parses. It is
            // recorded at log level: documentation and admin tooling send
            // complete queries as input, so this is evidence, not an attack.
            raw.then(|| {
                evidence(
                    "ast.raw_query",
                    5,
                    Action::Log,
                    Severity::Low,
                    "value parses as a SQL query",
                )
            })
        },
        Statement::Insert(_)
        | Statement::Update { .. }
        | Statement::Delete(_)
        | Statement::Drop { .. }
        | Statement::AlterTable { .. }
        | Statement::CreateTable(_)
        | Statement::Truncate { .. } => Some(evidence(
            "ast.dml_statement",
            40,
            Action::Block,
            Severity::Critical,
            "value parses as a data-modifying SQL statement",
        )),
        _ => None,
    }
}

fn inspect_set(body: &SetExpr) -> Option<AstEvidence> {
    match body {
        SetExpr::SetOperation { left, right, .. } => {
            if let Some(evidence) = inspect_set(left) {
                return Some(evidence);
            }
            if let Some(evidence) = inspect_set(right) {
                return Some(evidence);
            }
            Some(evidence(
                "ast.set_operation",
                35,
                Action::Block,
                Severity::High,
                "value contains a UNION/EXCEPT/INTERSECT query",
            ))
        },
        SetExpr::Query(inner) => inspect_set(&inner.body),
        SetExpr::Select(select) => {
            let selection = select.selection.as_ref()?;
            expr_tautology(selection).then(|| {
                evidence(
                    "ast.tautology",
                    35,
                    Action::Block,
                    Severity::High,
                    "value contains a tautological predicate",
                )
            })
        },
        _ => None,
    }
}

/// Whether a boolean expression contains a trivially true literal
/// comparison (`1 = 1`, `'a' = 'a'`, `1 <> 2`) anywhere in its tree.
fn expr_tautology(expr: &Expr) -> bool {
    match expr {
        Expr::BinaryOp { left, op, right } => match op {
            BinaryOperator::Eq => {
                literal_text(left) == literal_text(right)
                    && literal_text(left).is_some()
            },
            BinaryOperator::NotEq => {
                literal_text(left).is_some()
                    && literal_text(right).is_some()
                    && literal_text(left) != literal_text(right)
            },
            BinaryOperator::And | BinaryOperator::Or => {
                expr_tautology(left) || expr_tautology(right)
            },
            _ => false,
        },
        Expr::Nested(inner) => expr_tautology(inner),
        _ => false,
    }
}

/// The SQL text of a literal expression, when the expression is a literal.
fn literal_text(expr: &Expr) -> Option<String> {
    match expr {
        Expr::Value(value) => Some(match &**value {
            Value::Number(number, _) => number.clone(),
            Value::SingleQuotedString(text) => text.clone(),
            Value::DoubleQuotedString(text) => text.clone(),
            other => other.to_string(),
        }),
        Expr::Nested(inner) => literal_text(inner),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::{analyze, SqlAstDetector};
    use crate::canonical::{Canonicalizer, RequestParts};
    use crate::pipeline::{Action, DetectionContext, Detector};

    fn query(value: &str) -> crate::pipeline::DetectorResult {
        let target = format!("/?q={value}");
        let request = Canonicalizer::default().canonicalize(RequestParts::new(
            "GET",
            "example.com",
            target,
        ));
        let detector = SqlAstDetector::new();
        let mut ctx = DetectionContext::new();
        detector.inspect(&request, &mut ctx)
    }

    #[test]
    fn stacked_statements_block() {
        let evidence = analyze("1; DROP TABLE users --").expect("evidence");
        assert_eq!(evidence.rule, "ast.stacked_statements");
        assert_eq!(evidence.action, Action::Block);
    }

    #[test]
    fn union_queries_block() {
        let evidence = analyze("1 UNION SELECT username, password FROM users")
            .expect("evidence");
        assert_eq!(evidence.rule, "ast.set_operation");
    }

    #[test]
    fn tautologies_block() {
        let evidence = analyze("1' OR '1'='1").expect("evidence");
        assert_eq!(evidence.rule, "ast.tautology");
        let evidence = analyze("id = 5 OR 7 <> 8").expect("evidence");
        assert_eq!(evidence.rule, "ast.tautology");
    }

    #[test]
    fn dml_statements_block() {
        let evidence = analyze("DELETE FROM sessions WHERE user_id = 1")
            .expect("evidence");
        assert_eq!(evidence.rule, "ast.dml_statement");
    }

    #[test]
    fn raw_selects_are_recorded_at_log_level() {
        let evidence = analyze("SELECT name, price FROM products WHERE id = 3")
            .expect("evidence");
        assert_eq!(evidence.rule, "ast.raw_query");
        assert_eq!(evidence.action, Action::Log);
    }

    #[test]
    fn benign_and_unparseable_values_are_ignored() {
        assert!(analyze("hello world").is_none());
        assert!(
            analyze("this is a normal sentence with the word select").is_none()
        );
        assert!(analyze("search for blue shoes").is_none());
        // A plain integer or short token is below the parse threshold.
        assert!(analyze("1=1").is_none());
    }

    #[test]
    fn detector_flags_query_parameters() {
        let result = query("1%20UNION%20SELECT%20password%20FROM%20users");
        assert!(
            result
                .findings
                .iter()
                .any(|finding| finding.rule_id == "ast.set_operation"),
            "findings: {:?}",
            result.findings
        );
    }
}
