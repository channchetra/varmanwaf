//! SecLang line parser (Phase 7 skeleton).
//!
//! Parses one `SecRule` line into a structured [`SecRuleLine`]. Comments
//! (`#…`) and blank lines yield [`SecLangLine::Ignored`]. Malformed rules and
//! unsupported directives yield [`SecLangError`] — observability is a hard
//! requirement: an unsupported directive must never silently disappear.
//!
//! The tokenizer respects quoting: variables are bare, the operator and the
//! actions are double-quoted strings whose contents may contain spaces,
//! commas and regex syntax.

use std::fmt;

/// One parsed line of a SecLang file.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SecLangLine {
    /// Blank line or comment.
    Ignored,
    /// A parsed `SecRule`.
    Rule(SecRuleLine),
}

/// A parsed `SecRule` directive.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SecRuleLine {
    /// Pipe-separated variable list, e.g. `ARGS:id|REQUEST_HEADERS:Host`.
    pub variables: Vec<String>,
    pub operator: SecOperator,
    /// Raw action list, order preserved.
    pub actions: Vec<String>,
}

/// Detection operator with its argument.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SecOperator {
    Rx(String),
    Pm(Vec<String>),
    Contains(String),
    Streq(String),
    BeginsWith(String),
    EndsWith(String),
    DetectSqli,
    DetectXss,
    IpMatch(Vec<String>),
}

impl SecOperator {
    /// Operator name including `@`, for diagnostics.
    pub const fn name(&self) -> &'static str {
        match self {
            Self::Rx(_) => "@rx",
            Self::Pm(_) => "@pm",
            Self::Contains(_) => "@contains",
            Self::Streq(_) => "@streq",
            Self::BeginsWith(_) => "@beginsWith",
            Self::EndsWith(_) => "@endsWith",
            Self::DetectSqli => "@detectSQLi",
            Self::DetectXss => "@detectXSS",
            Self::IpMatch(_) => "@ipMatch",
        }
    }
}

/// Parse failure with a human-readable reason.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SecLangError {
    pub reason: String,
}

impl fmt::Display for SecLangError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "seclang: {}", self.reason)
    }
}

impl std::error::Error for SecLangError {}

fn err(reason: impl Into<String>) -> SecLangError {
    SecLangError {
        reason: reason.into(),
    }
}

/// Split a quoted field starting at `input[start] == '"'`; returns the inner
/// text and the index just past the closing quote. Backslash escapes `\"`.
fn parse_quoted(
    input: &str,
    start: usize,
) -> Result<(String, usize), SecLangError> {
    let bytes = input.as_bytes();
    if bytes.get(start) != Some(&b'"') {
        return Err(err(format!("expected '\"' at byte {start}")));
    }
    let mut out = String::new();
    let mut i = start + 1;
    while i < bytes.len() {
        match bytes[i] {
            b'\\' if bytes.get(i + 1) == Some(&b'"') => {
                out.push('"');
                i += 2;
            },
            b'"' => return Ok((out, i + 1)),
            _ => {
                let ch = input[i..]
                    .chars()
                    .next()
                    .ok_or_else(|| err("unexpected end of input"))?;
                out.push(ch);
                i += ch.len_utf8();
            },
        }
    }
    Err(err("unterminated quoted string"))
}

/// Split an actions string on commas that are outside quotes.
fn split_actions(input: &str) -> Vec<String> {
    let mut actions = Vec::new();
    let mut current = String::new();
    let mut in_double = false;
    let mut in_single = false;
    let mut escaped = false;
    for ch in input.chars() {
        if escaped {
            current.push(ch);
            escaped = false;
            continue;
        }
        match ch {
            '\\' => {
                current.push(ch);
                escaped = true;
            },
            '"' if !in_single => {
                in_double = !in_double;
                current.push(ch);
            },
            '\'' if !in_double => {
                in_single = !in_single;
                current.push(ch);
            },
            ',' if !in_double && !in_single => {
                let trimmed = current.trim();
                if !trimmed.is_empty() {
                    actions.push(trimmed.to_string());
                }
                current.clear();
            },
            _ => current.push(ch),
        }
    }
    let trimmed = current.trim();
    if !trimmed.is_empty() {
        actions.push(trimmed.to_string());
    }
    actions
}

fn parse_operator(raw: &str) -> Result<SecOperator, SecLangError> {
    let trimmed = raw.trim();
    if !trimmed.starts_with('@') {
        // ModSecurity allows a bare pattern meaning `@rx`.
        return Ok(SecOperator::Rx(trimmed.to_string()));
    }
    let (name, argument) = match trimmed.split_once(' ') {
        Some((name, argument)) => (name, argument.trim()),
        None => (trimmed, ""),
    };
    let operator = match name {
        "@rx" => SecOperator::Rx(argument.to_string()),
        "@pm" | "@pmFromFile" => SecOperator::Pm(
            argument.split_whitespace().map(str::to_string).collect(),
        ),
        "@contains" => SecOperator::Contains(argument.to_string()),
        "@streq" => SecOperator::Streq(argument.to_string()),
        "@beginsWith" => SecOperator::BeginsWith(argument.to_string()),
        "@endsWith" => SecOperator::EndsWith(argument.to_string()),
        "@detectSQLi" => SecOperator::DetectSqli,
        "@detectXSS" => SecOperator::DetectXss,
        "@ipMatch" => SecOperator::IpMatch(
            argument
                .split(',')
                .map(|entry| entry.trim().to_string())
                .filter(|entry| !entry.is_empty())
                .collect(),
        ),
        other => {
            return Err(err(format!("unsupported operator {other}")));
        },
    };
    Ok(operator)
}

/// Parse one line of a SecLang configuration.
pub fn parse_line(input: &str) -> Result<SecLangLine, SecLangError> {
    let trimmed = input.trim();
    if trimmed.is_empty() || trimmed.starts_with('#') {
        return Ok(SecLangLine::Ignored);
    }

    // Directives other than SecRule/SecAction are not supported yet and must
    // stay observable rather than being skipped.
    if !trimmed.starts_with("SecRule") {
        let directive = trimmed.split_whitespace().next().unwrap_or("");
        return Err(err(format!("unsupported directive {directive:?}")));
    }
    let rest = trimmed.trim_start_matches("SecRule");

    // variables up to the first quote
    let Some(quote_at) = rest.find('"') else {
        return Err(err("SecRule without a quoted operator"));
    };
    let variables_raw = rest[..quote_at].trim();
    if variables_raw.is_empty() {
        return Err(err("SecRule without variables"));
    }
    if variables_raw.contains(char::is_whitespace) {
        return Err(err(
            "SecRule variables must not contain whitespace (quote the operator)",
        ));
    }
    let variables = variables_raw
        .split('|')
        .map(str::to_string)
        .collect::<Vec<_>>();

    let (operator_raw, after_operator) = parse_quoted(rest, quote_at)?;
    let operator = parse_operator(&operator_raw)?;

    let actions_tail = rest[after_operator..].trim_start();
    let actions = if actions_tail.is_empty() {
        Vec::new()
    } else {
        let (actions_raw, _) = parse_quoted(actions_tail, 0)?;
        split_actions(&actions_raw)
    };

    Ok(SecLangLine::Rule(SecRuleLine {
        variables,
        operator,
        actions,
    }))
}

#[cfg(test)]
mod tests {
    use super::{parse_line, SecLangError, SecLangLine, SecOperator};

    fn rule(line: &str) -> super::SecRuleLine {
        match parse_line(line).expect("parses") {
            SecLangLine::Rule(rule) => rule,
            SecLangLine::Ignored => panic!("expected a rule"),
        }
    }

    fn error(line: &str) -> SecLangError {
        parse_line(line).expect_err("must fail")
    }

    #[test]
    fn parses_a_typical_crs_style_rule() {
        let parsed = rule(
            "SecRule ARGS:id \"@rx ^[0-9]+$\" \"id:900100,phase:1,block,msg:'id must be numeric',severity:'CRITICAL',tag:'custom/api'\"",
        );
        assert_eq!(parsed.variables, vec!["ARGS:id"]);
        assert_eq!(parsed.operator, SecOperator::Rx("^[0-9]+$".into()));
        assert_eq!(parsed.actions.len(), 6);
        assert_eq!(parsed.actions[0], "id:900100");
        assert_eq!(parsed.actions[1], "phase:1");
        assert_eq!(parsed.actions[2], "block");
        assert_eq!(parsed.actions[5], "tag:'custom/api'");
    }

    #[test]
    fn parses_pipe_separated_variables() {
        let parsed = rule(
            "SecRule ARGS|ARGS_NAMES|REQUEST_HEADERS:Host \"@contains evil\" \"id:1,log\"",
        );
        assert_eq!(
            parsed.variables,
            vec!["ARGS", "ARGS_NAMES", "REQUEST_HEADERS:Host"]
        );
    }

    #[test]
    fn parses_every_supported_operator() {
        let cases = [
            ("@rx ab+c", SecOperator::Rx("ab+c".into())),
            (
                "@pm alpha beta",
                SecOperator::Pm(vec!["alpha".into(), "beta".into()]),
            ),
            ("@contains needle", SecOperator::Contains("needle".into())),
            ("@streq exact", SecOperator::Streq("exact".into())),
            ("@beginsWith head", SecOperator::BeginsWith("head".into())),
            ("@endsWith tail", SecOperator::EndsWith("tail".into())),
            ("@detectSQLi", SecOperator::DetectSqli),
            ("@detectXSS", SecOperator::DetectXss),
            (
                "@ipMatch 10.0.0.0/8, 192.168.0.0/16",
                SecOperator::IpMatch(vec![
                    "10.0.0.0/8".into(),
                    "192.168.0.0/16".into(),
                ]),
            ),
            // A bare pattern means @rx, as in ModSecurity.
            ("plain.*pattern", SecOperator::Rx("plain.*pattern".into())),
        ];
        for (operator, expected) in cases {
            let parsed = rule(&format!("SecRule ARGS \"{operator}\" \"id:2\""));
            assert_eq!(parsed.operator, expected, "{operator}");
        }
    }

    #[test]
    fn quoted_commas_do_not_split_actions() {
        let parsed =
            rule("SecRule ARGS \"@rx x\" \"id:3,msg:'a, b and c',tag:'x,y'\"");
        assert_eq!(parsed.actions.len(), 3);
        assert_eq!(parsed.actions[1], "msg:'a, b and c'");
        assert_eq!(parsed.actions[2], "tag:'x,y'");
    }

    #[test]
    fn comments_and_blanks_are_ignored() {
        assert_eq!(parse_line("").expect("ok"), SecLangLine::Ignored);
        assert_eq!(parse_line("   ").expect("ok"), SecLangLine::Ignored);
        assert_eq!(
            parse_line("# SecRule ARGS \"@rx x\" \"id:1\"").expect("ok"),
            SecLangLine::Ignored
        );
    }

    #[test]
    fn unsupported_directives_error_observably() {
        let e = error("SecAction \"id:1,phase:1\"");
        assert!(e.reason.contains("unsupported directive"), "{e}");
        let e = error("SecDefaultAction \"phase:1,pass\"");
        assert!(e.reason.contains("unsupported directive"), "{e}");
    }

    #[test]
    fn unsupported_operators_error_observably() {
        let e = error("SecRule ARGS \"@weirdOperator x\" \"id:4\"");
        assert!(e.reason.contains("unsupported operator"), "{e}");
    }

    #[test]
    fn malformed_rules_error() {
        assert!(error("SecRule ARGS @rx x \"id:5\"")
            .reason
            .contains("whitespace"));
        assert!(error("SecRule \"@rx x\" \"id:6\"")
            .reason
            .contains("variables"));
        assert!(error("SecRule ARGS \"@rx x\" \"id:7")
            .reason
            .contains("unterminated"));
    }

    #[test]
    fn escaped_quotes_inside_operator_survive() {
        let parsed = rule(r#"SecRule ARGS "@rx a\"b" "id:8""#);
        assert_eq!(parsed.operator, SecOperator::Rx("a\"b".into()));
    }
}
