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
    /// `!` operator negation.
    pub negated: bool,
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
    /// Numeric comparison operators (`@eq`, `@ne`, `@lt`, `@le`, `@gt`,
    /// `@ge`); the argument is kept raw so `%{tx.*}` macros can resolve at
    /// evaluation time.
    Eq(String),
    Ne(String),
    Lt(String),
    Le(String),
    Gt(String),
    Ge(String),
    /// `@validateByteRange`: inclusive byte ranges, e.g. `8,10,13,32-126`.
    ValidateByteRange(Vec<(u8, u8)>),
    /// `@pmFromFile`: data file resolved against the rule-set base
    /// directory; expanded to `Pm` at rule-set build time.
    PmFromFile(String),
    /// `@validateUtf8Encoding`: matches values whose wire bytes were not
    /// valid UTF-8.
    ValidateUtf8Encoding,
    /// `@validateUrlEncoding`: matches malformed percent sequences
    /// (non-hex digits or truncated triplets); empty values never match.
    ValidateUrlEncoding,
    /// `SecAction` rules match unconditionally and take no variables.
    AlwaysMatch,
    /// `@unconditionalMatch`: resolves variables normally (so
    /// `MATCHED_VAR` binds) but always matches.
    UnconditionalMatch,
    /// `@within`: argument list is scanned for the value (substring search,
    /// mirroring ModSecurity's implementation; empty values match).
    Within(String),
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
            Self::Eq(_) => "@eq",
            Self::Ne(_) => "@ne",
            Self::Lt(_) => "@lt",
            Self::Le(_) => "@le",
            Self::Gt(_) => "@gt",
            Self::Ge(_) => "@ge",
            Self::ValidateByteRange(_) => "@validateByteRange",
            Self::PmFromFile(_) => "@pmFromFile",
            Self::ValidateUtf8Encoding => "@validateUtf8Encoding",
            Self::ValidateUrlEncoding => "@validateUrlEncoding",
            Self::AlwaysMatch => "@alwaysMatch",
            Self::UnconditionalMatch => "@unconditionalMatch",
            Self::Within(_) => "@within",
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
pub(crate) fn parse_quoted(
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
pub(crate) fn split_actions(input: &str) -> Vec<String> {
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
        "@pm" => SecOperator::Pm(
            argument.split_whitespace().map(str::to_string).collect(),
        ),
        "@pmFromFile" => {
            let path = argument.trim();
            if path.is_empty() {
                return Err(err("@pmFromFile without a file name"));
            }
            SecOperator::PmFromFile(path.to_string())
        },
        "@validateUtf8Encoding" => SecOperator::ValidateUtf8Encoding,
        "@validateUrlEncoding" => SecOperator::ValidateUrlEncoding,
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
        "@within" => SecOperator::Within(argument.to_string()),
        "@unconditionalMatch" => SecOperator::UnconditionalMatch,
        "@eq" => SecOperator::Eq(numeric_argument(name, argument)?),
        "@ne" => SecOperator::Ne(numeric_argument(name, argument)?),
        "@lt" => SecOperator::Lt(numeric_argument(name, argument)?),
        "@le" => SecOperator::Le(numeric_argument(name, argument)?),
        "@gt" => SecOperator::Gt(numeric_argument(name, argument)?),
        "@ge" => SecOperator::Ge(numeric_argument(name, argument)?),
        "@validateByteRange" => {
            SecOperator::ValidateByteRange(parse_byte_ranges(argument)?)
        },
        other => {
            return Err(err(format!("unsupported operator {other}")));
        },
    };
    Ok(operator)
}

/// Numeric operator argument: kept raw when it contains `%{tx.*}` macros
/// (resolved per evaluation), otherwise validated as a number now.
fn numeric_argument(
    operator: &str,
    argument: &str,
) -> Result<String, SecLangError> {
    let argument = argument.trim();
    validate_macros(argument)?;
    if !argument.contains("%{") && argument.parse::<i64>().is_err() {
        return Err(err(format!(
            "{operator} argument {argument:?} is not a number"
        )));
    }
    Ok(argument.to_string())
}

/// `@validateByteRange` argument: comma-separated bytes and inclusive
/// ranges (`8,10,13,32-126`).
fn parse_byte_ranges(argument: &str) -> Result<Vec<(u8, u8)>, SecLangError> {
    let mut ranges = Vec::new();
    for entry in argument.split(',') {
        let entry = entry.trim();
        if entry.is_empty() {
            continue;
        }
        let range = match entry.split_once('-') {
            Some((start, end)) => {
                let start = start.trim().parse::<u8>().map_err(|_| {
                    err(format!("invalid @validateByteRange entry {entry:?}"))
                })?;
                let end = end.trim().parse::<u8>().map_err(|_| {
                    err(format!("invalid @validateByteRange entry {entry:?}"))
                })?;
                (start, end)
            },
            None => {
                let byte = entry.parse::<u8>().map_err(|_| {
                    err(format!("invalid @validateByteRange entry {entry:?}"))
                })?;
                (byte, byte)
            },
        };
        if range.0 > range.1 {
            return Err(err(format!(
                "invalid @validateByteRange entry {entry:?}: start > end"
            )));
        }
        ranges.push(range);
    }
    if ranges.is_empty() {
        return Err(err("@validateByteRange without ranges"));
    }
    Ok(ranges)
}

/// Every `%{…}` macro must belong to the `tx` collection; anything else is
/// an observable unsupported-macro error.
pub(crate) fn validate_macros(raw: &str) -> Result<(), SecLangError> {
    let mut rest = raw;
    while let Some(start) = rest.find("%{") {
        let after = &rest[start + 2..];
        let Some(end) = after.find('}') else {
            return Err(err(format!("unterminated macro in {raw:?}")));
        };
        let token = &after[..end];
        let collection = token
            .split('.')
            .next()
            .unwrap_or(token)
            .to_ascii_lowercase();
        let known = matches!(
            collection.as_str(),
            "tx" | "matched_var"
                | "matched_var_name"
                | "remote_addr"
                | "request_line"
                | "request_headers"
                | "args"
        );
        if !known {
            return Err(err(format!(
                "macro collection %{{{token}}} is not supported yet"
            )));
        }
        rest = &after[end + 1..];
    }
    Ok(())
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
    let (negated, operator_raw) = match operator_raw.strip_prefix('!') {
        Some(stripped) => (true, stripped.to_string()),
        None => (false, operator_raw),
    };
    validate_macros(&operator_raw)?;
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
        negated,
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
    fn parses_numeric_comparison_operators() {
        for (op, expected) in [
            ("@eq 7", SecOperator::Eq("7".into())),
            ("@ne 7", SecOperator::Ne("7".into())),
            ("@lt 7", SecOperator::Lt("7".into())),
            ("@le 7", SecOperator::Le("7".into())),
            ("@gt 7", SecOperator::Gt("7".into())),
            ("@ge 7", SecOperator::Ge("7".into())),
        ] {
            let parsed = rule(&format!("SecRule TX:score \"{op}\" \"id:1\""));
            assert_eq!(parsed.operator, expected, "{op}");
        }
        // Macro arguments parse and resolve at evaluation time.
        let parsed = rule("SecRule TX:score \"@ge %{tx.threshold}\" \"id:1\"");
        assert_eq!(parsed.operator, SecOperator::Ge("%{tx.threshold}".into()));
        let e = error("SecRule TX:score \"@eq many\" \"id:1\"");
        assert!(e.reason.contains("not a number"), "{e}");
        let e = error("SecRule ARGS \"@rx %{REQUEST_URI}\" \"id:1\"");
        assert!(e.reason.contains("not supported yet"), "{e}");
        let pm =
            rule("SecRule ARGS \"@pmFromFile lfi-os-files.data\" \"id:1\"");
        assert_eq!(
            pm.operator,
            SecOperator::PmFromFile("lfi-os-files.data".into())
        );
    }

    #[test]
    fn parses_validate_byte_range() {
        let parsed =
            rule("SecRule ARGS \"@validateByteRange 8,10,13,32-126\" \"id:1\"");
        assert_eq!(
            parsed.operator,
            SecOperator::ValidateByteRange(vec![
                (8, 8),
                (10, 10),
                (13, 13),
                (32, 126)
            ])
        );
        let e = error("SecRule ARGS \"@validateByteRange 999\" \"id:1\"");
        assert!(e.reason.contains("validateByteRange"), "{e}");
        let e = error("SecRule ARGS \"@validateByteRange 9-2\" \"id:1\"");
        assert!(e.reason.contains("start > end"), "{e}");
    }

    #[test]
    fn parses_negation_within_and_unconditional_match() {
        let parsed =
            rule("SecRule REQUEST_METHOD \"!@within GET HEAD POST\" \"id:1\"");
        assert!(parsed.negated);
        assert_eq!(
            parsed.operator,
            SecOperator::Within("GET HEAD POST".into())
        );
        let unconditional =
            rule("SecRule ARGS \"@unconditionalMatch\" \"id:2\"");
        assert_eq!(unconditional.operator, SecOperator::UnconditionalMatch);
        let macro_pattern = rule("SecRule ARGS \"@rx %{tx.foo}\" \"id:3\"");
        assert_eq!(macro_pattern.operator, SecOperator::Rx("%{tx.foo}".into()));
        let utf8 = rule("SecRule ARGS \"@validateUtf8Encoding\" \"id:9\"");
        assert_eq!(utf8.operator, SecOperator::ValidateUtf8Encoding);
        let url = rule("SecRule ARGS \"@validateUrlEncoding\" \"id:10\"");
        assert_eq!(url.operator, SecOperator::ValidateUrlEncoding);
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
