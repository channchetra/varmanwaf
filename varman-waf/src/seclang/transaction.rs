//! SecLang transaction: variable resolution and operator execution
//! (Phase 7, second slice).
//!
//! The parser turns lines into AST; this module binds that AST to a real
//! request. A [`SecLangTransaction`] is built from the canonical request and
//! resolves the variables a rule names; [`CompiledSecRule`] pre-compiles its
//! operator once and evaluates it against every resolved value.
//!
//! Supported variables: `ARGS`, `ARGS_NAMES`, `REQUEST_HEADERS`,
//! `REQUEST_HEADERS:<name>` (case-insensitive name), `REQUEST_METHOD`,
//! `REQUEST_URI`, `QUERY_STRING`, `REQUEST_BODY`, `REMOTE_ADDR`, and `TX`
//! (`TX:<name>` set/get for future rule chains).
//!
//! Execution is bounded: variable resolution caps value counts and value
//! length, and a rule reports its first matching values only.

use std::collections::BTreeMap;

use regex::Regex;

use crate::canonical::CanonicalRequest;
use crate::rules::signatures::{detect_sqli, detect_xss};
use crate::seclang::parser::{SecLangError, SecOperator, SecRuleLine};

/// Maximum values resolved for one variable collection.
pub const MAX_VALUES: usize = 256;
/// Maximum length of a single resolved value considered by operators.
pub const MAX_VALUE_LEN: usize = 8 * 1024;

/// One resolved variable value.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolvedValue {
    /// Variable name with selector, e.g. `ARGS:id`.
    pub name: String,
    pub value: String,
}

/// Request-scoped variable state.
#[derive(Debug)]
pub struct SecLangTransaction {
    args: Vec<(String, String)>,
    headers: Vec<(String, String)>,
    method: String,
    uri: String,
    query_string: String,
    body: Option<String>,
    remote_addr: String,
    tx: BTreeMap<String, String>,
}

impl SecLangTransaction {
    pub fn from_request(request: &CanonicalRequest) -> Self {
        Self::from_parts(request)
    }

    /// Alias kept for readability at call sites that think in terms of the
    /// transaction lifecycle.
    pub fn from_parts(request: &CanonicalRequest) -> Self {
        let headers: Vec<(String, String)> = request
            .headers()
            .iter()
            .map(|(n, v)| (n.clone(), v.clone()))
            .collect();
        let mut args: Vec<(String, String)> = request
            .query()
            .iter()
            .map(|p| (p.name.clone(), p.value.clone()))
            .collect();
        // ModSecurity merges form-urlencoded body parameters into ARGS.
        let content_type = headers
            .iter()
            .find(|(n, _)| n.eq_ignore_ascii_case("content-type"))
            .map(|(_, v)| v.to_ascii_lowercase())
            .unwrap_or_default();
        let body_text = request
            .body()
            .and_then(|b| std::str::from_utf8(b).ok())
            .map(str::to_string);
        if content_type.contains("application/x-www-form-urlencoded") {
            if let Some(text) = &body_text {
                for pair in text.split('&') {
                    if pair.is_empty() {
                        continue;
                    }
                    let (name, value) = match pair.split_once('=') {
                        Some((name, value)) => (name, value),
                        None => (pair, ""),
                    };
                    args.push((
                        crate::normalize::url::multi_decode(name, 1),
                        crate::normalize::url::multi_decode(value, 1),
                    ));
                }
            }
        }
        Self {
            args,
            headers,
            method: request.method().to_string(),
            uri: request.path().to_string(),
            query_string: request.raw_query().to_string(),
            body: body_text,
            remote_addr: request
                .client()
                .ip
                .map(|ip| ip.to_string())
                .unwrap_or_default(),
            tx: BTreeMap::new(),
        }
    }

    pub fn tx_set(&mut self, name: &str, value: impl Into<String>) {
        self.tx.insert(name.to_string(), value.into());
    }

    pub fn tx_get(&self, name: &str) -> Option<&str> {
        self.tx.get(name).map(String::as_str)
    }

    /// Resolve one variable reference (`NAME` or `NAME:selector`).
    pub fn resolve(&self, reference: &str) -> Vec<ResolvedValue> {
        let (name, selector) = match reference.split_once(':') {
            Some((name, selector)) => (name, Some(selector)),
            None => (reference, None),
        };
        let cap = |values: Vec<ResolvedValue>| {
            values
                .into_iter()
                .take(MAX_VALUES)
                .map(|mut v| {
                    if v.value.len() > MAX_VALUE_LEN {
                        let mut end = MAX_VALUE_LEN;
                        while end > 0 && !v.value.is_char_boundary(end) {
                            end -= 1;
                        }
                        v.value.truncate(end);
                    }
                    v
                })
                .collect()
        };
        match (name, selector) {
            ("ARGS", None) => cap(self
                .args
                .iter()
                .map(|(n, v)| ResolvedValue {
                    name: format!("ARGS:{n}"),
                    value: v.clone(),
                })
                .collect()),
            ("ARGS", Some(selector)) => cap(self
                .args
                .iter()
                .filter(|(n, _)| n == selector)
                .map(|(n, v)| ResolvedValue {
                    name: format!("ARGS:{n}"),
                    value: v.clone(),
                })
                .collect()),
            ("ARGS_NAMES", _) => cap(self
                .args
                .iter()
                .map(|(n, _)| ResolvedValue {
                    name: "ARGS_NAMES".to_string(),
                    value: n.clone(),
                })
                .collect()),
            ("REQUEST_HEADERS", None) => cap(self
                .headers
                .iter()
                .map(|(n, v)| ResolvedValue {
                    name: format!("REQUEST_HEADERS:{n}"),
                    value: v.clone(),
                })
                .collect()),
            ("REQUEST_HEADERS", Some(selector)) => cap(self
                .headers
                .iter()
                .filter(|(n, _)| n.eq_ignore_ascii_case(selector))
                .map(|(n, v)| ResolvedValue {
                    name: format!("REQUEST_HEADERS:{n}"),
                    value: v.clone(),
                })
                .collect()),
            ("REQUEST_METHOD", _) => cap(vec![ResolvedValue {
                name: "REQUEST_METHOD".to_string(),
                value: self.method.clone(),
            }]),
            ("REQUEST_URI", _) => cap(vec![ResolvedValue {
                name: "REQUEST_URI".to_string(),
                value: self.uri.clone(),
            }]),
            ("QUERY_STRING", _) => cap(vec![ResolvedValue {
                name: "QUERY_STRING".to_string(),
                value: self.query_string.clone(),
            }]),
            ("REQUEST_BODY", _) => cap(self
                .body
                .iter()
                .map(|body| ResolvedValue {
                    name: "REQUEST_BODY".to_string(),
                    value: body.clone(),
                })
                .collect()),
            ("REMOTE_ADDR", _) => cap(vec![ResolvedValue {
                name: "REMOTE_ADDR".to_string(),
                value: self.remote_addr.clone(),
            }]),
            ("TX", Some(selector)) => cap(self
                .tx
                .get(selector)
                .map(|value| {
                    vec![ResolvedValue {
                        name: format!("TX:{selector}"),
                        value: value.clone(),
                    }]
                })
                .unwrap_or_default()),
            _ => Vec::new(),
        }
    }
}

/// A parsed rule with its operator pre-compiled.
#[derive(Debug)]
pub struct CompiledSecRule {
    pub line: SecRuleLine,
    regex: Option<Regex>,
    ips: Vec<ipnet::IpNet>,
    transforms: Vec<Transform>,
}

/// ModSecurity transformation applied to a value before the operator runs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Transform {
    Lowercase,
    Trim,
    CompressWhitespace,
    RemoveNulls,
    UrlDecode,
    HtmlEntityDecode,
    Base64Decode,
    RemoveWhitespace,
    CmdLine,
    JsDecode,
}

impl Transform {
    fn parse(name: &str) -> Option<Self> {
        match name.trim().to_ascii_lowercase().as_str() {
            "lowercase" => Some(Self::Lowercase),
            "trim" => Some(Self::Trim),
            "compresswhitespace" => Some(Self::CompressWhitespace),
            "removenulls" => Some(Self::RemoveNulls),
            // `urlDecodeUni` decodes one percent layer here; the canonical
            // request already applied the shared bounded decoding, and a
            // second layer is intentionally left to the rule author.
            "urldecode" | "urldecodeuni" => Some(Self::UrlDecode),
            "htmlentitydecode" => Some(Self::HtmlEntityDecode),
            "base64decode" => Some(Self::Base64Decode),
            "removewhitespace" => Some(Self::RemoveWhitespace),
            "cmdline" => Some(Self::CmdLine),
            "jsdecode" => Some(Self::JsDecode),
            _ => None,
        }
    }

    fn apply(self, value: &str) -> String {
        match self {
            Self::Lowercase => value.to_lowercase(),
            Self::Trim => value.trim().to_string(),
            Self::CompressWhitespace => {
                value.split_whitespace().collect::<Vec<_>>().join(" ")
            },
            Self::RemoveNulls => value.replace('\0', ""),
            Self::UrlDecode => crate::normalize::url::multi_decode(value, 1),
            Self::HtmlEntityDecode => {
                crate::normalize::html::decode_entities(value)
            },
            Self::Base64Decode => {
                use base64::Engine as _;
                base64::engine::general_purpose::STANDARD
                    .decode(value.trim())
                    .map(|bytes| String::from_utf8_lossy(&bytes).to_string())
                    // ModSecurity leaves a value unchanged when base64
                    // decoding fails; mirror that instead of erroring.
                    .unwrap_or_else(|_| value.to_string())
            },
            Self::RemoveWhitespace => {
                value.chars().filter(|c| !c.is_whitespace()).collect()
            },
            Self::CmdLine => cmd_line(value),
            Self::JsDecode => js_decode(value),
        }
    }
}

/// ModSecurity `cmdLine`: drops quotes/backslashes/carets, collapses
/// separators to one space, removes the space before `/` or `(`, lowercases.
fn cmd_line(value: &str) -> String {
    let mut out: Vec<char> = Vec::with_capacity(value.len());
    let mut space = false;
    for c in value.chars() {
        match c {
            '"' | '\'' | '\\' | '^' => {},
            ' ' | ',' | ';' | '\t' | '\r' | '\n' => {
                if !space {
                    out.push(' ');
                    space = true;
                }
            },
            '/' | '(' => {
                if space {
                    out.pop();
                }
                space = false;
                out.push(c);
            },
            c => {
                for lower in c.to_lowercase() {
                    out.push(lower);
                }
                space = false;
            },
        }
    }
    out.into_iter().collect()
}

/// ModSecurity `jsDecode`: `\uHHHH`, `\xHH`, octal `\OOO`, and single-char
/// escapes; any other escape drops the backslash.
fn js_decode(value: &str) -> String {
    let bytes = value.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] != b'\\' {
            out.push(bytes[i]);
            i += 1;
            continue;
        }
        // \uHHHH (full-width ASCII U+FF01–U+FF5E shifts down by 0x20).
        if i + 5 < bytes.len()
            && bytes[i + 1] == b'u'
            && bytes[i + 2..i + 6].iter().all(u8::is_ascii_hexdigit)
        {
            let mut byte = hex_byte(bytes[i + 4], bytes[i + 5]);
            if (1..0x5f).contains(&byte)
                && (bytes[i + 2] == b'f' || bytes[i + 2] == b'F')
                && (bytes[i + 3] == b'f' || bytes[i + 3] == b'F')
            {
                byte += 0x20;
            }
            out.push(byte);
            i += 6;
            continue;
        }
        // \xHH
        if i + 3 < bytes.len()
            && bytes[i + 1] == b'x'
            && bytes[i + 2].is_ascii_hexdigit()
            && bytes[i + 3].is_ascii_hexdigit()
        {
            out.push(hex_byte(bytes[i + 2], bytes[i + 3]));
            i += 4;
            continue;
        }
        // Octal \OOO (at most three digits; two when the first exceeds '3').
        if i + 1 < bytes.len() && (b'0'..=b'7').contains(&bytes[i + 1]) {
            let mut j = 0usize;
            let mut buf = [0u8; 3];
            while i + 1 + j < bytes.len() && j < 3 {
                buf[j] = bytes[i + 1 + j];
                j += 1;
                if i + 1 + j >= bytes.len()
                    || !(b'0'..=b'7').contains(&bytes[i + 1 + j])
                {
                    break;
                }
            }
            let mut digits = j;
            if digits == 3 && buf[0] > b'3' {
                digits = 2;
            }
            let text = std::str::from_utf8(&buf[..digits]).unwrap_or("");
            out.push(u8::from_str_radix(text, 8).unwrap_or(0));
            i += 1 + digits;
            continue;
        }
        if i + 1 < bytes.len() {
            let byte = match bytes[i + 1] {
                b'a' => 0x07,
                b'b' => 0x08,
                b'f' => 0x0c,
                b'n' => b'\n',
                b'r' => b'\r',
                b't' => b'\t',
                b'v' => 0x0b,
                // Remaining escapes (\?", \\, \', \") just drop the
                // backslash.
                other => other,
            };
            out.push(byte);
            i += 2;
            continue;
        }
        out.push(bytes[i]);
        i += 1;
    }
    String::from_utf8_lossy(&out).to_string()
}

fn hex_byte(high: u8, low: u8) -> u8 {
    fn nibble(byte: u8) -> u8 {
        match byte {
            b'0'..=b'9' => byte - b'0',
            b'a'..=b'f' => byte - b'a' + 10,
            _ => byte - b'A' + 10,
        }
    }
    (nibble(high) << 4) | nibble(low)
}

/// Collect `t:` actions in order; an unknown transformation is an observable
/// error (mandate §37: unsupported SecLang must never be silently ignored).
fn parse_transforms(
    actions: &[String],
) -> Result<Vec<Transform>, SecLangError> {
    let mut transforms = Vec::new();
    for action in actions {
        let Some(name) = action.trim().strip_prefix("t:") else {
            continue;
        };
        if name.trim().eq_ignore_ascii_case("none") {
            // `t:none` clears inherited transforms; this engine has none, so
            // it is a no-op by construction.
            continue;
        }
        let Some(transform) = Transform::parse(name) else {
            return Err(SecLangError {
                reason: format!("unsupported transformation {name:?}"),
            });
        };
        transforms.push(transform);
    }
    Ok(transforms)
}

/// Expand `%{tx.<name>}` macros against the transaction; unset variables
/// expand to the empty string (ModSecurity behaviour).
pub(crate) fn expand_macros(input: &str, txn: &SecLangTransaction) -> String {
    let mut output = String::with_capacity(input.len());
    let mut rest = input;
    while let Some(start) = rest.find("%{") {
        output.push_str(&rest[..start]);
        let after = &rest[start + 2..];
        let Some(end) = after.find('}') else {
            output.push_str(&rest[start..]);
            return output;
        };
        let token = &after[..end];
        let name = token
            .strip_prefix("tx.")
            .unwrap_or_else(|| token.rsplit('.').next().unwrap_or(token));
        let value = txn.tx_get(name).unwrap_or_default();
        output.push_str(value);
        rest = &after[end + 1..];
    }
    output.push_str(rest);
    output
}

/// Numeric comparison shared by `@eq`/`@ne`/`@lt`/`@le`/`@gt`/`@ge`:
/// both sides must resolve to numbers (after macro expansion).
fn compare_numbers(
    value: &str,
    argument: &str,
    txn: &SecLangTransaction,
    compare: impl FnOnce(i64, i64) -> bool,
) -> bool {
    let Some(value) = number(value) else {
        return false;
    };
    let expanded = expand_macros(argument, txn);
    let Some(expected) = number(&expanded) else {
        return false;
    };
    compare(value, expected)
}

/// Numeric value of a resolved string, for the numeric comparison operators.
/// Non-numeric values never match (documented in `docs/compatibility.md`).
fn number(value: &str) -> Option<i64> {
    value.trim().parse().ok()
}

impl CompiledSecRule {
    pub fn compile(line: SecRuleLine) -> Result<Self, SecLangError> {
        let mut regex = None;
        let mut ips = Vec::new();
        match &line.operator {
            SecOperator::Rx(pattern) => {
                // Patterns with `%{tx.*}` macros are compiled per evaluation
                // after expansion.
                if !pattern.contains("%{") {
                    regex = Some(Regex::new(pattern).map_err(|e| {
                        SecLangError {
                            reason: format!(
                                "invalid @rx pattern {pattern:?}: {e}"
                            ),
                        }
                    })?);
                }
            },
            SecOperator::IpMatch(entries) => {
                for entry in entries {
                    // CIDR blocks and single IPv4/IPv6 addresses (a bare
                    // address means a host route).
                    let net =
                        entry.parse::<ipnet::IpNet>().ok().or_else(|| {
                            let ip = entry.parse::<std::net::IpAddr>().ok()?;
                            let prefix = if ip.is_ipv4() { 32 } else { 128 };
                            ipnet::IpNet::new(ip, prefix).ok()
                        });
                    let Some(net) = net else {
                        return Err(SecLangError {
                            reason: format!("invalid @ipMatch entry {entry:?}"),
                        });
                    };
                    ips.push(net);
                }
            },
            _ => {},
        }
        let transforms = parse_transforms(&line.actions)?;
        Ok(Self {
            line,
            regex,
            ips,
            transforms,
        })
    }

    pub fn rule_id(&self) -> Option<u64> {
        self.line.actions.iter().find_map(|action| {
            action
                .strip_prefix("id:")
                .and_then(|id| id.trim().parse().ok())
        })
    }

    /// Evaluate the operator against every resolved value of every variable.
    /// Returns the matching values (first match per variable stops that
    /// variable, mirroring ModSecurity's per-variable short-circuit).
    pub fn matches(&self, txn: &SecLangTransaction) -> Vec<ResolvedValue> {
        if matches!(self.line.operator, SecOperator::AlwaysMatch) {
            // `SecAction`: unconditional, no variables.
            return vec![ResolvedValue {
                name: "ACTION".to_string(),
                value: String::new(),
            }];
        }
        let mut hits = Vec::new();
        for reference in &self.line.variables {
            for value in txn.resolve(reference) {
                if self.operator_matches(&value.value, txn) != self.line.negated
                {
                    hits.push(value);
                    break;
                }
            }
        }
        hits
    }

    fn operator_matches(&self, value: &str, txn: &SecLangTransaction) -> bool {
        let transformed = self.apply_transforms(value);
        let value = transformed.as_str();
        match &self.line.operator {
            SecOperator::Rx(pattern) => match &self.regex {
                Some(regex) => regex.is_match(value),
                None => {
                    // Macro pattern: expand against the transaction and
                    // compile per evaluation.
                    let expanded = expand_macros(pattern, txn);
                    Regex::new(&expanded)
                        .is_ok_and(|regex| regex.is_match(value))
                },
            },
            SecOperator::Pm(needles) => {
                needles.iter().any(|needle| value.contains(needle))
            },
            SecOperator::Contains(needle) => value.contains(needle),
            SecOperator::Streq(expected) => value == expected,
            SecOperator::BeginsWith(prefix) => value.starts_with(prefix),
            SecOperator::EndsWith(suffix) => value.ends_with(suffix),
            SecOperator::DetectSqli => detect_sqli(value).0,
            SecOperator::DetectXss => detect_xss(value).0,
            SecOperator::IpMatch(_) => value
                .parse::<std::net::IpAddr>()
                .ok()
                .is_some_and(|ip| self.ips.iter().any(|net| net.contains(&ip))),
            SecOperator::Eq(expected) => {
                compare_numbers(value, expected, txn, |a, b| a == b)
            },
            SecOperator::Ne(expected) => {
                compare_numbers(value, expected, txn, |a, b| a != b)
            },
            SecOperator::Lt(expected) => {
                compare_numbers(value, expected, txn, |a, b| a < b)
            },
            SecOperator::Le(expected) => {
                compare_numbers(value, expected, txn, |a, b| a <= b)
            },
            SecOperator::Gt(expected) => {
                compare_numbers(value, expected, txn, |a, b| a > b)
            },
            SecOperator::Ge(expected) => {
                compare_numbers(value, expected, txn, |a, b| a >= b)
            },
            SecOperator::Within(list) => {
                value.is_empty() || expand_macros(list, txn).contains(value)
            },
            SecOperator::ValidateByteRange(ranges) => {
                value.bytes().all(|byte| {
                    ranges
                        .iter()
                        .any(|(start, end)| byte >= *start && byte <= *end)
                })
            },
            SecOperator::AlwaysMatch => true,
        }
    }

    fn apply_transforms(&self, value: &str) -> String {
        let mut current = value.to_string();
        for transform in &self.transforms {
            current = transform.apply(&current);
        }
        current
    }

    /// `true` when the rule's actions include `capture`.
    pub(crate) fn has_capture(&self) -> bool {
        self.line.actions.iter().any(|a| a.trim() == "capture")
    }

    /// Apply the `capture` action: `TX:0` = whole match, `TX:1..9` = regex
    /// groups of the matched value. Non-regex operators capture nothing,
    /// mirroring ModSecurity.
    pub(crate) fn captures_into(
        &self,
        value: &str,
        txn: &mut SecLangTransaction,
    ) {
        let (Some(regex), SecOperator::Rx(_)) =
            (&self.regex, &self.line.operator)
        else {
            return;
        };
        let Some(captures) = regex.captures(value) else {
            return;
        };
        txn.tx_set("0", captures.get(0).map(|m| m.as_str()).unwrap_or(""));
        for index in 1..=9 {
            let text = captures.get(index).map(|m| m.as_str()).unwrap_or("");
            txn.tx_set(&index.to_string(), text);
        }
    }
}

/// One rule, or a `chain` group: every member must match for the group to
/// fire (ModSecurity chain semantics = logical AND; per-chain variable
/// capture — `TX:0…9` — is a later slice).
#[derive(Debug)]
pub struct SecRuleGroup {
    pub rules: Vec<CompiledSecRule>,
}

impl SecRuleGroup {
    /// `Some(hits)` when every rule matched (hits concatenated in rule
    /// order); `None` when any member did not match.
    pub fn matches(
        &self,
        txn: &SecLangTransaction,
    ) -> Option<Vec<ResolvedValue>> {
        let mut all = Vec::new();
        for rule in &self.rules {
            let hits = rule.matches(txn);
            if hits.is_empty() {
                return None;
            }
            all.extend(hits);
        }
        Some(all)
    }

    pub fn rule_ids(&self) -> Vec<Option<u64>> {
        self.rules.iter().map(CompiledSecRule::rule_id).collect()
    }
}

/// Group parsed rules into singletons and `chain` groups.
///
/// A rule whose actions contain `chain` opens/extend a group; the first rule
/// without `chain` closes it. A chain that reaches the end of the input
/// without a final rule is an observable error.
pub fn group_rules(
    lines: Vec<SecRuleLine>,
) -> Result<Vec<SecRuleGroup>, SecLangError> {
    let mut groups: Vec<SecRuleGroup> = Vec::new();
    let mut pending: Vec<CompiledSecRule> = Vec::new();
    for line in lines {
        let chained = line.actions.iter().any(|a| a.trim() == "chain");
        let compiled = CompiledSecRule::compile(line)?;
        pending.push(compiled);
        if !chained {
            groups.push(SecRuleGroup {
                rules: std::mem::take(&mut pending),
            });
        }
    }
    if !pending.is_empty() {
        return Err(SecLangError {
            reason: "chain ended without a final rule".to_string(),
        });
    }
    Ok(groups)
}

#[cfg(test)]
mod tests {
    use super::{CompiledSecRule, SecLangTransaction, Transform};
    use crate::canonical::{Canonicalizer, ClientIdentity, RequestParts};
    use crate::seclang::parser::{parse_line, SecLangLine};

    fn request() -> crate::canonical::CanonicalRequest {
        Canonicalizer::default().canonicalize(
            RequestParts::new(
                "POST",
                "example.com",
                "/api/items?id=42&q=hello",
            )
            .with_header("Host", "example.com")
            .with_header("User-Agent", "curl/8.4.0")
            .with_header("Content-Type", "application/x-www-form-urlencoded")
            .with_body("name=Ada&role=admin".as_bytes().to_vec())
            .with_client(ClientIdentity {
                ip: Some("203.0.113.9".parse().expect("ip")),
                ja4: None,
            }),
        )
    }

    fn rule(line: &str) -> CompiledSecRule {
        match parse_line(line).expect("parse") {
            SecLangLine::Rule(parsed) => {
                CompiledSecRule::compile(parsed).expect("compile")
            },
            SecLangLine::Ignored => panic!("expected rule"),
        }
    }

    #[test]
    fn resolves_args_and_names() {
        let txn = SecLangTransaction::from_request(&request());
        let args = txn.resolve("ARGS");
        // Query pairs plus form-body pairs merged into ARGS.
        assert_eq!(args.len(), 4);
        assert!(args.iter().any(|v| v.name == "ARGS:id" && v.value == "42"));
        assert!(args
            .iter()
            .any(|v| v.name == "ARGS:role" && v.value == "admin"));
        let only_id = txn.resolve("ARGS:id");
        assert_eq!(only_id.len(), 1);
        let names = txn.resolve("ARGS_NAMES");
        assert!(names.iter().any(|v| v.value == "q"));
        assert!(names.iter().any(|v| v.value == "role"));
    }

    #[test]
    fn resolves_headers_case_insensitively() {
        let txn = SecLangTransaction::from_request(&request());
        let host = txn.resolve("REQUEST_HEADERS:HOST");
        assert_eq!(host.len(), 1);
        assert_eq!(host[0].value, "example.com");
        let all = txn.resolve("REQUEST_HEADERS");
        assert_eq!(all.len(), 3);
    }

    #[test]
    fn resolves_scalars() {
        let txn = SecLangTransaction::from_request(&request());
        assert_eq!(txn.resolve("REQUEST_METHOD")[0].value, "POST");
        assert_eq!(txn.resolve("REQUEST_URI")[0].value, "/api/items");
        assert_eq!(txn.resolve("QUERY_STRING")[0].value, "id=42&q=hello");
        assert_eq!(txn.resolve("REMOTE_ADDR")[0].value, "203.0.113.9");
        assert_eq!(txn.resolve("REQUEST_BODY")[0].value, "name=Ada&role=admin");
    }

    #[test]
    fn tx_variables_round_trip() {
        let mut txn = SecLangTransaction::from_request(&request());
        txn.tx_set("score", "5");
        assert_eq!(txn.resolve("TX:score")[0].value, "5");
        assert!(txn.resolve("TX:missing").is_empty());
    }

    #[test]
    fn regex_operator_precompiled_and_matched() {
        let matcher =
            rule("SecRule ARGS:id \"@rx ^[0-9]+$\" \"id:900100,phase:1\"");
        let txn = SecLangTransaction::from_request(&request());
        let hits = matcher.matches(&txn);
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].name, "ARGS:id");
        assert_eq!(matcher.rule_id(), Some(900100));
    }

    #[test]
    fn invalid_regex_is_an_observable_error() {
        let parsed = match parse_line("SecRule ARGS \"@rx (\" \"id:1\"")
            .expect("parse")
        {
            SecLangLine::Rule(parsed) => parsed,
            SecLangLine::Ignored => panic!("expected rule"),
        };
        let error = CompiledSecRule::compile(parsed).expect_err("must fail");
        assert!(error.reason.contains("invalid @rx"), "{error}");
    }

    #[test]
    fn string_operators_match() {
        let cases = [
            ("@contains hello", true),
            ("@contains nope", false),
            ("@streq hello", true),
            ("@beginsWith hel", true),
            ("@endsWith llo", true),
            ("@pm nope hello", true),
            ("@pm nope nada", false),
        ];
        let txn = SecLangTransaction::from_request(&request());
        for (operator, expected) in cases {
            let matcher =
                rule(&format!("SecRule ARGS:q \"{operator}\" \"id:1\""));
            assert_eq!(
                !matcher.matches(&txn).is_empty(),
                expected,
                "{operator}"
            );
        }
    }

    #[test]
    fn numeric_operators_compare_and_reject_non_numbers() {
        // `request()` carries `id=42` and `q=hello`.
        let txn = SecLangTransaction::from_request(&request());
        let greater = rule("SecRule ARGS:id \"@gt 40\" \"id:1\"");
        assert_eq!(greater.matches(&txn).len(), 1);
        let less = rule("SecRule ARGS:id \"@lt 40\" \"id:1\"");
        assert!(less.matches(&txn).is_empty());
        let equal = rule("SecRule ARGS:id \"@eq 42\" \"id:1\"");
        assert_eq!(equal.matches(&txn).len(), 1);
        let not_non_numeric = rule("SecRule ARGS:q \"@ne 42\" \"id:1\"");
        assert!(
            not_non_numeric.matches(&txn).is_empty(),
            "non-numeric values never match numeric operators"
        );
    }

    #[test]
    fn within_and_negated_operators_match() {
        let txn = SecLangTransaction::from_request(&request());
        let within = rule("SecRule ARGS:q \"@within hello world\" \"id:1\"");
        assert_eq!(within.matches(&txn).len(), 1);
        let not_within =
            rule("SecRule ARGS:q \"!@within goodbye world\" \"id:2\"");
        assert_eq!(not_within.matches(&txn).len(), 1);
        let negated_hit =
            rule("SecRule ARGS:q \"!@within hello world\" \"id:3\"");
        assert!(negated_hit.matches(&txn).is_empty());
    }

    #[test]
    fn t_none_is_a_noop_and_unknown_transforms_error() {
        let matcher =
            rule("SecRule ARGS:q \"@streq hello\" \"id:1,t:none,t:lowercase\"");
        let txn = SecLangTransaction::from_request(&request());
        assert_eq!(matcher.matches(&txn).len(), 1);
        let parsed =
            match parse_line("SecRule ARGS \"@streq x\" \"id:1,t:bogus\"")
                .expect("parse")
            {
                SecLangLine::Rule(flat) => flat,
                SecLangLine::Ignored => panic!("expected rule"),
            };
        let error = CompiledSecRule::compile(parsed).expect_err("must fail");
        assert!(
            error.reason.contains("unsupported transformation"),
            "{error}"
        );
    }

    #[test]
    fn macros_expand_from_transaction_variables() {
        let mut txn = SecLangTransaction::from_request(&request());
        txn.tx_set("threshold", "40");
        let ge = rule("SecRule ARGS:id \"@ge %{tx.threshold}\" \"id:1\"");
        assert_eq!(ge.matches(&txn).len(), 1);
        txn.tx_set("pattern", "^4[0-9]$");
        let rx = rule("SecRule ARGS:id \"@rx %{tx.pattern}\" \"id:2\"");
        assert_eq!(rx.matches(&txn).len(), 1);
        // Unset macros expand to the empty string.
        let missing = rule("SecRule ARGS:id \"@streq %{tx.not_set}\" \"id:3\"");
        assert!(missing.matches(&txn).is_empty());
        // Non-numeric expansions never satisfy numeric operators.
        txn.tx_set("threshold", "many");
        let bad = rule("SecRule ARGS:id \"@ge %{tx.threshold}\" \"id:4\"");
        assert!(bad.matches(&txn).is_empty());
    }

    #[test]
    fn ip_match_accepts_single_addresses() {
        let matcher =
            rule("SecRule REMOTE_ADDR \"@ipMatch 203.0.113.9,::1\" \"id:1\"");
        let txn = SecLangTransaction::from_request(&request());
        assert_eq!(matcher.matches(&txn).len(), 1);
    }

    #[test]
    fn cmdline_jsdecode_and_removewhitespace_transforms() {
        let cmdline = Transform::parse("cmdLine").expect("cmdLine");
        assert_eq!(
            cmdline.apply("cmd.exe /c \"dir\" C:\\temp"),
            "cmd.exe/c dir c:temp"
        );
        let js = Transform::parse("jsDecode").expect("jsDecode");
        assert_eq!(js.apply("\\u0041\\x42\\103\\n"), "ABC\n");
        assert_eq!(js.apply("\\uFF21"), "A");
        let whitespace = Transform::parse("removeWhitespace").expect("remove");
        assert_eq!(whitespace.apply(" a\tb\u{a0}c\nd "), "abcd");
    }

    #[test]
    fn validate_byte_range_operator() {
        let txn = SecLangTransaction::from_request(&request());
        let ok = rule("SecRule ARGS:q \"@validateByteRange 97-122\" \"id:1\"");
        assert_eq!(ok.matches(&txn).len(), 1);
        let bad = rule("SecRule ARGS:q \"@validateByteRange 97-104\" \"id:2\"");
        assert!(bad.matches(&txn).is_empty());
    }

    #[test]
    fn injection_operators_reuse_the_detectors() {
        let request = Canonicalizer::default().canonicalize(RequestParts::new(
            "GET",
            "example.com",
            "/?q=id=1%20UNION%20SELECT%20NULL--",
        ));
        let txn = SecLangTransaction::from_request(&request);
        let sqli = rule("SecRule ARGS \"@detectSQLi\" \"id:1\"");
        assert!(!sqli.matches(&txn).is_empty());
        let xss = rule("SecRule ARGS \"@detectXSS\" \"id:2\"");
        assert!(xss.matches(&txn).is_empty());
    }

    #[test]
    fn ip_match_uses_cidr() {
        let matcher =
            rule("SecRule REMOTE_ADDR \"@ipMatch 203.0.113.0/24,10.0.0.0/8\" \"id:1\"");
        let txn = SecLangTransaction::from_request(&request());
        assert!(!matcher.matches(&txn).is_empty());
        let outside =
            rule("SecRule REMOTE_ADDR \"@ipMatch 10.0.0.0/8\" \"id:2\"");
        assert!(outside.matches(&txn).is_empty());
    }

    #[test]
    fn unknown_variables_resolve_empty() {
        let txn = SecLangTransaction::from_request(&request());
        assert!(txn.resolve("FILES").is_empty());
        assert!(txn.resolve("TX_WITHOUT_SELECTOR").is_empty());
    }

    #[test]
    fn transforms_apply_in_order() {
        // The canonical value arrives already decoded ("A  B"); lowercase
        // then compressWhitespace turn it into "a b".
        let matcher = rule(
            "SecRule ARGS:q \"@streq a b\" \"id:1,t:urlDecode,t:lowercase,t:compressWhitespace\"",
        );
        let request = Canonicalizer::default().canonicalize(RequestParts::new(
            "GET",
            "example.com",
            "/?q=A%20%20B",
        ));
        let txn = SecLangTransaction::from_request(&request);
        assert!(!matcher.matches(&txn).is_empty());
    }

    #[test]
    fn entity_and_null_transforms() {
        let entity = rule(
            "SecRule ARGS:q \"@contains <script>\" \"id:2,t:htmlEntityDecode\"",
        );
        let request = Canonicalizer::default().canonicalize(RequestParts::new(
            "GET",
            "example.com",
            "/?q=%26lt%3Bscript%26gt%3B",
        ));
        let txn = SecLangTransaction::from_request(&request);
        assert!(!entity.matches(&txn).is_empty());

        let nulls = rule("SecRule ARGS:q \"@streq ab\" \"id:3,t:removeNulls\"");
        let request = Canonicalizer::default().canonicalize(RequestParts::new(
            "GET",
            "example.com",
            "/?q=a%00b",
        ));
        let txn = SecLangTransaction::from_request(&request);
        assert!(!nulls.matches(&txn).is_empty());
    }

    #[test]
    fn unknown_transformations_error_observably() {
        let parsed = match parse_line(
            "SecRule ARGS \"@rx x\" \"id:1,t:noSuchTransform\"",
        )
        .expect("parse")
        {
            SecLangLine::Rule(parsed) => parsed,
            SecLangLine::Ignored => panic!("expected rule"),
        };
        let error = CompiledSecRule::compile(parsed).expect_err("must fail");
        assert!(
            error.reason.contains("unsupported transformation"),
            "{error}"
        );
    }

    #[test]
    fn chain_groups_require_every_member_to_match() {
        use super::group_rules;
        use crate::seclang::parser::parse_line;

        let lines = [
            "SecRule REQUEST_METHOD \"@streq POST\" \"id:1,chain\"",
            "SecRule ARGS:role \"@streq admin\" \"id:2\"",
        ];
        let parsed = lines
            .iter()
            .map(|line| match parse_line(line).expect("parse") {
                SecLangLine::Rule(rule) => rule,
                SecLangLine::Ignored => panic!("expected rule"),
            })
            .collect::<Vec<_>>();
        let groups = group_rules(parsed).expect("groups");
        assert_eq!(groups.len(), 1);
        assert_eq!(groups[0].rules.len(), 2);
        assert_eq!(groups[0].rule_ids(), vec![Some(1), Some(2)]);

        let txn = SecLangTransaction::from_request(&request());
        assert!(groups[0].matches(&txn).is_some());

        // A request that fails the second member must fail the whole chain.
        let get_request = Canonicalizer::default().canonicalize(
            RequestParts::new("GET", "example.com", "/?role=admin"),
        );
        let get_txn = SecLangTransaction::from_request(&get_request);
        assert!(groups[0].matches(&get_txn).is_none());
    }

    #[test]
    fn dangling_chain_is_an_observable_error() {
        use super::group_rules;
        use crate::seclang::parser::parse_line;

        let parsed =
            vec![match parse_line("SecRule ARGS \"@rx x\" \"id:1,chain\"")
                .expect("parse")
            {
                SecLangLine::Rule(rule) => rule,
                SecLangLine::Ignored => panic!("expected rule"),
            }];
        let error = group_rules(parsed).expect_err("must fail");
        assert!(error.reason.contains("chain ended"), "{error}");
    }

    #[test]
    fn long_values_are_bounded() {
        let body = "x".repeat(20_000);
        let request = Canonicalizer::default().canonicalize(
            RequestParts::new("POST", "example.com", "/")
                .with_body(body.into_bytes()),
        );
        let txn = SecLangTransaction::from_request(&request);
        let resolved = txn.resolve("REQUEST_BODY");
        assert_eq!(resolved.len(), 1);
        assert!(resolved[0].value.len() <= super::MAX_VALUE_LEN);
    }
}
