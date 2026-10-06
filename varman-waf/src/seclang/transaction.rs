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
        Self {
            args: request
                .query()
                .iter()
                .map(|p| (p.name.clone(), p.value.clone()))
                .collect(),
            headers: request
                .headers()
                .iter()
                .map(|(n, v)| (n.clone(), v.clone()))
                .collect(),
            method: request.method().to_string(),
            uri: request.path().to_string(),
            query_string: request.raw_query().to_string(),
            body: request
                .body()
                .and_then(|b| std::str::from_utf8(b).ok())
                .map(str::to_string),
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
        }
    }
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
        let Some(transform) = Transform::parse(name) else {
            return Err(SecLangError {
                reason: format!("unsupported transformation {name:?}"),
            });
        };
        transforms.push(transform);
    }
    Ok(transforms)
}

impl CompiledSecRule {
    pub fn compile(line: SecRuleLine) -> Result<Self, SecLangError> {
        let mut regex = None;
        let mut ips = Vec::new();
        match &line.operator {
            SecOperator::Rx(pattern) => {
                regex =
                    Some(Regex::new(pattern).map_err(|e| SecLangError {
                        reason: format!("invalid @rx pattern {pattern:?}: {e}"),
                    })?);
            },
            SecOperator::IpMatch(entries) => {
                for entry in entries {
                    let net = entry.parse::<ipnet::IpNet>().map_err(|e| {
                        SecLangError {
                            reason: format!(
                                "invalid @ipMatch entry {entry:?}: {e}"
                            ),
                        }
                    })?;
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
        let mut hits = Vec::new();
        for reference in &self.line.variables {
            for value in txn.resolve(reference) {
                if self.operator_matches(&value.value) {
                    hits.push(value);
                    break;
                }
            }
        }
        hits
    }

    fn operator_matches(&self, value: &str) -> bool {
        let transformed = self.apply_transforms(value);
        let value = transformed.as_str();
        match &self.line.operator {
            SecOperator::Rx(_) => self
                .regex
                .as_ref()
                .is_some_and(|regex| regex.is_match(value)),
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
        }
    }

    fn apply_transforms(&self, value: &str) -> String {
        let mut current = value.to_string();
        for transform in &self.transforms {
            current = transform.apply(&current);
        }
        current
    }
}

#[cfg(test)]
mod tests {
    use super::{CompiledSecRule, SecLangTransaction};
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
        assert_eq!(args.len(), 2);
        assert!(args.iter().any(|v| v.name == "ARGS:id" && v.value == "42"));
        let only_id = txn.resolve("ARGS:id");
        assert_eq!(only_id.len(), 1);
        let names = txn.resolve("ARGS_NAMES");
        assert!(names.iter().any(|v| v.value == "q"));
    }

    #[test]
    fn resolves_headers_case_insensitively() {
        let txn = SecLangTransaction::from_request(&request());
        let host = txn.resolve("REQUEST_HEADERS:HOST");
        assert_eq!(host.len(), 1);
        assert_eq!(host[0].value, "example.com");
        let all = txn.resolve("REQUEST_HEADERS");
        assert_eq!(all.len(), 2);
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
