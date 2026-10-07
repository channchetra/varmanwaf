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

use std::collections::{BTreeMap, BTreeSet};

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
    /// `true` when the underlying wire bytes were not valid UTF-8 (used by
    /// `@validateUtf8Encoding`; only body/args/path values can be flagged).
    pub invalid_utf8: bool,
}

/// One JSON container while flattening (mirrors ModSecurity's stack).
struct JsonContainer {
    name: String,
    array: bool,
    counter: usize,
}

/// Flatten JSON into `ARGS` names exactly like ModSecurity's processor:
/// object members contribute `key.`, array elements `.array_N`, and scalar
/// leaves become `path + key` (or just the path under an array).
fn flatten_json(
    value: &serde_json::Value,
    key: Option<&str>,
    containers: &mut Vec<JsonContainer>,
    out: &mut Vec<(String, String)>,
) {
    match value {
        serde_json::Value::Object(map) => {
            containers.push(JsonContainer {
                name: key.unwrap_or("").to_string(),
                array: false,
                counter: 0,
            });
            for (member, child) in map {
                flatten_json(child, Some(member), containers, out);
            }
            containers.pop();
        },
        serde_json::Value::Array(items) => {
            containers.push(JsonContainer {
                name: key.unwrap_or("").to_string(),
                array: true,
                counter: 0,
            });
            for child in items {
                flatten_json(child, None, containers, out);
            }
            containers.pop();
        },
        scalar => {
            let mut path = String::new();
            for container in containers.iter() {
                path.push_str(&container.name);
                if container.array {
                    path.push_str(&format!(".array_{}", container.counter));
                } else {
                    path.push('.');
                }
            }
            let mut data = String::new();
            if let Some(last) = containers.last_mut() {
                if last.array {
                    last.counter += 1;
                } else {
                    data = key.unwrap_or("").to_string();
                }
            } else {
                data = key.unwrap_or("").to_string();
            }
            let text = match scalar {
                serde_json::Value::String(text) => text.clone(),
                other => other.to_string(),
            };
            out.push((format!("{path}{data}"), text));
        },
    }
}

/// One decoded argument with its wire-byte validity.
#[derive(Debug, Clone)]
struct ArgValue {
    name: String,
    value: String,
    invalid_utf8: bool,
}

/// Request-scoped variable state.
#[derive(Debug)]
pub struct SecLangTransaction {
    args: Vec<ArgValue>,
    headers: Vec<(String, String)>,
    cookies: Vec<(String, String)>,
    method: String,
    uri: String,
    query_string: String,
    body: Option<Vec<u8>>,
    /// `XML:/*` values (element text nodes) when the XML processor is active.
    xml_texts: Vec<String>,
    /// `XML://@*` values (attribute values) when the XML processor is active.
    xml_attributes: Vec<String>,
    remote_addr: String,
    path_invalid_utf8: bool,
    tx: BTreeMap<String, String>,
    /// `initcol` collection instances: collection name → instance key →
    /// value. Per-transaction storage; cross-request persistence is not
    /// implemented yet (no stock CRS rule depends on it).
    collections: BTreeMap<String, BTreeMap<String, String>>,
    http_version: String,
    /// Variable that most recently matched, for `MATCHED_VAR` /
    /// `MATCHED_VAR_NAME`.
    matched: Option<ResolvedValue>,
    /// Values matched by the previous chain member, for `MATCHED_VARS`.
    matched_vars: Vec<ResolvedValue>,
    /// Body processor in effect (`URLENCODED` by default; `JSON` after
    /// `ctl:requestBodyProcessor=JSON`), exposed as `REQBODY_PROCESSOR`.
    body_processor: String,
    /// `ctl:forceRequestBodyVariable=On`: expose the raw body even when a
    /// processor consumes it.
    force_request_body: bool,
    /// `ctl:ruleRemoveById` ids for the rest of the transaction.
    removed_rule_ids: BTreeSet<u64>,
    /// `ctl:ruleRemoveByTag` tags for the rest of the transaction.
    removed_tags: BTreeSet<String>,
    /// `ctl:ruleRemoveTargetByTag` entries: `(tag, target)`.
    removed_targets: Vec<(String, String)>,
    /// Response state for phase-3/4 rules.
    response_status: Option<u16>,
    response_headers: Vec<(String, String)>,
    response_body: Option<Vec<u8>>,
}

/// Decode one form-urlencoded pair while keeping its wire-byte validity.
fn form_arg(name_raw: &[u8], value_raw: &[u8]) -> ArgValue {
    let name = String::from_utf8_lossy(name_raw).replace('+', " ");
    let value = String::from_utf8_lossy(value_raw).replace('+', " ");
    let invalid_utf8 = std::str::from_utf8(name_raw).is_err()
        || std::str::from_utf8(value_raw).is_err()
        || std::str::from_utf8(&crate::normalize::url::multi_decode_bytes(
            &name, 1,
        ))
        .is_err()
        || std::str::from_utf8(&crate::normalize::url::multi_decode_bytes(
            &value, 1,
        ))
        .is_err();
    ArgValue {
        name: crate::normalize::url::multi_decode(&name, 1),
        value: crate::normalize::url::multi_decode(&value, 1),
        invalid_utf8,
    }
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
        let mut args: Vec<ArgValue> = request
            .query()
            .iter()
            .map(|param| ArgValue {
                name: param.name.clone(),
                value: param.value.clone(),
                invalid_utf8: param.invalid_utf8,
            })
            .collect();
        // ModSecurity merges form-urlencoded body parameters into ARGS.
        let content_type = headers
            .iter()
            .find(|(n, _)| n.eq_ignore_ascii_case("content-type"))
            .map(|(_, v)| v.to_ascii_lowercase())
            .unwrap_or_default();
        // Processor selection mirrors ModSecurity: the raw body is consumed
        // by the processor and only re-exposed by
        // `ctl:forceRequestBodyVariable=On`.
        let body_processor =
            if content_type.contains("application/x-www-form-urlencoded") {
                "URLENCODED"
            } else if content_type.contains("multipart/form-data") {
                "MULTIPART"
            } else if content_type.contains("xml") {
                "XML"
            } else {
                "URLENCODED"
            };
        let body = request.body().map(<[u8]>::to_vec);
        let (xml_texts, xml_attributes) = if body_processor == "XML" {
            body.as_deref()
                .map(xml_texts_and_attributes)
                .unwrap_or_default()
        } else {
            (Vec::new(), Vec::new())
        };
        if content_type.contains("application/x-www-form-urlencoded") {
            if let Some(bytes) = &body {
                for pair in bytes.split(|&byte| byte == b'&') {
                    if pair.is_empty() {
                        continue;
                    }
                    let (name_raw, value_raw) =
                        match pair.iter().position(|&byte| byte == b'=') {
                            Some(position) => {
                                (&pair[..position], &pair[position + 1..])
                            },
                            None => (pair, &[][..]),
                        };
                    args.push(form_arg(name_raw, value_raw));
                }
            }
        }
        Self {
            args,
            headers,
            cookies: request
                .cookies()
                .iter()
                .map(|(name, value)| (name.clone(), value.clone()))
                .collect(),
            method: request.method().to_string(),
            uri: request.path().to_string(),
            query_string: request.raw_query().to_string(),
            body,
            xml_texts,
            xml_attributes,
            remote_addr: request
                .client()
                .ip
                .map(|ip| ip.to_string())
                .unwrap_or_default(),
            path_invalid_utf8: request.path_invalid_utf8(),
            tx: BTreeMap::new(),
            collections: BTreeMap::new(),
            http_version: request.http_version().to_string(),
            matched: None,
            matched_vars: Vec::new(),
            body_processor: body_processor.to_string(),
            force_request_body: false,
            removed_rule_ids: BTreeSet::new(),
            removed_tags: BTreeSet::new(),
            removed_targets: Vec::new(),
            response_status: None,
            response_headers: Vec::new(),
            response_body: None,
        }
    }

    /// TX names are case-insensitive (ModSecurity behaviour; CRS mixes
    /// `TX.`/`tx.` casing).
    pub fn tx_set(&mut self, name: &str, value: impl Into<String>) {
        self.tx.insert(name.to_ascii_lowercase(), value.into());
    }

    pub fn tx_get(&self, name: &str) -> Option<&str> {
        self.tx.get(&name.to_ascii_lowercase()).map(String::as_str)
    }

    /// Bind the variable that most recently matched, for `MATCHED_VAR` /
    /// `MATCHED_VAR_NAME` macros.
    pub(crate) fn set_matched(&mut self, matched: Option<ResolvedValue>) {
        self.matched = matched;
    }

    /// Bind the values matched by the previous chain member, for the
    /// `MATCHED_VARS` collection (ModSecurity chain semantics).
    pub(crate) fn set_matched_vars(&mut self, vars: Vec<ResolvedValue>) {
        self.matched_vars = vars;
    }

    /// Record the active body processor (`ctl:requestBodyProcessor`).
    pub(crate) fn set_body_processor(&mut self, processor: &str) {
        self.body_processor = processor.to_string();
    }

    /// `ctl:forceRequestBodyVariable=On`: expose the raw body even when a
    /// processor consumes it.
    pub(crate) fn set_force_request_body(&mut self, force: bool) {
        self.force_request_body = force;
    }

    /// Attach response data for phase-3/4 rules (`RESPONSE_STATUS`,
    /// `RESPONSE_HEADERS`, `RESPONSE_BODY`). The enforcement layer calls
    /// this before evaluating response-phase groups.
    pub fn set_response(
        &mut self,
        status: u16,
        headers: Vec<(String, String)>,
        body: Vec<u8>,
    ) {
        self.response_status = Some(status);
        self.response_headers = headers;
        self.response_body = Some(body);
    }

    /// Parse the request body as JSON and flatten it into `ARGS`, mirroring
    /// ModSecurity's JSON processor naming (`key.`, `.array_N`, dotted
    /// paths). Invalid JSON leaves `ARGS` untouched (the processor failed).
    pub(crate) fn parse_json_body(&mut self) {
        let Some(bytes) = &self.body else {
            return;
        };
        let Ok(value) = serde_json::from_slice::<serde_json::Value>(bytes)
        else {
            return;
        };
        let mut flattened = Vec::new();
        flatten_json(&value, None, &mut Vec::new(), &mut flattened);
        for (name, value) in flattened {
            self.args.push(ArgValue {
                name,
                value,
                invalid_utf8: false,
            });
        }
    }

    /// `ctl:ruleRemoveById`.
    pub(crate) fn remove_rule_id(&mut self, id: u64) {
        self.removed_rule_ids.insert(id);
    }

    /// `ctl:ruleRemoveByTag`.
    pub(crate) fn remove_rule_tag(&mut self, tag: &str) {
        self.removed_tags.insert(tag.to_string());
    }

    /// `ctl:ruleRemoveTargetByTag`.
    pub(crate) fn remove_rule_target(&mut self, tag: &str, target: &str) {
        self.removed_targets
            .push((tag.to_string(), target.to_string()));
    }

    /// `true` when `ctl:ruleRemoveById` disabled this rule.
    pub(crate) fn is_rule_removed(&self, id: u64) -> bool {
        self.removed_rule_ids.contains(&id)
    }

    /// `true` when `ctl:ruleRemoveByTag` disabled this tag.
    pub(crate) fn is_tag_removed(&self, tag: &str) -> bool {
        self.removed_tags.contains(tag)
    }

    /// Targets excluded from a rule carrying any of `tags`
    /// (`ctl:ruleRemoveTargetByTag`).
    pub(crate) fn removed_targets_for(&self, tags: &[String]) -> Vec<String> {
        self.removed_targets
            .iter()
            .filter(|(tag, _)| tags.iter().any(|t| t == tag))
            .map(|(_, target)| target.clone())
            .collect()
    }

    /// Register a collection instance created by `initcol`.
    pub(crate) fn register_collection(&mut self, collection: &str, key: &str) {
        self.collections
            .entry(collection.to_ascii_lowercase())
            .or_default()
            .entry(key.to_string())
            .or_default();
    }

    /// `true` when `initcol` created this collection instance.
    #[cfg(test)]
    pub(crate) fn has_collection(&self, collection: &str, key: &str) -> bool {
        self.collections
            .get(&collection.to_ascii_lowercase())
            .is_some_and(|instances| instances.contains_key(key))
    }

    /// `METHOD target HTTP/x.y`, ModSecurity's `REQUEST_LINE`.
    fn request_line(&self) -> String {
        if self.query_string.is_empty() {
            format!("{} {} {}", self.method, self.uri, self.http_version)
        } else {
            format!(
                "{} {}?{} {}",
                self.method, self.uri, self.query_string, self.http_version
            )
        }
    }

    /// Resolve one variable reference (`NAME` or `NAME:selector`). A leading
    /// `&` requests the instance count (`&TX:foo` → `0`/`1`), mirroring
    /// ModSecurity.
    pub fn resolve(&self, reference: &str) -> Vec<ResolvedValue> {
        if let Some(inner) = reference.strip_prefix('&') {
            let count = self.resolve(inner).len();
            return vec![ResolvedValue {
                name: format!("&{inner}"),
                value: count.to_string(),
                invalid_utf8: false,
            }];
        }
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
                .map(|arg| ResolvedValue {
                    name: format!("ARGS:{}", arg.name),
                    value: arg.value.clone(),
                    invalid_utf8: arg.invalid_utf8,
                })
                .collect()),
            ("ARGS", Some(selector)) => cap(self
                .args
                .iter()
                .filter(|arg| arg.name == selector)
                .map(|arg| ResolvedValue {
                    name: format!("ARGS:{}", arg.name),
                    value: arg.value.clone(),
                    invalid_utf8: arg.invalid_utf8,
                })
                .collect()),
            ("ARGS_NAMES", _) => cap(self
                .args
                .iter()
                .map(|arg| ResolvedValue {
                    name: "ARGS_NAMES".to_string(),
                    value: arg.name.clone(),
                    invalid_utf8: arg.invalid_utf8,
                })
                .collect()),
            ("REQUEST_HEADERS", None) => cap(self
                .headers
                .iter()
                .map(|(n, v)| ResolvedValue {
                    name: format!("REQUEST_HEADERS:{n}"),
                    value: v.clone(),
                    invalid_utf8: false,
                })
                .collect()),
            ("REQUEST_HEADERS", Some(selector)) => cap(self
                .headers
                .iter()
                .filter(|(n, _)| n.eq_ignore_ascii_case(selector))
                .map(|(n, v)| ResolvedValue {
                    name: format!("REQUEST_HEADERS:{n}"),
                    value: v.clone(),
                    invalid_utf8: false,
                })
                .collect()),
            ("REQUEST_COOKIES", None) => cap(self
                .cookies
                .iter()
                .map(|(n, v)| ResolvedValue {
                    name: format!("REQUEST_COOKIES:{n}"),
                    value: v.clone(),
                    invalid_utf8: false,
                })
                .collect()),
            ("REQUEST_COOKIES", Some(selector)) => cap(self
                .cookies
                .iter()
                .filter(|(n, _)| n == selector)
                .map(|(n, v)| ResolvedValue {
                    name: format!("REQUEST_COOKIES:{n}"),
                    value: v.clone(),
                    invalid_utf8: false,
                })
                .collect()),
            ("REQUEST_COOKIES_NAMES", _) => cap(self
                .cookies
                .iter()
                .map(|(n, _)| ResolvedValue {
                    name: "REQUEST_COOKIES_NAMES".to_string(),
                    value: n.clone(),
                    invalid_utf8: false,
                })
                .collect()),
            ("REQUEST_METHOD", _) => cap(vec![ResolvedValue {
                name: "REQUEST_METHOD".to_string(),
                value: self.method.clone(),
                invalid_utf8: false,
            }]),
            ("REQUEST_URI", _) => cap(vec![ResolvedValue {
                name: "REQUEST_URI".to_string(),
                value: self.uri.clone(),
                invalid_utf8: false,
            }]),
            ("REQUEST_FILENAME", _) => cap(vec![ResolvedValue {
                name: "REQUEST_FILENAME".to_string(),
                value: self.uri.clone(),
                invalid_utf8: self.path_invalid_utf8,
            }]),
            ("QUERY_STRING", _) => cap(vec![ResolvedValue {
                name: "QUERY_STRING".to_string(),
                value: self.query_string.clone(),
                invalid_utf8: false,
            }]),
            ("REQUEST_LINE", _) => cap(vec![ResolvedValue {
                name: "REQUEST_LINE".to_string(),
                value: self.request_line(),
                invalid_utf8: false,
            }]),
            ("REQUEST_BODY", _) => cap(
                if self.body_processor == "XML" && !self.force_request_body {
                    // The XML processor consumes the raw body; only `XML:/*`
                    // values would carry its text, and the raw bytes are not
                    // exposed unless forced.
                    Vec::new()
                } else {
                    self.body
                        .iter()
                        .map(|body| ResolvedValue {
                            name: "REQUEST_BODY".to_string(),
                            value: String::from_utf8_lossy(body).into_owned(),
                            invalid_utf8: std::str::from_utf8(body).is_err(),
                        })
                        .collect()
                },
            ),
            ("RESPONSE_STATUS", _) => cap(self
                .response_status
                .map(|status| ResolvedValue {
                    name: "RESPONSE_STATUS".to_string(),
                    value: status.to_string(),
                    invalid_utf8: false,
                })
                .into_iter()
                .collect()),
            ("RESPONSE_HEADERS", None) => cap(self
                .response_headers
                .iter()
                .map(|(n, v)| ResolvedValue {
                    name: format!("RESPONSE_HEADERS:{n}"),
                    value: v.clone(),
                    invalid_utf8: false,
                })
                .collect()),
            ("RESPONSE_HEADERS", Some(selector)) => cap(self
                .response_headers
                .iter()
                .filter(|(n, _)| n.eq_ignore_ascii_case(selector))
                .map(|(n, v)| ResolvedValue {
                    name: format!("RESPONSE_HEADERS:{n}"),
                    value: v.clone(),
                    invalid_utf8: false,
                })
                .collect()),
            ("RESPONSE_BODY", _) => cap(self
                .response_body
                .iter()
                .map(|body| ResolvedValue {
                    name: "RESPONSE_BODY".to_string(),
                    value: String::from_utf8_lossy(body).into_owned(),
                    invalid_utf8: std::str::from_utf8(body).is_err(),
                })
                .collect()),
            ("XML", Some("/*")) => cap(self
                .xml_texts
                .iter()
                .map(|text| ResolvedValue {
                    name: "XML:/*".to_string(),
                    value: text.clone(),
                    invalid_utf8: false,
                })
                .collect()),
            ("XML", Some("//@*")) => cap(self
                .xml_attributes
                .iter()
                .map(|text| ResolvedValue {
                    name: "XML://@*".to_string(),
                    value: text.clone(),
                    invalid_utf8: false,
                })
                .collect()),
            ("REMOTE_ADDR", _) => cap(vec![ResolvedValue {
                name: "REMOTE_ADDR".to_string(),
                value: self.remote_addr.clone(),
                invalid_utf8: false,
            }]),
            ("MATCHED_VARS", _) => cap(self.matched_vars.clone()),
            ("REQBODY_PROCESSOR", _) => cap(vec![ResolvedValue {
                name: "REQBODY_PROCESSOR".to_string(),
                value: self.body_processor.clone(),
                invalid_utf8: false,
            }]),
            ("TX", Some(selector)) => {
                // `TX:/regex/` selects variables by name (ModSecurity).
                if let Some(regex_body) = selector
                    .strip_prefix('/')
                    .and_then(|rest| rest.strip_suffix('/'))
                {
                    let Ok(regex) = Regex::new(regex_body) else {
                        return Vec::new();
                    };
                    cap(self
                        .tx
                        .iter()
                        .filter(|(name, _)| regex.is_match(name))
                        .map(|(name, value)| ResolvedValue {
                            name: format!("TX:{name}"),
                            value: value.clone(),
                            invalid_utf8: false,
                        })
                        .collect())
                } else {
                    cap(self
                        .tx
                        .get(&selector.to_ascii_lowercase())
                        .map(|value| {
                            vec![ResolvedValue {
                                name: format!("TX:{selector}"),
                                value: value.clone(),
                                invalid_utf8: false,
                            }]
                        })
                        .unwrap_or_default())
                }
            },
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
    /// `multiMatch`: record every matching value, not just the first per
    /// variable.
    multi_match: bool,
}

/// ModSecurity transformation applied to a value before the operator runs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Transform {
    Lowercase,
    Trim,
    CompressWhitespace,
    RemoveNulls,
    UrlDecode,
    UrlDecodeUni,
    HtmlEntityDecode,
    Base64Decode,
    RemoveWhitespace,
    CmdLine,
    JsDecode,
    ReplaceComments,
    NormalizePath,
    NormalizePathWin,
    Utf8ToUnicode,
    RemoveCommentsChar,
    EscapeSeqDecode,
    CssDecode,
    Sha1,
    HexEncode,
    Length,
}

impl Transform {
    fn parse(name: &str) -> Option<Self> {
        match name.trim().to_ascii_lowercase().as_str() {
            "lowercase" => Some(Self::Lowercase),
            "trim" => Some(Self::Trim),
            "compresswhitespace" => Some(Self::CompressWhitespace),
            "removenulls" => Some(Self::RemoveNulls),
            // `urlDecode` decodes one percent layer here; the canonical
            // request already applied the shared bounded decoding, and a
            // second layer is intentionally left to the rule author.
            "urldecode" => Some(Self::UrlDecode),
            // `urlDecodeUni` also decodes IIS `%uXXXX` escapes and `+`.
            "urldecodeuni" => Some(Self::UrlDecodeUni),
            "htmlentitydecode" => Some(Self::HtmlEntityDecode),
            "base64decode" => Some(Self::Base64Decode),
            "removewhitespace" => Some(Self::RemoveWhitespace),
            "cmdline" => Some(Self::CmdLine),
            "jsdecode" => Some(Self::JsDecode),
            "replacecomments" => Some(Self::ReplaceComments),
            "normalizepath" => Some(Self::NormalizePath),
            "normalizepathwin" => Some(Self::NormalizePathWin),
            "removecommentschar" => Some(Self::RemoveCommentsChar),
            "escapeseqdecode" => Some(Self::EscapeSeqDecode),
            "cssdecode" => Some(Self::CssDecode),
            "sha1" => Some(Self::Sha1),
            "hexencode" => Some(Self::HexEncode),
            "length" => Some(Self::Length),
            "utf8tounicode" => Some(Self::Utf8ToUnicode),
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
            Self::UrlDecodeUni => url_decode_uni(value),
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
            Self::ReplaceComments => replace_comments(value),
            Self::NormalizePath => normalize_path(value, false),
            Self::NormalizePathWin => normalize_path(value, true),
            Self::RemoveCommentsChar => remove_comments_char(value),
            Self::EscapeSeqDecode => escape_seq_decode(value),
            Self::CssDecode => css_decode(value),
            // ModSecurity emits the raw 20 digest bytes; in a string-valued
            // engine we emit the lowercase hex digest instead (documented in
            // `docs/compatibility.md`).
            Self::Sha1 => sha1_hex(value),
            Self::HexEncode => hex_encode(value),
            // ModSecurity `length`: byte length as a decimal string.
            Self::Length => value.len().to_string(),
            Self::Utf8ToUnicode => utf8_to_unicode(value),
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

/// ModSecurity `urlDecodeUni`: single-pass decode of `%XX`, IIS-style
/// `%uXXXX` (lower byte with a full-width ASCII adjustment), and `+` as
/// space. Invalid or truncated escapes stay literal.
fn url_decode_uni(value: &str) -> String {
    let input = value.as_bytes();
    let len = input.len();
    let mut out: Vec<u8> = Vec::with_capacity(len);
    let mut i = 0;
    while i < len {
        if input[i] != b'%' {
            if input[i] == b'+' {
                out.push(b' ');
            } else {
                out.push(input[i]);
            }
            i += 1;
            continue;
        }
        if i + 1 < len && (input[i + 1] == b'u' || input[i + 1] == b'U') {
            if i + 5 < len
                && input[i + 2].is_ascii_hexdigit()
                && input[i + 3].is_ascii_hexdigit()
                && input[i + 4].is_ascii_hexdigit()
                && input[i + 5].is_ascii_hexdigit()
            {
                let mut byte = hex_byte(input[i + 4], input[i + 5]);
                // Full width ASCII (ff01 - ff5e) needs 0x20 added.
                if byte > 0x00
                    && byte < 0x5f
                    && (input[i + 2] == b'f' || input[i + 2] == b'F')
                    && (input[i + 3] == b'f' || input[i + 3] == b'F')
                {
                    byte += 0x20;
                }
                out.push(byte);
                i += 6;
            } else {
                // Invalid or truncated `%u`: keep it literal.
                out.push(input[i]);
                out.push(input[i + 1]);
                i += 2;
            }
        } else if i + 2 < len
            && input[i + 1].is_ascii_hexdigit()
            && input[i + 2].is_ascii_hexdigit()
        {
            out.push(hex_byte(input[i + 1], input[i + 2]));
            i += 3;
        } else {
            out.push(input[i]);
            i += 1;
        }
    }
    // Latin-1 mapping keeps high bytes scannable (mirrors the bounded
    // decoder used by the canonical request).
    out.iter().map(|&byte| byte as char).collect()
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

/// SHA-1 digest (RFC 3174), used by the `sha1` transform.
fn sha1_digest(input: &[u8]) -> [u8; 20] {
    let mut state: [u32; 5] =
        [0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476, 0xC3D2E1F0];
    let bit_len = (input.len() as u64) * 8;
    let mut message = input.to_vec();
    message.push(0x80);
    while message.len() % 64 != 56 {
        message.push(0);
    }
    message.extend_from_slice(&bit_len.to_be_bytes());
    for chunk in message.as_chunks::<64>().0 {
        let mut words = [0u32; 80];
        for (index, word) in chunk.as_chunks::<4>().0.iter().enumerate() {
            words[index] =
                u32::from_be_bytes([word[0], word[1], word[2], word[3]]);
        }
        for index in 16..80 {
            words[index] = (words[index - 3]
                ^ words[index - 8]
                ^ words[index - 14]
                ^ words[index - 16])
                .rotate_left(1);
        }
        let (mut a, mut b, mut c, mut d, mut e) =
            (state[0], state[1], state[2], state[3], state[4]);
        for (index, word) in words.iter().enumerate() {
            let (f, k) = match index {
                0..=19 => ((b & c) | ((!b) & d), 0x5A827999u32),
                20..=39 => (b ^ c ^ d, 0x6ED9EBA1),
                40..=59 => ((b & c) | (b & d) | (c & d), 0x8F1BBCDC),
                _ => (b ^ c ^ d, 0xCA62C1D6),
            };
            let temp = a
                .rotate_left(5)
                .wrapping_add(f)
                .wrapping_add(e)
                .wrapping_add(k)
                .wrapping_add(*word);
            e = d;
            d = c;
            c = b.rotate_left(30);
            b = a;
            a = temp;
        }
        state[0] = state[0].wrapping_add(a);
        state[1] = state[1].wrapping_add(b);
        state[2] = state[2].wrapping_add(c);
        state[3] = state[3].wrapping_add(d);
        state[4] = state[4].wrapping_add(e);
    }
    let mut digest = [0u8; 20];
    for (index, word) in state.iter().enumerate() {
        digest[index * 4..index * 4 + 4].copy_from_slice(&word.to_be_bytes());
    }
    digest
}

/// Lowercase hex SHA-1 digest (see the `sha1` transform note above).
fn sha1_hex(value: &str) -> String {
    let digest = sha1_digest(value.as_bytes());
    let mut out = String::with_capacity(40);
    for byte in digest {
        out.push_str(&format!("{byte:02x}"));
    }
    out
}

/// ModSecurity `hexEncode`: lowercase hex of every byte; empty stays empty.
fn hex_encode(value: &str) -> String {
    if value.is_empty() {
        return String::new();
    }
    let mut out = String::with_capacity(value.len() * 2);
    for byte in value.bytes() {
        out.push_str(&format!("{byte:02x}"));
    }
    out
}

/// ModSecurity `replaceComments`: `/* … */` spans collapse to one space; an
/// unterminated comment also ends with one space.
fn replace_comments(value: &str) -> String {
    let input = value.as_bytes();
    let mut out: Vec<u8> = Vec::with_capacity(input.len());
    let mut in_comment = false;
    let mut i = 0;
    while i < input.len() {
        if !in_comment {
            if input[i] == b'/' && i + 1 < input.len() && input[i + 1] == b'*' {
                in_comment = true;
                i += 2;
            } else {
                out.push(input[i]);
                i += 1;
            }
        } else if input[i] == b'*'
            && i + 1 < input.len()
            && input[i + 1] == b'/'
        {
            in_comment = false;
            i += 2;
            out.push(b' ');
        } else {
            i += 1;
        }
    }
    if in_comment {
        out.push(b' ');
    }
    String::from_utf8_lossy(&out).to_string()
}

/// ModSecurity `normalizePath`, a faithful port of `normalize_path_inplace`:
/// collapses duplicate slashes, resolves `.` and `..` segments, never rises
/// above the root, and preserves an absent/present trailing slash.
fn normalize_path(value: &str, win: bool) -> String {
    let mut buf = value.as_bytes().to_vec();
    if buf.is_empty() {
        return String::new();
    }
    let end = buf.len() - 1;
    // `relative` mirrors ModSecurity's variable: 1 when the path does NOT
    // start with a slash.
    let relative = usize::from(!(buf[0] == b'/' || (win && buf[0] == b'\\')));
    let trailing = usize::from(buf[end] == b'/' || (win && buf[end] == b'\\'));
    let mut hitroot = 0usize;
    let mut src = 0usize;
    let mut dst = 0usize;
    let mut done = false;
    while !done && src <= end && dst <= end {
        if win {
            if buf[src] == b'\\' {
                buf[src] = b'/';
            }
            if src < end && buf[src + 1] == b'\\' {
                buf[src + 1] = b'/';
            }
        }
        let mut skip_copy = false;
        if src == end {
            done = true;
        } else if buf[src + 1] != b'/' {
            // Not the end of a path segment: copy below.
        } else if buf[src] == b'/' {
            // Empty path segment: the copy step collapses it.
        } else if buf[src] == b'.' {
            if dst > 0 && buf[dst - 1] == b'.' {
                if relative == 1 && (hitroot == 1 || dst <= 2) {
                    // Backref at the root of a relative path: keep as-is.
                    hitroot = 1;
                } else {
                    dst = dst.saturating_sub(3);
                    while dst > 0 && buf[dst] != b'/' {
                        dst -= 1;
                    }
                    if dst == 0 {
                        hitroot = 1;
                        if relative == 0 && src == end {
                            dst += 1;
                        }
                    }
                    if done {
                        skip_copy = true;
                    } else {
                        src += 1;
                    }
                }
            } else if dst == 0 {
                // Relative self-reference at the start: ignore.
                if done {
                    skip_copy = true;
                } else {
                    src += 1;
                }
            } else if buf[dst - 1] == b'/' {
                // Self-reference: drop the dot.
                if done {
                    skip_copy = true;
                } else {
                    dst -= 1;
                    src += 1;
                }
            }
        } else if dst > 0 {
            hitroot = 0;
        }
        if !skip_copy {
            if buf[src] == b'/' {
                while src < end && buf[src + 1] == b'/' {
                    src += 1;
                }
                if relative == 1 && dst == 0 {
                    src += 1;
                    continue;
                }
            }
            buf[dst] = buf[src];
            dst += 1;
            src += 1;
        }
    }
    if trailing == 0 && dst > 0 && buf[dst - 1] == b'/' {
        dst -= 1;
    }
    String::from_utf8_lossy(&buf[..dst]).to_string()
}

/// ModSecurity `utf8ToUnicode`: multi-byte UTF-8 sequences become `%uXXXX`
/// text (lowercase hex). Malformed sequences reproduce upstream behaviour
/// byte for byte: overlong/surrogate encodings emit the escape *and* the raw
/// lead byte, truncated leads are dropped, stray continuation bytes are kept.
fn utf8_to_unicode(value: &str) -> String {
    let input = value.as_bytes();
    let mut out: Vec<u8> = Vec::with_capacity(input.len() * 2);
    let mut i = 0usize;
    while i < input.len() {
        let c = input[i];
        let left = input.len() - i;
        let mut unicode_len = 0usize;
        let mut code: u32 = 0;
        if c & 0x80 == 0 {
            out.push(c);
        } else if c & 0xE0 == 0xC0 {
            if left < 2 || input[i + 1] & 0xC0 != 0x80 {
                // Missing/invalid continuation: the lead byte is dropped.
                i += 1;
                continue;
            }
            unicode_len = 2;
            code = ((c as u32 & 0x1F) << 6) | (input[i + 1] as u32 & 0x3F);
            push_unicode_escape(&mut out, code);
        } else if c & 0xF0 == 0xE0 {
            if left < 3
                || input[i + 1] & 0xC0 != 0x80
                || input[i + 2] & 0xC0 != 0x80
            {
                i += 1;
                continue;
            }
            unicode_len = 3;
            code = ((c as u32 & 0x0F) << 12)
                | ((input[i + 1] as u32 & 0x3F) << 6)
                | (input[i + 2] as u32 & 0x3F);
            push_unicode_escape(&mut out, code);
        } else if c & 0xF8 == 0xF0 {
            if c >= 0xF5 {
                // Outside the UTF-8 range: the byte survives raw.
                out.push(c);
            }
            if left < 4
                || input[i + 1] & 0xC0 != 0x80
                || input[i + 2] & 0xC0 != 0x80
                || input[i + 3] & 0xC0 != 0x80
            {
                i += 1;
                continue;
            }
            unicode_len = 4;
            code = ((c as u32 & 0x07) << 18)
                | ((input[i + 1] as u32 & 0x3F) << 12)
                | ((input[i + 2] as u32 & 0x3F) << 6)
                | (input[i + 3] as u32 & 0x3F);
            push_unicode_escape(&mut out, code);
        } else {
            // Any other lead byte is invalid (RFC 3629).
            out.push(c);
            i += 1;
            continue;
        }
        // Surrogates and overlong encodings keep the raw lead byte too,
        // mirroring ModSecurity.
        let surrogate = (0xD800..=0xDFFF).contains(&code);
        let overlong = (unicode_len == 4 && code < 0x010000)
            || (unicode_len == 3 && code < 0x0800)
            || (unicode_len == 2 && code < 0x80);
        if surrogate || overlong {
            out.push(c);
        }
        if unicode_len > 0 {
            i += unicode_len;
        } else {
            i += 1;
        }
    }
    String::from_utf8_lossy(&out).to_string()
}

fn push_unicode_escape(out: &mut Vec<u8>, code: u32) {
    let escape = if code < 0x10000 {
        format!("%u{code:04x}")
    } else {
        // Four-byte characters can exceed four hex digits; ModSecurity pads
        // only up to four.
        format!("%u{code:x}")
    };
    out.extend_from_slice(escape.as_bytes());
}

/// ModSecurity `removeCommentsChar`: strips comment *delimiters* only
/// (`/*`, `*/`, `<!--`, `-->`, `--`, `#`), keeping the contents.
fn remove_comments_char(value: &str) -> String {
    let input = value.as_bytes();
    let mut out: Vec<u8> = Vec::with_capacity(input.len());
    let mut s = 0usize;
    while s < input.len() {
        let opens =
            input[s] == b'/' && s + 1 < input.len() && input[s + 1] == b'*';
        let closes =
            input[s] == b'*' && s + 1 < input.len() && input[s + 1] == b'/';
        if opens || closes {
            s += 2;
        } else if input[s] == b'<'
            && s + 3 < input.len()
            && input[s + 1] == b'!'
            && input[s + 2] == b'-'
            && input[s + 3] == b'-'
        {
            s += 4;
        } else if input[s] == b'-'
            && s + 2 < input.len()
            && input[s + 1] == b'-'
            && input[s + 2] == b'>'
        {
            s += 3;
        } else if input[s] == b'-'
            && s + 1 < input.len()
            && input[s + 1] == b'-'
        {
            s += 2;
        } else if input[s] == b'#' {
            s += 1;
        } else {
            out.push(input[s]);
            s += 1;
        }
    }
    String::from_utf8_lossy(&out).to_string()
}

/// ModSecurity `escapeSeqDecode`: ANSI C escapes (`\a \b \f \n \r \t \v \\
/// \? \' \"`), `\xHH`, and octal `\OOO`. An invalid `\x` keeps the `x` raw.
fn escape_seq_decode(value: &str) -> String {
    let input = value.as_bytes();
    let mut out: Vec<u8> = Vec::with_capacity(input.len());
    let mut i = 0usize;
    while i < input.len() {
        if input[i] != b'\\' || i + 1 >= input.len() {
            out.push(input[i]);
            i += 1;
            continue;
        }
        let mut decoded: Option<u8> = None;
        match input[i + 1] {
            b'a' => decoded = Some(0x07),
            b'b' => decoded = Some(0x08),
            b'f' => decoded = Some(0x0c),
            b'n' => decoded = Some(b'\n'),
            b'r' => decoded = Some(b'\r'),
            b't' => decoded = Some(b'\t'),
            b'v' => decoded = Some(0x0b),
            b'\\' => decoded = Some(b'\\'),
            b'?' => decoded = Some(b'?'),
            b'\'' => decoded = Some(b'\''),
            b'"' => decoded = Some(b'"'),
            _ => {},
        }
        if decoded.is_some() {
            i += 2;
        } else if input[i + 1] == b'x' || input[i + 1] == b'X' {
            if i + 3 < input.len()
                && input[i + 2].is_ascii_hexdigit()
                && input[i + 3].is_ascii_hexdigit()
            {
                decoded = Some(hex_byte(input[i + 2], input[i + 3]));
                i += 4;
            }
        } else if (b'0'..=b'7').contains(&input[i + 1]) {
            let mut j = 0usize;
            let mut buf = [0u8; 3];
            while i + 1 + j < input.len() && j < 3 {
                buf[j] = input[i + 1 + j];
                j += 1;
                if i + 1 + j >= input.len()
                    || !(b'0'..=b'7').contains(&input[i + 1 + j])
                {
                    break;
                }
            }
            let text = std::str::from_utf8(&buf[..j]).unwrap_or("");
            // Up to three octal digits (values above 255 truncate as in C).
            decoded = Some(u32::from_str_radix(text, 8).unwrap_or(0) as u8);
            i += 1 + j;
        }
        match decoded {
            Some(byte) => out.push(byte),
            None => {
                // Unrecognised escape: copy the byte after the backslash.
                out.push(input[i + 1]);
                i += 2;
            },
        }
    }
    String::from_utf8_lossy(&out).to_string()
}

fn single_hex(byte: u8) -> u8 {
    match byte {
        b'0'..=b'9' => byte - b'0',
        b'a'..=b'f' => byte - b'a' + 10,
        _ => byte - b'A' + 10,
    }
}

/// ModSecurity `cssDecode`: CSS hex escapes of one to six digits, using the
/// last two digits with a full-width (`ff01`–`ff5e`) adjustment; one
/// whitespace after an escape is consumed; backslash-newline is swallowed.
fn css_decode(value: &str) -> String {
    let input = value.as_bytes();
    let len = input.len();
    let mut out: Vec<u8> = Vec::with_capacity(len);
    let mut i = 0usize;
    while i < len {
        if input[i] != b'\\' {
            out.push(input[i]);
            i += 1;
            continue;
        }
        if i + 1 >= len {
            // Backslash at the very end: dropped.
            i += 1;
            continue;
        }
        i += 1; // Skip the backslash.
        let mut j = 0usize;
        while j < 6 && i + j < len && input[i + j].is_ascii_hexdigit() {
            j += 1;
        }
        if j > 0 {
            let mut fullcheck = false;
            let byte = match j {
                1 => single_hex(input[i]),
                2 | 3 => hex_byte(input[i + j - 2], input[i + j - 1]),
                4 => {
                    fullcheck = true;
                    hex_byte(input[i + j - 2], input[i + j - 1])
                },
                5 => {
                    if input[i] == b'0' {
                        fullcheck = true;
                    }
                    hex_byte(input[i + j - 2], input[i + j - 1])
                },
                _ => {
                    if input[i] == b'0' && input[i + 1] == b'0' {
                        fullcheck = true;
                    }
                    hex_byte(input[i + j - 2], input[i + j - 1])
                },
            };
            out.push(byte);
            if fullcheck {
                if let Some(last) = out.last_mut() {
                    if *last > 0
                        && *last < 0x5f
                        && (input[i + j - 3] == b'f'
                            || input[i + j - 3] == b'F')
                        && (input[i + j - 4] == b'f'
                            || input[i + j - 4] == b'F')
                    {
                        *last += 0x20;
                    }
                }
            }
            if i + j < len && input[i + j].is_ascii_whitespace() {
                j += 1;
            }
            i += j;
        } else if input[i] == b'\n' {
            // Backslash-newline: both swallowed.
            i += 1;
        } else {
            // No hex digits: the character after the backslash is used as-is.
            out.push(input[i]);
            i += 1;
        }
    }
    String::from_utf8_lossy(&out).to_string()
}

/// Case-insensitive action prefix stripping (`t:`, `setvar:`, …): the
/// validator accepts ModSecurity's case-insensitive action names, so the
/// execution paths must match every spelling it accepts.
fn strip_prefix_ignore_case<'a>(
    value: &'a str,
    prefix: &str,
) -> Option<&'a str> {
    let head = value.get(..prefix.len())?;
    head.eq_ignore_ascii_case(prefix)
        .then(|| &value[prefix.len()..])
}

/// Collect `t:` actions in order; an unknown transformation is an observable
/// error (mandate §37: unsupported SecLang must never be silently ignored).
fn parse_transforms(
    actions: &[String],
) -> Result<Vec<Transform>, SecLangError> {
    let mut transforms = Vec::new();
    for action in actions {
        let Some(name) = strip_prefix_ignore_case(action.trim(), "t:") else {
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

/// Resolve one macro token (`tx.name`, `matched_var`, `remote_addr`,
/// `request_line`, `request_headers.<name>`, `args.<name>`) against the
/// transaction.
fn macro_value(token: &str, txn: &SecLangTransaction) -> Option<String> {
    let (collection, selector) = match token.split_once('.') {
        Some((collection, selector)) => (collection, Some(selector)),
        None => (token, None),
    };
    match collection.to_ascii_lowercase().as_str() {
        "tx" => txn.tx_get(selector.unwrap_or_default()).map(str::to_string),
        "matched_var" => txn.matched.as_ref().map(|m| m.value.clone()),
        "matched_var_name" => txn.matched.as_ref().map(|m| m.name.clone()),
        "remote_addr" => {
            txn.resolve("REMOTE_ADDR").first().map(|v| v.value.clone())
        },
        "request_line" => {
            txn.resolve("REQUEST_LINE").first().map(|v| v.value.clone())
        },
        "request_headers" => selector.and_then(|selector| {
            txn.resolve(&format!("REQUEST_HEADERS:{selector}"))
                .first()
                .map(|v| v.value.clone())
        }),
        "args" => selector.and_then(|selector| {
            txn.resolve(&format!("ARGS:{selector}"))
                .first()
                .map(|v| v.value.clone())
        }),
        _ => None,
    }
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
        let value = macro_value(token, txn).unwrap_or_default();
        output.push_str(&value);
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

/// `!VAR`, `!VAR:selector`, or `!VAR:/regex/` exclusion against a resolved
/// value name (`ARGS:name`, `REQUEST_COOKIES:name`, …).
fn matches_exclusion(exclusion: &str, name: &str) -> bool {
    let Some(pattern) = exclusion.strip_prefix('!') else {
        return false;
    };
    let Some((collection, selector)) = pattern.split_once(':') else {
        return name == pattern;
    };
    let Some(regex_body) = selector
        .strip_prefix('/')
        .and_then(|rest| rest.strip_suffix('/'))
    else {
        return name == pattern;
    };
    let Ok(regex) = Regex::new(regex_body) else {
        return name == pattern;
    };
    let Some((name_collection, name_selector)) = name.split_once(':') else {
        return false;
    };
    name_collection == collection && regex.is_match(name_selector)
}

/// Minimal XML scan for the `XML:/*` (element text) and `XML://@*`
/// (attribute value) collections: element and attribute *names* are never
/// values, mirroring ModSecurity's processor.
fn xml_texts_and_attributes(body: &[u8]) -> (Vec<String>, Vec<String>) {
    let text = String::from_utf8_lossy(body);
    let mut texts = Vec::new();
    let mut attributes = Vec::new();
    let mut i = 0;
    while i < text.len() {
        if text.as_bytes()[i] == b'<' {
            let Some(end) = text[i..].find('>') else {
                break;
            };
            attributes.extend(xml_attribute_values(&text[i + 1..i + end]));
            i += end + 1;
        } else {
            let next = text[i..]
                .find('<')
                .map(|offset| i + offset)
                .unwrap_or(text.len());
            let chunk = text[i..next].trim();
            if !chunk.is_empty() {
                texts.push(chunk.to_string());
            }
            i = next;
        }
    }
    (texts, attributes)
}

/// Attribute values inside one tag body (`name="value"` / `name='value'`).
fn xml_attribute_values(tag: &str) -> Vec<String> {
    let bytes = tag.as_bytes();
    let mut values = Vec::new();
    let mut i = 0;
    // Skip the element name (and any namespace prefix separator).
    while i < bytes.len() && !bytes[i].is_ascii_whitespace() && bytes[i] != b'/'
    {
        i += 1;
    }
    while i < bytes.len() {
        while i < bytes.len()
            && (bytes[i].is_ascii_whitespace() || bytes[i] == b'/')
        {
            i += 1;
        }
        while i < bytes.len()
            && bytes[i] != b'='
            && !bytes[i].is_ascii_whitespace()
        {
            i += 1;
        }
        while i < bytes.len() && bytes[i].is_ascii_whitespace() {
            i += 1;
        }
        if i >= bytes.len() || bytes[i] != b'=' {
            continue;
        }
        i += 1;
        while i < bytes.len() && bytes[i].is_ascii_whitespace() {
            i += 1;
        }
        if i >= bytes.len() || (bytes[i] != b'"' && bytes[i] != b'\'') {
            continue;
        }
        let quote = bytes[i];
        i += 1;
        let start = i;
        while i < bytes.len() && bytes[i] != quote {
            i += 1;
        }
        values.push(tag[start..i].to_string());
        i += 1;
    }
    values
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
        let multi_match = line
            .actions
            .iter()
            .any(|a| a.trim().eq_ignore_ascii_case("multimatch"));
        Ok(Self {
            line,
            regex,
            ips,
            transforms,
            multi_match,
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
        self.matches_excluding(txn, &[])
    }

    /// Like [`Self::matches`], with targets excluded from evaluation
    /// (`ctl:ruleRemoveTargetByTag`).
    pub fn matches_excluding(
        &self,
        txn: &SecLangTransaction,
        excluded: &[String],
    ) -> Vec<ResolvedValue> {
        if matches!(self.line.operator, SecOperator::AlwaysMatch) {
            // `SecAction`: unconditional, no variables.
            return vec![ResolvedValue {
                name: "ACTION".to_string(),
                value: String::new(),
                invalid_utf8: false,
            }];
        }
        let exclusions: Vec<&String> = self
            .line
            .variables
            .iter()
            .filter(|reference| reference.starts_with('!'))
            .collect();
        let mut hits = Vec::new();
        for reference in &self.line.variables {
            if reference.starts_with('!') {
                continue;
            }
            if excluded.iter().any(|target| target == reference) {
                continue;
            }
            for value in txn.resolve(reference) {
                if exclusions
                    .iter()
                    .any(|exclusion| matches_exclusion(exclusion, &value.name))
                {
                    continue;
                }
                if self.operator_matches(&value, txn) != self.line.negated {
                    hits.push(value);
                    if !self.multi_match {
                        break;
                    }
                }
            }
        }
        hits
    }

    /// `tag:'…'` values on this rule.
    pub(crate) fn tags(&self) -> Vec<String> {
        self.line
            .actions
            .iter()
            .filter_map(|action| {
                let value = strip_prefix_ignore_case(action.trim(), "tag:")?;
                Some(
                    value
                        .trim()
                        .trim_matches('\'')
                        .trim_matches('"')
                        .to_string(),
                )
            })
            .collect()
    }

    fn operator_matches(
        &self,
        resolved: &ResolvedValue,
        txn: &SecLangTransaction,
    ) -> bool {
        let transformed = self.apply_transforms(&resolved.value);
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
                // Matches when any byte falls OUTSIDE the ranges: the
                // operator detects invalid characters (ModSecurity
                // semantics), it does not validate conformity.
                value.bytes().any(|byte| {
                    !ranges
                        .iter()
                        .any(|(start, end)| byte >= *start && byte <= *end)
                })
            },
            SecOperator::PmFromFile(_) => false,
            SecOperator::ValidateUtf8Encoding => resolved.invalid_utf8,
            SecOperator::ValidateUrlEncoding => {
                !value.is_empty() && {
                    let bytes = value.as_bytes();
                    let mut index = 0;
                    let mut invalid = false;
                    while index < bytes.len() {
                        if bytes[index] != b'%' {
                            index += 1;
                            continue;
                        }
                        if index + 2 >= bytes.len()
                            || !bytes[index + 1].is_ascii_hexdigit()
                            || !bytes[index + 2].is_ascii_hexdigit()
                        {
                            invalid = true;
                            break;
                        }
                        index += 3;
                    }
                    invalid
                }
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

    /// Apply this rule's transforms to a value (used to bind `MATCHED_VARS`
    /// for the next chain member, which sees transformed values).
    pub(crate) fn transformed(&self, value: &str) -> String {
        self.apply_transforms(value)
    }

    /// `true` when the rule's actions include `capture`.
    pub(crate) fn has_capture(&self) -> bool {
        self.line
            .actions
            .iter()
            .any(|a| a.trim().eq_ignore_ascii_case("capture"))
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
        let chained = line
            .actions
            .iter()
            .any(|a| a.trim().eq_ignore_ascii_case("chain"));
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
    use super::{
        expand_macros, sha1_hex, CompiledSecRule, ResolvedValue,
        SecLangTransaction, Transform,
    };
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
    fn request_line_and_macro_collections_resolve() {
        let mut txn = SecLangTransaction::from_request(&request());
        let line = txn.resolve("REQUEST_LINE");
        assert_eq!(line[0].value, "POST /api/items?id=42&q=hello HTTP/1.1");
        txn.set_matched(Some(ResolvedValue {
            name: "ARGS:id".to_string(),
            value: "42".to_string(),
            invalid_utf8: false,
        }));
        assert_eq!(
            expand_macros("%{MATCHED_VAR_NAME}=%{MATCHED_VAR}", &txn),
            "ARGS:id=42"
        );
        assert_eq!(
            expand_macros("%{request_headers.host}", &txn),
            "example.com"
        );
        assert_eq!(expand_macros("%{remote_addr}", &txn), "203.0.113.9");
        assert_eq!(expand_macros("%{args.id}", &txn), "42");
    }

    #[test]
    fn tx_names_are_case_insensitive() {
        let mut txn = SecLangTransaction::from_request(&request());
        txn.tx_set("Score", "7");
        assert_eq!(txn.tx_get("score"), Some("7"));
        assert_eq!(expand_macros("%{TX.score}", &txn), "7");
        let matcher = rule("SecRule TX:SCORE \"@eq 7\" \"id:1\"");
        assert_eq!(matcher.matches(&txn).len(), 1);
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
    fn replace_normalize_path_and_utf8_transforms() {
        let comments = Transform::parse("replaceComments").expect("parse");
        assert_eq!(comments.apply("a/*x*/b"), "a b");
        assert_eq!(comments.apply("a/*unterminated"), "a ");
        assert_eq!(comments.apply("a/*/b"), "a ");
        assert_eq!(comments.apply("plain"), "plain");

        let path = Transform::parse("normalizePath").expect("parse");
        assert_eq!(path.apply("/a/b/../c"), "/a/c");
        assert_eq!(path.apply("a/./b"), "a/b");
        assert_eq!(path.apply("//a//b"), "/a/b");
        assert_eq!(path.apply("/a/../../b"), "/b");
        assert_eq!(path.apply("/a/b/"), "/a/b/");
        assert_eq!(path.apply("/a/b"), "/a/b");
        let win = Transform::parse("normalizePathWin").expect("parse");
        assert_eq!(win.apply("C:\\temp\\..\\windows"), "C:/windows");

        let utf8 = Transform::parse("utf8ToUnicode").expect("parse");
        assert_eq!(utf8.apply("abc"), "abc");
        assert_eq!(utf8.apply("é"), "%u00e9");
        assert_eq!(utf8.apply("€"), "%u20ac");
        assert_eq!(utf8.apply("😀"), "%u1f600");
    }

    #[test]
    fn remove_comments_char_escapeseqdecode_and_css_transforms() {
        let strip = Transform::parse("removeCommentsChar").expect("parse");
        assert_eq!(strip.apply("a/*x*/b"), "axb");
        assert_eq!(strip.apply("<!--x-->"), "x");
        assert_eq!(strip.apply("a-->b"), "ab");
        assert_eq!(strip.apply("#hash"), "hash");

        let escape = Transform::parse("escapeSeqDecode").expect("parse");
        assert_eq!(escape.apply("\\n\\x41\\101\\777"), "\nAA\u{fffd}");
        assert_eq!(escape.apply("\\xzz"), "xzz");
        assert_eq!(escape.apply("\\q"), "q");

        let css = Transform::parse("cssDecode").expect("parse");
        assert_eq!(css.apply("\\41"), "A");
        assert_eq!(css.apply("\\000041"), "A");
        assert_eq!(css.apply("\\ff41"), "a");
        assert_eq!(css.apply("\\41 rest"), "Arest");
        assert_eq!(css.apply("\\z"), "z");
        assert_eq!(css.apply("\\"), "");
        assert_eq!(css.apply("\\\n"), "");
    }

    #[test]
    fn cookies_resolve_and_exclusions_filter_values() {
        let request = Canonicalizer::default().canonicalize(
            RequestParts::new("GET", "example.com", "/")
                .with_header("Cookie", "_ga=tracker; sess=evil"),
        );
        let txn = SecLangTransaction::from_request(&request);
        assert_eq!(txn.resolve("REQUEST_COOKIES:sess")[0].value, "evil");
        assert_eq!(txn.resolve("REQUEST_COOKIES_NAMES").len(), 2);

        // `sess` matches; the `_ga` exclusion only removes the tracker.
        let first = rule(
            "SecRule REQUEST_COOKIES|!REQUEST_COOKIES:/^_ga/ \"@streq evil\" \"id:1\"",
        );
        assert_eq!(first.matches(&txn).len(), 1);
        // Excluding `sess` leaves only the tracker, which does not match.
        let second = rule(
            "SecRule REQUEST_COOKIES|!REQUEST_COOKIES:/^sess/ \"@streq evil\" \"id:2\"",
        );
        assert!(second.matches(&txn).is_empty());
    }

    #[test]
    fn xml_bodies_are_consumed_by_the_processor() {
        let request = Canonicalizer::default().canonicalize(
            RequestParts::new("POST", "example.com", "/")
                .with_header("Content-Type", "application/xml")
                .with_body(
                    b"<xml><ProcessBuilder.evil.clonetransformer/></xml>"
                        .to_vec(),
                ),
        );
        let txn = SecLangTransaction::from_request(&request);
        assert!(txn.resolve("REQUEST_BODY").is_empty());
        assert_eq!(txn.resolve("REQBODY_PROCESSOR")[0].value, "XML");
        // The payload is an element *name*: no text nodes, no attributes.
        assert!(txn.resolve("XML:/*").is_empty());
        assert!(txn.resolve("XML://@*").is_empty());
        let request = Canonicalizer::default().canonicalize(
            RequestParts::new("POST", "example.com", "/")
                .with_header("Content-Type", "application/xml")
                .with_body(b"<tag attr=\"value\">text content</tag>".to_vec()),
        );
        let txn = SecLangTransaction::from_request(&request);
        assert_eq!(txn.resolve("XML:/*")[0].value, "text content");
        assert_eq!(txn.resolve("XML://@*")[0].value, "value");
        // `ctl:forceRequestBodyVariable=On` restores the raw body.
        let mut txn = SecLangTransaction::from_request(&request);
        txn.set_force_request_body(true);
        assert_eq!(txn.resolve("REQUEST_BODY").len(), 1);
    }

    #[test]
    fn response_variables_resolve() {
        let mut txn = SecLangTransaction::from_request(&request());
        txn.set_response(
            500,
            vec![("Content-Type".to_string(), "text/plain".to_string())],
            b"ORA-00933".to_vec(),
        );
        assert_eq!(txn.resolve("RESPONSE_STATUS")[0].value, "500");
        assert_eq!(txn.resolve("RESPONSE_BODY")[0].value, "ORA-00933");
        assert_eq!(
            txn.resolve("RESPONSE_HEADERS:content-type")[0].value,
            "text/plain"
        );
        let rule =
            rule("SecRule RESPONSE_BODY \"@contains ORA-00933\" \"id:1\"");
        assert_eq!(rule.matches(&txn).len(), 1);
    }

    #[test]
    fn json_body_flattens_like_modsecurity() {
        let request = Canonicalizer::default().canonicalize(
            RequestParts::new("POST", "example.com", "/")
                .with_body(br#"{"a":{"b":"c"},"arr":[1,2]}"#.to_vec()),
        );
        let mut txn = SecLangTransaction::from_request(&request);
        txn.parse_json_body();
        let names: Vec<String> = txn
            .resolve("ARGS")
            .into_iter()
            .map(|value| value.name)
            .collect();
        assert!(names.contains(&"ARGS:.a.b".to_string()), "{names:?}");
        assert!(
            names.contains(&"ARGS:.arr.array_0".to_string()),
            "{names:?}"
        );
        assert!(
            names.contains(&"ARGS:.arr.array_1".to_string()),
            "{names:?}"
        );
    }

    #[test]
    fn url_decode_uni_transform() {
        let uni = Transform::parse("urlDecodeUni").expect("parse");
        assert_eq!(uni.apply("%u0041"), "A");
        // Full-width ASCII (ff01-ff5e) shifts down by 0x20.
        assert_eq!(uni.apply("%uFF41"), "a");
        assert_eq!(uni.apply("%41"), "A");
        assert_eq!(uni.apply("a+b"), "a b");
        // Invalid or truncated escapes stay literal.
        assert_eq!(uni.apply("%uZZZZ"), "%uZZZZ");
        assert_eq!(uni.apply("abc%"), "abc%");
        assert_eq!(uni.apply("%zz"), "%zz");
    }

    #[test]
    fn sha1_and_hex_encode_transforms() {
        // RFC 3174 test vectors.
        assert_eq!(sha1_hex(""), "da39a3ee5e6b4b0d3255bfef95601890afd80709");
        assert_eq!(sha1_hex("abc"), "a9993e364706816aba3e25717850c26c9cd0d89d");
        assert_eq!(
            sha1_hex(
                "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"
            ),
            "84983e441c3bd26ebaae4aa1f95129e5e54670f1"
        );
        let sha1 = Transform::parse("sha1").expect("parse");
        assert_eq!(
            sha1.apply("abc"),
            "a9993e364706816aba3e25717850c26c9cd0d89d"
        );
        let hex = Transform::parse("hexEncode").expect("parse");
        assert_eq!(hex.apply("Ab"), "4162");
        assert_eq!(hex.apply(""), "");
        // Case-insensitive action names must still resolve.
        assert!(Transform::parse("HexEncode").is_some());
        assert!(Transform::parse("SHA1").is_some());
        let length = Transform::parse("length").expect("parse");
        assert_eq!(length.apply("abcd"), "4");
        assert_eq!(length.apply("é"), "2");
    }

    #[test]
    fn validate_utf8_encoding_detects_invalid_bytes() {
        // `%FF` decodes to a byte that is not valid UTF-8.
        let request = Canonicalizer::default().canonicalize(RequestParts::new(
            "GET",
            "example.com",
            "/?a=%FF",
        ));
        let txn = SecLangTransaction::from_request(&request);
        let invalid = rule("SecRule ARGS:a \"@validateUtf8Encoding\" \"id:1\"");
        assert_eq!(invalid.matches(&txn).len(), 1);
        let negation =
            rule("SecRule ARGS:a \"!@validateUtf8Encoding\" \"id:2\"");
        assert!(negation.matches(&txn).is_empty());

        // Invalid UTF-8 request bodies are flagged too.
        let request = Canonicalizer::default().canonicalize(
            RequestParts::new("POST", "example.com", "/")
                .with_header("Content-Type", "application/octet-stream")
                .with_body(vec![0xFF, 0xFE]),
        );
        let txn = SecLangTransaction::from_request(&request);
        let body =
            rule("SecRule REQUEST_BODY \"@validateUtf8Encoding\" \"id:3\"");
        assert_eq!(body.matches(&txn).len(), 1);
    }

    #[test]
    fn validate_url_encoding_operator() {
        let txn = SecLangTransaction::from_request(&request());
        // `q=hello` has no percent sequences: valid, never matches.
        let valid = rule("SecRule ARGS:q \"@validateUrlEncoding\" \"id:1\"");
        assert!(valid.matches(&txn).is_empty());

        let mut txn = SecLangTransaction::from_request(&request());
        txn.tx_set("raw", "abc%zz");
        let bad_hex = rule("SecRule TX:raw \"@validateUrlEncoding\" \"id:2\"");
        assert_eq!(bad_hex.matches(&txn).len(), 1);
        txn.tx_set("raw", "abc%41");
        assert!(bad_hex.matches(&txn).is_empty());
        txn.tx_set("raw", "trailing%");
        assert_eq!(bad_hex.matches(&txn).len(), 1);
    }

    #[test]
    fn validate_byte_range_operator() {
        let txn = SecLangTransaction::from_request(&request());
        // `hello` is fully inside 97-122: no invalid characters, no match.
        let inside =
            rule("SecRule ARGS:q \"@validateByteRange 97-122\" \"id:1\"");
        assert!(inside.matches(&txn).is_empty());
        // `l` (108) falls outside 97-104: match.
        let outside =
            rule("SecRule ARGS:q \"@validateByteRange 97-104\" \"id:2\"");
        assert_eq!(outside.matches(&txn).len(), 1);
        // A NUL byte falls outside 1-255: match.
        let mut txn = SecLangTransaction::from_request(&request());
        txn.tx_set("raw", "a\u{0}b");
        let nul = rule("SecRule TX:raw \"@validateByteRange 1-255\" \"id:3\"");
        assert_eq!(nul.matches(&txn).len(), 1);
    }

    #[test]
    fn ampersand_variables_count_instances() {
        let mut txn = SecLangTransaction::from_request(&request());
        let unset = rule("SecRule &TX:missing \"@eq 0\" \"id:1\"");
        assert_eq!(unset.matches(&txn).len(), 1);
        txn.tx_set("present", "x");
        let set = rule("SecRule &TX:present \"@eq 1\" \"id:2\"");
        assert_eq!(set.matches(&txn).len(), 1);
        // Collections count instances too (`request()` carries two query
        // parameters plus two form-urlencoded body parameters).
        let args = rule("SecRule &ARGS \"@eq 4\" \"id:3\"");
        assert_eq!(args.matches(&txn).len(), 1);
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
