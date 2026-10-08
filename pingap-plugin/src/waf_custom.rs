//! Per-site custom security layers: SecLang virtual patches and OpenAPI
//! request-shape validation (Phase 8).
//!
//! Both layers are configured per site in the dashboard and compiled once per
//! site context:
//!
//! * **Virtual patches** — a SecLang rule source evaluated by the native
//!   engine (`SecRuleSet`). Rules carrying a disruptive action (`block`,
//!   `deny`) block matching requests; other rules record. The control plane
//!   validates the source at upload time, so a compile error here means a
//!   stale cache and is logged loudly.
//! * **OpenAPI validation** — a JSON OpenAPI document; requests are checked
//!   against the declared operations: an unmatched path under the spec's base
//!   prefix **Monitors** as `api.unknown_operation`, a declared path with an
//!   undeclared method as `api.method_not_allowed`, and a missing required
//!   query parameter as `api.missing_required_param`. Paths outside the
//!   spec's base prefix are out of scope and stay untouched.
//!
//! Both layers can only escalate the verdict — they never weaken the native
//! engine.

use std::collections::BTreeSet;
use std::sync::Arc;

use serde_json::Value;

use varman_waf::canonical::CanonicalRequest;
use varman_waf::seclang::{SecLangTransaction, SecRuleSet};
use varman_waf::{ScoreBreakdown, WafAction, WafVerdict};

/// A compiled SecLang virtual-patch rule set.
pub struct VirtualPatches {
    rules: SecRuleSet,
}

impl VirtualPatches {
    /// Compile a SecLang source. `Err` carries the engine's reason.
    pub fn compile(source: &str) -> Result<Self, String> {
        SecRuleSet::from_source(source)
            .map(|rules| Self { rules })
            .map_err(|error| error.to_string())
    }

    /// Evaluate against one canonical request. Returns `(blocking rule ids,
    /// matched rule count)` when any disruptive rule matched.
    fn evaluate(
        &self,
        request: &CanonicalRequest,
    ) -> Option<(Vec<u64>, usize)> {
        let mut txn = SecLangTransaction::from_request(request);
        let hits = self.rules.evaluate(&mut txn);
        if hits.is_empty() {
            return None;
        }
        let mut blocking: Vec<u64> = Vec::new();
        let mut disruptive = false;
        for hit in &hits {
            let blocks = hit.actions.iter().any(|action| {
                let action = action.trim();
                action.eq_ignore_ascii_case("block")
                    || action.eq_ignore_ascii_case("deny")
                    || action.eq_ignore_ascii_case("drop")
            });
            if blocks {
                disruptive = true;
                blocking.extend(hit.rule_ids.iter().flatten().copied());
            }
        }
        disruptive.then_some((blocking, hits.len()))
    }
}

/// One OpenAPI operation template.
struct Operation {
    /// Path segments; `None` is a `{parameter}` placeholder.
    segments: Vec<Option<String>>,
    /// Lowercase methods declared for the path.
    methods: BTreeSet<String>,
    /// Required query parameters per method.
    required_query: Vec<(String, String)>,
    /// JSON request-body schema per method: `(method, schema, required)`.
    body_schemas: Vec<(String, Value, bool)>,
}

/// A parsed OpenAPI document (paths, methods, required query parameters and
/// JSON request-body schemas).
pub struct OpenApiSpec {
    base_prefix: String,
    operations: Vec<Operation>,
    /// `components.schemas` for local `$ref` resolution.
    schemas: serde_json::Map<String, Value>,
}

impl OpenApiSpec {
    /// Parse a JSON OpenAPI document.
    pub fn parse(source: &str) -> Result<Self, String> {
        let value: Value = serde_json::from_str(source).map_err(|error| {
            format!("OpenAPI spec is not valid JSON: {error}")
        })?;
        let paths = value
            .get("paths")
            .and_then(Value::as_object)
            .ok_or_else(|| "OpenAPI spec has no `paths` object".to_string())?;
        let mut operations = Vec::new();
        for (path, item) in paths {
            let Some(item) = item.as_object() else {
                continue;
            };
            let path_parameters = item.get("parameters");
            let mut methods = BTreeSet::new();
            let mut required_query = Vec::new();
            let mut body_schemas = Vec::new();
            for (key, operation) in item {
                let method = key.to_ascii_lowercase();
                if !matches!(
                    method.as_str(),
                    "get"
                        | "put"
                        | "post"
                        | "delete"
                        | "patch"
                        | "head"
                        | "options"
                        | "trace"
                ) {
                    continue;
                }
                methods.insert(method.clone());
                if let Some(request_body) = operation.get("requestBody") {
                    let required = request_body
                        .get("required")
                        .and_then(Value::as_bool)
                        .unwrap_or(false);
                    if let Some(schema) = json_body_schema(request_body) {
                        body_schemas.push((
                            method.clone(),
                            schema.clone(),
                            required,
                        ));
                    }
                }
                for parameters in [path_parameters, operation.get("parameters")]
                    .into_iter()
                    .flatten()
                    .filter_map(Value::as_array)
                {
                    for parameter in parameters {
                        let location = parameter
                            .get("in")
                            .and_then(Value::as_str)
                            .unwrap_or_default();
                        let required = parameter
                            .get("required")
                            .and_then(Value::as_bool)
                            .unwrap_or(false);
                        let name = parameter
                            .get("name")
                            .and_then(Value::as_str)
                            .unwrap_or_default();
                        if location == "query" && required && !name.is_empty() {
                            required_query
                                .push((method.clone(), name.to_string()));
                        }
                    }
                }
            }
            if methods.is_empty() {
                continue;
            }
            operations.push(Operation {
                segments: split_path(path),
                methods,
                required_query,
                body_schemas,
            });
        }
        if operations.is_empty() {
            return Err("OpenAPI spec declares no operations".to_string());
        }
        // Base prefix: the spec's server path when present, otherwise the
        // longest leading segment run shared by every declared path.
        let base_prefix = server_base_prefix(&value)
            .unwrap_or_else(|| common_prefix(&operations));
        let schemas = value
            .get("components")
            .and_then(|components| components.get("schemas"))
            .and_then(Value::as_object)
            .cloned()
            .unwrap_or_default();
        Ok(Self {
            base_prefix,
            operations,
            schemas,
        })
    }

    /// Validate one request. Returns `(rule_id, score, detail)` findings.
    fn validate(
        &self,
        request: &CanonicalRequest,
    ) -> Vec<(&'static str, u32, String)> {
        let Some(path) = self.relative_path(request.path()) else {
            return Vec::new();
        };
        let segments = split_path(path);
        let Some(operation) = self.find_operation(&segments) else {
            return vec![(
                "api.unknown_operation",
                20,
                format!("no declared operation matches {path}"),
            )];
        };
        let method = request.method().to_ascii_lowercase();
        if !operation.methods.contains(&method) {
            return vec![(
                "api.method_not_allowed",
                20,
                format!(
                    "{method} is not declared for {}",
                    join_segments(&operation.segments)
                ),
            )];
        }
        let present: BTreeSet<&str> = request
            .query()
            .iter()
            .map(|param| param.name.as_str())
            .collect();
        for (declared_method, name) in &operation.required_query {
            if declared_method == &method && !present.contains(name.as_str()) {
                return vec![(
                    "api.missing_required_param",
                    15,
                    format!("required query parameter {name:?} is missing"),
                )];
            }
        }
        Vec::new()
    }

    /// Validate the JSON request body of a matched operation against its
    /// schema. `body_complete` is false when only the head window of a larger
    /// body was captured: a truncated body cannot be parsed, so it is skipped
    /// rather than reported.
    fn validate_body(
        &self,
        request: &CanonicalRequest,
        body_complete: bool,
    ) -> Option<(&'static str, u32, String)> {
        let path = self.relative_path(request.path())?;
        let segments = split_path(path);
        let operation = self.find_operation(&segments)?;
        let method = request.method().to_ascii_lowercase();
        if !operation.methods.contains(&method) {
            // Reported by `validate` as a method violation.
            return None;
        }
        let (_, schema, required) = operation
            .body_schemas
            .iter()
            .find(|(declared, _, _)| declared == &method)?;
        let body = request.body().unwrap_or_default();
        if body.is_empty() {
            return required.then(|| {
                (
                    "api.missing_body",
                    15,
                    "the operation declares a required JSON body".to_string(),
                )
            });
        }
        if !body_complete {
            return None;
        }
        let instance: Value = match serde_json::from_slice(body) {
            Ok(instance) => instance,
            Err(error) => {
                return Some((
                    "api.invalid_json",
                    15,
                    format!("request body is not valid JSON: {error}"),
                ));
            },
        };
        let mut checker = SchemaChecker {
            schemas: &self.schemas,
            budget: 20_000,
        };
        match checker.check(schema, &instance, "body", 0) {
            Ok(()) => None,
            Err(detail) => Some(("api.schema_violation", 15, detail)),
        }
    }

    /// The request path relative to the spec's base prefix, when in scope.
    fn relative_path<'a>(&self, path: &'a str) -> Option<&'a str> {
        if !self.base_prefix.is_empty() && !path.starts_with(&self.base_prefix)
        {
            return None;
        }
        Some(path.strip_prefix(&self.base_prefix).unwrap_or(path))
    }

    /// The operation whose path template matches `segments`.
    fn find_operation(
        &self,
        segments: &[Option<String>],
    ) -> Option<&Operation> {
        self.operations
            .iter()
            .find(|operation| segments_match(&operation.segments, segments))
    }
}

/// The JSON request-body schema of an OpenAPI `requestBody` object, when it
/// declares one for `application/json` or a `+json` media type.
fn json_body_schema(request_body: &Value) -> Option<&Value> {
    let content = request_body.get("content")?.as_object()?;
    let (_, media) = content.iter().find(|(media_type, _)| {
        let media_type = media_type.to_ascii_lowercase();
        media_type == "application/json" || media_type.ends_with("+json")
    })?;
    media.get("schema")
}

/// A JSON Schema validator for the OpenAPI 3.0 dialect subset.
///
/// Supported: local `$ref` (`#/components/schemas/...`), `type` (string or
/// list), `nullable`, `enum`, `required`, `properties`,
/// `additionalProperties: false`, `items`, `minItems`/`maxItems`,
/// `minLength`/`maxLength`, `pattern`, numeric `minimum`/`maximum`,
/// `allOf`/`anyOf`/`oneOf`. Unsupported keywords are ignored rather than
/// guessed. The walk is budgeted: a pathological instance stops validating
/// instead of burning the edge's time, and the budget is conservative (a
/// stopped walk reports nothing).
struct SchemaChecker<'a> {
    schemas: &'a serde_json::Map<String, Value>,
    budget: usize,
}

impl SchemaChecker<'_> {
    fn check(
        &mut self,
        schema: &Value,
        instance: &Value,
        path: &str,
        depth: usize,
    ) -> Result<(), String> {
        if self.budget == 0 || depth > 16 {
            return Ok(());
        }
        self.budget -= 1;
        let Some(object) = schema.as_object() else {
            return Ok(());
        };
        if let Some(reference) = object.get("$ref").and_then(Value::as_str) {
            // Copy the shared reference out so the recursive call is free to
            // borrow `self` mutably.
            let schemas = self.schemas;
            let Some(target) = resolve_ref(schemas, reference) else {
                return Ok(());
            };
            return self.check(target, instance, path, depth + 1);
        }
        if instance.is_null() {
            if self.allows_null(object) {
                return Ok(());
            }
            if object.contains_key("type") {
                return Err(format!(
                    "{path}: expected {}, found null",
                    declared_type(object)
                ));
            }
        } else if let Some(type_error) = self.check_type(object, instance, path)
        {
            return Err(type_error);
        }
        if let Some(enum_values) = object.get("enum").and_then(Value::as_array)
            && !enum_values.iter().any(|candidate| candidate == instance)
        {
            return Err(format!(
                "{path}: value is not one of the allowed enum values"
            ));
        }
        if let Some(branches) = object.get("allOf").and_then(Value::as_array) {
            for branch in branches {
                self.check(branch, instance, path, depth + 1)?;
            }
        }
        if let Some(branches) = object.get("anyOf").and_then(Value::as_array) {
            let matched = branches
                .iter()
                .any(|branch| self.branch_ok(branch, instance, path, depth));
            if !matched {
                return Err(format!("{path}: no anyOf branch matched"));
            }
        }
        if let Some(branches) = object.get("oneOf").and_then(Value::as_array) {
            let matched = branches
                .iter()
                .filter(|branch| self.branch_ok(branch, instance, path, depth))
                .count();
            if matched != 1 {
                return Err(format!(
                    "{path}: expected exactly one oneOf branch to match, {matched} matched"
                ));
            }
        }
        if let Some(instance_object) = instance.as_object() {
            if let Some(required) =
                object.get("required").and_then(Value::as_array)
            {
                for name in required.iter().filter_map(Value::as_str) {
                    if !instance_object.contains_key(name) {
                        return Err(format!(
                            "{path}: required property {name:?} is missing"
                        ));
                    }
                }
            }
            let properties =
                object.get("properties").and_then(Value::as_object);
            if let Some(properties) = properties {
                for (name, subschema) in properties {
                    if let Some(value) = instance_object.get(name) {
                        self.check(
                            subschema,
                            value,
                            &format!("{path}.{name}"),
                            depth + 1,
                        )?;
                    }
                }
            }
            if object.get("additionalProperties") == Some(&Value::Bool(false))
                && let Some(properties) = properties
            {
                for name in instance_object.keys() {
                    if !properties.contains_key(name) {
                        return Err(format!(
                            "{path}: unexpected property {name:?}"
                        ));
                    }
                }
            }
        }
        if let Some(instance_array) = instance.as_array() {
            if let Some(items) = object.get("items") {
                for (index, value) in instance_array.iter().enumerate() {
                    self.check(
                        items,
                        value,
                        &format!("{path}[{index}]"),
                        depth + 1,
                    )?;
                }
            }
            if let Some(min) = object.get("minItems").and_then(Value::as_u64)
                && (instance_array.len() as u64) < min
            {
                return Err(format!("{path}: expected at least {min} items"));
            }
            if let Some(max) = object.get("maxItems").and_then(Value::as_u64)
                && (instance_array.len() as u64) > max
            {
                return Err(format!("{path}: expected at most {max} items"));
            }
        }
        if let Some(instance_string) = instance.as_str() {
            let length = instance_string.chars().count() as u64;
            if let Some(min) = object.get("minLength").and_then(Value::as_u64)
                && length < min
            {
                return Err(format!("{path}: shorter than minLength {min}"));
            }
            if let Some(max) = object.get("maxLength").and_then(Value::as_u64)
                && length > max
            {
                return Err(format!("{path}: longer than maxLength {max}"));
            }
            if let Some(pattern) = object.get("pattern").and_then(Value::as_str)
                && pattern.len() <= 512
                && let Ok(regex) = regex::Regex::new(pattern)
                && !regex.is_match(instance_string)
            {
                return Err(format!(
                    "{path}: does not match pattern {pattern:?}"
                ));
            }
        }
        if let Some(instance_number) = instance.as_f64() {
            if let Some(min) = object.get("minimum").and_then(Value::as_f64)
                && instance_number < min
            {
                return Err(format!("{path}: below minimum {min}"));
            }
            if let Some(max) = object.get("maximum").and_then(Value::as_f64)
                && instance_number > max
            {
                return Err(format!("{path}: above maximum {max}"));
            }
        }
        Ok(())
    }

    /// Whether a combinator branch accepts the instance; errors are
    /// swallowed and the branch runs under a small budget of its own.
    fn branch_ok(
        &mut self,
        schema: &Value,
        instance: &Value,
        path: &str,
        depth: usize,
    ) -> bool {
        let allowance = self.budget.min(2_000);
        let mut branch = SchemaChecker {
            schemas: self.schemas,
            budget: allowance,
        };
        let ok = branch.check(schema, instance, path, depth + 1).is_ok();
        self.budget = self.budget.saturating_sub(allowance - branch.budget);
        ok
    }

    fn allows_null(&self, object: &serde_json::Map<String, Value>) -> bool {
        if object.get("nullable").and_then(Value::as_bool) == Some(true) {
            return true;
        }
        match object.get("type") {
            Some(Value::String(kind)) => kind == "null",
            Some(Value::Array(kinds)) => {
                kinds.iter().any(|kind| kind == "null")
            },
            _ => false,
        }
    }

    fn check_type(
        &self,
        object: &serde_json::Map<String, Value>,
        instance: &Value,
        path: &str,
    ) -> Option<String> {
        let declared = match object.get("type") {
            Some(Value::String(kind)) => vec![kind.as_str()],
            Some(Value::Array(kinds)) => {
                kinds.iter().filter_map(Value::as_str).collect()
            },
            _ => return None,
        };
        if declared.is_empty() {
            return None;
        }
        let actual = match instance {
            Value::Null => "null",
            Value::Bool(_) => "boolean",
            Value::Number(number) => {
                if number.is_i64() || number.is_u64() {
                    "integer"
                } else {
                    "number"
                }
            },
            Value::String(_) => "string",
            Value::Array(_) => "array",
            Value::Object(_) => "object",
        };
        let ok = declared.iter().any(|kind| {
            *kind == actual || (*kind == "number" && actual == "integer")
        });
        (!ok).then(|| {
            format!(
                "{path}: expected {}, found {actual}",
                declared.join(" or ")
            )
        })
    }
}

/// Resolve a local `$ref` into `components.schemas`; remote or nested
/// references are not guessed.
fn resolve_ref<'a>(
    schemas: &'a serde_json::Map<String, Value>,
    reference: &str,
) -> Option<&'a Value> {
    let name = reference.strip_prefix("#/components/schemas/")?;
    if name.contains('/') {
        return None;
    }
    schemas.get(name)
}

fn declared_type(object: &serde_json::Map<String, Value>) -> String {
    match object.get("type") {
        Some(Value::String(kind)) => kind.clone(),
        Some(Value::Array(kinds)) => kinds
            .iter()
            .filter_map(Value::as_str)
            .collect::<Vec<_>>()
            .join(" or "),
        _ => "a typed value".to_string(),
    }
}

/// Split a path into segments; `{param}` placeholders become `None`.
fn split_path(path: &str) -> Vec<Option<String>> {
    path.split('/')
        .filter(|segment| !segment.is_empty())
        .map(|segment| {
            let trimmed = segment.trim();
            if trimmed.starts_with('{') && trimmed.ends_with('}') {
                None
            } else {
                Some(trimmed.to_string())
            }
        })
        .collect()
}

fn join_segments(segments: &[Option<String>]) -> String {
    let mut out = String::new();
    for segment in segments {
        out.push('/');
        match segment {
            Some(value) => out.push_str(value),
            None => out.push_str("{param}"),
        }
    }
    if out.is_empty() {
        out.push('/');
    }
    out
}

fn segments_match(
    template: &[Option<String>],
    actual: &[Option<String>],
) -> bool {
    if template.len() != actual.len() {
        return false;
    }
    template
        .iter()
        .zip(actual)
        .all(|(expected, found)| match expected {
            Some(value) => Some(value) == found.as_ref(),
            None => found.is_some(),
        })
}

/// `servers[0].url` path component when it declares one.
fn server_base_prefix(value: &Value) -> Option<String> {
    let url = value
        .get("servers")
        .and_then(Value::as_array)
        .and_then(|servers| servers.first())
        .and_then(|server| server.get("url"))
        .and_then(Value::as_str)?;
    let path = url.split_once("://").map_or(url, |(_, rest)| rest);
    let path = path.split_once('/').map(|(_, rest)| format!("/{rest}"))?;
    let prefix = path.trim_end_matches('/').to_string();
    (!prefix.is_empty()).then_some(prefix)
}

/// Longest leading segment run shared by every declared path.
fn common_prefix(operations: &[Operation]) -> String {
    let mut prefix: Vec<&Option<String>> = Vec::new();
    for (index, segment) in operations[0].segments.iter().enumerate() {
        let shared = operations.iter().all(|operation| {
            operation
                .segments
                .get(index)
                .is_some_and(|candidate| candidate == segment)
        });
        if shared {
            prefix.push(segment);
        } else {
            break;
        }
    }
    let mut out = String::new();
    for value in prefix.into_iter().flatten() {
        out.push('/');
        out.push_str(value);
    }
    out
}

/// Compiled per-site custom layers.
#[derive(Default)]
pub struct CustomLayers {
    patches: Option<VirtualPatches>,
    openapi: Option<OpenApiSpec>,
}

impl CustomLayers {
    /// Compile the configured layers; compile errors are returned so the
    /// caller can log them (the control plane validates at upload time, so
    /// this only trips on a stale cache).
    pub fn build(
        virtual_patches: &str,
        openapi_spec: &str,
    ) -> (Option<Arc<Self>>, Vec<String>) {
        let mut errors = Vec::new();
        let patches = if virtual_patches.trim().is_empty() {
            None
        } else {
            match VirtualPatches::compile(virtual_patches) {
                Ok(patches) => Some(patches),
                Err(error) => {
                    errors.push(format!("virtual patches: {error}"));
                    None
                },
            }
        };
        let openapi = if openapi_spec.trim().is_empty() {
            None
        } else {
            match OpenApiSpec::parse(openapi_spec) {
                Ok(spec) => Some(spec),
                Err(error) => {
                    errors.push(format!("openapi spec: {error}"));
                    None
                },
            }
        };
        if patches.is_none() && openapi.is_none() {
            return (None, errors);
        }
        (Some(Arc::new(Self { patches, openapi })), errors)
    }

    /// Evaluate both layers against one canonical request, returning a
    /// verdict when anything fired. The caller escalates it with the native
    /// verdict, so these layers can only add protection.
    pub fn evaluate(
        &self,
        request: &CanonicalRequest,
        body_complete: bool,
    ) -> Option<WafVerdict> {
        if let Some((rule_ids, matched)) = self
            .patches
            .as_ref()
            .and_then(|patches| patches.evaluate(request))
        {
            let ids = if rule_ids.is_empty() {
                format!("{matched} rule(s)")
            } else {
                rule_ids
                    .iter()
                    .map(u64::to_string)
                    .collect::<Vec<_>>()
                    .join(", ")
            };
            return Some(verdict(
                WafAction::Block,
                40,
                vec![format!("virtual-patch:{ids}")],
                format!("SecLang virtual patch matched ({ids})"),
            ));
        }
        if let Some(openapi) = &self.openapi {
            let findings = openapi.validate(request);
            let finding = findings
                .into_iter()
                .next()
                .or_else(|| openapi.validate_body(request, body_complete));
            if let Some((rule_id, score, detail)) = finding {
                return Some(verdict(
                    WafAction::Monitor,
                    score,
                    vec![rule_id.to_string()],
                    detail,
                ));
            }
        }
        None
    }
}

fn verdict(
    action: WafAction,
    score: u32,
    matched_rules: Vec<String>,
    details: String,
) -> WafVerdict {
    let mut breakdown = ScoreBreakdown::clean();
    breakdown.total = score;
    WafVerdict {
        action,
        score: u8::try_from(score).unwrap_or(u8::MAX),
        matched_rules,
        details,
        breakdown,
    }
}

#[cfg(test)]
mod tests {
    use super::{CustomLayers, OpenApiSpec, VirtualPatches};
    use varman_waf::WafAction;
    use varman_waf::canonical::{Canonicalizer, RequestParts};

    fn canonical(
        target: &str,
        method: &str,
    ) -> varman_waf::canonical::CanonicalRequest {
        Canonicalizer::default().canonicalize(RequestParts::new(
            method,
            "api.example.com",
            target,
        ))
    }

    fn canonical_body(
        target: &str,
        method: &str,
        body: &str,
    ) -> varman_waf::canonical::CanonicalRequest {
        Canonicalizer::default().canonicalize(
            RequestParts::new(method, "api.example.com", target)
                .with_header("Content-Type", "application/json")
                .with_body(body.as_bytes().to_vec()),
        )
    }

    #[test]
    fn virtual_patch_blocks_matching_requests() {
        let layers = CustomLayers::build(
            "SecRule REQUEST_URI \"@contains /cve-2026-0001\" \
             \"id:900001,phase:1,block,msg:'CVE patch'\"",
            "",
        )
        .0
        .expect("layers");

        let hit = layers
            .evaluate(&canonical("/cve-2026-0001/exploit", "GET"), true)
            .expect("must block");
        assert_eq!(hit.action, WafAction::Block);
        assert!(hit.matched_rules[0].contains("900001"));

        assert!(layers.evaluate(&canonical("/safe", "GET"), true).is_none());
    }

    #[test]
    fn virtual_patch_compile_errors_are_reported() {
        let (layers, errors) = CustomLayers::build(
            "SecRule ARGS \"@definitelyNotAnOperator x\" \"id:1,block\"",
            "",
        );
        assert!(layers.is_none());
        assert_eq!(errors.len(), 1);
        assert!(errors[0].contains("virtual patches"));
        assert!(
            VirtualPatches::compile("SecRule ARGS \"@rx x\" \"id:2,block\"")
                .is_ok()
        );
    }

    const SPEC: &str = r###"
    {
      "openapi": "3.0.0",
      "servers": [{"url": "https://api.example.com/v1"}],
      "components": {
        "schemas": {
          "Item": {
            "type": "object",
            "required": ["name"],
            "properties": {
              "name": {"type": "string", "minLength": 1, "maxLength": 64},
              "price": {"type": "number", "minimum": 0},
              "tags": {"type": "array", "items": {"type": "string"}, "maxItems": 3},
              "kind": {"type": "string", "enum": ["book", "food"]}
            },
            "additionalProperties": false
          }
        }
      },
      "paths": {
        "/items": {
          "get": {"parameters": [{"in": "query", "name": "page", "required": true}]},
          "post": {
            "requestBody": {
              "required": true,
              "content": {
                "application/json": {
                  "schema": {"$ref": "#/components/schemas/Item"}
                }
              }
            }
          }
        },
        "/items/{id}": {"get": {}}
      }
    }
    "###;

    #[test]
    fn openapi_validation_covers_operation_method_and_parameters() {
        let spec = OpenApiSpec::parse(SPEC).expect("spec");

        // Declared operation with its required parameter: clean.
        assert!(
            spec.validate(&canonical("/v1/items?page=1", "GET"))
                .is_empty()
        );
        // Templated path.
        assert!(spec.validate(&canonical("/v1/items/42", "GET")).is_empty());
        // Missing required query parameter.
        let findings = spec.validate(&canonical("/v1/items", "GET"));
        assert_eq!(findings[0].0, "api.missing_required_param");
        // Undeclared method on a declared path.
        let findings = spec.validate(&canonical("/v1/items/42", "DELETE"));
        assert_eq!(findings[0].0, "api.method_not_allowed");
        // Unknown operation under the base prefix.
        let findings = spec.validate(&canonical("/v1/unknown", "GET"));
        assert_eq!(findings[0].0, "api.unknown_operation");
        // Outside the base prefix: out of scope.
        assert!(spec.validate(&canonical("/favicon.ico", "GET")).is_empty());
        assert!(spec.validate(&canonical("/", "GET")).is_empty());
    }

    #[test]
    fn openapi_layers_monitor_and_escalate_only() {
        let layers = CustomLayers::build("", SPEC).0.expect("layers");
        let hit = layers
            .evaluate(&canonical("/v1/unknown", "GET"), true)
            .expect("must monitor");
        assert_eq!(hit.action, WafAction::Monitor);
        assert!(
            layers
                .evaluate(&canonical("/v1/items?page=1", "GET"), true)
                .is_none()
        );
    }

    #[test]
    fn openapi_body_schema_validation() {
        let spec = OpenApiSpec::parse(SPEC).expect("spec");

        // Valid body through the $ref'd schema: clean.
        assert!(
            spec.validate_body(
                &canonical_body(
                    "/v1/items",
                    "POST",
                    r#"{"name":"widget","price":9.5,"kind":"book"}"#,
                ),
                true,
            )
            .is_none()
        );
        // Missing required property.
        let finding = spec
            .validate_body(
                &canonical_body("/v1/items", "POST", r#"{"price":9.5}"#),
                true,
            )
            .expect("must flag");
        assert_eq!(finding.0, "api.schema_violation");
        assert!(finding.2.contains("name"), "detail: {}", finding.2);
        // Wrong type.
        let finding = spec
            .validate_body(
                &canonical_body("/v1/items", "POST", r#"{"name":7}"#),
                true,
            )
            .expect("must flag");
        assert!(finding.2.contains("expected string"));
        // additionalProperties: false.
        let finding = spec
            .validate_body(
                &canonical_body(
                    "/v1/items",
                    "POST",
                    r#"{"name":"a","nope":1}"#,
                ),
                true,
            )
            .expect("must flag");
        assert!(finding.2.contains("unexpected property"));
        // enum violation.
        let finding = spec
            .validate_body(
                &canonical_body(
                    "/v1/items",
                    "POST",
                    r#"{"name":"a","kind":"drink"}"#,
                ),
                true,
            )
            .expect("must flag");
        assert!(finding.2.contains("enum"));
        // Array item bounds.
        let finding = spec
            .validate_body(
                &canonical_body(
                    "/v1/items",
                    "POST",
                    r#"{"name":"a","tags":["x","y","z","w"]}"#,
                ),
                true,
            )
            .expect("must flag");
        assert!(finding.2.contains("at most 3"));
        // Numeric bound.
        let finding = spec
            .validate_body(
                &canonical_body(
                    "/v1/items",
                    "POST",
                    r#"{"name":"a","price":-1}"#,
                ),
                true,
            )
            .expect("must flag");
        assert!(finding.2.contains("below minimum"));
        // Missing body where the operation requires one.
        let finding = spec
            .validate_body(&canonical_body("/v1/items", "POST", ""), true)
            .expect("must flag");
        assert_eq!(finding.0, "api.missing_body");
        // Invalid JSON.
        let finding = spec
            .validate_body(&canonical_body("/v1/items", "POST", "{oops"), true)
            .expect("must flag");
        assert_eq!(finding.0, "api.invalid_json");
        // A truncated capture is skipped, never reported.
        assert!(
            spec.validate_body(
                &canonical_body("/v1/items", "POST", r#"{"name":"wid"#),
                false,
            )
            .is_none()
        );
        // No declared body schema: clean.
        assert!(
            spec.validate_body(
                &canonical_body("/v1/items/42", "GET", ""),
                true
            )
            .is_none()
        );
    }

    #[test]
    fn openapi_body_violation_monitors_through_layers() {
        let layers = CustomLayers::build("", SPEC).0.expect("layers");
        let hit = layers
            .evaluate(
                &canonical_body("/v1/items", "POST", r#"{"price":1}"#),
                true,
            )
            .expect("must monitor");
        assert_eq!(hit.action, WafAction::Monitor);
        assert_eq!(hit.matched_rules[0], "api.schema_violation");
        assert!(
            layers
                .evaluate(
                    &canonical_body("/v1/items", "POST", r#"{"name":"ok"}"#,),
                    true,
                )
                .is_none()
        );
    }

    #[test]
    fn schema_combinators_and_nullable() {
        let spec = OpenApiSpec::parse(
            r###"{
              "openapi": "3.0.0",
              "servers": [{"url": "https://api.example.com/v2"}],
              "paths": {"/n": {"post": {"requestBody": {"content": {"application/json": {"schema": {
                "type": "object",
                "properties": {
                  "pick": {"oneOf": [{"type": "integer"}, {"type": "string"}]},
                  "maybe": {"type": "string", "nullable": true},
                  "all": {"allOf": [{"type": "string", "minLength": 2}]},
                  "any": {"anyOf": [{"type": "boolean"}, {"type": "null"}]}
                },
                "additionalProperties": false
              }}}}}}}
            }"###,
        )
        .expect("spec");
        assert!(
            spec.validate_body(
                &canonical_body(
                    "/v2/n",
                    "POST",
                    r#"{"pick":3,"maybe":null,"all":"xy","any":null}"#,
                ),
                true,
            )
            .is_none()
        );
        // oneOf with no matching branch.
        let finding = spec
            .validate_body(
                &canonical_body("/v2/n", "POST", r#"{"pick":true}"#),
                true,
            )
            .expect("must flag");
        assert!(finding.2.contains("oneOf"), "detail: {}", finding.2);
        // allOf branch violation.
        let finding = spec
            .validate_body(
                &canonical_body("/v2/n", "POST", r#"{"all":"x"}"#),
                true,
            )
            .expect("must flag");
        assert!(finding.2.contains("minLength"));
        // A typed schema rejects null without `nullable`.
        let finding = spec
            .validate_body(
                &canonical_body("/v2/n", "POST", r#"{"all":null}"#),
                true,
            )
            .expect("must flag");
        assert!(finding.2.contains("found null"));
    }

    #[test]
    fn invalid_specs_are_rejected() {
        assert!(OpenApiSpec::parse("not json").is_err());
        assert!(OpenApiSpec::parse("{}").is_err());
        assert!(OpenApiSpec::parse(r#"{"paths": {}}"#).is_err());
    }
}
