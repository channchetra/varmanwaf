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
}

/// A parsed OpenAPI document (first slice: paths, methods, required query
/// parameters).
pub struct OpenApiSpec {
    base_prefix: String,
    operations: Vec<Operation>,
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
            });
        }
        if operations.is_empty() {
            return Err("OpenAPI spec declares no operations".to_string());
        }
        // Base prefix: the spec's server path when present, otherwise the
        // longest leading segment run shared by every declared path.
        let base_prefix = server_base_prefix(&value)
            .unwrap_or_else(|| common_prefix(&operations));
        Ok(Self {
            base_prefix,
            operations,
        })
    }

    /// Validate one request. Returns `(rule_id, score, detail)` findings.
    fn validate(
        &self,
        request: &CanonicalRequest,
    ) -> Vec<(&'static str, u32, String)> {
        let path = request.path();
        if !self.base_prefix.is_empty() && !path.starts_with(&self.base_prefix)
        {
            return Vec::new();
        }
        // Declared paths are relative to the spec's base prefix.
        let path = path
            .strip_prefix(&self.base_prefix)
            .unwrap_or(path)
            .to_string();
        let segments = split_path(&path);
        for operation in &self.operations {
            if !segments_match(&operation.segments, &segments) {
                continue;
            }
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
                if declared_method == &method
                    && !present.contains(name.as_str())
                {
                    return vec![(
                        "api.missing_required_param",
                        15,
                        format!("required query parameter {name:?} is missing"),
                    )];
                }
            }
            return Vec::new();
        }
        vec![(
            "api.unknown_operation",
            20,
            format!("no declared operation matches {path}"),
        )]
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
    pub fn evaluate(&self, request: &CanonicalRequest) -> Option<WafVerdict> {
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
            if let Some((rule_id, score, detail)) = findings.into_iter().next()
            {
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
            .evaluate(&canonical("/cve-2026-0001/exploit", "GET"))
            .expect("must block");
        assert_eq!(hit.action, WafAction::Block);
        assert!(hit.matched_rules[0].contains("900001"));

        assert!(layers.evaluate(&canonical("/safe", "GET")).is_none());
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
      "paths": {
        "/items": {
          "get": {"parameters": [{"in": "query", "name": "page", "required": true}]},
          "post": {}
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
            .evaluate(&canonical("/v1/unknown", "GET"))
            .expect("must monitor");
        assert_eq!(hit.action, WafAction::Monitor);
        assert!(
            layers
                .evaluate(&canonical("/v1/items?page=1", "GET"))
                .is_none()
        );
    }

    #[test]
    fn invalid_specs_are_rejected() {
        assert!(OpenApiSpec::parse("not json").is_err());
        assert!(OpenApiSpec::parse("{}").is_err());
        assert!(OpenApiSpec::parse(r#"{"paths": {}}"#).is_err());
    }
}
