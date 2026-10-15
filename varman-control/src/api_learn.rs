//! Bounded structural learning for API assets.
//!
//! The learner reads stored request bodies and query strings and merges
//! **structure only**: keys, JSON types and counts. Values are never read
//! out of the sample (the parsed `Value` is walked, not captured), and every
//! dimension is bounded - depth, keys per object, array elements merged per
//! sample, samples per run. A truncated body is skipped and counted, never
//! guessed at. The OpenAPI draft is generated from the learned rows and says
//! it is a draft from observed traffic.

use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

/// Deepest object/array nesting the learner follows.
pub const MAX_DEPTH: usize = 8;
/// Most keys recorded per object node.
pub const MAX_KEYS_PER_OBJECT: usize = 100;
/// Most query parameters recorded per endpoint.
pub const MAX_QUERY_KEYS: usize = 50;
/// Most array elements merged per sample (structure, not values).
pub const MAX_ARRAY_ITEMS_MERGED: usize = 20;

/// One node of the learned structure.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct SchemaNode {
    /// JSON types seen at this position (`object`, `array`, `string`,
    /// `number`, `boolean`, `null`).
    #[serde(default, skip_serializing_if = "BTreeSet::is_empty")]
    pub types: BTreeSet<String>,
    /// Object members, each merged recursively.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub keys: BTreeMap<String, SchemaNode>,
    /// Element structure for arrays.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub items: Option<Box<SchemaNode>>,
    /// Samples this node appeared in.
    #[serde(default)]
    pub presence: u64,
}

impl SchemaNode {
    fn note_type(&mut self, value: &Value) -> &'static str {
        let name = match value {
            Value::Null => "null",
            Value::Bool(_) => "boolean",
            Value::Number(_) => "number",
            Value::String(_) => "string",
            Value::Array(_) => "array",
            Value::Object(_) => "object",
        };
        self.types.insert(name.to_string());
        name
    }

    /// Merges one sample into this node. Values are inspected for their
    /// type only and dropped immediately.
    pub fn merge(&mut self, value: &Value, depth: usize) {
        self.presence += 1;
        match self.note_type(value) {
            "object" => {
                let Some(map) = value.as_object() else { return };
                for (key, child) in map {
                    if !self.keys.contains_key(key)
                        && self.keys.len() >= MAX_KEYS_PER_OBJECT
                    {
                        continue;
                    }
                    if depth >= MAX_DEPTH {
                        continue;
                    }
                    self.keys
                        .entry(key.clone())
                        .or_default()
                        .merge(child, depth + 1);
                }
            },
            "array" => {
                if depth >= MAX_DEPTH {
                    return;
                }
                let Some(items) = value.as_array() else {
                    return;
                };
                let slot = self.items.get_or_insert_with(Default::default);
                for child in items.iter().take(MAX_ARRAY_ITEMS_MERGED) {
                    slot.merge(child, depth + 1);
                }
            },
            _ => {},
        }
    }
}

/// A learned query parameter: the types its values parsed to and how often
/// it was present.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct QueryParam {
    pub types: BTreeSet<String>,
    pub count: u64,
}

/// Merges a query string into the parameter map (values classify, never
/// store).
pub fn learn_query(query: &str, params: &mut BTreeMap<String, QueryParam>) {
    for pair in query.split('&').filter(|pair| !pair.is_empty()) {
        let mut parts = pair.splitn(2, '=');
        let name = parts.next().unwrap_or_default();
        if name.is_empty() {
            continue;
        }
        let name = decode(name);
        if !params.contains_key(&name) && params.len() >= MAX_QUERY_KEYS {
            continue;
        }
        let raw = decode(parts.next().unwrap_or_default());
        let kind = classify_scalar(&raw);
        let slot = params.entry(name).or_default();
        slot.types.insert(kind.to_string());
        slot.count += 1;
    }
}

/// Whether a raw scalar looks like a number, a boolean or a string.
fn classify_scalar(raw: &str) -> &'static str {
    if raw == "true" || raw == "false" {
        return "boolean";
    }
    if !raw.is_empty() && raw.parse::<f64>().is_ok() {
        return "number";
    }
    "string"
}

/// Minimal percent-decoding for parameter names and value classification.
fn decode(raw: &str) -> String {
    let bytes = raw.as_bytes();
    let mut out = String::with_capacity(raw.len());
    let mut index = 0;
    while index < bytes.len() {
        match bytes[index] {
            b'%' if index + 2 < bytes.len() => {
                let hex = std::str::from_utf8(&bytes[index + 1..index + 3])
                    .ok()
                    .and_then(|hex| u8::from_str_radix(hex, 16).ok());
                match hex {
                    Some(byte) => {
                        out.push(byte as char);
                        index += 3;
                    },
                    None => {
                        out.push('%');
                        index += 1;
                    },
                }
            },
            b'+' => {
                out.push(' ');
                index += 1;
            },
            byte => {
                out.push(byte as char);
                index += 1;
            },
        }
    }
    out
}

/// Parses one body and merges it; `None` when the body is not JSON.
pub fn merge_body(node: &mut SchemaNode, body: &str) -> bool {
    match serde_json::from_str::<Value>(body) {
        Ok(value) => {
            node.merge(&value, 0);
            true
        },
        Err(_) => false,
    }
}

/// The status class of a response code (`2xx`, `4xx`, `5xx`; `1xx`/`3xx`
/// included for completeness).
pub fn status_class(status: i32) -> String {
    match status / 100 {
        1 => "1xx".to_string(),
        2 => "2xx".to_string(),
        3 => "3xx".to_string(),
        4 => "4xx".to_string(),
        _ => "5xx".to_string(),
    }
}

/// The representative status code the OpenAPI draft uses for a class.
pub fn class_status_code(class: &str) -> &'static str {
    match class {
        "1xx" => "100",
        "2xx" => "200",
        "3xx" => "300",
        "4xx" => "400",
        _ => "500",
    }
}

/// Replaces numeric and uuid-like path segments with a single template
/// parameter, so the draft is usable as a declaration.
pub fn templatize_path(path: &str) -> String {
    let mut out = String::with_capacity(path.len());
    for segment in path.split('/') {
        if segment.is_empty() {
            continue;
        }
        let numeric = segment.chars().all(|c| c.is_ascii_digit());
        let uuid_like = segment.len() == 36
            && segment.chars().all(|c| c.is_ascii_hexdigit() || c == '-');
        if numeric || uuid_like {
            out.push_str("/{id}");
        } else {
            out.push('/');
            out.push_str(segment);
        }
    }
    if out.is_empty() {
        out.push('/');
    }
    out
}

/// One learned endpoint as the draft generator consumes it.
#[derive(Debug, Clone)]
pub struct LearnedEndpoint {
    pub method: String,
    pub path: String,
    pub request_schema: Option<SchemaNode>,
    pub query_schema: BTreeMap<String, QueryParam>,
    /// Response structures per status class (`2xx`, `4xx`, ...).
    pub response_schemas: BTreeMap<String, SchemaNode>,
    /// JSON response bodies merged into `response_schemas`.
    pub response_samples: i64,
    pub sample_count: i64,
}

/// Builds the OpenAPI 3.0 draft from the learned rows.
///
/// It is explicitly a draft from observed traffic: no `required` lists, no
/// value constraints - presence counts ride along as `x-observed-*`
/// extensions so the document never claims more than was seen.
pub fn openapi_draft(
    site_name: &str,
    window_days: i64,
    endpoints: &[LearnedEndpoint],
) -> Value {
    let mut paths: BTreeMap<String, Value> = BTreeMap::new();
    let mut operations = 0u64;
    let mut samples = 0u64;

    for endpoint in endpoints {
        let template = templatize_path(&endpoint.path);
        let mut operation = serde_json::Map::new();
        operation.insert(
            "operationId".to_string(),
            json!(format!(
                "{}_{}",
                endpoint.method.to_lowercase(),
                template
                    .trim_matches('/')
                    .replace('/', "_")
                    .replace(['{', '}'], "")
            )),
        );
        operation.insert(
            "x-observed-samples".to_string(),
            json!(endpoint.sample_count),
        );

        if !endpoint.query_schema.is_empty() {
            let parameters: Vec<Value> = endpoint
                .query_schema
                .iter()
                .map(|(name, param)| {
                    let schema_type = if param.types.contains("number") {
                        "number"
                    } else if param.types.contains("boolean") {
                        "boolean"
                    } else {
                        "string"
                    };
                    json!({
                        "name": name,
                        "in": "query",
                        "required": false,
                        "schema": { "type": schema_type },
                        "x-observed-count": param.count,
                        "x-observed-types": param.types.iter().collect::<Vec<_>>(),
                    })
                })
                .collect();
            operation.insert("parameters".to_string(), json!(parameters));
        }

        if let Some(schema) = &endpoint.request_schema {
            operation.insert(
                "requestBody".to_string(),
                json!({
                    "required": false,
                    "content": {
                        "application/json": {
                            "schema": node_to_json_schema(schema),
                        }
                    }
                }),
            );
        }

        operation.insert(
            "responses".to_string(),
            response_section(
                &endpoint.response_schemas,
                endpoint.response_samples,
            ),
        );

        let entry = paths.entry(template).or_insert_with(|| json!({}));
        if let Some(map) = entry.as_object_mut() {
            map.insert(
                endpoint.method.to_lowercase(),
                Value::Object(operation),
            );
        }
        operations += 1;
        samples += endpoint.sample_count.max(0) as u64;
    }

    json!({
        "openapi": "3.0.3",
        "info": {
            "title": format!("{site_name} - learned API draft"),
            "version": "0.0.0-learned",
            "description": format!(
                "Generated from {operations} observed endpoint(s), {samples} \
                 JSON sample(s) over {window_days} day(s). Structures and \
                 counts only: no values were read, no fields are marked \
                 required, and response shapes are not learned yet."
            ),
        },
        "x-varman-learned": {
            "window_days": window_days,
            "endpoints": operations,
            "samples": samples,
        },
        "paths": paths,
    })
}

/// The `responses` object of one operation: one entry per learned status
/// class, or the honest default note when no JSON response body was
/// captured.
fn response_section(
    schemas: &BTreeMap<String, SchemaNode>,
    samples: i64,
) -> Value {
    if schemas.is_empty() {
        return json!({
            "default": {
                "description": format!(
                    "Observed traffic; no JSON response body was captured \
                     ({samples} merged). Response shapes are learned only \
                     when the agent captures response bodies."
                ),
            }
        });
    }
    let mut responses = serde_json::Map::new();
    for (class, node) in schemas {
        responses.insert(
            class_status_code(class).to_string(),
            json!({
                "description": format!(
                    "Observed {class} responses (structure and counts only)."
                ),
                "x-observed-class": class,
                "content": {
                    "application/json": {
                        "schema": node_to_json_schema(node),
                    }
                },
            }),
        );
    }
    Value::Object(responses)
}

/// Converts a learned node into a JSON-schema fragment.
fn node_to_json_schema(node: &SchemaNode) -> Value {
    let mut schema = serde_json::Map::new();
    schema.insert("x-observed-presence".to_string(), json!(node.presence));

    if node.types.contains("object") {
        schema.insert("type".to_string(), json!("object"));
        let properties: BTreeMap<String, Value> = node
            .keys
            .iter()
            .map(|(key, child)| (key.clone(), node_to_json_schema(child)))
            .collect();
        schema.insert("properties".to_string(), json!(properties));
        // Never claim more than was seen: everything stays optional.
        schema.insert("additionalProperties".to_string(), json!(true));
    } else if node.types.contains("array") {
        schema.insert("type".to_string(), json!("array"));
        if let Some(items) = &node.items {
            schema.insert("items".to_string(), node_to_json_schema(items));
        }
    } else {
        // A scalar position may have carried several types across samples.
        let types: Vec<&String> = node.types.iter().collect();
        if types.len() == 1 {
            schema.insert("type".to_string(), json!(types[0]));
        } else {
            schema.insert(
                "type".to_string(),
                json!(types
                    .iter()
                    .map(|name| name.as_str())
                    .collect::<Vec<_>>()),
            );
        }
    }
    Value::Object(schema)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn learning_merges_structure_and_counts_only() {
        let mut node = SchemaNode::default();
        assert!(merge_body(
            &mut node,
            r#"{"id": 12345, "name": "ada-lovelace", "tags": ["alpha-tag", "beta-tag"]}"#
        ));
        assert!(merge_body(
            &mut node,
            r#"{"id": "second-id", "items": [{"sku": "sku-x", "qty": 67890}], "ok": true}"#
        ));

        assert_eq!(node.presence, 2);
        assert!(node.types.contains("object"));
        assert_eq!(node.keys["id"].types.len(), 2, "number and string");
        assert_eq!(node.keys["name"].types.iter().next().unwrap(), "string");
        assert!(node.keys["tags"].items.is_some());
        assert_eq!(node.keys["items"].items.as_ref().unwrap().presence, 1);
        assert!(node.keys["ok"].types.contains("boolean"));

        // The serialized structure carries keys and types, never values.
        // The assertions use distinctive sample values so counts (presence)
        // cannot collide with them.
        let serialized = serde_json::to_string(&node).unwrap();
        for value in [
            "ada-lovelace",
            "second-id",
            "alpha-tag",
            "beta-tag",
            "sku-x",
            "12345",
            "67890",
        ] {
            assert!(
                !serialized.contains(value),
                "value {value} leaked into the structure"
            );
        }
    }

    #[test]
    fn bounds_hold() {
        let mut node = SchemaNode::default();
        let deep = format!(
            "{}{}{}",
            "{\"a\":".repeat(MAX_DEPTH + 4),
            "1",
            "}".repeat(MAX_DEPTH + 4)
        );
        assert!(merge_body(&mut node, &deep));
        let mut cursor = &node;
        let mut depth = 0;
        while let Some(next) = cursor.keys.get("a") {
            cursor = next;
            depth += 1;
            assert!(depth <= MAX_DEPTH + 1, "depth bound breached");
        }

        let wide: String = format!(
            "{{{}}}",
            (0..MAX_KEYS_PER_OBJECT + 20)
                .map(|index| format!("\"k{index}\": 1"))
                .collect::<Vec<_>>()
                .join(",")
        );
        let mut node = SchemaNode::default();
        assert!(merge_body(&mut node, &wide));
        assert!(node.keys.len() <= MAX_KEYS_PER_OBJECT);

        assert!(!merge_body(&mut node, "not json"));
    }

    #[test]
    fn query_learning_classifies_without_storing() {
        let mut params = BTreeMap::new();
        learn_query("page=2&q=hello%20world&flag=true&page=3", &mut params);
        assert_eq!(params["page"].count, 2);
        assert!(params["page"].types.contains("number"));
        assert!(params["q"].types.contains("string"));
        assert!(params["flag"].types.contains("boolean"));
        assert_eq!(params.len(), 3);
    }

    #[test]
    fn paths_templatize_ids() {
        assert_eq!(templatize_path("/orders/42/items"), "/orders/{id}/items");
        assert_eq!(
            templatize_path("/users/550e8400-e29b-41d4-a716-446655440000"),
            "/users/{id}"
        );
        assert_eq!(templatize_path("/orders"), "/orders");
    }

    #[test]
    fn the_draft_is_honest_and_parsable() {
        let mut request = SchemaNode::default();
        assert!(merge_body(&mut request, r#"{"sku": "a", "qty": 2}"#));
        let mut params = BTreeMap::new();
        learn_query("page=1", &mut params);
        let draft = openapi_draft(
            "example.com",
            7,
            &[LearnedEndpoint {
                method: "POST".to_string(),
                path: "/orders/42".to_string(),
                request_schema: Some(request),
                query_schema: params,
                response_schemas: {
                    let mut schemas = BTreeMap::new();
                    let mut ok = SchemaNode::default();
                    assert!(merge_body(&mut ok, r#"{"id": "abc-123"}"#));
                    schemas.insert("2xx".to_string(), ok);
                    let mut bad = SchemaNode::default();
                    assert!(merge_body(&mut bad, r#"{"error": "not found"}"#));
                    schemas.insert("4xx".to_string(), bad);
                    schemas
                },
                response_samples: 2,
                sample_count: 3,
            }],
        );

        assert_eq!(draft["openapi"], "3.0.3");
        assert_eq!(draft["x-varman-learned"]["endpoints"], 1);
        let operation = &draft["paths"]["/orders/{id}"]["post"];
        assert_eq!(operation["x-observed-samples"], 3);
        assert_eq!(
            operation["requestBody"]["content"]["application/json"]["schema"]
                ["type"],
            "object"
        );
        // No required lists anywhere: the draft claims only what was seen.
        let serialized = serde_json::to_string(&draft).unwrap();
        assert!(!serialized.contains("\"required\":["));
        assert!(serialized.contains("x-observed-presence"));

        // The response side: one entry per learned status class, structures
        // only, and the class is stated.
        let responses = &operation["responses"];
        assert_eq!(responses["200"]["x-observed-class"], "2xx");
        assert_eq!(responses["400"]["x-observed-class"], "4xx");
        assert_eq!(
            responses["200"]["content"]["application/json"]["schema"]
                ["properties"]["id"]["type"],
            "string"
        );
        for value in ["abc-123", "not found"] {
            assert!(
                !serialized.contains(value),
                "response value {value} leaked into the draft"
            );
        }
    }

    #[test]
    fn response_sections_state_when_nothing_was_captured() {
        let draft = openapi_draft(
            "example.com",
            7,
            &[LearnedEndpoint {
                method: "GET".to_string(),
                path: "/items".to_string(),
                request_schema: None,
                query_schema: BTreeMap::new(),
                response_schemas: BTreeMap::new(),
                response_samples: 0,
                sample_count: 1,
            }],
        );
        let description = draft["paths"]["/items"]["get"]["responses"]
            ["default"]["description"]
            .as_str()
            .unwrap_or_default()
            .to_string();
        assert!(
            description.contains("no JSON response body was captured"),
            "description: {description}"
        );
    }

    #[test]
    fn status_classes_group_codes() {
        assert_eq!(status_class(204), "2xx");
        assert_eq!(status_class(404), "4xx");
        assert_eq!(status_class(503), "5xx");
        assert_eq!(status_class(301), "3xx");
        assert_eq!(class_status_code("4xx"), "400");
    }
}
