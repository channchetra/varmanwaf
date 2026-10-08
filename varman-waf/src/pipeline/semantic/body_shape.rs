//! JSON body-shape detector (Phase 5 / Phase 8 API security).
//!
//! Reasons about the *shape* of a JSON request body with a byte-wise scanner
//! that is bounded, allocation-free and panic-free on hostile input — it never
//! builds a document tree, so a deeply nested payload cannot exhaust the
//! stack the way a recursive parser would.
//!
//! | Evidence | Tier |
//! | --- | --- |
//! | Nesting depth >= [`DEEP_NESTING_DEPTH`] | Monitor (`sem.body.deep_nesting`) |
//! | One array with >= [`LARGE_ARRAY_ELEMENTS`] elements | Monitor (`sem.body.large_array`) |
//!
//! Nothing blocks by default: bulk APIs legitimately send large arrays and
//! machine-generated payloads can nest deeply. The findings surface the shape
//! so policy (rate limits, size limits) can act on it, and the benign corpus
//! locks ordinary API payloads clean.

use super::super::{
    Action, AttackCategory, Confidence, Detector, DetectorId, DetectorResult,
    EvidenceSource, Finding, Severity,
};

use crate::canonical::CanonicalRequest;

/// Nesting depth at which a JSON body is reported.
pub const DEEP_NESTING_DEPTH: u32 = 24;
/// Element count at which a single array is reported.
pub const LARGE_ARRAY_ELEMENTS: u32 = 4096;

/// Shape of one JSON-ish byte stream.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
struct JsonShape {
    max_depth: u32,
    max_array_elements: u32,
    containers: u32,
}

/// Byte-wise scan: tracks string/escape state and a stack of container kinds
/// with their element counters. Never allocates beyond the (bounded) stack.
fn scan_shape(bytes: &[u8]) -> JsonShape {
    let mut shape = JsonShape::default();
    // Stack of (is_array, elements). Depth is bounded by the input length.
    let mut stack: Vec<(bool, u32)> = Vec::new();
    let mut in_string = false;
    let mut escaped = false;
    for &byte in bytes {
        if in_string {
            if escaped {
                escaped = false;
            } else if byte == b'\\' {
                escaped = true;
            } else if byte == b'"' {
                in_string = false;
            }
            continue;
        }
        match byte {
            b'"' => in_string = true,
            b'{' | b'[' => {
                stack.push((byte == b'[', 0));
                shape.containers = shape.containers.saturating_add(1);
                shape.max_depth = shape.max_depth.max(stack.len() as u32);
            },
            b'}' | b']' => {
                if let Some((is_array, elements)) = stack.pop() {
                    if is_array && elements > 0 {
                        shape.max_array_elements =
                            shape.max_array_elements.max(elements + 1);
                    }
                }
            },
            b',' => {
                if let Some(top) = stack.last_mut() {
                    top.1 = top.1.saturating_add(1);
                }
            },
            _ => {},
        }
    }
    shape
}

/// `true` when the body should be treated as JSON: an explicit JSON content
/// type or a first non-space byte that opens an object/array.
fn looks_like_json(content_type: Option<&str>, bytes: &[u8]) -> bool {
    if content_type
        .is_some_and(|value| value.to_ascii_lowercase().contains("json"))
    {
        return true;
    }
    bytes
        .iter()
        .find(|byte| !byte.is_ascii_whitespace())
        .is_some_and(|byte| *byte == b'{' || *byte == b'[')
}

/// JSON body-shape detector.
#[derive(Debug, Clone, Copy)]
pub struct BodyShapeDetector {
    deep_nesting_depth: u32,
    large_array_elements: u32,
}

impl BodyShapeDetector {
    pub const fn new() -> Self {
        Self {
            deep_nesting_depth: DEEP_NESTING_DEPTH,
            large_array_elements: LARGE_ARRAY_ELEMENTS,
        }
    }

    /// Thresholds for tests and tuned deployments.
    pub const fn with_thresholds(
        deep_nesting_depth: u32,
        large_array_elements: u32,
    ) -> Self {
        Self {
            deep_nesting_depth,
            large_array_elements,
        }
    }
}

impl Default for BodyShapeDetector {
    fn default() -> Self {
        Self::new()
    }
}

impl Detector for BodyShapeDetector {
    fn id(&self) -> DetectorId {
        DetectorId("semantic.body.shape")
    }

    fn inspect(
        &self,
        request: &CanonicalRequest,
        ctx: &mut super::super::DetectionContext,
    ) -> DetectorResult {
        let mut findings: Vec<Finding> = Vec::new();
        let mut degraded = None;

        let Some(body) = request.body() else {
            return DetectorResult { findings, degraded };
        };
        if !looks_like_json(request.header("content-type"), body) {
            return DetectorResult { findings, degraded };
        }
        let limit = ctx.budget().max_body_bytes.min(body.len());
        if body.len() > limit && degraded.is_none() {
            degraded = Some("body scan truncated at budget");
        }
        let shape = scan_shape(&body[..limit]);

        if shape.max_depth >= self.deep_nesting_depth {
            findings.push(
                Finding::new(
                    DetectorId("semantic.body.shape"),
                    "sem.body.deep_nesting",
                    AttackCategory::ApiAbuse,
                )
                .confidence(Confidence::Medium)
                .severity(Severity::Medium)
                .score(20)
                .action(Action::Monitor)
                .source(EvidenceSource::Body)
                .detail(format!(
                    "JSON body nests {} levels deep (limit {})",
                    shape.max_depth, self.deep_nesting_depth
                )),
            );
        }
        if shape.max_array_elements >= self.large_array_elements {
            findings.push(
                Finding::new(
                    DetectorId("semantic.body.shape"),
                    "sem.body.large_array",
                    AttackCategory::ApiAbuse,
                )
                .confidence(Confidence::Medium)
                .severity(Severity::Medium)
                .score(15)
                .action(Action::Monitor)
                .source(EvidenceSource::Body)
                .detail(format!(
                    "JSON body contains an array of {} elements (limit {})",
                    shape.max_array_elements, self.large_array_elements
                )),
            );
        }

        DetectorResult { findings, degraded }
    }
}

#[cfg(test)]
mod tests {
    use super::{scan_shape, BodyShapeDetector};
    use crate::canonical::{Canonicalizer, RequestParts};
    use crate::pipeline::{Action, AttackCategory, DetectionContext, Detector};

    fn post(content_type: &str, body: &str) -> crate::pipeline::DetectorResult {
        let request = Canonicalizer::default().canonicalize(
            RequestParts::new("POST", "api.example.com", "/v1/items")
                .with_header("Content-Type", content_type)
                .with_body(body.as_bytes().to_vec()),
        );
        let detector = BodyShapeDetector::new();
        let mut ctx = DetectionContext::new();
        detector.inspect(&request, &mut ctx)
    }

    #[test]
    fn shape_scanner_counts_depth_and_arrays() {
        let shape = scan_shape(br#"{"a":{"b":[1,2,3]},"c":[[1],[2,3]]}"#);
        assert_eq!(shape.max_depth, 3);
        assert_eq!(shape.max_array_elements, 3);
        assert_eq!(shape.containers, 6);

        // Braces inside strings and escaped quotes do not count.
        let shape = scan_shape(br#"{"a":"{{{{","b":"\" [ [ ["}"#);
        assert_eq!(shape.max_depth, 1);
        assert_eq!(shape.max_array_elements, 0);

        // Truncated input must not panic or mis-count.
        let shape = scan_shape(br#"{"a":[1,2"#);
        assert_eq!(shape.max_depth, 2);
        assert_eq!(shape.max_array_elements, 0);
    }

    #[test]
    fn deep_nesting_monitors() {
        let mut body = String::new();
        for _ in 0..30 {
            body.push_str("{\"a\":");
        }
        body.push('1');
        for _ in 0..30 {
            body.push('}');
        }
        let result = post("application/json", &body);
        assert_eq!(result.findings.len(), 1);
        assert_eq!(result.findings[0].rule_id, "sem.body.deep_nesting");
        assert_eq!(result.findings[0].action_hint, Action::Monitor);
        assert_eq!(result.findings[0].category, AttackCategory::ApiAbuse);
    }

    #[test]
    fn large_arrays_monitor() {
        let elements: Vec<String> =
            (0..5000).map(|index| index.to_string()).collect();
        let body = format!("{{\"items\":[{}]}}", elements.join(","));
        let result = post("application/json; charset=utf-8", &body);
        assert_eq!(result.findings.len(), 1);
        assert_eq!(result.findings[0].rule_id, "sem.body.large_array");
        assert_eq!(result.findings[0].action_hint, Action::Monitor);
    }

    #[test]
    fn ordinary_payloads_stay_clean() {
        // Depth 6, 100-element array: ordinary API traffic.
        let items: Vec<String> =
            (0..100).map(|index| index.to_string()).collect();
        let body = format!(
            "{{\"page\":1,\"data\":{{\"items\":[{}],\"meta\":{{\"total\":100}}}}}}",
            elements_join(&items)
        );
        assert!(post("application/json", &body).findings.is_empty());

        // JSON detected by shape even without a content type.
        assert!(post("text/plain", "{\"a\":1}").findings.is_empty());

        // Non-JSON bodies are never scanned.
        assert!(post("text/plain", "not json at all").findings.is_empty());
        assert!(post("application/x-www-form-urlencoded", "a=1&b=2")
            .findings
            .is_empty());

        // No body: nothing to inspect.
        let request = Canonicalizer::default().canonicalize(RequestParts::new(
            "GET",
            "api.example.com",
            "/v1/items",
        ));
        let mut ctx = DetectionContext::new();
        assert!(BodyShapeDetector::new()
            .inspect(&request, &mut ctx)
            .findings
            .is_empty());
    }

    fn elements_join(items: &[String]) -> String {
        items.join(",")
    }

    #[test]
    fn thresholds_are_configurable() {
        let body = "{\"a\":[1,2,3]}";
        let request = Canonicalizer::default().canonicalize(
            RequestParts::new("POST", "api.example.com", "/")
                .with_header("Content-Type", "application/json")
                .with_body(body.as_bytes().to_vec()),
        );
        let detector = BodyShapeDetector::with_thresholds(1, 3);
        let mut ctx = DetectionContext::new();
        let result = detector.inspect(&request, &mut ctx);
        assert_eq!(result.findings.len(), 2);
    }
}
