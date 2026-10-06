//! Lane 1 — fast detectors (Phase 4).
//!
//! Fast detectors run before any semantic parsing: they are pure functions
//! over the canonical request with no allocations on the happy path, and
//! their findings carry weak actions (never `Block` until policy says so).
//!
//! Detectors:
//! - [`signatures::SignatureDetector`] — Aho-Corasick signature scanning of
//!   the canonical request (starter table, tiered Block/Log).
//! - [`RawPathTraversalDetector`] — dot-segment evidence in the raw path,
//!   resolved by the canonicalizer.

pub mod signatures;

pub use signatures::SignatureDetector;

use super::{
    Action, AttackCategory, Detector, DetectorId, DetectorResult,
    EvidenceSource, Finding, Severity,
};

use crate::canonical::{
    decode_layers, CanonicalRequest, DEFAULT_DECODE_LAYERS,
};

/// Rule id for traversal evidence.
pub const RULE_TRAVERSAL: &str = "VARMAN-FAST-101";

/// Flags dot segments (`..`) in the decoded raw path.
///
/// Two tiers:
/// - the dot segments tried to climb above the root (`/../etc/passwd`,
///   encoded or not) — high confidence, `Medium` severity;
/// - the dot segments stayed inside the tree (`/a/../b` — common in real
///   links) — low severity.
///
/// The action hint is `Log` on purpose: enforcement for traversal is a policy
/// decision (paths and backend behaviour differ per site), and during the
/// shadow period this detector must not influence blocking.
#[derive(Debug, Clone, Copy)]
pub struct RawPathTraversalDetector {
    layers: u8,
}

impl RawPathTraversalDetector {
    pub const fn new() -> Self {
        Self {
            layers: DEFAULT_DECODE_LAYERS,
        }
    }

    /// Override the decoding depth (strict profiles decode one more layer).
    pub const fn with_layers(layers: u8) -> Self {
        Self { layers }
    }
}

impl Default for RawPathTraversalDetector {
    fn default() -> Self {
        Self::new()
    }
}

/// `true` when any `..` segment tries to climb above the root
/// (`/../etc` escapes; `/a/../b` does not, and neither does `/a/../../b`
/// only until its second `..` — that one escapes).
fn escapes_root(decoded: &str) -> bool {
    let mut depth = 0i32;
    for segment in decoded.split('/') {
        match segment {
            ".." => {
                depth -= 1;
                if depth < 0 {
                    return true;
                }
            },
            "" | "." => {},
            _ => depth += 1,
        }
    }
    false
}

impl Detector for RawPathTraversalDetector {
    fn id(&self) -> DetectorId {
        DetectorId("fast.path_traversal")
    }

    fn inspect(
        &self,
        request: &CanonicalRequest,
        _ctx: &mut super::DetectionContext,
    ) -> DetectorResult {
        let decoded = decode_layers(request.raw_path(), self.layers);
        if !decoded.split('/').any(|segment| segment == "..") {
            return DetectorResult::clean();
        }

        let escaped = escapes_root(&decoded);
        let (severity, score) = if escaped {
            (Severity::Medium, 15)
        } else {
            (Severity::Low, 5)
        };
        let finding = Finding::new(
            self.id(),
            RULE_TRAVERSAL,
            AttackCategory::PathTraversal,
        )
        .confidence(super::Confidence::High)
        .severity(severity)
        .score(score)
        .action(Action::Log)
        .source(EvidenceSource::Path)
        .field("path")
        .detail(format!(
            "dot segments in raw path resolved to {:?} (decoded: {:?})",
            request.path(),
            decoded
        ));

        DetectorResult::finding(finding)
    }
}

#[cfg(test)]
mod tests {
    use super::RawPathTraversalDetector;
    use crate::canonical::{Canonicalizer, RequestParts};
    use crate::pipeline::{Action, DetectionContext, Detector};

    fn inspect(target: &str) -> crate::pipeline::DetectorResult {
        let request = Canonicalizer::default().canonicalize(RequestParts::new(
            "GET",
            "example.com",
            target,
        ));
        let detector = RawPathTraversalDetector::new();
        let mut ctx = DetectionContext::new();
        detector.inspect(&request, &mut ctx)
    }

    #[test]
    fn clean_path_has_no_findings() {
        assert!(inspect("/a/b/c").findings.is_empty());
        // A single dot is not traversal material.
        assert!(inspect("/a/./b").findings.is_empty());
        assert!(inspect("/a.b/c..d").findings.is_empty());
    }

    #[test]
    fn in_tree_dot_segments_are_low_severity() {
        let result = inspect("/a/../b");
        assert_eq!(result.findings.len(), 1);
        let finding = &result.findings[0];
        assert_eq!(finding.action_hint, Action::Log);
        assert_eq!(finding.severity, crate::pipeline::Severity::Low);
        assert_eq!(finding.rule_id, super::RULE_TRAVERSAL);
    }

    #[test]
    fn root_escape_is_medium_severity() {
        let result = inspect("/../etc/passwd");
        assert_eq!(result.findings.len(), 1);
        assert_eq!(
            result.findings[0].severity,
            crate::pipeline::Severity::Medium
        );
        assert_eq!(result.findings[0].score, 15);
    }

    #[test]
    fn escape_is_detected_whenever_depth_crosses_the_root() {
        // The second `..` escapes even though a later segment exists.
        let escaping = inspect("/a/../../b");
        assert_eq!(
            escaping.findings[0].severity,
            crate::pipeline::Severity::Medium
        );
        // .../../.. returns exactly to the root: still in-tree.
        let in_tree = inspect("/a/b/../..");
        assert_eq!(
            in_tree.findings[0].severity,
            crate::pipeline::Severity::Low
        );
    }

    #[test]
    fn encoded_traversal_is_detected_on_the_raw_path() {
        let result = inspect("/%2e%2e/%2e%2e/etc/passwd");
        assert_eq!(result.findings.len(), 1);
        assert_eq!(
            result.findings[0].severity,
            crate::pipeline::Severity::Medium
        );
        let detail = result.findings[0].detail.as_deref().unwrap_or_default();
        assert!(detail.contains("/etc/passwd"), "detail: {detail}");
    }

    #[test]
    fn query_dots_do_not_trigger_the_path_detector() {
        assert!(inspect("/search?q=..%2f..%2fetc").findings.is_empty());
    }
}
