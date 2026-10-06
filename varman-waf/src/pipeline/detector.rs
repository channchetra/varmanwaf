//! Detector contract and per-request detection context.
//!
//! Every Varman detection module implements [`Detector`]. The pipeline owns
//! the detector list and the execution order; a detector only inspects the
//! [`CanonicalRequest`] and returns structured
//! [`Finding`](super::Finding)s. Expansion beyond the native engine
//! (external processors, later) must go through this trait rather than
//! reaching into the request path directly.

use super::{DetectorId, Finding};

use crate::canonical::CanonicalRequest;

/// A degradation reason: the detector could not do its full job.
///
/// Degradation is data, not an error: the pipeline records it, metrics count
/// it, and remaining layers still run (mandate §8 / §38).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Degradation {
    pub detector: DetectorId,
    pub reason: &'static str,
}

/// Per-request resource limits for detection.
///
/// Unbounded attacker-controlled work is forbidden; a detector that reaches a
/// budget marks itself degraded and returns what it has.
#[derive(Debug, Clone, Copy)]
pub struct InspectionBudget {
    /// Maximum number of findings retained for one request. Beyond this the
    /// pipeline truncates and records a degradation.
    pub max_findings: usize,
    /// Largest body slice a detector may inspect (semantic parsers use this;
    /// streaming windows arrive in Phase 5).
    pub max_body_bytes: usize,
}

impl Default for InspectionBudget {
    fn default() -> Self {
        Self {
            max_findings: 256,
            max_body_bytes: 1024 * 1024,
        }
    }
}

/// Shared state handed to every detector for one request.
///
/// Contains the findings accumulated so far (detectors may read earlier
/// findings to avoid duplicating a signal), recorded degradations and the
/// enforcement budget. Detectors return their own findings via
/// [`DetectorResult`]; the pipeline appends them here.
#[derive(Debug)]
pub struct DetectionContext {
    findings: Vec<Finding>,
    degraded: Vec<Degradation>,
    budget: InspectionBudget,
    cap_recorded: bool,
}

impl DetectionContext {
    pub fn new() -> Self {
        Self::with_budget(InspectionBudget::default())
    }

    pub fn with_budget(budget: InspectionBudget) -> Self {
        Self {
            findings: Vec::new(),
            degraded: Vec::new(),
            budget,
            cap_recorded: false,
        }
    }

    pub fn budget(&self) -> InspectionBudget {
        self.budget
    }

    /// Findings recorded so far (from earlier detectors).
    pub fn findings(&self) -> &[Finding] {
        &self.findings
    }

    /// Record additional findings, honouring `max_findings`.
    ///
    /// Returns `true` when every finding was retained.
    pub fn push_findings(
        &mut self,
        findings: impl IntoIterator<Item = Finding>,
    ) -> bool {
        let mut complete = true;
        for finding in findings {
            if self.findings.len() >= self.budget.max_findings {
                if !self.cap_recorded {
                    self.degraded.push(Degradation {
                        detector: DetectorId("pipeline"),
                        reason: "finding cap reached",
                    });
                    self.cap_recorded = true;
                }
                complete = false;
                continue;
            }
            self.findings.push(finding);
        }
        complete
    }

    /// Record that a detector could not complete its inspection.
    pub fn mark_degraded(
        &mut self,
        detector: DetectorId,
        reason: &'static str,
    ) {
        self.degraded.push(Degradation { detector, reason });
    }

    pub fn degraded(&self) -> &[Degradation] {
        &self.degraded
    }

    pub(crate) fn take_findings(&mut self) -> Vec<Finding> {
        std::mem::take(&mut self.findings)
    }

    pub(crate) fn take_degraded(&mut self) -> Vec<Degradation> {
        std::mem::take(&mut self.degraded)
    }
}

impl Default for DetectionContext {
    fn default() -> Self {
        Self::new()
    }
}

/// What a detector returns for one request.
#[derive(Debug, Default)]
pub struct DetectorResult {
    pub findings: Vec<Finding>,
    /// `Some(reason)` when the detector hit a limit or could not parse.
    pub degraded: Option<&'static str>,
}

impl DetectorResult {
    /// No findings, no degradation.
    pub fn clean() -> Self {
        Self::default()
    }

    pub fn finding(finding: Finding) -> Self {
        Self {
            findings: vec![finding],
            degraded: None,
        }
    }

    pub fn with_findings(findings: Vec<Finding>) -> Self {
        Self {
            findings,
            degraded: None,
        }
    }

    pub fn degraded(reason: &'static str) -> Self {
        Self {
            findings: Vec::new(),
            degraded: Some(reason),
        }
    }
}

/// A detection module.
///
/// Implementations must be cheap to share across threads (`Send + Sync`) and
/// must never panic on attacker input; resource exhaustion or parser failure
/// is reported as degradation.
pub trait Detector: Send + Sync {
    /// Stable detector identifier (see [`DetectorId`] conventions).
    fn id(&self) -> DetectorId;

    /// Inspect one canonical request.
    fn inspect(
        &self,
        request: &CanonicalRequest,
        ctx: &mut DetectionContext,
    ) -> DetectorResult;
}

#[cfg(test)]
mod tests {
    use super::{DetectionContext, DetectorResult, InspectionBudget};
    use crate::pipeline::{AttackCategory, DetectorId, Finding};

    fn finding(rule: &'static str) -> Finding {
        Finding::new(DetectorId("test"), rule, AttackCategory::Unknown)
    }

    #[test]
    fn finding_cap_truncates_and_degrades_once() {
        let mut ctx = DetectionContext::with_budget(InspectionBudget {
            max_findings: 2,
            ..InspectionBudget::default()
        });
        let complete = ctx.push_findings(vec![
            finding("A"),
            finding("B"),
            finding("C"),
            finding("D"),
        ]);
        assert!(!complete);
        assert_eq!(ctx.findings().len(), 2);
        assert_eq!(ctx.degraded().len(), 1);
        assert_eq!(ctx.degraded()[0].reason, "finding cap reached");

        // A second overflow does not duplicate the degradation record.
        ctx.push_findings(vec![finding("E")]);
        assert_eq!(ctx.degraded().len(), 1);
    }

    #[test]
    fn detector_result_constructors() {
        assert!(DetectorResult::clean().findings.is_empty());
        assert_eq!(DetectorResult::finding(finding("A")).findings.len(), 1);
        assert_eq!(
            DetectorResult::degraded("parse depth limit").degraded,
            Some("parse depth limit")
        );
    }
}
