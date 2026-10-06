//! The Varman detection pipeline (Phase 2 skeleton).
//!
//! # Scope of this module
//!
//! This is the *shape* of the new engine, landed while the legacy engine
//! (`crate::engine`, `crate::rules`, `crate::score`) keeps serving every
//! request. Nothing here is wired into the proxy yet: the pipeline exists to
//! host detectors, enforce the action and budget invariants, and support
//! shadow comparison (`shadow::compare`) before any enforcement switch.
//!
//! # Architecture (target)
//!
//! ```text
//! CanonicalRequest
//!   │
//!   ▼
//! Lane 1 — fast detectors      (signatures, protocol, cheap screens)
//!   │
//!   ▼
//! Structured extraction        (body → JSON/XML/form/multipart/GraphQL)
//!   │
//!   ▼
//! Lane 2 — semantic detectors  (SQL structural/AST, DOM XSS, shell, …)
//!   │
//!   ▼
//! Lane 3 — SecLang / CRS       (Phase 7)
//!   │
//!   ▼
//! PipelineVerdict { action, score, findings, degraded }
//! ```
//!
//! Lane ordering is detector *list order*: detectors run in the order they
//! were registered, deterministically. Cheap detectors come first so they can
//! short-circuit expensive ones (Phase 4/6), and `Block` may stop inspection
//! when [`PipelineConfig::stop_on_block`] is set.
//!
//! # Invariants
//!
//! - **Monotonic escalation** — the verdict action is the maximum
//!   [`Action`] among findings (mandate §7); later weak findings never
//!   downgrade.
//! - **Bounded work** — findings are capped per request
//!   ([`InspectionBudget`]); overflow is recorded as degradation, never as a
//!   panic or unbounded allocation.
//! - **Degradation is data** — detectors that hit limits return
//!   [`DetectorResult::degraded`]; the remaining layers still run.
//! - **No I/O, no locks** — detectors inspect only the request and return
//!   findings; state lives behind snapshots owned by the caller.

pub mod action;
pub mod category;
pub mod detector;
pub mod fast;
pub mod finding;
pub mod shadow;

pub use action::Action;
pub use category::AttackCategory;
pub use detector::{
    Degradation, DetectionContext, Detector, DetectorResult, InspectionBudget,
};
pub use finding::{Confidence, DetectorId, EvidenceSource, Finding, Severity};

use crate::canonical::CanonicalRequest;

/// Pipeline-wide behaviour switches.
///
/// Defaults to running every detector (`stop_on_block: false`): shadow mode
/// wants the complete picture of what *would* have fired. Fast-lane
/// enforcement turns it on.
#[derive(Debug, Clone, Copy, Default)]
pub struct PipelineConfig {
    /// Stop after the detector that first escalates to [`Action::Block`].
    pub stop_on_block: bool,
}

/// Aggregate result for one inspected request.
#[derive(Debug, Clone)]
pub struct PipelineVerdict {
    /// Strongest action among all findings (monotonic).
    pub action: Action,
    /// Saturating sum of finding scores.
    pub score: u32,
    pub findings: Vec<Finding>,
    /// Detectors that could not complete their inspection.
    pub degraded: Vec<Degradation>,
}

impl PipelineVerdict {
    /// A clean pass with no findings.
    pub fn pass() -> Self {
        Self {
            action: Action::Pass,
            score: 0,
            findings: Vec::new(),
            degraded: Vec::new(),
        }
    }
}

/// Ordered collection of detectors.
pub struct SecurityPipeline {
    detectors: Vec<Box<dyn Detector>>,
    config: PipelineConfig,
}

impl SecurityPipeline {
    pub fn new(detectors: Vec<Box<dyn Detector>>) -> Self {
        Self {
            detectors,
            config: PipelineConfig::default(),
        }
    }

    pub fn with_config(
        detectors: Vec<Box<dyn Detector>>,
        config: PipelineConfig,
    ) -> Self {
        Self { detectors, config }
    }

    pub fn detector_count(&self) -> usize {
        self.detectors.len()
    }

    /// Run every detector (in registration order) against one request.
    pub fn inspect(&self, request: &CanonicalRequest) -> PipelineVerdict {
        let mut ctx = DetectionContext::new();
        let mut action = Action::Pass;

        for detector in &self.detectors {
            let result = detector.inspect(request, &mut ctx);
            if let Some(reason) = result.degraded {
                ctx.mark_degraded(detector.id(), reason);
            }
            for finding in result.findings {
                action = action.escalate(finding.action_hint);
                ctx.push_findings(std::iter::once(finding));
            }
            if self.config.stop_on_block && action.is_terminal() {
                break;
            }
        }

        let findings = ctx.take_findings();
        let degraded = ctx.take_degraded();
        let score = findings
            .iter()
            .fold(0u32, |acc, f| acc.saturating_add(f.score));

        PipelineVerdict {
            action,
            score,
            findings,
            degraded,
        }
    }
}

impl std::fmt::Debug for SecurityPipeline {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SecurityPipeline")
            .field(
                "detectors",
                &self
                    .detectors
                    .iter()
                    .map(|d| d.id().as_str())
                    .collect::<Vec<_>>(),
            )
            .field("config", &self.config)
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::{
        Action, AttackCategory, DetectionContext, Detector, DetectorId,
        DetectorResult, Finding, PipelineConfig, SecurityPipeline,
    };
    use crate::canonical::CanonicalRequest;

    /// A detector that returns a fixed script of results and records how often
    /// it ran. The run counter is shared with the test so pipeline ordering can
    /// be asserted after the boxes moved into the pipeline.
    struct Scripted {
        id: DetectorId,
        findings: Vec<Finding>,
        degraded: Option<&'static str>,
        runs: std::sync::Arc<std::sync::atomic::AtomicUsize>,
    }

    impl Scripted {
        fn new(id: DetectorId) -> Self {
            Self {
                id,
                findings: Vec::new(),
                degraded: None,
                runs: std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(
                    0,
                )),
            }
        }

        fn counter(&self) -> std::sync::Arc<std::sync::atomic::AtomicUsize> {
            std::sync::Arc::clone(&self.runs)
        }

        fn hitting(
            mut self,
            rule: &'static str,
            score: u32,
            action: Action,
        ) -> Self {
            let finding = Finding::new(self.id, rule, AttackCategory::Unknown)
                .score(score)
                .action(action);
            self.findings.push(finding);
            self
        }

        fn degrading(mut self, reason: &'static str) -> Self {
            self.degraded = Some(reason);
            self
        }
    }

    fn runs(counter: &std::sync::atomic::AtomicUsize) -> usize {
        counter.load(std::sync::atomic::Ordering::SeqCst)
    }

    impl Detector for Scripted {
        fn id(&self) -> DetectorId {
            self.id
        }

        fn inspect(
            &self,
            _request: &CanonicalRequest,
            _ctx: &mut DetectionContext,
        ) -> DetectorResult {
            self.runs.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            let mut result =
                DetectorResult::with_findings(self.findings.clone());
            result.degraded = self.degraded;
            result
        }
    }

    fn request() -> CanonicalRequest {
        CanonicalRequest::new("GET", "example.com", "/")
    }

    #[test]
    fn verdict_action_is_the_maximum_hint() {
        let pipeline = SecurityPipeline::new(vec![
            Box::new(Scripted::new(DetectorId("a")).hitting(
                "A-1",
                10,
                Action::Log,
            )),
            Box::new(Scripted::new(DetectorId("b")).hitting(
                "B-1",
                20,
                Action::Challenge,
            )),
            Box::new(Scripted::new(DetectorId("c")).hitting(
                "C-1",
                5,
                Action::Pass,
            )),
        ]);
        let verdict = pipeline.inspect(&request());
        assert_eq!(verdict.action, Action::Challenge);
        assert_eq!(verdict.score, 35);
        assert_eq!(verdict.findings.len(), 3);
    }

    #[test]
    fn later_weak_findings_never_downgrade() {
        let pipeline = SecurityPipeline::new(vec![
            Box::new(Scripted::new(DetectorId("strong")).hitting(
                "S-1",
                40,
                Action::Block,
            )),
            Box::new(Scripted::new(DetectorId("weak")).hitting(
                "W-1",
                1,
                Action::Log,
            )),
        ]);
        let verdict = pipeline.inspect(&request());
        assert_eq!(verdict.action, Action::Block);
        assert_eq!(verdict.findings.len(), 2);
    }

    #[test]
    fn stop_on_block_skips_remaining_detectors() {
        let first = Scripted::new(DetectorId("first")).hitting(
            "F-1",
            40,
            Action::Block,
        );
        let first_runs = first.counter();
        let second = Scripted::new(DetectorId("second"));
        let second_runs = second.counter();

        let pipeline = SecurityPipeline::with_config(
            vec![Box::new(first), Box::new(second)],
            PipelineConfig {
                stop_on_block: true,
            },
        );
        let verdict = pipeline.inspect(&request());
        assert_eq!(verdict.action, Action::Block);
        assert_eq!(verdict.findings.len(), 1);
        assert_eq!(runs(&first_runs), 1);
        assert_eq!(
            runs(&second_runs),
            0,
            "second detector must not run after block"
        );
    }

    #[test]
    fn every_detector_runs_without_stop_on_block() {
        let first = Scripted::new(DetectorId("first")).hitting(
            "F-1",
            40,
            Action::Block,
        );
        let first_runs = first.counter();
        let second = Scripted::new(DetectorId("second"));
        let second_runs = second.counter();

        let pipeline =
            SecurityPipeline::new(vec![Box::new(first), Box::new(second)]);
        let verdict = pipeline.inspect(&request());
        assert_eq!(verdict.action, Action::Block);
        assert_eq!(runs(&first_runs), 1);
        assert_eq!(runs(&second_runs), 1);
    }

    #[test]
    fn degradation_is_recorded_and_other_detectors_still_run() {
        let pipeline = SecurityPipeline::new(vec![
            Box::new(
                Scripted::new(DetectorId("sick")).degrading("parse budget"),
            ),
            Box::new(Scripted::new(DetectorId("healthy")).hitting(
                "H-1",
                10,
                Action::Log,
            )),
        ]);
        let verdict = pipeline.inspect(&request());
        assert_eq!(verdict.findings.len(), 1);
        assert_eq!(verdict.degraded.len(), 1);
        assert_eq!(verdict.degraded[0].detector.as_str(), "sick");
        assert_eq!(verdict.degraded[0].reason, "parse budget");
        assert_eq!(verdict.action, Action::Log);
    }

    #[test]
    fn empty_pipeline_passes() {
        let pipeline = SecurityPipeline::new(Vec::new());
        let verdict = pipeline.inspect(&request());
        assert_eq!(verdict.action, Action::Pass);
        assert_eq!(verdict.score, 0);
        assert!(verdict.findings.is_empty());
        assert!(verdict.degraded.is_empty());
    }
}
