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
pub mod policy;
pub mod semantic;
pub mod shadow;
pub mod snapshot;

pub use action::Action;
pub use category::AttackCategory;
pub use detector::{
    Degradation, DetectionContext, Detector, DetectorResult, InspectionBudget,
};
pub use finding::{Confidence, DetectorId, EvidenceSource, Finding, Severity};
pub use semantic::SqlStructuralDetector;
pub use snapshot::{SecurityRuntime, SecuritySnapshot, SiteRuntime};

use crate::canonical::CanonicalRequest;

/// Byte-window slice that never cuts a UTF-8 character.
///
/// Detectors scan arbitrary attacker bytes; slicing at `start + max_len` can
/// land mid-character and panic. All window readers go through this helper.
pub(crate) fn safe_window(s: &str, start: usize, max_len: usize) -> &str {
    let mut start = start.min(s.len());
    while start < s.len() && !s.is_char_boundary(start) {
        start += 1;
    }
    let mut end = start.saturating_add(max_len).min(s.len());
    while end > start && !s.is_char_boundary(end) {
        end -= 1;
    }
    &s[start..end]
}

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

    /// Convert into the proxy-facing [`crate::WafVerdict`] shape so an
    /// enforcing caller can apply the pipeline's verdict with the same
    /// response mapping the legacy engine uses.
    ///
    /// `Log` and `Monitor` both map to [`crate::WafAction::Monitor`]: the
    /// event is recorded and the request proceeds. The score breakdown is
    /// rebuilt from the findings' categories so event/dashboard consumers see
    /// the same shape they see from the legacy engine.
    pub fn to_waf_verdict(&self) -> crate::WafVerdict {
        use crate::{ScoreBreakdown, ScoreClass, WafAction, WafVerdict};

        let action = match self.action {
            Action::Pass => WafAction::Pass,
            Action::Log | Action::Monitor => WafAction::Monitor,
            Action::Challenge => WafAction::Challenge,
            Action::Block => WafAction::Block,
        };

        let mut breakdown = ScoreBreakdown::clean();
        for finding in &self.findings {
            let score = u8::try_from(finding.score.min(99)).unwrap_or(99);
            match finding.category {
                AttackCategory::SqlInjection => {
                    breakdown.sqli_score =
                        breakdown.sqli_score.saturating_add(score).min(99);
                },
                AttackCategory::Xss => {
                    breakdown.xss_score =
                        breakdown.xss_score.saturating_add(score).min(99);
                },
                AttackCategory::CommandInjection => {
                    breakdown.rce_score =
                        breakdown.rce_score.saturating_add(score).min(99);
                },
                _ => {},
            }
        }
        breakdown.total = self.score;
        breakdown.block_total = self.score;
        breakdown.block_sqli_score = breakdown.sqli_score;
        breakdown.block_xss_score = breakdown.xss_score;
        breakdown.block_rce_score = breakdown.rce_score;
        breakdown.overall_class = match self.action {
            Action::Pass => ScoreClass::Clean,
            Action::Log => ScoreClass::LikelyClean,
            Action::Monitor => ScoreClass::LikelyAttack,
            Action::Challenge | Action::Block => ScoreClass::Attack,
        };

        let matched_rules = self
            .findings
            .iter()
            .map(|finding| finding.rule_id.to_string())
            .collect();
        let details = if self.findings.is_empty() {
            String::new()
        } else {
            let mut details = format!(
                "varman-pipeline: {} finding(s), score {}",
                self.findings.len(),
                self.score
            );
            for finding in self.findings.iter().take(4) {
                details.push_str(&format!(
                    "; {} {}",
                    finding.detector.as_str(),
                    finding.rule_id
                ));
            }
            details
        };

        WafVerdict {
            action,
            score: u8::try_from(self.score).unwrap_or(u8::MAX),
            matched_rules,
            details,
            breakdown,
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

    #[test]
    fn to_waf_verdict_maps_actions_scores_and_rules() {
        use super::PipelineVerdict;
        use crate::{ScoreClass, WafAction};

        let mut verdict = PipelineVerdict {
            action: Action::Block,
            score: 40,
            findings: vec![
                Finding::new(
                    DetectorId("sql"),
                    "sql-1",
                    AttackCategory::SqlInjection,
                )
                .score(40)
                .action(Action::Block),
                Finding::new(DetectorId("xss"), "xss-1", AttackCategory::Xss)
                    .score(25)
                    .action(Action::Log),
            ],
            degraded: Vec::new(),
        };
        let mapped = verdict.to_waf_verdict();
        assert_eq!(mapped.action, WafAction::Block);
        assert_eq!(mapped.score, 40);
        assert_eq!(mapped.matched_rules, vec!["sql-1", "xss-1"]);
        assert_eq!(mapped.breakdown.sqli_score, 40);
        assert_eq!(mapped.breakdown.xss_score, 25);
        assert_eq!(mapped.breakdown.total, 40);
        assert_eq!(mapped.breakdown.overall_class, ScoreClass::Attack);
        assert!(mapped.details.contains("varman-pipeline"));

        // Log/Monitor hints map to Monitor; the score saturates at u8::MAX.
        verdict.action = Action::Monitor;
        verdict.score = 1000;
        let mapped = verdict.to_waf_verdict();
        assert_eq!(mapped.action, WafAction::Monitor);
        assert_eq!(mapped.score, u8::MAX);
        assert_eq!(mapped.breakdown.overall_class, ScoreClass::LikelyAttack);

        let clean = PipelineVerdict::pass().to_waf_verdict();
        assert_eq!(clean.action, WafAction::Pass);
        assert_eq!(clean.breakdown.overall_class, ScoreClass::Clean);
        assert!(clean.matched_rules.is_empty());
        assert!(clean.details.is_empty());
    }
}
