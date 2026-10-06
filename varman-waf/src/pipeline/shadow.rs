//! Shadow comparison between the legacy engine and the Varman pipeline.
//!
//! Phase 2 runs both engines side by side: the legacy verdict is the only one
//! enforced, the pipeline verdict is recorded and compared. Replacing the
//! legacy engine is only allowed once the comparison shows no downgrades on
//! the attack corpus and no new blocks on the benign corpus (mandate §34).
//!
//! A **downgrade** — the pipeline would allow (or barely log) something the
//! legacy engine blocked/challenged — is the dangerous class of mismatch and
//! is surfaced separately so it can alert rather than blend into aggregate
//! agreement numbers.

use super::{Action, PipelineVerdict};

use crate::{WafAction, WafVerdict};

/// Relationship between the two engines' actions for one request.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Agreement {
    /// Same effective strength.
    Agree,
    /// The pipeline is stricter than the legacy engine.
    PipelineStricter,
    /// The pipeline is weaker — must never be silently enforced.
    PipelineWeaker,
}

/// One comparison result, cheap enough to log per request in shadow mode.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ShadowComparison {
    pub legacy_action: Action,
    pub pipeline_action: Action,
    pub agreement: Agreement,
    /// `pipeline_score - legacy_score` (`u8` legacy score widened to `i64`).
    pub score_delta: i64,
}

impl ShadowComparison {
    /// `true` when enforcement differences require human review.
    pub fn is_downgrade(self) -> bool {
        self.agreement == Agreement::PipelineWeaker
    }
}

/// Map a legacy engine action onto the pipeline's escalation ladder.
pub const fn map_legacy_action(action: WafAction) -> Action {
    match action {
        WafAction::Pass => Action::Pass,
        WafAction::Monitor => Action::Monitor,
        WafAction::Challenge => Action::Challenge,
        WafAction::Block => Action::Block,
    }
}

/// Compare the legacy verdict against the pipeline verdict for one request.
pub fn compare(
    legacy: &WafVerdict,
    pipeline: &PipelineVerdict,
) -> ShadowComparison {
    let legacy_action = map_legacy_action(legacy.action);
    let pipeline_action = pipeline.action;
    let agreement = match pipeline_action.cmp(&legacy_action) {
        std::cmp::Ordering::Equal => Agreement::Agree,
        std::cmp::Ordering::Greater => Agreement::PipelineStricter,
        std::cmp::Ordering::Less => Agreement::PipelineWeaker,
    };
    ShadowComparison {
        legacy_action,
        pipeline_action,
        agreement,
        score_delta: i64::from(pipeline.score) - i64::from(legacy.score),
    }
}

#[cfg(test)]
mod tests {
    use super::{compare, map_legacy_action, Agreement};
    use crate::pipeline::{Action, PipelineVerdict};
    use crate::{WafAction, WafVerdict};

    fn verdict(action: WafAction, score: u8) -> WafVerdict {
        WafVerdict {
            action,
            score,
            ..WafVerdict::pass()
        }
    }

    fn pipeline_verdict(action: Action, score: u32) -> PipelineVerdict {
        PipelineVerdict {
            action,
            score,
            findings: Vec::new(),
            degraded: Vec::new(),
        }
    }

    #[test]
    fn maps_every_legacy_action() {
        assert_eq!(map_legacy_action(WafAction::Pass), Action::Pass);
        assert_eq!(map_legacy_action(WafAction::Monitor), Action::Monitor);
        assert_eq!(map_legacy_action(WafAction::Challenge), Action::Challenge);
        assert_eq!(map_legacy_action(WafAction::Block), Action::Block);
    }

    #[test]
    fn classifies_agreement_strictness_and_downgrades() {
        let legacy = verdict(WafAction::Monitor, 10);

        let weaker = compare(&legacy, &pipeline_verdict(Action::Log, 3));
        assert_eq!(weaker.agreement, Agreement::PipelineWeaker);
        assert!(weaker.is_downgrade());
        assert_eq!(weaker.score_delta, -7);

        let same = compare(&legacy, &pipeline_verdict(Action::Monitor, 12));
        assert_eq!(same.agreement, Agreement::Agree);
        assert_eq!(same.score_delta, 2);

        let stricter = compare(&legacy, &pipeline_verdict(Action::Block, 40));
        assert_eq!(stricter.agreement, Agreement::PipelineStricter);
        assert!(!stricter.is_downgrade());
    }
}
