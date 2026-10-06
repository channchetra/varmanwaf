//! Enforcement actions with *monotonic* escalation.
//!
//! The project mandate (§7) requires that actions escalate monotonically:
//!
//! ```text
//! Pass < Log < Monitor < Challenge < Block
//! ```
//!
//! A later, weaker detection must never downgrade an earlier, stronger one.
//! The legacy engine does not model this ordering explicitly; the Varman
//! pipeline does, by declaration order of this enum (the derived [`Ord`]
//! follows it) plus the explicit [`Action::escalate`] helper.
//!
//! `Block` is *terminal for normal inspection*: the pipeline may stop running
//! further detectors once it is reached (see
//! [`PipelineConfig::stop_on_block`](super::PipelineConfig)), but
//! response-hardening hooks still run so Varman-generated block responses
//! carry the required security headers.

use serde::{Deserialize, Serialize};

/// Action the pipeline decides (or a detector suggests) for a request.
///
/// Variant order **is** the escalation order; do not reorder without updating
/// [`Action::rank`].
#[derive(
    Debug,
    Clone,
    Copy,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Hash,
    Serialize,
    Deserialize,
)]
#[serde(rename_all = "snake_case")]
pub enum Action {
    /// No threat detected; the request proceeds untouched.
    Pass,
    /// Record the finding, take no other action (weak-signal tier).
    Log,
    /// Record the finding and enforce per the configured monitor policy.
    Monitor,
    /// Interpose a challenge (JS / managed) before reaching the origin.
    Challenge,
    /// Refuse the request.
    Block,
}

impl Action {
    /// Numeric rank backing the escalation order (higher is stronger).
    pub const fn rank(self) -> u8 {
        match self {
            Self::Pass => 0,
            Self::Log => 1,
            Self::Monitor => 2,
            Self::Challenge => 3,
            Self::Block => 4,
        }
    }

    /// The stronger of two actions; never downgrades.
    pub const fn escalate(self, other: Self) -> Self {
        if self.rank() >= other.rank() {
            self
        } else {
            other
        }
    }

    /// `true` when this action stops normal inspection.
    pub const fn is_terminal(self) -> bool {
        matches!(self, Self::Block)
    }

    /// Stable lowercase name used in logs, events and wire formats.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Pass => "pass",
            Self::Log => "log",
            Self::Monitor => "monitor",
            Self::Challenge => "challenge",
            Self::Block => "block",
        }
    }
}

impl std::fmt::Display for Action {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

#[cfg(test)]
mod tests {
    use super::Action;

    #[test]
    fn escalation_order_is_monotonic() {
        let ladder = [
            Action::Pass,
            Action::Log,
            Action::Monitor,
            Action::Challenge,
            Action::Block,
        ];
        for (i, weaker) in ladder.iter().enumerate() {
            for stronger in &ladder[i..] {
                assert_eq!(weaker.escalate(*stronger), *stronger);
                assert_eq!(stronger.escalate(*weaker), *stronger);
            }
        }
    }

    #[test]
    fn escalate_never_downgrades() {
        // A strong detection followed by a weak one stays strong.
        let first = Action::Challenge;
        let later = Action::Log;
        assert_eq!(first.escalate(later), Action::Challenge);
    }

    #[test]
    fn block_is_terminal() {
        assert!(Action::Block.is_terminal());
        assert!(!Action::Challenge.is_terminal());
    }
}
