//! Anomaly scoring (OWASP-inspired).
//!
//! Each fired rule contributes its severity to a running total; if the total
//! crosses the configured threshold the request is blocked. Sub-scores per
//! attack family (SQLi / XSS / RCE) are tracked separately so the rule engine
//! can write expressions like `cf.waf.score.sqli ge 60`.

use serde::{Deserialize, Serialize};

use crate::rules::signatures::AttackCategory;

/// How suspicious the aggregate score makes a request look.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ScoreClass {
    /// Definitely safe (score 0).
    Clean,
    /// Probably safe (below half the threshold).
    LikelyClean,
    /// Probably malicious (between half the threshold and the threshold).
    LikelyAttack,
    /// Definitely malicious (at or above the threshold).
    Attack,
}

/// Per-request score breakdown.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct ScoreBreakdown {
    /// Aggregate anomaly score.
    pub total: u32,
    /// SQLi sub-score, 0–99 (higher = more likely attack).
    pub sqli_score: u8,
    /// XSS sub-score, 0–99.
    pub xss_score: u8,
    /// RCE / command-injection sub-score, 0–99.
    pub rce_score: u8,
    /// Final classification derived from `block_total` vs the engine threshold.
    pub overall_class: ScoreClass,
    /// Blocking subset of `total`: excludes hits downgraded to monitor-only
    /// by per-site category/stack config. Equal to `total` when nothing is
    /// downgraded.
    #[serde(default)]
    pub block_total: u32,
    /// Blocking subset of `sqli_score`.
    #[serde(default)]
    pub block_sqli_score: u8,
    /// Blocking subset of `xss_score`.
    #[serde(default)]
    pub block_xss_score: u8,
    /// Blocking subset of `rce_score`.
    #[serde(default)]
    pub block_rce_score: u8,
}

impl Default for ScoreBreakdown {
    fn default() -> Self {
        Self::clean()
    }
}

impl ScoreBreakdown {
    pub fn clean() -> Self {
        Self {
            total: 0,
            sqli_score: 0,
            xss_score: 0,
            rce_score: 0,
            overall_class: ScoreClass::Clean,
            block_total: 0,
            block_sqli_score: 0,
            block_xss_score: 0,
            block_rce_score: 0,
        }
    }

    /// Saturating u8 view of the aggregate score for the verdict struct.
    pub fn total_u8(&self) -> u8 {
        u8::try_from(self.total).unwrap_or(u8::MAX)
    }
}

/// Anomaly scorer. Stateless apart from configuration; safe to share.
#[derive(Debug, Clone)]
pub struct AnomalyScorer {
    /// Block threshold for the aggregate score. Default: 40 (medium).
    pub threshold: u32,
    /// 1 (least strict) … 4 (paranoid). Filters out rules whose
    /// `paranoia_level` exceeds this.
    pub paranoia_level: u8,
}

impl Default for AnomalyScorer {
    fn default() -> Self {
        Self {
            threshold: 40,
            paranoia_level: 2,
        }
    }
}

impl AnomalyScorer {
    pub fn new(threshold: u32, paranoia_level: u8) -> Self {
        Self {
            threshold: threshold.max(1),
            paranoia_level: paranoia_level.clamp(1, 4),
        }
    }

    /// Points contributed by a single severity level (1-5). Mirrors the
    /// OWASP CRS scoring: critical=5, error=4, warning=3, notice=2, info=1.
    pub fn points_for_severity(severity: u8) -> u32 {
        match severity.clamp(1, 5) {
            5 => 5,
            4 => 4,
            3 => 3,
            2 => 2,
            _ => 1,
        }
    }

    /// Add a generic severity-weighted hit.
    pub fn add_severity_hit(
        &self,
        breakdown: &mut ScoreBreakdown,
        severity: u8,
    ) {
        self.add_severity_hit_ex(breakdown, severity, false);
    }

    /// [`AnomalyScorer::add_severity_hit`] with a monitor-only downgrade
    /// flag: downgraded hits keep the aggregate (visibility) but are
    /// excluded from the blocking subset.
    pub fn add_severity_hit_ex(
        &self,
        breakdown: &mut ScoreBreakdown,
        severity: u8,
        monitored: bool,
    ) {
        let points = Self::points_for_severity(severity);
        breakdown.total = breakdown.total.saturating_add(points);
        if !monitored {
            breakdown.block_total =
                breakdown.block_total.saturating_add(points);
        }
        breakdown.overall_class = self.classify(breakdown.block_total);
    }

    /// Add a hit attributed to a specific attack category. Updates both the
    /// aggregate and the per-family sub-score.
    pub fn add_category_hit(
        &self,
        breakdown: &mut ScoreBreakdown,
        category: AttackCategory,
        severity: u8,
    ) {
        self.add_category_hit_ex(breakdown, category, severity, false);
    }

    /// [`AnomalyScorer::add_category_hit`] with a monitor-only downgrade
    /// flag (see [`AnomalyScorer::add_severity_hit_ex`]).
    pub fn add_category_hit_ex(
        &self,
        breakdown: &mut ScoreBreakdown,
        category: AttackCategory,
        severity: u8,
        monitored: bool,
    ) {
        let points = Self::points_for_severity(severity);
        breakdown.total = breakdown.total.saturating_add(points);
        if !monitored {
            breakdown.block_total =
                breakdown.block_total.saturating_add(points);
        }
        let bump = u8::try_from(points * 12).unwrap_or(u8::MAX);
        match category {
            AttackCategory::SqlInjection => {
                breakdown.sqli_score =
                    breakdown.sqli_score.saturating_add(bump);
                if !monitored {
                    breakdown.block_sqli_score =
                        breakdown.block_sqli_score.saturating_add(bump);
                }
            },
            AttackCategory::Xss => {
                breakdown.xss_score = breakdown.xss_score.saturating_add(bump);
                if !monitored {
                    breakdown.block_xss_score =
                        breakdown.block_xss_score.saturating_add(bump);
                }
            },
            AttackCategory::CommandInjection
            | AttackCategory::Deserialization => {
                breakdown.rce_score = breakdown.rce_score.saturating_add(bump);
                if !monitored {
                    breakdown.block_rce_score =
                        breakdown.block_rce_score.saturating_add(bump);
                }
            },
            // Template-injection openers (`{{`, `${`, …) are weak signals on
            // their own — they stay out of the RCE sub-score so the Strict
            // RCE gate only trips on confirmed structure. Structural hits
            // feed the sub-score through [`AnomalyScorer::add_expr_hit`].
            AttackCategory::TemplateInjection
            | AttackCategory::PathTraversal
            | AttackCategory::Ssrf
            | AttackCategory::CrlfInjection
            | AttackCategory::Xxe => {
                // Non-family attacks contribute to the aggregate only.
            },
        }
        breakdown.overall_class = self.classify(breakdown.block_total);
    }

    /// Add a structural expression-injection hit — a `${…}` / `{{…}}` /
    /// `{%…%}` container whose content shows interpreter-facing shape
    /// (see `detect_expr_injection`). Confirmed template evaluation is RCE
    /// territory, so this feeds the RCE sub-score directly.
    pub fn add_expr_hit(&self, breakdown: &mut ScoreBreakdown) {
        self.add_expr_hit_ex(breakdown, false);
    }

    /// [`AnomalyScorer::add_expr_hit`] with a monitor-only downgrade flag.
    pub fn add_expr_hit_ex(
        &self,
        breakdown: &mut ScoreBreakdown,
        monitored: bool,
    ) {
        breakdown.total = breakdown.total.saturating_add(4);
        breakdown.rce_score = breakdown.rce_score.saturating_add(48);
        if !monitored {
            breakdown.block_total = breakdown.block_total.saturating_add(4);
            breakdown.block_rce_score =
                breakdown.block_rce_score.saturating_add(48);
        }
        breakdown.overall_class = self.classify(breakdown.block_total);
    }

    /// Map an aggregate score onto a [`ScoreClass`].
    pub fn classify(&self, total: u32) -> ScoreClass {
        if total == 0 {
            ScoreClass::Clean
        } else if total >= self.threshold {
            ScoreClass::Attack
        } else if total * 2 >= self.threshold {
            ScoreClass::LikelyAttack
        } else {
            ScoreClass::LikelyClean
        }
    }

    /// `true` when the aggregate score has crossed the block threshold.
    pub fn should_block(&self, total: u32) -> bool {
        total >= self.threshold
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defaults_are_sane() {
        let s = AnomalyScorer::default();
        assert_eq!(s.threshold, 40);
        assert_eq!(s.paranoia_level, 2);
    }

    #[test]
    fn classifies_clean() {
        let s = AnomalyScorer::new(40, 2);
        assert_eq!(s.classify(0), ScoreClass::Clean);
        assert_eq!(s.classify(5), ScoreClass::LikelyClean);
        assert_eq!(s.classify(25), ScoreClass::LikelyAttack);
        assert_eq!(s.classify(40), ScoreClass::Attack);
        assert_eq!(s.classify(100), ScoreClass::Attack);
    }

    #[test]
    fn accumulates_category_scores() {
        let s = AnomalyScorer::new(40, 2);
        let mut b = ScoreBreakdown::clean();
        s.add_category_hit(&mut b, AttackCategory::SqlInjection, 5);
        s.add_category_hit(&mut b, AttackCategory::SqlInjection, 4);
        assert_eq!(b.total, 9);
        assert!(b.sqli_score >= 60);
        assert_eq!(b.xss_score, 0);
    }

    #[test]
    fn caps_at_u8_max() {
        let s = AnomalyScorer::new(40, 2);
        let mut b = ScoreBreakdown::clean();
        for _ in 0..200 {
            s.add_category_hit(&mut b, AttackCategory::Xss, 5);
        }
        assert_eq!(b.xss_score, u8::MAX);
        assert!(b.total > u32::from(u8::MAX));
        assert_eq!(b.total_u8(), u8::MAX);
    }
}
