//! Structured findings — the only currency between detectors and the rest of
//! the platform.
//!
//! The mandate (§17) requires every detection to carry structured metadata
//! instead of passing plain strings between subsystems. A [`Finding`] is that
//! structure: which detector fired, under which rule id, on which evidence,
//! with how much confidence, severity and score, and what action it suggests.

use std::borrow::Cow;
use std::fmt;

use serde::{Deserialize, Serialize};

use super::{Action, AttackCategory};

/// Identifier of a detector implementation.
///
/// Built-in detectors carry static identifiers (`"fast.signatures"`,
/// `"semantic.sql.structural"`, …). The newtype keeps the door open for
/// plugin-provided detectors later without changing [`Finding`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct DetectorId(pub &'static str);

impl DetectorId {
    pub const fn as_str(self) -> &'static str {
        self.0
    }
}

impl fmt::Display for DetectorId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.0)
    }
}

/// How sure the detector is that its semantic judgement is correct.
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
pub enum Confidence {
    /// Heuristic signal; must not block on its own.
    Low,
    /// Strong signal, possibly context dependent.
    Medium,
    /// Structural / parse-backed judgement with no known bypass.
    High,
}

impl Confidence {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Low => "low",
            Self::Medium => "medium",
            Self::High => "high",
        }
    }
}

/// Impact estimate used for scoring and response selection.
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
pub enum Severity {
    Info,
    Low,
    Medium,
    High,
    Critical,
}

impl Severity {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Info => "info",
            Self::Low => "low",
            Self::Medium => "medium",
            Self::High => "high",
            Self::Critical => "critical",
        }
    }
}

/// Where in the request the evidence was found.
///
/// The variant is allocation-free; the exact field name travels separately in
/// [`Finding::field`] so findings stay cheap on the happy path.
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
pub enum EvidenceSource {
    Method,
    Authority,
    Path,
    Query,
    Header,
    Cookie,
    Body,
    Client,
    Response,
    /// Not attached to request data (configuration / protocol-level checks).
    Metadata,
}

impl EvidenceSource {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Method => "method",
            Self::Authority => "authority",
            Self::Path => "path",
            Self::Query => "query",
            Self::Header => "header",
            Self::Cookie => "cookie",
            Self::Body => "body",
            Self::Client => "client",
            Self::Response => "response",
            Self::Metadata => "metadata",
        }
    }
}

/// One structured detection result.
///
/// Not `serde`-serializable yet: `DetectorId` carries a `&'static str` and
/// deserialization cannot produce one. The event model will serialize a
/// dedicated DTO (with owned detector names) when events land; findings stay
/// allocation-free on the hot path.
#[derive(Debug, Clone)]
pub struct Finding {
    /// Detector that produced the finding.
    pub detector: DetectorId,
    /// Rule / signature identifier, static for built-ins.
    pub rule_id: Cow<'static, str>,
    /// Attack family the finding belongs to.
    pub category: AttackCategory,
    pub confidence: Confidence,
    pub severity: Severity,
    /// Anomaly contribution; the pipeline sums these (saturating).
    pub score: u32,
    /// Where the evidence was found.
    pub source: EvidenceSource,
    /// Exact field name (`id`, `X-Forwarded-Host`, …) when applicable.
    pub field: Option<String>,
    /// Action this detector suggests; the pipeline escalates monotonically.
    pub action_hint: Action,
    /// Human-readable explanation for logs / the dashboard. Callers redact
    /// sensitive values before persisting; the pipeline never logs bodies.
    pub detail: Option<String>,
}

impl Finding {
    /// Start a finding with sensible, conservative defaults.
    ///
    /// Defaults: `Medium` confidence and severity, score `0`, `Metadata`
    /// source, `Pass` action hint — a detector must opt into anything louder.
    pub fn new(
        detector: DetectorId,
        rule_id: impl Into<Cow<'static, str>>,
        category: AttackCategory,
    ) -> Self {
        Self {
            detector,
            rule_id: rule_id.into(),
            category,
            confidence: Confidence::Medium,
            severity: Severity::Medium,
            score: 0,
            source: EvidenceSource::Metadata,
            field: None,
            action_hint: Action::Pass,
            detail: None,
        }
    }

    pub fn confidence(mut self, confidence: Confidence) -> Self {
        self.confidence = confidence;
        self
    }

    pub fn severity(mut self, severity: Severity) -> Self {
        self.severity = severity;
        self
    }

    pub fn score(mut self, score: u32) -> Self {
        self.score = score;
        self
    }

    pub fn action(mut self, action: Action) -> Self {
        self.action_hint = action;
        self
    }

    pub fn source(mut self, source: EvidenceSource) -> Self {
        self.source = source;
        self
    }

    pub fn field(mut self, field: impl Into<String>) -> Self {
        self.field = Some(field.into());
        self
    }

    pub fn detail(mut self, detail: impl Into<String>) -> Self {
        self.detail = Some(detail.into());
        self
    }
}

#[cfg(test)]
mod tests {
    use super::{Confidence, DetectorId, EvidenceSource, Finding, Severity};
    use crate::pipeline::{Action, AttackCategory};

    #[test]
    fn defaults_are_conservative() {
        let f = Finding::new(
            DetectorId("test.detector"),
            "TEST-001",
            AttackCategory::Unknown,
        );
        assert_eq!(f.confidence, Confidence::Medium);
        assert_eq!(f.severity, Severity::Medium);
        assert_eq!(f.score, 0);
        assert_eq!(f.action_hint, Action::Pass);
        assert_eq!(f.source, EvidenceSource::Metadata);
        assert!(f.field.is_none());
        assert!(f.detail.is_none());
    }

    #[test]
    fn builder_sets_every_field() {
        let f = Finding::new(
            DetectorId("test.detector"),
            "TEST-002",
            AttackCategory::SqlInjection,
        )
        .confidence(Confidence::High)
        .severity(Severity::Critical)
        .score(30)
        .action(Action::Block)
        .source(EvidenceSource::Query)
        .field("id")
        .detail("tautology in WHERE clause");

        assert_eq!(f.detector.as_str(), "test.detector");
        assert_eq!(f.rule_id, "TEST-002");
        assert_eq!(f.confidence.as_str(), "high");
        assert_eq!(f.severity.as_str(), "critical");
        assert_eq!(f.score, 30);
        assert_eq!(f.action_hint, Action::Block);
        assert_eq!(f.source, EvidenceSource::Query);
        assert_eq!(f.field.as_deref(), Some("id"));
        assert!(f.detail.is_some());
    }

    #[test]
    fn severity_orders_low_to_critical() {
        assert!(Severity::Info < Severity::Low);
        assert!(Severity::Low < Severity::Medium);
        assert!(Severity::Medium < Severity::High);
        assert!(Severity::High < Severity::Critical);
    }
}
