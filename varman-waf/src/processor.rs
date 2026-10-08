//! Optional external-processor contract (Phase 9).
//!
//! Zentinel-inspired processors are out-of-process components that inspect a
//! request and contribute extra findings (fraud checks, tenant-specific
//! logic, external threat feeds). This module owns the **contract and the
//! failure semantics** so they are testable without a network; the transport
//! (UDS/gRPC client) lands next and stays a thin adapter over
//! [`ExternalProcessor`].
//!
//! # Invariants (mandate §9)
//!
//! - **The native engine stays the authority.** A processor can only *add*
//!   findings; merging is monotonic, so a processor can never weaken the
//!   pipeline's action.
//! - **Bounded contribution.** A response is truncated to
//!   [`MAX_PROCESSOR_FINDINGS`], each finding's score is capped at
//!   [`MAX_PROCESSOR_FINDING_SCORE`] and one processor contributes at most
//!   [`MAX_PROCESSOR_SCORE`] in total.
//! - **Explicit failure policy.** A timed-out or failed call resolves through
//!   [`FailurePolicy`] (`fail_open` / `monitor_only` / `fail_closed`); it is
//!   never silently ignored.

use crate::canonical::CanonicalRequest;
use crate::pipeline::{
    Action, AttackCategory, DetectorId, Finding, PipelineVerdict,
};
use serde::{Deserialize, Serialize};

/// Maximum findings a single processor response contributes.
pub const MAX_PROCESSOR_FINDINGS: usize = 16;
/// Maximum anomaly score a single processor finding contributes.
pub const MAX_PROCESSOR_FINDING_SCORE: u32 = 40;
/// Maximum anomaly score one processor contributes in total.
pub const MAX_PROCESSOR_SCORE: u32 = 60;

/// Request summary handed to a processor. Owned so it can cross a transport
/// without borrowing the transaction.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProcessorRequest {
    pub method: String,
    pub authority: String,
    pub path: String,
    pub raw_query: String,
    pub headers: Vec<(String, String)>,
    pub client_ip: String,
}

impl ProcessorRequest {
    /// Build the summary from the canonical request the pipeline inspected.
    pub fn from_canonical(request: &CanonicalRequest) -> Self {
        Self {
            method: request.method().to_string(),
            authority: request.authority().to_string(),
            path: request.path().to_string(),
            raw_query: request.raw_query().to_string(),
            headers: request.headers().to_vec(),
            client_ip: request
                .client()
                .ip
                .map(|ip| ip.to_string())
                .unwrap_or_default(),
        }
    }
}

/// One finding a processor contributes.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProcessorFinding {
    /// Processor-defined rule identifier (namespaced by the caller).
    pub rule_id: String,
    pub category: AttackCategory,
    pub score: u32,
    pub action_hint: Action,
    pub detail: Option<String>,
}

/// A processor's successful response.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProcessorResponse {
    #[serde(default)]
    pub findings: Vec<ProcessorFinding>,
    /// Optional identity the processor declares (capability negotiation).
    #[serde(default)]
    pub processor: Option<ProcessorHello>,
}

/// Identity a processor may declare on its responses: the WAF namespaces
/// findings with the declared name and clamps its limits to the declared
/// ones, so a processor can describe itself without extra configuration.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProcessorHello {
    /// Processor name used in rule ids (`ext.<name>.<rule>`).
    #[serde(default)]
    pub name: Option<String>,
    /// Informational version, logged when it changes.
    #[serde(default)]
    pub version: Option<String>,
    /// Findings the processor itself will return at most.
    #[serde(default)]
    pub max_findings: Option<usize>,
}

/// Failure policy for a processor call.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FailurePolicy {
    /// A failed call contributes nothing; the native verdict stands.
    FailOpen,
    /// A failed call records a `Monitor` finding so the blind spot is
    /// visible without blocking traffic.
    MonitorOnly,
    /// A failed call blocks the request (the processor is a security
    /// requirement, not an enhancement).
    FailClosed,
}

impl FailurePolicy {
    /// Parse the policy name used by configuration and the wire protocol.
    pub fn parse(name: &str) -> Option<Self> {
        match name.trim().to_ascii_lowercase().as_str() {
            "fail_open" | "failopen" => Some(Self::FailOpen),
            "monitor_only" | "monitoronly" | "monitor" => {
                Some(Self::MonitorOnly)
            },
            "fail_closed" | "failclosed" => Some(Self::FailClosed),
            _ => None,
        }
    }
}

/// What happened during one processor call.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProcessorOutcome {
    Responded(ProcessorResponse),
    TimedOut,
    Failed(String),
}

impl ProcessorOutcome {
    /// Resolve the outcome under `policy` into the findings the processor
    /// contributes, namespaced by `name`.
    ///
    /// Successful responses are sanitized (truncated, per-finding and total
    /// score caps). Failures resolve through the policy — never silently.
    pub fn findings(
        self,
        name: &str,
        policy: FailurePolicy,
    ) -> Vec<ProcessorFinding> {
        match self {
            Self::Responded(response) => sanitize(name, response),
            Self::TimedOut => failure_findings(
                name,
                policy,
                "processor timed out".to_string(),
            ),
            Self::Failed(reason) => failure_findings(
                name,
                policy,
                format!("processor failed: {reason}"),
            ),
        }
    }
}

/// The namespace to use for a response: the declared processor name when the
/// processor announced one, the configured name otherwise.
fn namespace(configured: &str, hello: Option<&ProcessorHello>) -> String {
    hello
        .and_then(|hello| hello.name.as_deref())
        .map(str::trim)
        .filter(|name| {
            !name.is_empty()
                && name
                    .chars()
                    .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
        })
        .unwrap_or(configured)
        .to_string()
}

fn failure_findings(
    name: &str,
    policy: FailurePolicy,
    detail: String,
) -> Vec<ProcessorFinding> {
    match policy {
        FailurePolicy::FailOpen => Vec::new(),
        FailurePolicy::MonitorOnly => vec![ProcessorFinding {
            rule_id: format!("ext.{name}.unavailable"),
            category: AttackCategory::Unknown,
            score: 10,
            action_hint: Action::Monitor,
            detail: Some(detail),
        }],
        FailurePolicy::FailClosed => vec![ProcessorFinding {
            rule_id: format!("ext.{name}.unavailable"),
            category: AttackCategory::Unknown,
            score: 30,
            action_hint: Action::Block,
            detail: Some(detail),
        }],
    }
}

fn sanitize(name: &str, response: ProcessorResponse) -> Vec<ProcessorFinding> {
    let namespace = namespace(name, response.processor.as_ref());
    let cap = response
        .processor
        .as_ref()
        .and_then(|hello| hello.max_findings)
        .map(|declared| declared.min(MAX_PROCESSOR_FINDINGS))
        .unwrap_or(MAX_PROCESSOR_FINDINGS);
    let mut out: Vec<ProcessorFinding> = Vec::new();
    let mut total = 0u32;
    for mut finding in response.findings {
        if out.len() >= cap {
            break;
        }
        let score = finding.score.min(MAX_PROCESSOR_FINDING_SCORE);
        if total + score > MAX_PROCESSOR_SCORE {
            break;
        }
        total += score;
        finding.score = score;
        if !finding.rule_id.starts_with("ext.") {
            finding.rule_id = format!("ext.{namespace}.{}", finding.rule_id);
        }
        out.push(finding);
    }
    out
}

/// Merge processor findings into a pipeline verdict, monotonically.
///
/// The verdict action is recomputed as the maximum of the existing action and
/// the merged hints: a processor can escalate, never weaken.
pub fn merge_findings(
    verdict: &mut PipelineVerdict,
    findings: Vec<ProcessorFinding>,
) {
    if findings.is_empty() {
        return;
    }
    for finding in findings {
        verdict.score = verdict.score.saturating_add(finding.score);
        verdict.action = verdict.action.escalate(finding.action_hint);
        let mut built = Finding::new(
            DetectorId("external.processor"),
            finding.rule_id,
            finding.category,
        )
        .score(finding.score)
        .action(finding.action_hint);
        if let Some(detail) = finding.detail {
            built = built.detail(detail);
        }
        verdict.findings.push(built);
    }
}

/// The contract every processor implementation (and transport adapter)
/// satisfies. Synchronous by design: the caller owns the async runtime and
/// applies its own timeout before resolving a [`ProcessorOutcome`].
pub trait ExternalProcessor: Send + Sync {
    /// Stable processor name used in rule ids and logs.
    fn name(&self) -> &str;

    /// Inspect one request. `Err` carries a transport-level reason.
    fn inspect(
        &self,
        request: &ProcessorRequest,
    ) -> Result<ProcessorResponse, String>;
}

#[cfg(test)]
mod tests {
    use super::{
        merge_findings, ExternalProcessor, FailurePolicy, ProcessorFinding,
        ProcessorOutcome, ProcessorRequest, ProcessorResponse,
        MAX_PROCESSOR_FINDINGS, MAX_PROCESSOR_FINDING_SCORE,
        MAX_PROCESSOR_SCORE,
    };
    use crate::canonical::{Canonicalizer, RequestParts};
    use crate::pipeline::{Action, AttackCategory, PipelineVerdict};

    fn finding(score: u32, action: Action) -> ProcessorFinding {
        ProcessorFinding {
            rule_id: "rule-1".to_string(),
            category: AttackCategory::ApiAbuse,
            score,
            action_hint: action,
            detail: None,
        }
    }

    #[test]
    fn successful_responses_are_bounded_and_namespaced() {
        let mut response = ProcessorResponse::default();
        for index in 0..(MAX_PROCESSOR_FINDINGS + 8) {
            let mut item = finding(5, Action::Monitor);
            item.rule_id = format!("rule-{index}");
            response.findings.push(item);
        }
        let out = ProcessorOutcome::Responded(response)
            .findings("fraud", FailurePolicy::FailOpen);
        assert!(out.len() <= MAX_PROCESSOR_FINDINGS);
        assert!(out.iter().all(|f| f.rule_id.starts_with("ext.fraud.")));

        // Per-finding and total caps hold.
        let mut response = ProcessorResponse::default();
        for _ in 0..10 {
            response.findings.push(finding(100, Action::Block));
        }
        let out = ProcessorOutcome::Responded(response)
            .findings("feed", FailurePolicy::FailOpen);
        assert!(out.iter().all(|f| f.score <= MAX_PROCESSOR_FINDING_SCORE));
        let total: u32 = out.iter().map(|f| f.score).sum();
        assert!(total <= MAX_PROCESSOR_SCORE, "total {total} exceeded");
    }

    #[test]
    fn failure_policies_are_explicit() {
        let open = ProcessorOutcome::TimedOut
            .findings("feed", FailurePolicy::FailOpen);
        assert!(open.is_empty());

        let monitor = ProcessorOutcome::TimedOut
            .findings("feed", FailurePolicy::MonitorOnly);
        assert_eq!(monitor.len(), 1);
        assert_eq!(monitor[0].action_hint, Action::Monitor);
        assert!(monitor[0].rule_id.starts_with("ext.feed."));

        let closed = ProcessorOutcome::Failed("connection reset".into())
            .findings("feed", FailurePolicy::FailClosed);
        assert_eq!(closed.len(), 1);
        assert_eq!(closed[0].action_hint, Action::Block);
        assert!(closed[0]
            .detail
            .as_deref()
            .is_some_and(|d| d.contains("connection reset")));

        assert_eq!(
            FailurePolicy::parse(" FAIL_OPEN "),
            Some(FailurePolicy::FailOpen)
        );
        assert_eq!(
            FailurePolicy::parse("monitor_only"),
            Some(FailurePolicy::MonitorOnly)
        );
        assert_eq!(
            FailurePolicy::parse("fail_closed"),
            Some(FailurePolicy::FailClosed)
        );
        assert_eq!(FailurePolicy::parse("whatever"), None);
    }

    #[test]
    fn declared_identity_namespaces_and_clamps() {
        use super::ProcessorHello;

        // A processor that declares its name and a tighter finding cap.
        let mut response = ProcessorResponse {
            findings: Vec::new(),
            processor: Some(ProcessorHello {
                name: Some("fraud-svc".to_string()),
                version: Some("2.1.0".to_string()),
                max_findings: Some(2),
            }),
        };
        for index in 0..5 {
            let mut item = finding(5, Action::Monitor);
            item.rule_id = format!("rule-{index}");
            response.findings.push(item);
        }
        let out = ProcessorOutcome::Responded(response)
            .findings("configured", FailurePolicy::FailOpen);
        assert_eq!(out.len(), 2, "declared max_findings must clamp");
        assert!(out[0].rule_id.starts_with("ext.fraud-svc."));

        // An invalid declared name falls back to the configured one.
        let response = ProcessorResponse {
            findings: vec![finding(5, Action::Monitor)],
            processor: Some(ProcessorHello {
                name: Some("../evil".to_string()),
                version: None,
                max_findings: None,
            }),
        };
        let out = ProcessorOutcome::Responded(response)
            .findings("configured", FailurePolicy::FailOpen);
        assert!(out[0].rule_id.starts_with("ext.configured."));
    }

    #[test]
    fn merging_never_weakens_the_native_verdict() {
        let mut verdict = PipelineVerdict::pass();
        merge_findings(&mut verdict, vec![finding(20, Action::Monitor)]);
        assert_eq!(verdict.action, Action::Monitor);
        assert_eq!(verdict.score, 20);
        assert_eq!(verdict.findings.len(), 1);

        // A processor hint below the current action cannot lower it.
        merge_findings(
            &mut verdict,
            vec![ProcessorFinding {
                rule_id: "ext.x.weak".to_string(),
                category: AttackCategory::Unknown,
                score: 5,
                action_hint: Action::Log,
                detail: None,
            }],
        );
        assert_eq!(verdict.action, Action::Monitor);

        // A stronger hint escalates.
        merge_findings(&mut verdict, vec![finding(40, Action::Block)]);
        assert_eq!(verdict.action, Action::Block);
    }

    #[test]
    fn processor_request_summarizes_the_canonical_request() {
        let request = Canonicalizer::default().canonicalize(
            RequestParts::new("POST", "api.example.com", "/v1/orders?id=7")
                .with_header("Host", "api.example.com")
                .with_client(crate::canonical::ClientIdentity {
                    ip: Some("203.0.113.9".parse().expect("ip")),
                    ja4: None,
                }),
        );
        let summary = ProcessorRequest::from_canonical(&request);
        assert_eq!(summary.method, "POST");
        assert_eq!(summary.authority, "api.example.com");
        assert_eq!(summary.path, "/v1/orders");
        assert_eq!(summary.raw_query, "id=7");
        assert_eq!(summary.client_ip, "203.0.113.9");
        assert!(summary.headers.iter().any(|(name, _)| name == "host"));
    }

    #[test]
    fn the_trait_is_object_safe_and_usable() {
        struct Echo;
        impl ExternalProcessor for Echo {
            fn name(&self) -> &str {
                "echo"
            }
            fn inspect(
                &self,
                _request: &ProcessorRequest,
            ) -> Result<ProcessorResponse, String> {
                Ok(ProcessorResponse {
                    findings: vec![finding(15, Action::Monitor)],
                    processor: None,
                })
            }
        }
        let processors: Vec<Box<dyn ExternalProcessor>> = vec![Box::new(Echo)];
        assert_eq!(processors[0].name(), "echo");
        let summary = ProcessorRequest {
            method: "GET".into(),
            authority: "example.com".into(),
            path: "/".into(),
            raw_query: String::new(),
            headers: Vec::new(),
            client_ip: "203.0.113.9".into(),
        };
        let outcome = match processors[0].inspect(&summary) {
            Ok(response) => ProcessorOutcome::Responded(response),
            Err(reason) => ProcessorOutcome::Failed(reason),
        };
        assert_eq!(outcome.findings("echo", FailurePolicy::FailOpen).len(), 1);
    }
}
