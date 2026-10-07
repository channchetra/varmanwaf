//! External-processor transport (Phase 9).
//!
//! Calls an out-of-process processor over a Unix domain socket or TCP and
//! resolves the result through the contract in `varman_waf::processor`:
//! bounded contribution, monotonic merge, explicit failure policy. The
//! processor can only *add* findings — the native engine stays the authority.
//!
//! # Configuration
//!
//! | Variable | Meaning |
//! | --- | --- |
//! | `VARMAN_WAF_PROCESSOR_ENDPOINT` | `unix:/path/to.sock`, `tcp:host:port` or a bare `host:port` (TCP). Unset disables the feature. |
//! | `VARMAN_WAF_PROCESSOR_POLICY` | `fail_open` (default), `monitor_only`, `fail_closed` |
//! | `VARMAN_WAF_PROCESSOR_TIMEOUT_MS` | Per-call timeout, 1–5000 ms (default 50) |
//! | `VARMAN_WAF_PROCESSOR_NAME` | Name used in rule ids (default `processor`) |
//!
//! # Wire format
//!
//! Newline-delimited JSON, one request per connection: the client sends
//! `ProcessorRequest` followed by `\n`, the processor answers with
//! `ProcessorResponse` followed by `\n`. Responses are read with a 64 KiB
//! cap so a misbehaving processor cannot exhaust memory.

use std::sync::LazyLock;
use std::time::Duration;

use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};

use varman_agent::heartbeat::{MetricsCollector, ProcessorResult};
use varman_waf::processor::{
    FailurePolicy, ProcessorFinding, ProcessorOutcome, ProcessorRequest,
    ProcessorResponse,
};
use varman_waf::{RequestData, ScoreBreakdown, WafAction, WafVerdict};

/// Environment variable selecting the processor endpoint.
pub const ENDPOINT_ENV: &str = "VARMAN_WAF_PROCESSOR_ENDPOINT";
/// Environment variable selecting the failure policy.
pub const POLICY_ENV: &str = "VARMAN_WAF_PROCESSOR_POLICY";
/// Environment variable for the per-call timeout in milliseconds.
pub const TIMEOUT_ENV: &str = "VARMAN_WAF_PROCESSOR_TIMEOUT_MS";
/// Environment variable for the processor name used in rule ids.
pub const NAME_ENV: &str = "VARMAN_WAF_PROCESSOR_NAME";

/// Maximum response line accepted from a processor (64 KiB).
const MAX_RESPONSE_BYTES: u64 = 64 * 1024;

/// Where the processor listens.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Endpoint {
    Unix(String),
    Tcp(String),
}

impl Endpoint {
    /// Parse `unix:/path`, `tcp:host:port` or a bare `host:port`.
    pub fn parse(value: &str) -> Result<Self, String> {
        let value = value.trim();
        if value.is_empty() {
            return Err("empty endpoint".to_string());
        }
        if let Some(path) = value.strip_prefix("unix:") {
            if path.is_empty() {
                return Err("unix endpoint without a path".to_string());
            }
            return Ok(Self::Unix(path.to_string()));
        }
        let host_port = value.strip_prefix("tcp:").unwrap_or(value);
        let Some((host, port)) = host_port.rsplit_once(':') else {
            return Err(format!("endpoint {value:?} has no port"));
        };
        if host.is_empty() || port.parse::<u16>().is_err() {
            return Err(format!("endpoint {value:?} is not host:port"));
        }
        Ok(Self::Tcp(host_port.to_string()))
    }
}

struct Runtime {
    endpoint: Option<Endpoint>,
    policy: FailurePolicy,
    timeout: Duration,
    name: String,
}

static PROCESSOR: LazyLock<Runtime> = LazyLock::new(|| {
    let endpoint = match std::env::var(ENDPOINT_ENV) {
        Ok(value) if !value.trim().is_empty() => {
            match Endpoint::parse(&value) {
                Ok(endpoint) => Some(endpoint),
                Err(error) => {
                    tracing::error!(
                        %error,
                        "invalid WAF processor endpoint; processor disabled"
                    );
                    None
                },
            }
        },
        _ => None,
    };
    let policy = match std::env::var(POLICY_ENV) {
        Ok(value) => FailurePolicy::parse(&value).unwrap_or_else(|| {
            tracing::error!(
                value = %value,
                "unknown WAF processor policy; using fail_open"
            );
            FailurePolicy::FailOpen
        }),
        Err(_) => FailurePolicy::FailOpen,
    };
    let timeout = std::env::var(TIMEOUT_ENV)
        .ok()
        .and_then(|value| value.trim().parse::<u64>().ok())
        .map(|ms| Duration::from_millis(ms.clamp(1, 5000)))
        .unwrap_or_else(|| Duration::from_millis(50));
    let name = std::env::var(NAME_ENV)
        .ok()
        .filter(|value| !value.trim().is_empty())
        .unwrap_or_else(|| "processor".to_string());
    Runtime {
        endpoint,
        policy,
        timeout,
        name,
    }
});

/// `true` when a processor endpoint is configured.
pub fn is_enabled() -> bool {
    PROCESSOR.endpoint.is_some()
}

/// The configured failure policy.
pub fn policy() -> FailurePolicy {
    PROCESSOR.policy
}

/// The configured per-call timeout.
pub fn timeout() -> Duration {
    PROCESSOR.timeout
}

/// The configured processor name.
pub fn name() -> &'static str {
    &PROCESSOR.name
}

/// Call the configured processor for one request and resolve its outcome
/// under the failure policy. `metrics` receives the call outcome for the
/// control plane's engine telemetry. `None` when no processor is configured.
pub async fn evaluate(
    request: &RequestData,
    metrics: Option<&MetricsCollector>,
) -> Option<Vec<ProcessorFinding>> {
    let endpoint = PROCESSOR.endpoint.as_ref()?;
    let summary = summary(request);
    let outcome = invoke(endpoint, &summary, PROCESSOR.timeout).await;
    if let Some(metrics) = metrics {
        metrics.record_processor(match &outcome {
            ProcessorOutcome::Responded(_) => ProcessorResult::Ok,
            ProcessorOutcome::TimedOut => ProcessorResult::Timeout,
            ProcessorOutcome::Failed(_) => ProcessorResult::Failed,
        });
    }
    Some(outcome.findings(&PROCESSOR.name, PROCESSOR.policy))
}

/// Build the processor summary from the request the engines inspected.
fn summary(request: &RequestData) -> ProcessorRequest {
    let authority = request
        .headers
        .iter()
        .find(|(name, _)| name.eq_ignore_ascii_case("host"))
        .map(|(_, value)| value.clone())
        .unwrap_or_default();
    ProcessorRequest {
        method: request.method.clone(),
        authority,
        path: request.path.clone(),
        raw_query: request.query.clone(),
        headers: request.headers.clone(),
        client_ip: request.client_ip.clone(),
    }
}

/// One bounded call: connect, exchange one line, classify the outcome.
async fn invoke(
    endpoint: &Endpoint,
    request: &ProcessorRequest,
    timeout: Duration,
) -> ProcessorOutcome {
    let call = async {
        let line = match serde_json::to_string(request) {
            Ok(line) => line,
            Err(error) => return ProcessorOutcome::Failed(error.to_string()),
        };
        match endpoint {
            Endpoint::Unix(path) => {
                match tokio::net::UnixStream::connect(path).await {
                    Ok(stream) => exchange(stream, &line).await,
                    Err(error) => ProcessorOutcome::Failed(error.to_string()),
                }
            },
            Endpoint::Tcp(addr) => {
                match tokio::net::TcpStream::connect(addr).await {
                    Ok(stream) => exchange(stream, &line).await,
                    Err(error) => ProcessorOutcome::Failed(error.to_string()),
                }
            },
        }
    };
    match tokio::time::timeout(timeout, call).await {
        Ok(outcome) => outcome,
        Err(_) => ProcessorOutcome::TimedOut,
    }
}

async fn exchange<S>(mut stream: S, line: &str) -> ProcessorOutcome
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    if let Err(error) = stream.write_all(line.as_bytes()).await {
        return ProcessorOutcome::Failed(error.to_string());
    }
    if let Err(error) = stream.write_all(b"\n").await {
        return ProcessorOutcome::Failed(error.to_string());
    }
    if let Err(error) = stream.flush().await {
        return ProcessorOutcome::Failed(error.to_string());
    }
    let mut reader = BufReader::new(stream).take(MAX_RESPONSE_BYTES);
    let mut response = String::new();
    match reader.read_line(&mut response).await {
        Ok(0) => {
            ProcessorOutcome::Failed("processor closed the connection".into())
        },
        Ok(_) => match serde_json::from_str::<ProcessorResponse>(&response) {
            Ok(parsed) => ProcessorOutcome::Responded(parsed),
            Err(error) => ProcessorOutcome::Failed(format!(
                "invalid processor response: {error}"
            )),
        },
        Err(error) => ProcessorOutcome::Failed(error.to_string()),
    }
}

/// Convert resolved processor findings into the proxy verdict shape so the
/// caller can escalate them with `waf_shadow::effective_verdict`.
pub fn to_waf_verdict(findings: &[ProcessorFinding]) -> WafVerdict {
    if findings.is_empty() {
        return WafVerdict::pass();
    }
    let action = findings
        .iter()
        .map(|finding| match finding.action_hint {
            varman_waf::pipeline::Action::Pass => WafAction::Pass,
            varman_waf::pipeline::Action::Log
            | varman_waf::pipeline::Action::Monitor => WafAction::Monitor,
            varman_waf::pipeline::Action::Challenge => WafAction::Challenge,
            varman_waf::pipeline::Action::Block => WafAction::Block,
        })
        .max_by_key(|action| match action {
            WafAction::Pass => 0,
            WafAction::Monitor => 1,
            WafAction::Challenge => 2,
            WafAction::Block => 3,
        })
        .unwrap_or(WafAction::Pass);
    let score: u32 = findings.iter().map(|finding| finding.score).sum();
    let matched_rules = findings
        .iter()
        .map(|finding| finding.rule_id.clone())
        .collect();
    let mut details = format!(
        "external processor: {} finding(s), score {}",
        findings.len(),
        score
    );
    for finding in findings.iter().take(4) {
        details.push_str(&format!("; {}", finding.rule_id));
    }
    let mut breakdown = ScoreBreakdown::clean();
    breakdown.total = score;
    WafVerdict {
        action,
        score: u8::try_from(score).unwrap_or(u8::MAX),
        matched_rules,
        details,
        breakdown,
    }
}

#[cfg(test)]
mod tests {
    use super::{Endpoint, exchange, invoke, to_waf_verdict};
    use std::time::Duration;
    use varman_waf::WafAction;
    use varman_waf::pipeline::{Action, AttackCategory};
    use varman_waf::processor::{
        FailurePolicy, ProcessorFinding, ProcessorOutcome, ProcessorRequest,
    };

    fn summary() -> ProcessorRequest {
        ProcessorRequest {
            method: "GET".into(),
            authority: "example.com".into(),
            path: "/".into(),
            raw_query: String::new(),
            headers: Vec::new(),
            client_ip: "203.0.113.9".into(),
        }
    }

    #[test]
    fn endpoint_parsing() {
        assert_eq!(
            Endpoint::parse("unix:/run/varman/proc.sock"),
            Ok(Endpoint::Unix("/run/varman/proc.sock".into()))
        );
        assert_eq!(
            Endpoint::parse("tcp:processor:9100"),
            Ok(Endpoint::Tcp("processor:9100".into()))
        );
        assert_eq!(
            Endpoint::parse("processor:9100"),
            Ok(Endpoint::Tcp("processor:9100".into()))
        );
        assert!(Endpoint::parse("").is_err());
        assert!(Endpoint::parse("unix:").is_err());
        assert!(Endpoint::parse("noport").is_err());
        assert!(Endpoint::parse("host:notaport").is_err());
    }

    #[test]
    fn findings_convert_to_a_verdict() {
        let findings = vec![
            ProcessorFinding {
                rule_id: "ext.proc.fraud".into(),
                category: AttackCategory::ApiAbuse,
                score: 25,
                action_hint: Action::Monitor,
                detail: None,
            },
            ProcessorFinding {
                rule_id: "ext.proc.bad".into(),
                category: AttackCategory::CredentialAbuse,
                score: 30,
                action_hint: Action::Block,
                detail: Some("blocked by processor".into()),
            },
        ];
        let verdict = to_waf_verdict(&findings);
        assert_eq!(verdict.action, WafAction::Block);
        assert_eq!(verdict.score, 55);
        assert_eq!(
            verdict.matched_rules,
            vec!["ext.proc.fraud", "ext.proc.bad"]
        );
        assert!(verdict.details.contains("external processor"));

        assert_eq!(to_waf_verdict(&[]).action, WafAction::Pass);
    }

    #[tokio::test]
    async fn unix_round_trip_and_timeout() {
        let dir = tempfile::tempdir().expect("tempdir");
        let socket = dir.path().join("proc.sock");
        let listener =
            tokio::net::UnixListener::bind(&socket).expect("bind unix socket");

        // Server: answer the first call, stall the second.
        let server = tokio::spawn(async move {
            for round in 0..2 {
                let Ok((mut stream, _)) = listener.accept().await else {
                    return;
                };
                let mut reader = tokio::io::BufReader::new(&mut stream);
                let mut line = String::new();
                let _ = tokio::io::AsyncBufReadExt::read_line(
                    &mut reader,
                    &mut line,
                )
                .await;
                if round == 0 {
                    let response = varman_waf::processor::ProcessorResponse {
                        findings: vec![ProcessorFinding {
                            rule_id: "seen".into(),
                            category: AttackCategory::BotActivity,
                            score: 10,
                            action_hint: Action::Monitor,
                            detail: None,
                        }],
                    };
                    let mut body =
                        serde_json::to_string(&response).expect("serialize");
                    body.push('\n');
                    let _ = tokio::io::AsyncWriteExt::write_all(
                        &mut stream,
                        body.as_bytes(),
                    )
                    .await;
                } else {
                    tokio::time::sleep(Duration::from_millis(300)).await;
                }
            }
        });

        let endpoint = Endpoint::Unix(socket.to_string_lossy().into_owned());
        let outcome =
            invoke(&endpoint, &summary(), Duration::from_millis(200)).await;
        match outcome {
            ProcessorOutcome::Responded(response) => {
                assert_eq!(response.findings.len(), 1);
                assert_eq!(response.findings[0].rule_id, "seen");
            },
            other => panic!("expected a response, got {other:?}"),
        }

        let outcome =
            invoke(&endpoint, &summary(), Duration::from_millis(50)).await;
        assert_eq!(outcome, ProcessorOutcome::TimedOut);
        assert_eq!(
            outcome.findings("proc", FailurePolicy::FailClosed)[0].action_hint,
            Action::Block
        );
        server.abort();
    }

    #[tokio::test]
    async fn a_missing_socket_is_a_failure_not_a_panic() {
        let endpoint = Endpoint::Unix("/nonexistent/varman-proc.sock".into());
        let outcome =
            invoke(&endpoint, &summary(), Duration::from_millis(50)).await;
        assert!(matches!(outcome, ProcessorOutcome::Failed(_)));
        assert!(outcome.findings("proc", FailurePolicy::FailOpen).is_empty());
    }

    #[tokio::test]
    async fn an_invalid_response_is_a_failure() {
        let (client, mut server) = tokio::io::duplex(256);
        let writer = tokio::spawn(async move {
            let mut line = String::new();
            let _ = tokio::io::AsyncBufReadExt::read_line(
                &mut tokio::io::BufReader::new(&mut server),
                &mut line,
            )
            .await;
            let _ =
                tokio::io::AsyncWriteExt::write_all(&mut server, b"not json\n")
                    .await;
        });
        let outcome = exchange(client, "{\"method\":\"GET\"}").await;
        assert!(matches!(outcome, ProcessorOutcome::Failed(_)));
        writer.abort();
    }
}
