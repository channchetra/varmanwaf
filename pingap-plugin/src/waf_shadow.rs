//! Shadow execution of the Varman detection pipeline next to the legacy
//! engine (Phase 2 wiring), and the engine switch.
//!
//! Three modes, selected with `VARMAN_WAF_ENGINE` (`legacy` default):
//! * `legacy` — the pipeline does not run; the legacy engine is authoritative.
//! * `shadow` — every inspected request is canonicalized and run through the
//!   Varman pipeline; the result is compared against the legacy verdict and
//!   recorded. **Enforcement never changes.** Also enabled by the older
//!   `VARMAN_WAF_SHADOW=1`.
//! * `varman` — the pipeline's verdict is enforced: it escalates with the
//!   legacy verdict (the stronger action wins), so dashboard-configured
//!   custom rules stay effective and the new engine can only add protection.
//!
//! Comparison classes (see `varman_waf::pipeline::shadow`):
//! - `Agree` — same effective strength;
//! - `PipelineStricter` — the pipeline sees more than the legacy engine;
//! - `PipelineWeaker` — the pipeline would allow something the legacy engine
//!   refuses; counted in every mode as the switch's evidence trail.

use std::sync::LazyLock;
use std::sync::atomic::{AtomicU64, Ordering};

use varman_agent::heartbeat::{MetricsCollector, ShadowResult};
use varman_waf::canonical::{Canonicalizer, ClientIdentity, RequestParts};
use varman_waf::pipeline::SecurityPipeline;
use varman_waf::pipeline::fast::{
    ProtocolDetector, RawPathTraversalDetector, SignatureDetector,
};
use varman_waf::pipeline::semantic::{
    BodyShapeDetector, CommandInjectionDetector, DeserializationDetector,
    DlpDetector, GraphqlAbuseDetector, HtmlXssDetector, JwtDetector,
    LdapXPathDetector, NosqlInjectionDetector, PrototypePollutionDetector,
    SqlStructuralDetector, SsrfStructuralDetector, SstiDetector, TiDetector,
    WebSocketDetector, XxeDetector,
};
use varman_waf::pipeline::shadow::{self, Agreement, ShadowComparison};
use varman_waf::{RequestData, WafAction, WafVerdict};

/// Environment variable that turns shadow execution on.
pub const SHADOW_ENV: &str = "VARMAN_WAF_SHADOW";

/// Environment variable that selects how the pipeline participates in
/// enforcement (`legacy` | `shadow` | `varman`).
pub const ENGINE_ENV: &str = "VARMAN_WAF_ENGINE";

/// How the Varman pipeline participates in request handling.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EngineMode {
    /// Legacy engine only; the pipeline does not run (default).
    Legacy,
    /// Legacy engine enforces; the pipeline runs and is compared.
    Shadow,
    /// The pipeline's verdict is enforced, escalated with the legacy verdict.
    Varman,
}

/// Parse the engine mode from the environment values.
///
/// `VARMAN_WAF_ENGINE` wins when set; otherwise `VARMAN_WAF_SHADOW=1`
/// upgrades the default to [`EngineMode::Shadow`]. Unknown values are an
/// error (the caller logs and falls back to the safe default).
fn parse_engine_mode(
    engine: Option<&str>,
    shadow: bool,
) -> Result<EngineMode, String> {
    let Some(value) = engine else {
        return Ok(if shadow {
            EngineMode::Shadow
        } else {
            EngineMode::Legacy
        });
    };
    match value.trim().to_ascii_lowercase().as_str() {
        "legacy" | "base" => Ok(EngineMode::Legacy),
        "shadow" | "observe" => Ok(EngineMode::Shadow),
        "varman" | "enforce" => Ok(EngineMode::Varman),
        other => Err(format!(
            "unsupported {ENGINE_ENV} value {other:?} (expected legacy|shadow|varman)"
        )),
    }
}

fn engine_mode_from_env() -> EngineMode {
    let shadow = shadow_enabled_from_env();
    match parse_engine_mode(std::env::var(ENGINE_ENV).ok().as_deref(), shadow) {
        Ok(mode) => mode,
        Err(error) => {
            tracing::error!(
                %error,
                "invalid WAF engine mode; falling back to legacy enforcement"
            );
            EngineMode::Legacy
        },
    }
}

/// Counters for the shadow comparison. Atomic so the request path never
/// takes a lock; a read for metrics/telemetry is lock-free too.
#[derive(Debug, Default)]
struct ShadowCounters {
    checked: AtomicU64,
    agree: AtomicU64,
    stricter: AtomicU64,
    weaker: AtomicU64,
}

impl ShadowCounters {
    fn record(&self, comparison: &ShadowComparison) {
        self.checked.fetch_add(1, Ordering::Relaxed);
        let bucket = match comparison.agreement {
            Agreement::Agree => &self.agree,
            Agreement::PipelineStricter => &self.stricter,
            Agreement::PipelineWeaker => &self.weaker,
        };
        bucket.fetch_add(1, Ordering::Relaxed);
    }
}

/// Snapshot of the shadow counters (metrics / diagnostics).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ShadowStats {
    pub checked: u64,
    pub agree: u64,
    pub stricter: u64,
    pub weaker: u64,
}

struct ShadowRuntime {
    mode: EngineMode,
    pipeline: SecurityPipeline,
    counters: ShadowCounters,
}

static SHADOW: LazyLock<ShadowRuntime> = LazyLock::new(|| ShadowRuntime {
    mode: engine_mode_from_env(),
    // Lane ordering is detector list order: cheapest protocol checks first,
    // then signatures, then raw-path evidence, then semantic analysis.
    pipeline: SecurityPipeline::new(vec![
        Box::new(ProtocolDetector::new()),
        Box::new(SignatureDetector::new()),
        Box::new(RawPathTraversalDetector::new()),
        Box::new(SqlStructuralDetector::new()),
        Box::new(HtmlXssDetector::new()),
        Box::new(CommandInjectionDetector::new()),
        Box::new(SsrfStructuralDetector::new()),
        Box::new(NosqlInjectionDetector::new()),
        Box::new(SstiDetector::new()),
        Box::new(XxeDetector::new()),
        Box::new(DeserializationDetector::new()),
        Box::new(PrototypePollutionDetector::new()),
        Box::new(LdapXPathDetector::new()),
        Box::new(GraphqlAbuseDetector::new()),
        Box::new(JwtDetector::new()),
        Box::new(DlpDetector::new()),
        Box::new(BodyShapeDetector::new()),
        Box::new(ti_detector()),
        Box::new(WebSocketDetector::new()),
    ]),
    counters: ShadowCounters::default(),
});

fn shadow_enabled_from_env() -> bool {
    std::env::var(SHADOW_ENV)
        .map(|value| value == "1" || value.eq_ignore_ascii_case("true"))
        .unwrap_or(false)
}

/// Threat-intelligence detector for the pipeline.
///
/// `VARMAN_WAF_TI_FILE` selects an operator feed (same line format as the
/// bundled starter); unset uses the starter feed, `off`/`none` disables the
/// detector. A missing or malformed feed logs and falls back to the starter
/// (the safe default) — never silently to an empty detector.
fn ti_detector() -> TiDetector {
    match std::env::var("VARMAN_WAF_TI_FILE") {
        Ok(value)
            if value.trim().eq_ignore_ascii_case("off")
                || value.trim().eq_ignore_ascii_case("none") =>
        {
            TiDetector::new(
                varman_waf::pipeline::semantic::TiIndicators::default(),
            )
        },
        Ok(path) if !path.trim().is_empty() => {
            match std::fs::read_to_string(path.trim()) {
                Ok(feed) => match TiDetector::from_feed_str(&feed) {
                    Ok(detector) => detector,
                    Err(error) => {
                        tracing::error!(
                            %error,
                            path = %path,
                            "invalid threat-intelligence feed; using the starter feed"
                        );
                        TiDetector::starter()
                    },
                },
                Err(error) => {
                    tracing::error!(
                        %error,
                        path = %path,
                        "cannot read threat-intelligence feed; using the starter feed"
                    );
                    TiDetector::starter()
                },
            }
        },
        _ => TiDetector::starter(),
    }
}

/// `true` when the pipeline runs (shadow or enforce mode).
pub fn is_enabled() -> bool {
    SHADOW.mode != EngineMode::Legacy
}

/// The engine mode this process was started with.
pub fn engine_mode() -> EngineMode {
    SHADOW.mode
}

/// Current counter values.
pub fn stats() -> ShadowStats {
    let counters = &SHADOW.counters;
    ShadowStats {
        checked: counters.checked.load(Ordering::Relaxed),
        agree: counters.agree.load(Ordering::Relaxed),
        stricter: counters.stricter.load(Ordering::Relaxed),
        weaker: counters.weaker.load(Ordering::Relaxed),
    }
}

/// Resolve the engine mode for one request: an explicit per-site value wins
/// over the process-wide `VARMAN_WAF_ENGINE`; `inherit`/empty follow it, and
/// an invalid value logs and falls back to it.
pub fn resolve_mode(site: Option<&str>) -> EngineMode {
    match site.map(str::trim) {
        None | Some("") | Some("inherit") => engine_mode(),
        Some(value) => {
            parse_engine_mode(Some(value), false).unwrap_or_else(|error| {
                tracing::error!(
                    %error,
                    "invalid per-site WAF engine mode; using process default"
                );
                engine_mode()
            })
        },
    }
}

/// Run the pipeline for one inspected request and return its verdict in the
/// engine shape. `monitored` is the site's monitor-only category list
/// (`waf_settings.monitor_categories`); matching findings are downgraded
/// before the verdict is compared and returned, so both engines agree on the
/// site's policy. `metrics` receives the comparison class for the control
/// plane's engine telemetry. Records the shadow comparison counters so
/// telemetry stays valid in every mode. `None` when the mode is
/// [`EngineMode::Legacy`].
pub fn analyze(
    request: &RequestData,
    legacy: &WafVerdict,
    mode: EngineMode,
    monitored: &[String],
    metrics: Option<&MetricsCollector>,
) -> Option<WafVerdict> {
    if mode == EngineMode::Legacy {
        return None;
    }
    let (comparison, verdict) = analyze_with(
        &SHADOW.pipeline,
        &SHADOW.counters,
        request,
        legacy,
        monitored,
    );
    if let Some(metrics) = metrics {
        metrics.record_shadow(match comparison.agreement {
            Agreement::Agree => ShadowResult::Agree,
            Agreement::PipelineStricter => ShadowResult::Stricter,
            Agreement::PipelineWeaker => ShadowResult::Weaker,
        });
    }
    Some(verdict)
}

/// Run the shadow comparison for one inspected request.
///
/// No-op unless the pipeline runs; never affects the returned verdict or any
/// response.
pub fn observe(request: &RequestData, legacy: &WafVerdict) {
    let _ = analyze(request, legacy, engine_mode(), &[], None);
}

/// The enforcing verdict in [`EngineMode::Varman`] mode: the stronger of the
/// legacy and pipeline actions.
///
/// The pipeline can only escalate, never weaken — ties keep the legacy
/// verdict (richer custom-rule attribution), so dashboard-configured rules
/// stay effective alongside the new engine.
pub fn effective_verdict(
    legacy: &WafVerdict,
    pipeline: &WafVerdict,
) -> WafVerdict {
    if action_rank(pipeline.action) > action_rank(legacy.action) {
        pipeline.clone()
    } else {
        legacy.clone()
    }
}

const fn action_rank(action: WafAction) -> u8 {
    match action {
        WafAction::Pass => 0,
        WafAction::Monitor => 1,
        WafAction::Challenge => 2,
        WafAction::Block => 3,
    }
}

fn analyze_with(
    pipeline: &SecurityPipeline,
    counters: &ShadowCounters,
    request: &RequestData,
    legacy: &WafVerdict,
    monitored: &[String],
) -> (ShadowComparison, WafVerdict) {
    let canonical = canonicalize(request);
    let mut verdict = pipeline.inspect(&canonical);
    varman_waf::pipeline::policy::downgrade_monitored(&mut verdict, monitored);
    let comparison = shadow::compare(legacy, &verdict);
    counters.record(&comparison);

    tracing::debug!(
        legacy = %comparison.legacy_action,
        pipeline = %comparison.pipeline_action,
        agreement = ?comparison.agreement,
        score_delta = comparison.score_delta,
        findings = verdict.findings.len(),
        path = %request.path,
        "[shadow] varman pipeline verdict"
    );
    (comparison, verdict.to_waf_verdict())
}

/// Build the canonical request from the data the legacy engine received.
///
/// The plugin already holds method/path/query/headers/body/client IP; the
/// canonicalizer applies the one shared normalization policy on top.
pub(crate) fn canonicalize(
    request: &RequestData,
) -> varman_waf::canonical::CanonicalRequest {
    let target = if request.query.is_empty() {
        request.path.clone()
    } else {
        format!("{}?{}", request.path, request.query)
    };
    let authority = request
        .headers
        .iter()
        .find(|(name, _)| name.eq_ignore_ascii_case("host"))
        .map(|(_, value)| value.clone())
        .unwrap_or_default();

    let mut parts =
        RequestParts::new(request.method.clone(), authority, target);
    for (name, value) in &request.headers {
        parts = parts.with_header(name.clone(), value.clone());
    }
    if let Some(body) = &request.body {
        parts = parts.with_body(body.clone());
    }
    parts = parts.with_client(ClientIdentity {
        ip: request.client_ip.parse().ok(),
        ja4: None,
    });
    Canonicalizer::default().canonicalize(parts)
}

#[cfg(test)]
mod tests {
    use super::{ShadowCounters, analyze_with, canonicalize};
    use varman_waf::pipeline::SecurityPipeline;
    use varman_waf::pipeline::fast::RawPathTraversalDetector;
    use varman_waf::pipeline::shadow::Agreement;
    use varman_waf::{RequestData, WafAction, WafVerdict};

    fn pipeline() -> SecurityPipeline {
        SecurityPipeline::new(vec![Box::new(RawPathTraversalDetector::new())])
    }

    fn request(path: &str, query: &str) -> RequestData {
        RequestData {
            method: "GET".into(),
            path: path.into(),
            query: query.into(),
            headers: vec![("Host".into(), "example.com".into())],
            body: None,
            client_ip: "203.0.113.9".into(),
            country_code: None,
            scheme: "https".into(),
            protocol: "HTTP/1.1".into(),
        }
    }

    fn verdict(action: WafAction) -> WafVerdict {
        WafVerdict {
            action,
            ..WafVerdict::pass()
        }
    }

    #[test]
    fn engine_mode_parsing() {
        use super::{EngineMode, parse_engine_mode};

        assert_eq!(parse_engine_mode(None, false).unwrap(), EngineMode::Legacy);
        assert_eq!(parse_engine_mode(None, true).unwrap(), EngineMode::Shadow);
        assert_eq!(
            parse_engine_mode(Some("varman"), false).unwrap(),
            EngineMode::Varman
        );
        // Explicit engine selection wins over the shadow flag.
        assert_eq!(
            parse_engine_mode(Some("legacy"), true).unwrap(),
            EngineMode::Legacy
        );
        assert_eq!(
            parse_engine_mode(Some(" SHADOW "), false).unwrap(),
            EngineMode::Shadow
        );
        assert!(parse_engine_mode(Some("bogus"), false).is_err());
    }

    #[test]
    fn resolve_mode_prefers_the_site_value() {
        use super::{EngineMode, resolve_mode};

        // `inherit`/empty/absent follow the process mode; explicit values win.
        let process = super::engine_mode();
        assert_eq!(resolve_mode(None), process);
        assert_eq!(resolve_mode(Some("inherit")), process);
        assert_eq!(resolve_mode(Some("")), process);
        assert_eq!(resolve_mode(Some("varman")), EngineMode::Varman);
        assert_eq!(resolve_mode(Some("legacy")), EngineMode::Legacy);
        // Invalid values fall back to the process mode.
        assert_eq!(resolve_mode(Some("bogus")), process);
    }

    #[test]
    fn effective_verdict_escalates_only() {
        use super::effective_verdict;

        let pass = verdict(WafAction::Pass);
        let block = verdict(WafAction::Block);
        let monitor = verdict(WafAction::Monitor);

        // Pipeline stricter: the pipeline verdict wins.
        assert_eq!(effective_verdict(&pass, &block).action, WafAction::Block);
        // Legacy stricter: the legacy verdict wins (no downgrade).
        assert_eq!(
            effective_verdict(&block, &monitor).action,
            WafAction::Block
        );
        // Tie: the legacy verdict stays (custom-rule attribution).
        let legacy = WafVerdict {
            details: "legacy".into(),
            ..verdict(WafAction::Block)
        };
        let pipeline = WafVerdict {
            details: "pipeline".into(),
            ..verdict(WafAction::Block)
        };
        assert_eq!(effective_verdict(&legacy, &pipeline).details, "legacy");
    }

    #[test]
    fn canonicalize_maps_request_data_onto_the_model() {
        let req = request("/a/../b", "id=1+OR+1%3D1");
        let canonical = canonicalize(&req);
        assert_eq!(canonical.path(), "/b");
        assert_eq!(canonical.raw_path(), "/a/../b");
        assert_eq!(canonical.header("host"), Some("example.com"));
        assert_eq!(canonical.query()[0].value, "1 OR 1=1");
        assert_eq!(
            canonical.client().ip.map(|ip| ip.to_string()),
            Some("203.0.113.9".into())
        );
    }

    #[test]
    fn clean_request_agrees_with_a_clean_legacy_verdict() {
        let counters = ShadowCounters::default();
        let comparison = analyze_with(
            &pipeline(),
            &counters,
            &request("/a/b", ""),
            &verdict(WafAction::Pass),
            &[],
        )
        .0;
        assert_eq!(comparison.agreement, Agreement::Agree);
        assert_eq!(
            counters.checked.load(std::sync::atomic::Ordering::Relaxed),
            1
        );
        assert_eq!(
            counters.agree.load(std::sync::atomic::Ordering::Relaxed),
            1
        );
    }

    #[test]
    fn legacy_block_with_shadow_log_is_classified_weaker() {
        let counters = ShadowCounters::default();
        let comparison = analyze_with(
            &pipeline(),
            &counters,
            &request("/%2e%2e/etc/passwd", ""),
            &verdict(WafAction::Block),
            &[],
        )
        .0;
        assert_eq!(comparison.agreement, Agreement::PipelineWeaker);
        assert!(comparison.is_downgrade());
        assert_eq!(
            counters.weaker.load(std::sync::atomic::Ordering::Relaxed),
            1
        );
    }

    #[test]
    fn shadow_only_observes_and_counters_are_independent() {
        let counters = ShadowCounters::default();
        let pipeline = pipeline();
        // Same request through both classes: the pipeline verdict is a fact
        // about the request, the comparison is a fact about the pair.
        let req = request("/a/../b", "");
        let against_pass = analyze_with(
            &pipeline,
            &counters,
            &req,
            &verdict(WafAction::Pass),
            &[],
        )
        .0;
        let against_monitor = analyze_with(
            &pipeline,
            &counters,
            &req,
            &verdict(WafAction::Monitor),
            &[],
        )
        .0;
        assert_eq!(against_pass.agreement, Agreement::PipelineStricter);
        assert_eq!(against_monitor.agreement, Agreement::PipelineWeaker);
        assert_eq!(
            counters.checked.load(std::sync::atomic::Ordering::Relaxed),
            2
        );
    }

    #[test]
    fn analyze_records_engine_telemetry() {
        use varman_agent::heartbeat::MetricsCollector;

        let metrics = MetricsCollector::new();
        let result = super::analyze(
            &request("/a/b", ""),
            &verdict(WafAction::Pass),
            super::EngineMode::Shadow,
            &[],
            Some(&metrics),
        );
        assert!(result.is_some());
        assert_eq!(metrics.shadow_checked(), 1);
        assert_eq!(metrics.shadow_agree(), 1);

        // Legacy mode does not run the pipeline and records nothing.
        let result = super::analyze(
            &request("/a/b", ""),
            &verdict(WafAction::Pass),
            super::EngineMode::Legacy,
            &[],
            Some(&metrics),
        );
        assert!(result.is_none());
        assert_eq!(metrics.shadow_checked(), 1);
    }

    #[test]
    fn site_monitor_categories_downgrade_the_pipeline_verdict() {
        use varman_waf::pipeline::Action;
        use varman_waf::pipeline::semantic::SqlStructuralDetector;

        let counters = ShadowCounters::default();
        let pipeline =
            SecurityPipeline::new(vec![Box::new(SqlStructuralDetector::new())]);
        let req = request("/page", "id=1;xp_cmdshell('whoami')");

        // Without a monitor list the pipeline blocks the stacked command.
        let (_, converted) = analyze_with(
            &pipeline,
            &counters,
            &req,
            &verdict(WafAction::Pass),
            &[],
        );
        assert_eq!(converted.action, WafAction::Block);

        // The site's monitor list downgrades it to monitor-only — both the
        // comparison and the enforcing verdict.
        let monitored = vec!["sqli".to_string()];
        let (comparison, converted) = analyze_with(
            &pipeline,
            &counters,
            &req,
            &verdict(WafAction::Pass),
            &monitored,
        );
        assert_eq!(comparison.pipeline_action, Action::Monitor);
        assert_eq!(converted.action, WafAction::Monitor);
        // The score is kept for the event.
        assert!(converted.score > 0);
    }
}
