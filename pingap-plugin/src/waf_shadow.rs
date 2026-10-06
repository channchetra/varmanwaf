//! Shadow execution of the Varman detection pipeline next to the legacy
//! engine (Phase 2 wiring).
//!
//! With `VARMAN_WAF_SHADOW=1` set, every inspected request is canonicalized
//! and run through the Varman pipeline; the result is compared against the
//! legacy verdict and recorded. **Enforcement never changes** — the legacy
//! verdict stays authoritative until corpus evidence says otherwise
//! (mandate §34). With the flag unset (default) the only cost is one cached
//! boolean read.
//!
//! Comparison classes (see `varman_waf::pipeline::shadow`):
//! - `Agree` — same effective strength;
//! - `PipelineStricter` — the pipeline sees more than the legacy engine;
//! - `PipelineWeaker` — the pipeline would allow something the legacy engine
//!   refuses. Expected during construction; the counter exists to drive it
//!   to zero before any switch.

use std::sync::LazyLock;
use std::sync::atomic::{AtomicU64, Ordering};

use varman_waf::canonical::{Canonicalizer, ClientIdentity, RequestParts};
use varman_waf::pipeline::SecurityPipeline;
use varman_waf::pipeline::fast::{
    ProtocolDetector, RawPathTraversalDetector, SignatureDetector,
};
use varman_waf::pipeline::semantic::{
    CommandInjectionDetector, DeserializationDetector, HtmlXssDetector,
    NosqlInjectionDetector, PrototypePollutionDetector, SqlStructuralDetector,
    SsrfStructuralDetector, SstiDetector, XxeDetector,
};
use varman_waf::pipeline::shadow::{self, Agreement, ShadowComparison};
use varman_waf::{RequestData, WafVerdict};

/// Environment variable that turns shadow execution on.
pub const SHADOW_ENV: &str = "VARMAN_WAF_SHADOW";

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
    enabled: bool,
    pipeline: SecurityPipeline,
    counters: ShadowCounters,
}

static SHADOW: LazyLock<ShadowRuntime> = LazyLock::new(|| ShadowRuntime {
    enabled: shadow_enabled_from_env(),
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
    ]),
    counters: ShadowCounters::default(),
});

fn shadow_enabled_from_env() -> bool {
    std::env::var(SHADOW_ENV)
        .map(|value| value == "1" || value.eq_ignore_ascii_case("true"))
        .unwrap_or(false)
}

/// `true` when shadow execution is enabled for this process.
pub fn is_enabled() -> bool {
    SHADOW.enabled
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

/// Run the shadow comparison for one inspected request.
///
/// No-op unless `VARMAN_WAF_SHADOW` enabled the runtime; never affects the
/// returned verdict or any response.
pub fn observe(request: &RequestData, legacy: &WafVerdict) {
    if SHADOW.enabled {
        observe_with(&SHADOW.pipeline, &SHADOW.counters, request, legacy);
    }
}

fn observe_with(
    pipeline: &SecurityPipeline,
    counters: &ShadowCounters,
    request: &RequestData,
    legacy: &WafVerdict,
) -> ShadowComparison {
    let canonical = canonicalize(request);
    let verdict = pipeline.inspect(&canonical);
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
    comparison
}

/// Build the canonical request from the data the legacy engine received.
///
/// The plugin already holds method/path/query/headers/body/client IP; the
/// canonicalizer applies the one shared normalization policy on top.
fn canonicalize(
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
    use super::{ShadowCounters, canonicalize, observe_with};
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
        let comparison = observe_with(
            &pipeline(),
            &counters,
            &request("/a/b", ""),
            &verdict(WafAction::Pass),
        );
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
        let comparison = observe_with(
            &pipeline(),
            &counters,
            &request("/%2e%2e/etc/passwd", ""),
            &verdict(WafAction::Block),
        );
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
        let against_pass =
            observe_with(&pipeline, &counters, &req, &verdict(WafAction::Pass));
        let against_monitor = observe_with(
            &pipeline,
            &counters,
            &req,
            &verdict(WafAction::Monitor),
        );
        assert_eq!(against_pass.agreement, Agreement::PipelineStricter);
        assert_eq!(against_monitor.agreement, Agreement::PipelineWeaker);
        assert_eq!(
            counters.checked.load(std::sync::atomic::Ordering::Relaxed),
            2
        );
    }
}
