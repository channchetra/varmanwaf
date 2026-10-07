//! Sensitive-data-exposure detector (Phase 8, DLP).
//!
//! Flags secrets that have no legitimate reason to travel inside request
//! *payloads* (query strings, cookies, bodies) and, where the location is
//! unambiguous, anywhere at all:
//!
//! | Evidence | Tier |
//! | --- | --- |
//! | PEM private key block (`-----BEGIN … PRIVATE KEY-----`) | Block |
//! | URL / connection string with embedded credentials (`scheme://user:pass@`) | Monitor |
//! | Provider token (GitHub, Slack, Stripe live, Google, npm, SendGrid) in query/cookie/body | Monitor |
//!
//! Two deliberate exclusions keep legitimate traffic clean:
//!
//! * **Headers are exempt from provider-token checks** — clients authenticate
//!   to upstreams with `Authorization: Bearer ghp_…`, `X-Api-Key: AIza…`, and
//!   SigV4 headers carry the AWS access-key id by design.
//! * **AWS access-key ids are never flagged** — presigned URLs and SigV4
//!   credentials legitimately carry `AKIA…` in queries and headers.
//!
//! Public keys, test-mode provider keys (`sk_test_…`) and credential-free
//! connection strings stay clean.

use once_cell::sync::Lazy;
use regex::Regex;

use super::super::{
    Action, AttackCategory, Confidence, Detector, DetectorId, DetectorResult,
    EvidenceSource, Finding, Severity,
};

use crate::canonical::CanonicalRequest;

/// Default maximum value length considered by the structural analysis.
pub const DEFAULT_MAX_VALUE_LEN: usize = 8 * 1024;

/// PEM private-key markers (`RSA`/`EC`/`OPENSSH`/`ENCRYPTED`/`PGP … BLOCK`).
static PRIVATE_KEY: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"(?i)-----BEGIN [A-Z0-9 ]*PRIVATE KEY").unwrap());

/// `scheme://user:pass@host` — credentials embedded in a URL.
static CREDENTIALED_URL: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"\b[a-z][a-z0-9+.-]{1,15}://[^/\s:@]{1,64}:[^/\s:@]{1,64}@")
        .unwrap()
});

/// Provider tokens that are leaked when they appear in a payload.
static PROVIDER_TOKENS: Lazy<Regex> = Lazy::new(|| {
    Regex::new(
        r"(?x)
        \bgh[pousr]_[A-Za-z0-9]{36,}\b          # GitHub
        | \bxox[baprs]-[A-Za-z0-9-]{10,}\b      # Slack
        | \bsk_live_[A-Za-z0-9]{24,}\b          # Stripe (live only)
        | \bAIza[0-9A-Za-z_-]{35}\b             # Google API key
        | \bnpm_[A-Za-z0-9]{36}\b               # npm
        | \bSG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}\b  # SendGrid
        ",
    )
    .unwrap()
});

struct Evidence {
    rule: &'static str,
    severity: Severity,
    action: Action,
    score: u32,
    detail: String,
}

/// Analyse one value. `allow_provider_tokens` is false for headers, where
/// provider tokens are a normal way to authenticate.
fn analyze(value: &str, allow_provider_tokens: bool) -> Option<Evidence> {
    if PRIVATE_KEY.is_match(value) {
        return Some(Evidence {
            rule: "sem.dlp.private_key",
            severity: Severity::High,
            action: Action::Block,
            score: 40,
            detail: "PEM private key in request data".to_string(),
        });
    }
    if CREDENTIALED_URL.is_match(value) {
        return Some(Evidence {
            rule: "sem.dlp.credentialed_url",
            severity: Severity::Medium,
            action: Action::Monitor,
            score: 20,
            detail: "URL or connection string with embedded credentials"
                .to_string(),
        });
    }
    if allow_provider_tokens && PROVIDER_TOKENS.is_match(value) {
        return Some(Evidence {
            rule: "sem.dlp.provider_token",
            severity: Severity::Medium,
            action: Action::Monitor,
            score: 20,
            detail: "Provider token in a request payload".to_string(),
        });
    }
    None
}

/// Sensitive-data-exposure (DLP) detector.
#[derive(Debug, Clone, Copy)]
pub struct DlpDetector {
    max_value_len: usize,
}

impl DlpDetector {
    pub const fn new() -> Self {
        Self {
            max_value_len: DEFAULT_MAX_VALUE_LEN,
        }
    }

    pub const fn with_max_value_len(max_value_len: usize) -> Self {
        Self { max_value_len }
    }
}

impl Default for DlpDetector {
    fn default() -> Self {
        Self::new()
    }
}

impl Detector for DlpDetector {
    fn id(&self) -> DetectorId {
        DetectorId("semantic.dlp.structural")
    }

    fn inspect(
        &self,
        request: &CanonicalRequest,
        ctx: &mut super::super::DetectionContext,
    ) -> DetectorResult {
        let mut findings: Vec<Finding> = Vec::new();
        let mut degraded = None;

        let scan = |value: &str,
                    source: EvidenceSource,
                    field: Option<&str>,
                    findings: &mut Vec<Finding>,
                    degraded: &mut Option<&'static str>| {
            if value.len() > self.max_value_len {
                if degraded.is_none() {
                    *degraded = Some("value exceeds semantic budget");
                }
                return;
            }
            let Some(evidence) =
                analyze(value, source != EvidenceSource::Header)
            else {
                return;
            };
            let mut finding = Finding::new(
                DetectorId("semantic.dlp.structural"),
                evidence.rule,
                AttackCategory::SensitiveDataExposure,
            )
            .confidence(match evidence.action {
                Action::Block => Confidence::High,
                Action::Monitor => Confidence::Medium,
                _ => Confidence::Low,
            })
            .severity(evidence.severity)
            .score(evidence.score)
            .action(evidence.action)
            .source(source)
            .detail(evidence.detail);
            if let Some(field) = field {
                finding = finding.field(field.to_string());
            }
            findings.push(finding);
        };

        for (name, value) in request.headers() {
            // Cookies are scanned through the parsed list; scanning the raw
            // `Cookie` header would double-score the same value.
            if name.eq_ignore_ascii_case("cookie") {
                continue;
            }
            scan(
                value,
                EvidenceSource::Header,
                Some(name),
                &mut findings,
                &mut degraded,
            );
        }
        for param in request.query() {
            scan(
                &param.value,
                EvidenceSource::Query,
                Some(&param.name),
                &mut findings,
                &mut degraded,
            );
        }
        for (name, value) in request.cookies() {
            scan(
                value,
                EvidenceSource::Cookie,
                Some(name),
                &mut findings,
                &mut degraded,
            );
        }
        if let Some(body) = request.body() {
            let limit = ctx.budget().max_body_bytes.min(body.len());
            match std::str::from_utf8(&body[..limit]) {
                Ok(text) => {
                    scan(
                        text,
                        EvidenceSource::Body,
                        None,
                        &mut findings,
                        &mut degraded,
                    );
                    if body.len() > limit && degraded.is_none() {
                        degraded = Some("body scan truncated at budget");
                    }
                },
                Err(_) => {
                    if degraded.is_none() {
                        degraded = Some("body is not valid utf-8");
                    }
                },
            }
        }

        DetectorResult { findings, degraded }
    }
}

#[cfg(test)]
mod tests {
    use super::DlpDetector;
    use crate::canonical::{Canonicalizer, RequestParts};
    use crate::pipeline::{Action, AttackCategory, DetectionContext, Detector};

    fn inspect(request: RequestParts) -> crate::pipeline::DetectorResult {
        let request = Canonicalizer::default().canonicalize(request);
        let detector = DlpDetector::new();
        let mut ctx = DetectionContext::new();
        detector.inspect(&request, &mut ctx)
    }

    fn query(value: &str) -> crate::pipeline::DetectorResult {
        let encoded = value.replace('%', "%25");
        inspect(RequestParts::new(
            "GET",
            "example.com",
            format!("/?q={encoded}"),
        ))
    }

    fn tier(value: &str) -> Option<(String, Action)> {
        query(value)
            .findings
            .first()
            .map(|finding| (finding.rule_id.to_string(), finding.action_hint))
    }

    #[test]
    fn private_keys_block_anywhere() {
        let rsa = "-----BEGIN RSA PRIVATE KEY-----MIIEowIBAAKCAQEA";
        assert_eq!(
            tier(rsa),
            Some(("sem.dlp.private_key".to_string(), Action::Block))
        );
        let openssh = "-----BEGIN OPENSSH PRIVATE KEY-----b3BlbnNzaC1rZXk";
        assert_eq!(
            tier(openssh),
            Some(("sem.dlp.private_key".to_string(), Action::Block))
        );
        let pgp = "-----BEGIN PGP PRIVATE KEY BLOCK-----";
        assert_eq!(
            tier(pgp),
            Some(("sem.dlp.private_key".to_string(), Action::Block))
        );
    }

    #[test]
    fn credentialed_urls_monitor() {
        assert_eq!(
            tier("postgres://admin:s3cr3t@db.internal:5432/app"),
            Some(("sem.dlp.credentialed_url".to_string(), Action::Monitor))
        );
        assert_eq!(
            tier("https://deploy:s3cr3t@ci.example.com/run"),
            Some(("sem.dlp.credentialed_url".to_string(), Action::Monitor))
        );
    }

    #[test]
    fn provider_tokens_monitor_in_payloads_only() {
        let github = format!("ghp_{}", "A".repeat(36));
        assert_eq!(
            tier(&github),
            Some(("sem.dlp.provider_token".to_string(), Action::Monitor))
        );
        let google = format!("AIza{}", "B".repeat(35));
        assert_eq!(
            tier(&google),
            Some(("sem.dlp.provider_token".to_string(), Action::Monitor))
        );

        // The same token in an Authorization header is normal client auth.
        let header = inspect(
            RequestParts::new("GET", "example.com", "/")
                .with_header("Authorization", format!("Bearer {github}")),
        );
        assert!(header.findings.is_empty(), "{:?}", header.findings);
        // ...and in X-Api-Key headers for Google.
        let key_header = inspect(
            RequestParts::new("GET", "example.com", "/")
                .with_header("X-Api-Key", google),
        );
        assert!(key_header.findings.is_empty(), "{:?}", key_header.findings);
    }

    #[test]
    fn benign_shapes_stay_clean() {
        for value in [
            "https://api.example.com/v1/items?page=2",
            "postgres://db.internal:5432/app",
            "AKIAIOSFODNN7EXAMPLE",
            "-----BEGIN PUBLIC KEY-----MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcD",
            // Stripe test keys are not secrets to protect; built at runtime
            // so the repository never contains a token-shaped literal.
            &format!("sk_test_{}", "T".repeat(24)),
            "ghp_short",
            "opaque-session-token-12345",
        ] {
            assert_eq!(tier(value), None, "{value:?} should stay clean");
        }
    }

    #[test]
    fn findings_carry_the_sensitive_data_category() {
        let rsa = "-----BEGIN PRIVATE KEY-----MIIEvQIBADANBg";
        let result = query(rsa);
        assert_eq!(
            result.findings[0].category,
            AttackCategory::SensitiveDataExposure
        );
    }

    #[test]
    fn cookies_and_bodies_are_scanned() {
        let github = format!("ghp_{}", "C".repeat(36));
        let cookie = inspect(
            RequestParts::new("GET", "example.com", "/")
                .with_header("Cookie", format!("token={github}")),
        );
        assert_eq!(cookie.findings.len(), 1);
        assert_eq!(cookie.findings[0].source.as_str(), "cookie");

        let body = inspect(
            RequestParts::new("POST", "example.com", "/")
                .with_header("Content-Type", "text/plain")
                .with_body(
                    "-----BEGIN RSA PRIVATE KEY-----\nMIIEow"
                        .as_bytes()
                        .to_vec(),
                ),
        );
        assert_eq!(body.findings.len(), 1);
        assert_eq!(body.findings[0].source.as_str(), "body");
        assert_eq!(body.findings[0].action_hint, Action::Block);
    }
}
