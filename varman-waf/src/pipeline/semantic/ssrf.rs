//! SSRF structural detector (Phase 6).
//!
//! Signature scanning catches literal metadata addresses; this detector
//! reasons about *structure*: dangerous URL schemes, hostnames that can only
//! resolve locally, private/loopback address ranges, and obfuscated address
//! forms (decimal / hex IPv4) — the classic bypasses of string blocklists.
//!
//! Tiering: an explicit URL carrying an internal target, a dangerous scheme
//! or an obfuscated loopback address blocks; a bare mention of `localhost`
//! or a private address in prose stays at Log so documentation and log
//! payloads do not trip.

use super::super::{
    Action, AttackCategory, Confidence, Detector, DetectorId, DetectorResult,
    EvidenceSource, Finding, Severity,
};

use crate::canonical::CanonicalRequest;
use crate::pipeline::safe_window;

/// Default maximum value length considered by the structural analysis.
pub const DEFAULT_MAX_VALUE_LEN: usize = 8 * 1024;

/// Schemes that exist to reach local or non-HTTP endpoints.
const DANGEROUS_SCHEMES: &[&str] = &[
    "gopher://",
    "dict://",
    "file://",
    "tftp://",
    "smb://",
    "jar://",
    "netdoc://",
];

/// Loopback / link-local / metadata hostnames.
const INTERNAL_HOSTS: &[&str] = &[
    "localhost",
    "127.0.0.1",
    "0.0.0.0",
    "[::1]",
    "::1",
    "metadata.google.internal",
];

/// `true` for a dotted-quad inside a private, loopback or link-local range.
fn private_ipv4(value: &str) -> bool {
    let mut octets = [0u16; 4];
    let mut seen = 0usize;
    for part in value.split('.') {
        if seen >= 4 || part.is_empty() || part.len() > 3 {
            return false;
        }
        let Ok(n) = part.parse::<u16>() else {
            return false;
        };
        if n > 255 {
            return false;
        }
        octets[seen] = n;
        seen += 1;
    }
    if seen != 4 {
        return false;
    }
    matches!(octets[0], 10 | 127)
        || (octets[0] == 172 && (16..=31).contains(&octets[1]))
        || (octets[0] == 192 && octets[1] == 168)
        || (octets[0] == 169 && octets[1] == 254)
}

/// First dotted-quad-like token in `low`, when it is a private address.
fn contains_private_ipv4(low: &str) -> bool {
    let bytes = low.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i].is_ascii_digit() {
            let start = i;
            let mut dots = 0;
            while i < bytes.len()
                && (bytes[i].is_ascii_digit() || bytes[i] == b'.')
            {
                if bytes[i] == b'.' {
                    dots += 1;
                }
                i += 1;
            }
            if dots == 3 && private_ipv4(safe_window(low, start, i - start)) {
                return true;
            }
        } else {
            i += 1;
        }
    }
    false
}

/// Decimal or hex IPv4 that decodes into a private/loopback range.
fn obfuscated_private_ip(low: &str) -> bool {
    let mut i = 0;
    let bytes = low.as_bytes();
    while i < bytes.len() {
        let start = i;
        let hex = bytes[i] == b'0' && bytes.get(i + 1) == Some(&b'x');
        if hex {
            i += 2;
        }
        let digits_start = i;
        while i < bytes.len()
            && (bytes[i].is_ascii_hexdigit())
            && (hex || bytes[i].is_ascii_digit())
        {
            i += 1;
        }
        let token_len = i - digits_start;
        if token_len >= 8 {
            let radix = if hex { 16 } else { 10 };
            if let Ok(n) = u32::from_str_radix(
                safe_window(low, digits_start, token_len),
                radix,
            ) {
                let a = (n >> 24) as u8;
                let b = (n >> 16) as u8;
                let addr = format!("{a}.{b}.{}.{}", (n >> 8) as u8, n as u8);
                if private_ipv4(&addr) {
                    return true;
                }
            }
        }
        if start == i {
            i += 1;
        }
    }
    false
}

/// `true` when the value contains an explicit URL whose host is internal.
fn url_with_internal_host(low: &str) -> bool {
    let Some(scheme_pos) = low.find("://") else {
        return false;
    };
    let after = &low[scheme_pos + 3..];
    let host_end = after
        .find(['/', '?', '#', ' ', '"', '\'', ')'])
        .unwrap_or(after.len());
    let host = after[..host_end].trim_end_matches(':');
    let host = host.split('@').next_back().unwrap_or(host);
    let host = host.split(':').next().unwrap_or(host);
    INTERNAL_HOSTS
        .iter()
        .any(|internal| host == *internal || host.starts_with("127."))
        || private_ipv4(host)
}

struct Evidence {
    rule: &'static str,
    severity: Severity,
    action: Action,
    score: u32,
    detail: String,
}

fn analyze(value: &str) -> Option<Evidence> {
    let low = value.to_ascii_lowercase();

    if let Some(scheme) = DANGEROUS_SCHEMES.iter().find(|s| low.contains(**s)) {
        return Some(Evidence {
            rule: "sem.ssrf.dangerous_scheme",
            severity: Severity::High,
            action: Action::Block,
            score: 30,
            detail: format!("dangerous URL scheme {scheme:?}"),
        });
    }
    if url_with_internal_host(&low) {
        return Some(Evidence {
            rule: "sem.ssrf.internal_host",
            severity: Severity::High,
            action: Action::Block,
            score: 30,
            detail: "URL targeting a loopback/private host".to_string(),
        });
    }
    if obfuscated_private_ip(&low) {
        return Some(Evidence {
            rule: "sem.ssrf.obfuscated_ip",
            severity: Severity::High,
            action: Action::Block,
            score: 30,
            detail: "decimal/hex IPv4 decoding to a private address"
                .to_string(),
        });
    }
    if low.contains("://") && contains_private_ipv4(&low) {
        return Some(Evidence {
            rule: "sem.ssrf.private_ip",
            severity: Severity::High,
            action: Action::Block,
            score: 30,
            detail: "URL containing a private IPv4 address".to_string(),
        });
    }
    if INTERNAL_HOSTS.iter().any(|h| low.contains(*h))
        || contains_private_ipv4(&low)
    {
        return Some(Evidence {
            rule: "sem.ssrf.internal_mention",
            severity: Severity::Low,
            action: Action::Log,
            score: 5,
            detail: "internal hostname or private address mentioned without URL context"
                .to_string(),
        });
    }
    None
}

/// SSRF structural detector.
#[derive(Debug, Clone, Copy)]
pub struct SsrfStructuralDetector {
    max_value_len: usize,
}

impl SsrfStructuralDetector {
    pub const fn new() -> Self {
        Self {
            max_value_len: DEFAULT_MAX_VALUE_LEN,
        }
    }

    pub const fn with_max_value_len(max_value_len: usize) -> Self {
        Self { max_value_len }
    }
}

impl Default for SsrfStructuralDetector {
    fn default() -> Self {
        Self::new()
    }
}

impl Detector for SsrfStructuralDetector {
    fn id(&self) -> DetectorId {
        DetectorId("semantic.ssrf.structural")
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
            let Some(evidence) = analyze(value) else {
                return;
            };
            let mut finding = Finding::new(
                DetectorId("semantic.ssrf.structural"),
                evidence.rule,
                AttackCategory::Ssrf,
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
    use super::SsrfStructuralDetector;
    use crate::canonical::{Canonicalizer, RequestParts};
    use crate::pipeline::{Action, AttackCategory, DetectionContext, Detector};

    fn query(value: &str) -> crate::pipeline::DetectorResult {
        let encoded = value.replace('%', "%25").replace('&', "%26");
        let target = format!("/?q={encoded}");
        let request = Canonicalizer::default().canonicalize(RequestParts::new(
            "GET",
            "example.com",
            target,
        ));
        let detector = SsrfStructuralDetector::new();
        let mut ctx = DetectionContext::new();
        detector.inspect(&request, &mut ctx)
    }

    fn tier(value: &str) -> Option<(String, Action)> {
        let result = query(value);
        result
            .findings
            .first()
            .map(|f| (f.rule_id.to_string(), f.action_hint))
    }

    #[test]
    fn dangerous_schemes_block() {
        for payload in [
            "gopher://127.0.0.1:6379/_INFO",
            "file:///etc/passwd",
            "dict://localhost:11211/",
        ] {
            let (_, action) = tier(payload).expect(payload);
            assert_eq!(action, Action::Block, "{payload}");
        }
    }

    #[test]
    fn urls_with_internal_hosts_block() {
        for payload in [
            "http://localhost:8080/admin",
            "http://127.0.0.1/status",
            "http://192.168.1.1/router",
            "http://172.16.0.10/internal",
        ] {
            let (_, action) = tier(payload).expect(payload);
            assert_eq!(action, Action::Block, "{payload}");
        }
    }

    #[test]
    fn obfuscated_loopback_blocks() {
        let (rule, action) = tier("http://2130706433/").expect("finding");
        assert_eq!(rule, "sem.ssrf.obfuscated_ip");
        assert_eq!(action, Action::Block);

        let (_, action) = tier("http://0x7f000001/").expect("finding");
        assert_eq!(action, Action::Block);
    }

    #[test]
    fn public_urls_pass() {
        assert!(tier("https://api.example.com/v1/items").is_none());
        assert!(tier("http://10.0.0.5.evil.example/").is_none());
    }

    #[test]
    fn prose_mentions_stay_weak() {
        let cases = [
            "Deploy the service on localhost during development.",
            "The 192.168.0.0/16 range is reserved for private networks.",
        ];
        for case in cases {
            if let Some((_, action)) = tier(case) {
                assert!(action < Action::Monitor, "{case:?} reached {action}");
            }
        }
    }

    #[test]
    fn category_is_ssrf() {
        let result = query("http://127.0.0.1/");
        assert_eq!(result.findings[0].category, AttackCategory::Ssrf);
    }

    #[test]
    fn oversized_values_degrade() {
        let detector = SsrfStructuralDetector::with_max_value_len(16);
        let target = format!("/?q={}", "http://127.0.0.1/".repeat(4));
        let request = Canonicalizer::default().canonicalize(RequestParts::new(
            "GET",
            "example.com",
            target,
        ));
        let mut ctx = DetectionContext::new();
        let result = detector.inspect(&request, &mut ctx);
        assert!(result.findings.is_empty());
        assert_eq!(result.degraded, Some("value exceeds semantic budget"));
    }
}
