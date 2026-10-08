//! Threat-intelligence detector (Phase 8).
//!
//! Matches requests against indicators loaded from a feed: attack-tool user
//! agents, client IPs/CIDRs, hostnames and path prefixes. The bundled starter
//! feed ([`TiIndicators::starter`]) carries attack-tool user agents only —
//! every token is an unambiguous scanner or exploitation tool, so a match
//! blocks (CRS's scanner rule blocks at PL1 too). Operators replace the feed
//! with `VARMAN_WAF_TI_FILE` (same line format, documented in the starter
//! file).
//!
//! | Indicator | Evidence | Tier |
//! | --- | --- | --- |
//! | `ua` | `User-Agent` header contains the token | Block (`ti.ua`) |
//! | `ip` | client IP inside the address/CIDR | Block (`ti.ip`) |
//! | `domain` | `Host` equals the name or a subdomain | Block (`ti.domain`) |
//! | `path` | canonical path starts with the prefix | Block (`ti.path`) |
//!
//! Malformed feed lines are observable errors, never silent no-ops.

use std::net::IpAddr;

use ipnet::IpNet;

use super::super::{
    Action, AttackCategory, Confidence, Detector, DetectorId, DetectorResult,
    EvidenceSource, Finding, Severity,
};

use crate::canonical::CanonicalRequest;

/// Bundled starter feed (attack-tool user agents).
pub const STARTER_FEED: &str = include_str!("ti_starter.txt");

/// Parsed threat-intelligence indicators.
#[derive(Debug, Clone, Default)]
pub struct TiIndicators {
    user_agents: Vec<String>,
    ips: Vec<IpNet>,
    domains: Vec<String>,
    paths: Vec<String>,
}

impl TiIndicators {
    /// Parse a feed. Unknown types and malformed values are errors.
    pub fn parse(feed: &str) -> Result<Self, String> {
        let mut indicators = Self::default();
        for (index, raw) in feed.lines().enumerate() {
            let line = raw.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            let number = index + 1;
            let Some((kind, value)) = line.split_once(char::is_whitespace)
            else {
                return Err(format!("line {number}: missing value"));
            };
            let value = value.trim();
            if value.is_empty() {
                return Err(format!("line {number}: empty value"));
            }
            match kind.to_ascii_lowercase().as_str() {
                "ua" => {
                    indicators.user_agents.push(value.to_ascii_lowercase());
                },
                "ip" => {
                    let net = value
                        .parse::<IpNet>()
                        .or_else(|_| value.parse::<IpAddr>().map(IpNet::from))
                        .map_err(|_| {
                            format!("line {number}: invalid IP/CIDR {value:?}")
                        })?;
                    indicators.ips.push(net);
                },
                "domain" => indicators
                    .domains
                    .push(value.trim_start_matches('.').to_ascii_lowercase()),
                "path" => indicators.paths.push(value.to_string()),
                other => {
                    return Err(format!(
                        "line {number}: unknown indicator type {other:?}"
                    ));
                },
            }
        }
        Ok(indicators)
    }

    /// The bundled starter feed. A malformed bundled feed is a build-time
    /// bug; the unit tests assert it parses and is not empty.
    pub fn starter() -> Self {
        Self::parse(STARTER_FEED).unwrap_or_default()
    }

    /// No indicators configured (the detector is a no-op).
    pub fn is_empty(&self) -> bool {
        self.user_agents.is_empty()
            && self.ips.is_empty()
            && self.domains.is_empty()
            && self.paths.is_empty()
    }
}

struct Evidence {
    rule: &'static str,
    score: u32,
    source: EvidenceSource,
    field: Option<String>,
    detail: String,
}

/// Threat-intelligence indicator detector.
#[derive(Debug, Clone)]
pub struct TiDetector {
    indicators: TiIndicators,
}

impl TiDetector {
    pub fn new(indicators: TiIndicators) -> Self {
        Self { indicators }
    }

    /// Detector with the bundled starter feed.
    pub fn starter() -> Self {
        Self::new(TiIndicators::starter())
    }

    /// Detector from an operator feed (`Err` on a malformed line).
    pub fn from_feed_str(feed: &str) -> Result<Self, String> {
        Ok(Self::new(TiIndicators::parse(feed)?))
    }
}

impl Default for TiDetector {
    fn default() -> Self {
        Self::starter()
    }
}

impl TiDetector {
    fn first_match(&self, request: &CanonicalRequest) -> Option<Evidence> {
        if let Some(user_agent) = request.header("user-agent") {
            let lower = user_agent.to_ascii_lowercase();
            if let Some(token) = self
                .indicators
                .user_agents
                .iter()
                .find(|token| lower.contains(token.as_str()))
            {
                return Some(Evidence {
                    rule: "ti.ua",
                    score: 25,
                    source: EvidenceSource::Header,
                    field: Some("user-agent".to_string()),
                    detail: format!(
                        "User-Agent matches threat-intelligence indicator {token:?}"
                    ),
                });
            }
        }
        if let Some(ip) = request.client().ip {
            if let Some(net) =
                self.indicators.ips.iter().find(|net| net.contains(&ip))
            {
                return Some(Evidence {
                    rule: "ti.ip",
                    score: 40,
                    source: EvidenceSource::Client,
                    field: None,
                    detail: format!(
                        "client IP {ip} is inside threat-intelligence range {net}"
                    ),
                });
            }
        }
        let host = request
            .authority()
            .split(':')
            .next()
            .unwrap_or_default()
            .trim_end_matches('.')
            .to_ascii_lowercase();
        if !host.is_empty() {
            if let Some(domain) =
                self.indicators.domains.iter().find(|domain| {
                    host == domain.as_str()
                        || host.ends_with(&format!(".{domain}"))
                })
            {
                return Some(Evidence {
                    rule: "ti.domain",
                    score: 35,
                    source: EvidenceSource::Authority,
                    field: None,
                    detail: format!(
                        "Host {host:?} matches threat-intelligence domain {domain:?}"
                    ),
                });
            }
        }
        if let Some(prefix) = self
            .indicators
            .paths
            .iter()
            .find(|prefix| request.path().starts_with(prefix.as_str()))
        {
            return Some(Evidence {
                rule: "ti.path",
                score: 25,
                source: EvidenceSource::Path,
                field: None,
                detail: format!(
                    "path matches threat-intelligence prefix {prefix:?}"
                ),
            });
        }
        None
    }
}

impl Detector for TiDetector {
    fn id(&self) -> DetectorId {
        DetectorId("semantic.ti.indicators")
    }

    fn inspect(
        &self,
        request: &CanonicalRequest,
        _ctx: &mut super::super::DetectionContext,
    ) -> DetectorResult {
        if self.indicators.is_empty() {
            return DetectorResult {
                findings: Vec::new(),
                degraded: None,
            };
        }
        let Some(evidence) = self.first_match(request) else {
            return DetectorResult {
                findings: Vec::new(),
                degraded: None,
            };
        };
        let mut finding = Finding::new(
            DetectorId("semantic.ti.indicators"),
            evidence.rule,
            AttackCategory::ThreatIntelligence,
        )
        .confidence(Confidence::High)
        .severity(Severity::High)
        .score(evidence.score)
        .action(Action::Block)
        .source(evidence.source)
        .detail(evidence.detail);
        if let Some(field) = evidence.field {
            finding = finding.field(field);
        }
        DetectorResult {
            findings: vec![finding],
            degraded: None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{TiDetector, TiIndicators, STARTER_FEED};
    use crate::canonical::{Canonicalizer, ClientIdentity, RequestParts};
    use crate::pipeline::{Action, AttackCategory, DetectionContext, Detector};

    fn inspect(parts: RequestParts) -> crate::pipeline::DetectorResult {
        let request = Canonicalizer::default().canonicalize(parts);
        let detector = TiDetector::starter();
        let mut ctx = DetectionContext::new();
        detector.inspect(&request, &mut ctx)
    }

    fn with_ua(user_agent: &str) -> crate::pipeline::DetectorResult {
        inspect(
            RequestParts::new("GET", "example.com", "/")
                .with_header("User-Agent", user_agent),
        )
    }

    #[test]
    fn starter_feed_parses_and_is_not_empty() {
        let indicators = TiIndicators::parse(STARTER_FEED).expect("starter");
        assert!(!indicators.is_empty());
        assert!(indicators.user_agents.contains(&"sqlmap".to_string()));
    }

    #[test]
    fn scanner_user_agents_block() {
        for user_agent in [
            "sqlmap/1.7#stable (https://sqlmap.org)",
            "Nikto/2.5.0",
            "Mozilla/5.0 (compatible; Nmap Scripting Engine)",
            "masscan/1.3",
            "Nuclei - Open-source project",
            "WPScan v3.8.25",
        ] {
            let result = with_ua(user_agent);
            assert_eq!(result.findings.len(), 1, "{user_agent}");
            assert_eq!(result.findings[0].rule_id, "ti.ua");
            assert_eq!(result.findings[0].action_hint, Action::Block);
            assert_eq!(
                result.findings[0].category,
                AttackCategory::ThreatIntelligence
            );
            assert_eq!(result.findings[0].source.as_str(), "header");
        }
    }

    #[test]
    fn ordinary_user_agents_stay_clean() {
        for user_agent in [
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0 Safari/537.36",
            "Googlebot/2.1 (+http://www.google.com/bot.html)",
            "curl/8.4.0",
            "OWASP CRS test agent",
            "VarmanWAF monitor/1.0",
        ] {
            assert!(
                with_ua(user_agent).findings.is_empty(),
                "{user_agent} should stay clean"
            );
        }
    }

    #[test]
    fn operator_indicators_cover_ip_domain_and_path() {
        let feed = "\
            # operator feed\n\
            ip 203.0.113.0/24\n\
            domain evil.example\n\
            path /wp-login.php\n";
        let detector = TiDetector::from_feed_str(feed).expect("feed");

        let request = Canonicalizer::default().canonicalize(
            RequestParts::new("GET", "example.com", "/").with_client(
                ClientIdentity {
                    ip: Some("203.0.113.9".parse().expect("ip")),
                    ja4: None,
                },
            ),
        );
        let mut ctx = DetectionContext::new();
        let result = detector.inspect(&request, &mut ctx);
        assert_eq!(result.findings[0].rule_id, "ti.ip");
        assert_eq!(result.findings[0].score, 40);

        let request = Canonicalizer::default().canonicalize(RequestParts::new(
            "GET",
            "a.evil.example",
            "/",
        ));
        let mut ctx = DetectionContext::new();
        let result = detector.inspect(&request, &mut ctx);
        assert_eq!(result.findings[0].rule_id, "ti.domain");

        let request = Canonicalizer::default().canonicalize(RequestParts::new(
            "GET",
            "example.com",
            "/wp-login.php",
        ));
        let mut ctx = DetectionContext::new();
        let result = detector.inspect(&request, &mut ctx);
        assert_eq!(result.findings[0].rule_id, "ti.path");

        // A lookalike host that merely contains the name does not match.
        let request = Canonicalizer::default().canonicalize(RequestParts::new(
            "GET",
            "notevil.example.com",
            "/",
        ));
        let mut ctx = DetectionContext::new();
        assert!(detector.inspect(&request, &mut ctx).findings.is_empty());
    }

    #[test]
    fn malformed_feeds_are_observable_errors() {
        assert!(TiDetector::from_feed_str("ua").is_err());
        assert!(TiDetector::from_feed_str("ua ").is_err());
        assert!(TiDetector::from_feed_str("ip not-an-ip").is_err());
        assert!(TiDetector::from_feed_str("wat value").is_err());
        // Comments and blank lines are fine.
        assert!(TiDetector::from_feed_str("\n# comment\nua sqlmap\n").is_ok());
    }
}
