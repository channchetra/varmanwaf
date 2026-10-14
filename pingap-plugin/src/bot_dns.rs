//! DNS verification of well-known crawler user agents.
//!
//! A user agent claiming to be Googlebot & co. is cheap to forge. When a
//! site enables DNS verification, such a claim is only honoured after the
//! client IP proves itself: the PTR record must point into the operator's
//! own DNS zone and a forward lookup of that hostname must return the
//! original IP. Verdicts are cached so every site shares at most one pair
//! of DNS round trips per client IP and claimed bot family.

use std::net::IpAddr;
use std::sync::Arc;
use std::sync::OnceLock;
use std::sync::atomic::{AtomicU8, AtomicU64, Ordering};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use ahash::RandomState;
use hickory_resolver::TokioResolver;
use hickory_resolver::config::{ResolverConfig, ResolverOpts};
use hickory_resolver::net::runtime::TokioRuntimeProvider;
use hickory_resolver::proto::rr::RData;
use hickory_resolver::system_conf::read_system_conf;
use tinyufo::TinyUfo;
use tracing::{debug, warn};

/// Well-known crawler families: the user-agent token and the DNS zones the
/// operator's crawlers reverse-resolve into. Custom whitelist entries stay
/// out of this table ΓÇö user-agent matching remains their only signal.
const KNOWN_BOT_FAMILIES: &[(&str, &[&str])] = &[
    ("googlebot", &["googlebot.com", "google.com"]),
    ("bingbot", &["search.msn.com"]),
    ("yandexbot", &["yandex.com", "yandex.ru"]),
    ("duckduckbot", &["duckduckgo.com"]),
    ("baiduspider", &["baidu.com"]),
];

/// Returns the crawler family whose token appears in the user agent, if any.
pub(crate) fn known_bot_family(
    user_agent: &str,
) -> Option<(&'static str, &'static [&'static str])> {
    KNOWN_BOT_FAMILIES
        .iter()
        .find(|(token, _)| crate::waf::contains_ignore_case(user_agent, token))
        .map(|(token, suffixes)| (*token, *suffixes))
}

/// Outcome of verifying one client IP against a claimed crawler family.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum DnsVerdict {
    /// PTR + forward lookup both agree: the client is the crawler it claims
    /// to be.
    Confirmed,
    /// The lookups decisively disagree with the claim: a spoofed user agent.
    Refuted,
    /// DNS infrastructure failure: the caller degrades to the
    /// user-agent-only verdict instead of blocking on the outage.
    Unknown,
}

impl DnsVerdict {
    fn ttl(self) -> Duration {
        match self {
            // Genuine crawler assignments are stable for months.
            Self::Confirmed => Duration::from_secs(3600),
            // Spoofers churn client IPs much faster.
            Self::Refuted => Duration::from_secs(600),
            // Retry failures quickly so a resolver outage degrades only briefly.
            Self::Unknown => Duration::from_secs(60),
        }
    }

    fn as_u8(self) -> u8 {
        match self {
            Self::Confirmed => 0,
            Self::Refuted => 1,
            Self::Unknown => 2,
        }
    }

    fn from_u8(value: u8) -> Self {
        match value {
            0 => Self::Confirmed,
            1 => Self::Refuted,
            _ => Self::Unknown,
        }
    }
}

/// Cached verdict entry. Shared behind an `Arc` so an expired hit can be
/// refreshed in place ΓÇö TinyUfo has no removal, and replacing the value
/// would leave other holders with a stale verdict.
struct CacheEntry {
    expires_at_ms: AtomicU64,
    verdict: AtomicU8,
}

/// Resolves and caches crawler IP verdicts. One instance serves every site:
/// a verdict depends only on the client IP and the claimed family.
pub(crate) struct BotDnsVerifier {
    resolver: TokioResolver,
    cache: TinyUfo<u64, Arc<CacheEntry>>,
    hasher: RandomState,
}

impl BotDnsVerifier {
    fn build() -> Self {
        let (config, mut options) = match read_system_conf() {
            Ok((config, options)) => (config, options),
            Err(error) => {
                warn!(
                    error = %error,
                    "bot dns: reading the system resolver config failed, \
                     falling back to the default resolver"
                );
                (ResolverConfig::default(), ResolverOpts::default())
            },
        };
        // Verification runs on the request path: fail fast, cache the
        // outcome (even failures) and never pile up retries.
        options.timeout = Duration::from_secs(2);
        options.attempts = 1;
        options.cache_size = 1024;
        let mut builder = TokioResolver::builder_with_config(
            config,
            TokioRuntimeProvider::default(),
        );
        *builder.options_mut() = options;
        let resolver = match builder.build() {
            Ok(resolver) => resolver,
            Err(error) => {
                warn!(
                    error = %error,
                    "bot dns: building the system resolver failed, \
                     falling back to the default resolver"
                );
                TokioResolver::builder_with_config(
                    ResolverConfig::default(),
                    TokioRuntimeProvider::default(),
                )
                .build()
                .expect("the default resolver configuration always builds")
            },
        };
        Self {
            resolver,
            cache: TinyUfo::new(10_000, 10_000),
            hasher: RandomState::new(),
        }
    }

    /// Verifies `ip` against the family `token` claims, consulting the cache
    /// first. The key pairs the IP with the family because the same IP may
    /// carry different verdicts for different operators.
    pub(crate) async fn verify(
        &self,
        ip: IpAddr,
        token: &'static str,
    ) -> DnsVerdict {
        let key = self.hasher.hash_one((ip, token));
        if let Some(entry) = self.cache.get(&key) {
            let expires_at_ms = entry.expires_at_ms.load(Ordering::Relaxed);
            if expires_at_ms > now_ms() {
                return DnsVerdict::from_u8(
                    entry.verdict.load(Ordering::Relaxed),
                );
            }
        }
        let verdict = match KNOWN_BOT_FAMILIES
            .iter()
            .find(|(known, _)| *known == token)
            .map(|(_, suffixes)| *suffixes)
        {
            Some(suffixes) => self.resolve(ip, suffixes).await,
            None => DnsVerdict::Unknown,
        };
        debug!(%ip, token, verdict = ?verdict, "bot dns verification");
        let expires_at_ms =
            now_ms().saturating_add(verdict.ttl().as_millis() as u64);
        if let Some(entry) = self.cache.get(&key) {
            entry.expires_at_ms.store(expires_at_ms, Ordering::Relaxed);
            entry.verdict.store(verdict.as_u8(), Ordering::Relaxed);
        } else {
            self.cache.put(
                key,
                Arc::new(CacheEntry {
                    expires_at_ms: AtomicU64::new(expires_at_ms),
                    verdict: AtomicU8::new(verdict.as_u8()),
                }),
                1,
            );
        }
        verdict
    }

    async fn resolve(&self, ip: IpAddr, suffixes: &[&str]) -> DnsVerdict {
        let ptr_lookup = match self.resolver.reverse_lookup(ip).await {
            Ok(lookup) => lookup,
            Err(error) => {
                return if error.is_nx_domain() || error.is_no_records_found() {
                    // No PTR record at all: this IP definitively does not
                    // belong to the claimed operator's crawlers.
                    DnsVerdict::Refuted
                } else {
                    DnsVerdict::Unknown
                };
            },
        };
        for record in ptr_lookup.answers() {
            let RData::PTR(ptr) = &record.data else {
                continue;
            };
            let hostname = ptr.to_string();
            let hostname =
                hostname.strip_suffix('.').unwrap_or(hostname.as_str());
            if !suffixes
                .iter()
                .any(|suffix| is_subdomain_of(hostname, suffix))
            {
                continue;
            }
            // The network owner of the IP can often set arbitrary PTR names,
            // including ones inside the operator's zones; the forward lookup
            // of that name is what the operator alone controls.
            let Ok(forward) = self.resolver.lookup_ip(hostname).await else {
                return DnsVerdict::Refuted;
            };
            return if forward.iter().any(|candidate| candidate == ip) {
                DnsVerdict::Confirmed
            } else {
                DnsVerdict::Refuted
            };
        }
        // PTR names exist, but none of them live in the operator's zones.
        DnsVerdict::Refuted
    }
}

static BOT_DNS_VERIFIER: OnceLock<Arc<BotDnsVerifier>> = OnceLock::new();

/// The process-wide verifier, built lazily on the first DNS-verified bot
/// check so sites without the feature pay nothing.
pub(crate) fn bot_dns_verifier() -> &'static Arc<BotDnsVerifier> {
    BOT_DNS_VERIFIER.get_or_init(|| Arc::new(BotDnsVerifier::build()))
}

/// True when `hostname` equals `suffix` or is a subdomain of it (ASCII
/// case-insensitive, dot-boundary aware: `evilgooglebot.com` does not match
/// `googlebot.com`).
fn is_subdomain_of(hostname: &str, suffix: &str) -> bool {
    let name = hostname.to_ascii_lowercase();
    name == suffix || name.ends_with(&format!(".{suffix}"))
}

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}

#[cfg(test)]
mod test {
    use super::{DnsVerdict, is_subdomain_of, known_bot_family};
    use pretty_assertions::assert_eq;

    #[test]
    fn known_family_matches_case_insensitively() {
        let (token, suffixes) = known_bot_family(
            "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)",
        )
        .expect("googlebot is a known family");
        assert_eq!(token, "googlebot");
        assert_eq!(suffixes, &["googlebot.com", "google.com"][..]);

        let (token, _) =
            known_bot_family("Mozilla/5.0 (compatible; bingbot/2.0)")
                .expect("bingbot");
        assert_eq!(token, "bingbot");

        // A user agent may contain other text around the family token.
        assert!(known_bot_family("Googlebot-Image/1.0").is_some());

        assert!(known_bot_family("curl/8.4.0").is_none());
        assert!(known_bot_family("").is_none());
        assert!(known_bot_family("python-requests/2.31.0").is_none());
    }

    #[test]
    fn suffix_match_requires_a_dot_boundary() {
        assert!(is_subdomain_of(
            "crawl-66-249-66-1.googlebot.com",
            "googlebot.com"
        ));
        assert!(is_subdomain_of("GOOGLEBOT.COM", "googlebot.com"));
        assert!(is_subdomain_of("googlebot.com", "googlebot.com"));
        assert!(!is_subdomain_of("evilgooglebot.com", "googlebot.com"));
        assert!(!is_subdomain_of("google.com.attacker.net", "google.com"));
        assert!(!is_subdomain_of("notgooglebot.com", "googlebot.com"));
    }

    #[test]
    fn verdict_ttls_are_tiered_by_confidence() {
        assert_eq!(DnsVerdict::Confirmed.ttl().as_secs(), 3600);
        assert_eq!(DnsVerdict::Refuted.ttl().as_secs(), 600);
        assert_eq!(DnsVerdict::Unknown.ttl().as_secs(), 60);
    }
}
