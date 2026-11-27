use super::*;

// ─────────────────────────────────────────────────────────────
// Access restrictions (IP rules and geo)
// ─────────────────────────────────────────────────────────────

/// Embedded GeoIP database backing country/ASN facts: it feeds geo
/// restrictions, the `ip.src.country` rule variable and the country reported
/// with access logs.
pub(crate) static GEO_DB: LazyLock<Arc<GeoipDb>> =
    LazyLock::new(GeoipDb::new_embedded);

/// Country code (ISO 3166-1 alpha-2) of `ip`, when the database knows it.
pub(crate) fn lookup_country(ip: &str) -> Option<String> {
    ip.parse().ok().and_then(lookup_country_addr)
}

/// Same as [`lookup_country`] for an already parsed address, so the request
/// hot path parses the client ip once for every consumer.
pub(crate) fn lookup_country_addr(addr: IpAddr) -> Option<String> {
    GEO_DB
        .lookup_country_code(addr)
        .map(|code| code.as_ref().to_string())
}

/// Resolves the ASN with the embedded database (display/rate-limit counting
/// only; the embedded data carries no ASN entries, so this is `None` today
/// and ASN counting falls back to a single bucket).
pub(crate) fn lookup_asn_addr(addr: IpAddr) -> Option<u32> {
    GEO_DB.lookup_asn(addr)
}

/// What an IP access rule does when the client IP matches it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum IpRuleAction {
    Allow,
    Challenge,
    Block,
    /// The matching client must pass the site's basic auth gate.
    BasicAuth,
}

/// One IP access rule with its ranges parsed once.
pub(crate) struct IpRule {
    pub(crate) id: String,
    pub(crate) name: String,
    pub(crate) action: IpRuleAction,
    pub(crate) ranges: IpRules,
}

/// Geo restrictions: the enforcement data is IP ranges synced from ipverse
/// (country datasets and ASN datasets), matched against the client address.
pub(crate) struct GeoRule {
    pub(crate) enabled: bool,
    /// Ranges of the listed countries (blocked, or allowed in whitelist
    /// mode).
    pub(crate) country_ranges: IpRules,
    /// Ranges of the blocked ASNs.
    pub(crate) asn_ranges: IpRules,
    /// Whitelist mode: an address outside `country_ranges` is denied.
    pub(crate) allow_list: bool,
    pub(crate) block_unknown: bool,
    pub(crate) challenge: bool,
    /// The policy answers with a basic auth prompt instead of a block page.
    pub(crate) basic_auth: bool,
    /// Monitor action (`log`): a match is recorded, never enforced.
    pub(crate) monitor: bool,
}

/// Why a request was denied, and by which rule.
pub(crate) struct Denial {
    pub(crate) rule_id: String,
    pub(crate) rule_name: String,
    pub(crate) detail: String,
    pub(crate) challenge: bool,
    /// The request must pass the site's basic auth gate to proceed.
    pub(crate) basic_auth: bool,
    /// Monitor action: the caller records the denial and lets the request
    /// continue (geo policy only).
    pub(crate) monitor: bool,
}

/// What the access restrictions decided for one request.
pub(crate) enum PolicyOutcome {
    /// No rule matched; the request continues.
    NoMatch,
    /// An explicit `allow` rule matched: the client is trusted, so the
    /// site-wide basic auth gate is skipped along with the rules below it.
    Allowed,
    /// A rule stopped the request.
    Denied(Denial),
}

impl PolicyOutcome {
    /// The denial, when the request was stopped.
    pub(crate) fn denial(&self) -> Option<&Denial> {
        match self {
            Self::Denied(denial) => Some(denial),
            _ => None,
        }
    }
}

/// Access restrictions of one site: IP rules plus the geo policy.
///
/// IP rules are evaluated first-match-wins in the order the control plane sent
/// them (priority ascending), so an `Allow` rule placed above a catch-all
/// `Block` yields a whitelist and sits below a blacklist. An explicit `Allow`
/// match short-circuits every rule below it — and the site-wide basic auth
/// gate with them; when nothing matches, the request continues.
#[derive(Default)]
pub(crate) struct AccessPolicy {
    pub(crate) ip_rules: Vec<IpRule>,
    pub(crate) geo: Option<GeoRule>,
}

impl AccessPolicy {
    pub(crate) fn build(site_rules: &CacheSiteRules) -> Self {
        let ip_rules = site_rules
            .ip_access_rules
            .iter()
            .filter(|rule| rule.enabled && !rule.ip_ranges.is_empty())
            .map(|rule| IpRule {
                id: rule.id.clone(),
                name: rule.name.clone(),
                action: match rule.action {
                    CacheIpAccessAction::Allow => IpRuleAction::Allow,
                    CacheIpAccessAction::Challenge
                    | CacheIpAccessAction::JsChallenge => {
                        IpRuleAction::Challenge
                    },
                    CacheIpAccessAction::Block => IpRuleAction::Block,
                    CacheIpAccessAction::BasicAuth => IpRuleAction::BasicAuth,
                },
                ranges: IpRules::new(&rule.ip_ranges),
            })
            .collect();
        Self {
            ip_rules,
            geo: site_rules.geo_config.as_ref().map(GeoRule::build),
        }
    }

    /// Decides whether `ip` — and the country it resolves to — may proceed.
    /// `addr` is the same address already parsed by the caller; IP rules are
    /// skipped when it could not be parsed.
    pub(crate) fn evaluate(
        &self,
        ip: &str,
        addr: Option<IpAddr>,
        _country: Option<&str>,
    ) -> PolicyOutcome {
        if let Some(addr) = addr {
            for rule in &self.ip_rules {
                if !rule.ranges.is_match_addr(&addr) {
                    continue;
                }
                return match rule.action {
                    IpRuleAction::Allow => PolicyOutcome::Allowed,
                    IpRuleAction::Block => PolicyOutcome::Denied(Denial {
                        rule_id: rule.id.clone(),
                        rule_name: rule.name.clone(),
                        detail: format!(
                            "client ip {ip} matched block rule {}",
                            rule.id
                        ),
                        challenge: false,
                        basic_auth: false,
                        monitor: false,
                    }),
                    IpRuleAction::Challenge => PolicyOutcome::Denied(Denial {
                        rule_id: rule.id.clone(),
                        rule_name: rule.name.clone(),
                        detail: format!(
                            "client ip {ip} matched challenge rule {}",
                            rule.id
                        ),
                        challenge: true,
                        basic_auth: false,
                        monitor: false,
                    }),
                    IpRuleAction::BasicAuth => PolicyOutcome::Denied(Denial {
                        rule_id: rule.id.clone(),
                        rule_name: rule.name.clone(),
                        detail: format!(
                            "client ip {ip} matched basic auth rule {}",
                            rule.id
                        ),
                        challenge: false,
                        basic_auth: true,
                        monitor: false,
                    }),
                };
            }
        }

        let Some(geo) = self.geo.as_ref().filter(|geo| geo.enabled) else {
            return PolicyOutcome::NoMatch;
        };
        let Some(addr) = addr else {
            // Ranges need a parsed address; without one the geo policy
            // cannot match.
            return PolicyOutcome::NoMatch;
        };
        let in_country = geo.country_ranges.is_match_addr(&addr);
        let in_asn = geo.asn_ranges.is_match_addr(&addr);
        let denied = if geo.allow_list {
            !in_country
        } else {
            in_country || in_asn || (geo.block_unknown && !in_country)
        };
        if !denied {
            return PolicyOutcome::NoMatch;
        }
        let detail = if geo.allow_list {
            "the client address is outside the allowed countries".to_string()
        } else if in_country {
            "the client address is in a blocked country range".to_string()
        } else if in_asn {
            "the client address is in a blocked network (ASN) range".to_string()
        } else {
            "the client address is outside the listed countries (block \
             unknown is on)"
                .to_string()
        };
        PolicyOutcome::Denied(Denial {
            rule_id: "geo_restriction".to_string(),
            rule_name: "Geo restriction".to_string(),
            detail,
            challenge: geo.challenge,
            basic_auth: geo.basic_auth,
            monitor: geo.monitor,
        })
    }
}

impl GeoRule {
    pub(crate) fn build(cfg: &CacheGeoConfig) -> Self {
        let rule = Self {
            enabled: cfg.enabled,
            country_ranges: IpRules::new(&cfg.country_ranges),
            asn_ranges: IpRules::new(&cfg.asn_ranges),
            allow_list: !cfg.allowed_countries.is_empty(),
            block_unknown: cfg.block_unknown,
            challenge: matches!(
                cfg.action,
                CacheWafAction::Challenge | CacheWafAction::JsChallenge
            ),
            basic_auth: matches!(cfg.action, CacheWafAction::BasicAuth),
            monitor: matches!(cfg.action, CacheWafAction::Log),
        };
        // Listed countries/ASNs whose ipverse dataset is not synced cannot
        // match. Say so once per compiled site instead of letting the
        // operator believe they are enforced.
        if rule.enabled && !cfg.missing_keys.is_empty() {
            warn!(
                keys = ?cfg.missing_keys,
                "geo policy lists countries/ASNs whose ipverse dataset is \
                 not synced; they cannot match until the data exists"
            );
        }
        rule
    }
}
