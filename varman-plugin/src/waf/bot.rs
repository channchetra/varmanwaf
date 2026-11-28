use super::*;
use pingap_plugin::text::contains_ignore_case;

// ─────────────────────────────────────────────────────────────
// Bot protection (user-agent classification)
// ─────────────────────────────────────────────────────────────

/// What bot protection does with a non-browser user agent.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum BotAction {
    Log,
    Challenge,
    Block,
}

/// Bot protection compiled from the site bundle: verified-bot user agent
/// substrings normalized for case-insensitive matching plus the action for
/// everything that does not look like a browser.
pub(crate) struct BotPolicy {
    pub(crate) whitelist: Vec<String>,
    pub(crate) action: BotAction,
    /// Browser-like UAs must also present browser request headers.
    pub(crate) js_detection: bool,
    /// Browser-like UAs must arrive over a TLS session.
    pub(crate) tls_fingerprint: bool,
    /// Per-IP request bursts receive the configured action.
    pub(crate) behavioral_analysis: bool,
    /// Client IPs inside any of these ranges count as verified bots without
    /// further inspection: the control plane expands the configured IP group
    /// and only fills this when IP verification is enabled.
    pub(crate) verified_ranges: Vec<IpNet>,
    /// Known crawler user agents are only trusted after a DNS reverse +
    /// forward confirmation of the client IP.
    pub(crate) dns_verification: bool,
}

/// Outcome of classifying one request's user agent.
pub(crate) enum BotDecision {
    /// Verified bot or real browser: continue.
    Pass,
    /// Stop the request with the challenge or block page.
    Deny(Denial),
    /// Record a security event but let the request through.
    LogOnly(Denial),
}

/// Connection-level signals for bot classification.
#[derive(Debug, Clone, Copy)]
pub(crate) struct ClientSignals {
    /// `Accept` + `Accept-Language` present.
    pub(crate) browser_hints: bool,
    /// The connection presented a TLS session.
    pub(crate) tls_verified: bool,
    /// The client exceeded the edge-local request burst threshold.
    pub(crate) burst: bool,
}

/// Edge-local behavior tracker: per-IP request bursts inside a sliding
/// window. Bounded — entries are swept once the map grows past a cap.
static BOT_BEHAVIOR: LazyLock<DashMap<String, (Instant, u32)>> =
    LazyLock::new(DashMap::new);

/// Burst window and threshold for behavioral analysis.
const BURST_WINDOW: Duration = Duration::from_secs(60);
const BURST_THRESHOLD: u32 = 120;
const BEHAVIOR_CAP: usize = 65_536;

/// Records one request for `ip`; `true` when the rate exceeds the threshold
/// within the window.
pub(crate) fn request_burst(ip: &str) -> bool {
    request_burst_with(
        &BOT_BEHAVIOR,
        ip,
        Instant::now(),
        BURST_WINDOW,
        BURST_THRESHOLD,
    )
}

pub(crate) fn request_burst_with(
    map: &DashMap<String, (Instant, u32)>,
    ip: &str,
    now: Instant,
    window: Duration,
    threshold: u32,
) -> bool {
    if map.len() > BEHAVIOR_CAP {
        map.retain(|_, (start, _)| now.duration_since(*start) < window * 2);
    }
    let mut entry = map.entry(ip.to_string()).or_insert((now, 0));
    if now.duration_since(entry.0) >= window {
        *entry = (now, 1);
        return false;
    }
    entry.1 = entry.1.saturating_add(1);
    entry.1 > threshold
}

impl BotPolicy {
    pub(crate) fn build(cfg: &CacheBotProtection) -> Self {
        let action = match cfg.action {
            CacheWafAction::Log => BotAction::Log,
            CacheWafAction::Challenge | CacheWafAction::JsChallenge => {
                BotAction::Challenge
            },
            _ => BotAction::Block,
        };
        Self {
            whitelist: cfg
                .known_bots_whitelist
                .iter()
                .map(|ua| ua.trim().to_lowercase())
                .filter(|ua| !ua.is_empty())
                .collect(),
            action,
            js_detection: cfg.js_detection,
            tls_fingerprint: cfg.tls_fingerprint,
            behavioral_analysis: cfg.behavioral_analysis,
            verified_ranges: cfg
                .verified_bot_ranges
                .iter()
                .filter_map(|range| {
                    let raw = range.trim();
                    raw.parse::<IpNet>()
                        .or_else(|_| raw.parse::<IpAddr>().map(IpNet::from))
                        .ok()
                })
                .collect(),
            dns_verification: cfg.dns_verification_enabled,
        }
    }

    /// `true` when this policy needs the edge-local burst tracker.
    pub(crate) fn uses_behavioral(&self) -> bool {
        self.behavioral_analysis
    }

    /// Builds the denial for this policy's action (challenge vs block page).
    pub(crate) fn denial(&self, detail: String) -> Denial {
        Denial {
            rule_id: "bot_protection".to_string(),
            rule_name: "Bot protection".to_string(),
            detail,
            challenge: self.action == BotAction::Challenge,
            basic_auth: false,
            monitor: false,
        }
    }

    /// Applies the configured action to a denial: `log` records, everything
    /// else denies.
    pub(crate) fn decide(&self, denial: Denial) -> BotDecision {
        match self.action {
            BotAction::Log => BotDecision::LogOnly(denial),
            _ => BotDecision::Deny(denial),
        }
    }

    /// Classifies one request, assuming real browser request headers were
    /// present (the historical behaviour; callers with request context should
    /// use [`Self::evaluate_with_hints`]).
    #[cfg(test)]
    pub(crate) fn evaluate(&self, user_agent: &str) -> BotDecision {
        self.evaluate_with_hints(user_agent, true)
    }

    /// Classifies one request assuming a TLS session and, when
    /// `browser_hints` is false, no browser request headers; used by tests.
    #[cfg(test)]
    pub(crate) fn evaluate_with_hints(
        &self,
        user_agent: &str,
        browser_hints: bool,
    ) -> BotDecision {
        self.classify_with_signals(
            user_agent,
            ClientSignals {
                browser_hints,
                tls_verified: true,
                burst: false,
            },
        )
    }

    /// Classifies one request with the verified-bot checks first: a client IP
    /// inside a configured verified-bot range passes outright, and a user
    /// agent claiming a well-known crawler family is only trusted after the
    /// client IP proves it over DNS (see [`crate::bot_dns`]). A resolver
    /// outage degrades to the user-agent-only verdict instead of blocking on
    /// it.
    pub(crate) async fn evaluate_with_signals(
        &self,
        client_ip: Option<IpAddr>,
        user_agent: &str,
        signals: ClientSignals,
    ) -> BotDecision {
        if let Some(ip) = client_ip
            && self.verified_ranges.iter().any(|range| range.contains(&ip))
        {
            return BotDecision::Pass;
        }
        if self.dns_verification
            && let Some(ip) = client_ip
            && let Some((token, _)) =
                pingap_plugin::bot_dns::known_bot_family(user_agent)
        {
            match pingap_plugin::bot_dns::bot_dns_verifier()
                .verify(ip, token)
                .await
            {
                pingap_plugin::bot_dns::DnsVerdict::Confirmed => {
                    return BotDecision::Pass;
                },
                pingap_plugin::bot_dns::DnsVerdict::Refuted => {
                    return self.decide(self.denial(format!(
                        "user agent claims to be a '{token}' crawler but {ip} does not resolve to its network"
                    )));
                },
                pingap_plugin::bot_dns::DnsVerdict::Unknown => {},
            }
        }
        self.classify_with_signals(user_agent, signals)
    }

    /// The user-agent side of the classification (DNS already resolved).
    ///
    /// Whitelisted verified bots pass first, then real browsers; everything
    /// else receives the configured action. When JS detection is enabled, a
    /// browser-like UA must also present browser request headers (`Accept` +
    /// `Accept-Language`), otherwise it is treated as a scripted client
    /// pretending to be a browser. Matching is ASCII case-insensitive without
    /// lowercasing, so the common pass-through path allocates nothing.
    pub(crate) fn classify_with_signals(
        &self,
        user_agent: &str,
        signals: ClientSignals,
    ) -> BotDecision {
        if self
            .whitelist
            .iter()
            .any(|bot| contains_ignore_case(user_agent, bot))
        {
            return BotDecision::Pass;
        }
        if is_browser_ua(user_agent) {
            if self.js_detection && !signals.browser_hints {
                let denial = Denial {
                    rule_id: "bot_protection".to_string(),
                    rule_name: "Bot protection".to_string(),
                    detail: format!(
                        "browser-like user agent '{user_agent}' without browser request headers (JS detection)"
                    ),
                    challenge: self.action == BotAction::Challenge,
                    basic_auth: false,
                    monitor: false,
                };
                return match self.action {
                    BotAction::Log => BotDecision::LogOnly(denial),
                    _ => BotDecision::Deny(denial),
                };
            }
            if self.tls_fingerprint && !signals.tls_verified {
                let denial = Denial {
                    rule_id: "bot_protection".to_string(),
                    rule_name: "Bot protection".to_string(),
                    detail: format!(
                        "browser-like user agent '{user_agent}' without a TLS session (TLS fingerprinting)"
                    ),
                    challenge: self.action == BotAction::Challenge,
                    basic_auth: false,
                    monitor: false,
                };
                return match self.action {
                    BotAction::Log => BotDecision::LogOnly(denial),
                    _ => BotDecision::Deny(denial),
                };
            }
            if self.behavioral_analysis && signals.burst {
                let denial = Denial {
                    rule_id: "bot_protection".to_string(),
                    rule_name: "Bot protection".to_string(),
                    detail: format!(
                        "browser-like user agent '{user_agent}' exceeded the request burst threshold (behavioral analysis)"
                    ),
                    challenge: self.action == BotAction::Challenge,
                    basic_auth: false,
                    monitor: false,
                };
                return match self.action {
                    BotAction::Log => BotDecision::LogOnly(denial),
                    _ => BotDecision::Deny(denial),
                };
            }
            return BotDecision::Pass;
        }
        let denial = Denial {
            rule_id: "bot_protection".to_string(),
            rule_name: "Bot protection".to_string(),
            detail: if user_agent.is_empty() {
                "the request carries no user agent".to_string()
            } else {
                format!(
                    "user agent '{user_agent}' is neither a verified bot nor a browser"
                )
            },
            challenge: self.action == BotAction::Challenge,
            basic_auth: false,
            monitor: false,
        };
        match self.action {
            BotAction::Log => BotDecision::LogOnly(denial),
            _ => BotDecision::Deny(denial),
        }
    }
}

/// `true` when the request carries the two headers every real browser sends:
/// a non-empty `Accept` and `Accept-Language`. Used by JS detection.
pub(crate) fn browser_header_hints(headers: &[(String, String)]) -> bool {
    let mut accept = false;
    let mut language = false;
    for (name, value) in headers {
        if name.eq_ignore_ascii_case("accept") && !value.trim().is_empty() {
            accept = true;
        }
        if name.eq_ignore_ascii_case("accept-language")
            && !value.trim().is_empty()
        {
            language = true;
        }
    }
    accept && language
}

/// Loose fingerprint of a real browser user agent: browsers declare
/// `Mozilla/5.0` plus a concrete engine token, while scripting clients,
/// scanners and empty agents do not.
pub(crate) fn is_browser_ua(ua: &str) -> bool {
    contains_ignore_case(ua, "mozilla/5.0")
        && (contains_ignore_case(ua, "chrome/")
            || contains_ignore_case(ua, "safari/")
            || contains_ignore_case(ua, "firefox/")
            || contains_ignore_case(ua, "trident/")
            || contains_ignore_case(ua, "edg/")
            || contains_ignore_case(ua, "opr/")
            || contains_ignore_case(ua, "samsungbrowser/"))
}
