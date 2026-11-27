use super::*;

// ─────────────────────────────────────────────────────────────
// Rate limiting (per-site rules over fixed-window counters)
// ─────────────────────────────────────────────────────────────

/// Counter key dimension of a rate limit rule. Rules that reference a
/// characteristic that cannot be keyed at the edge (e.g. ja3), or a
/// parameterized one without a name, are ignored at build time rather than
/// enforced with a degraded key.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum RateChar {
    Ip,
    Host,
    Path,
    Asn,
    Country,
    /// Named request header, matched case-insensitively.
    Header(String),
    /// Named cookie from the `Cookie` header(s), matched case-sensitively.
    Cookie(String),
    /// Named query-string parameter, matched case-sensitively against the raw
    /// (undecoded) query.
    Query(String),
}

/// What an exhausted rate limit rule does to matching requests.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum RateAction {
    /// Record a security event only.
    Log,
    /// Serve the browser challenge; clients holding a valid clearance are
    /// exempt (they already proved a human is behind the traffic).
    Challenge,
    /// Reject with 429 for the mitigation window.
    Block,
}

/// One enabled rate limit rule compiled for evaluation. Rules keep the order
/// the control plane sent them in (priority ascending) and the first
/// enforcing rule to trip stops the request.
pub(crate) struct CompiledRateRule {
    pub(crate) id: String,
    pub(crate) name: String,
    /// Optional match condition; `None` applies to every request.
    pub(crate) expression: Option<Expression>,
    pub(crate) chars: Vec<RateChar>,
    pub(crate) period_secs: u64,
    pub(crate) threshold: u32,
    pub(crate) mitigation_secs: u64,
    pub(crate) action: RateAction,
}

impl CompiledRateRule {
    /// Compiles one control-plane rule; `None` when disabled, unenforceable
    /// (zero threshold or period, unsupported characteristic, allow action)
    /// or carrying an expression that fails to parse.
    pub(crate) fn build(rule: &CacheRateLimitRule) -> Option<Self> {
        if !rule.enabled || rule.threshold == 0 || rule.period_seconds == 0 {
            return None;
        }
        let mut chars = Vec::with_capacity(rule.characteristics.len());
        for (idx, raw) in rule.characteristics.iter().enumerate() {
            let lower = raw.trim().to_lowercase();
            let param = || {
                rule.characteristic_params
                    .get(idx)
                    .map(|p| p.trim())
                    .unwrap_or("")
            };
            let kind = match lower
                .strip_prefix("ratelimitchar")
                .unwrap_or(&lower)
            {
                "ip" | "ipnat" | "ip_nat" => RateChar::Ip,
                "host" => RateChar::Host,
                "path" => RateChar::Path,
                "asn" => RateChar::Asn,
                "country" => RateChar::Country,
                "header" => {
                    let name = param().to_lowercase();
                    if name.is_empty() {
                        debug!(
                            rule = %rule.id,
                            characteristic = %raw,
                            "header characteristic without a parameter name; rule ignored"
                        );
                        return None;
                    }
                    RateChar::Header(name)
                },
                "cookie" => {
                    let name = param().to_string();
                    if name.is_empty() {
                        debug!(
                            rule = %rule.id,
                            characteristic = %raw,
                            "cookie characteristic without a parameter name; rule ignored"
                        );
                        return None;
                    }
                    RateChar::Cookie(name)
                },
                "query" => {
                    let name = param().to_string();
                    if name.is_empty() {
                        debug!(
                            rule = %rule.id,
                            characteristic = %raw,
                            "query characteristic without a parameter name; rule ignored"
                        );
                        return None;
                    }
                    RateChar::Query(name)
                },
                _ => {
                    debug!(
                        rule = %rule.id,
                        characteristic = %raw,
                        "rate limit characteristic unsupported at the edge; rule ignored"
                    );
                    return None;
                },
            };
            chars.push(kind);
        }
        let expression = if rule.expression.trim().is_empty() {
            None
        } else {
            match parse_expression(&rule.expression) {
                Ok(expr) => Some(expr),
                Err(e) => {
                    debug!(
                        rule = %rule.id,
                        error = %e,
                        "rate limit expression failed to parse; rule ignored"
                    );
                    return None;
                },
            }
        };
        let action = match rule.action {
            CacheWafAction::Log => RateAction::Log,
            CacheWafAction::Challenge | CacheWafAction::JsChallenge => {
                RateAction::Challenge
            },
            CacheWafAction::Block => RateAction::Block,
            // Counting without consequence would only burn CPU, and basic
            // auth is not a rate limit outcome.
            CacheWafAction::Allow | CacheWafAction::BasicAuth => return None,
        };
        Some(Self {
            id: rule.id.clone(),
            name: rule.name.clone(),
            expression,
            chars,
            period_secs: u64::from(rule.period_seconds),
            threshold: rule.threshold,
            mitigation_secs: u64::from(rule.mitigation_timeout_seconds),
            action,
        })
    }

    /// Counter key for this rule and request: the rule id (a UUID, unique
    /// across sites) plus the value of every tracked characteristic. Requests
    /// missing a parameterized value (absent header/cookie/query) share the
    /// `-` bucket instead of bypassing the counter.
    pub(crate) fn counter_key(
        &self,
        request_data: &RequestData,
        host: &str,
        asn: Option<u32>,
    ) -> String {
        let mut key = String::with_capacity(64);
        key.push_str(&self.id);
        for c in &self.chars {
            key.push('\u{1f}');
            match c {
                RateChar::Ip => key.push_str(&request_data.client_ip),
                RateChar::Host => key.push_str(host),
                RateChar::Path => key.push_str(&request_data.path),
                RateChar::Country => key.push_str(
                    request_data.country_code.as_deref().unwrap_or("-"),
                ),
                RateChar::Asn => match asn {
                    Some(n) => key.push_str(&n.to_string()),
                    None => key.push('-'),
                },
                RateChar::Header(name) => key.push_str(
                    request_data
                        .headers
                        .iter()
                        .find(|(k, _)| k.eq_ignore_ascii_case(name))
                        .map(|(_, v)| v.trim())
                        .unwrap_or("-"),
                ),
                RateChar::Cookie(name) => key.push_str(
                    request_data
                        .headers
                        .iter()
                        .filter(|(k, _)| k.eq_ignore_ascii_case("cookie"))
                        .flat_map(|(_, v)| v.split(';'))
                        .find_map(|pair| {
                            let (n, v) = pair.trim().split_once('=')?;
                            (n == name.as_str()).then(|| v.trim())
                        })
                        .unwrap_or("-"),
                ),
                RateChar::Query(name) => key.push_str(
                    request_data
                        .query
                        .split('&')
                        .find_map(|pair| {
                            let (n, v) = pair.split_once('=')?;
                            (n == name.as_str()).then_some(v)
                        })
                        .unwrap_or("-"),
                ),
            }
        }
        key
    }
}

pub(crate) fn rate_tripped(
    rule: &CompiledRateRule,
    retry_after: u64,
) -> RateTripped {
    RateTripped {
        rule_id: rule.id.clone(),
        rule_name: rule.name.clone(),
        detail: format!(
            "rate limit rule '{}' exceeded {} requests per {}s",
            rule.name, rule.threshold, rule.period_secs
        ),
        challenge: rule.action == RateAction::Challenge,
        retry_after,
    }
}

/// A tripped rate limit rule.
pub(crate) struct RateTripped {
    pub(crate) rule_id: String,
    pub(crate) rule_name: String,
    pub(crate) detail: String,
    pub(crate) challenge: bool,
    /// Suggested Retry-After in seconds: the mitigation timeout, or the rest
    /// of the current window when no mitigation is configured.
    pub(crate) retry_after: u64,
}

/// What rate limiting decided for one request.
pub(crate) struct RateOutcome {
    /// First enforcing rule that tripped: the request must be stopped.
    pub(crate) deny: Option<RateTripped>,
    /// Log-only rules that tripped: recorded as events only.
    pub(crate) logged: Vec<RateTripped>,
}

/// Fixed-window counter state for one rate limit key.
#[derive(Debug)]
pub(crate) struct RateCounter {
    /// Current window index (`unix seconds / period`).
    pub(crate) window: u64,
    pub(crate) count: u32,
    /// Unix seconds until which the key stays blocked (0 = clear); only set
    /// while a mitigation timeout is running.
    pub(crate) blocked_until: u64,
    /// Unix seconds after which the entry becomes collectable.
    pub(crate) expires_at: u64,
}

/// Only pay for garbage collection above this many live counters.
const RATE_COUNTERS_GC_THRESHOLD: usize = 65_536;

pub(crate) fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

/// All rate limit rules of one site in evaluation order.
#[derive(Default)]
pub(crate) struct RateLimitPolicy {
    pub(crate) rules: Vec<CompiledRateRule>,
}

impl RateLimitPolicy {
    pub(crate) fn build(site_rules: &CacheSiteRules) -> Self {
        Self {
            rules: site_rules
                .rate_limit_rules
                .iter()
                .filter_map(CompiledRateRule::build)
                .collect(),
        }
    }

    /// Counts the request against every matching rule. Enforcement rules stop
    /// at the first one that trips; log-only rules accumulate events and let
    /// the request continue.
    pub(crate) fn evaluate(
        &self,
        counters: &DashMap<String, RateCounter>,
        request_data: &RequestData,
        host: &str,
        cleared: bool,
        client_addr: Option<IpAddr>,
    ) -> RateOutcome {
        let mut logged = Vec::new();
        if self.rules.is_empty() {
            return RateOutcome { deny: None, logged };
        }
        let now = unix_now();
        let asn = if self.rules.iter().any(|r| r.chars.contains(&RateChar::Asn))
        {
            client_addr.and_then(lookup_asn_addr)
        } else {
            None
        };
        let expression_state = self
            .rules
            .iter()
            .any(|r| r.expression.is_some())
            .then(|| ExpressionState::build(request_data));
        for rule in &self.rules {
            if let (Some(state), Some(expr)) =
                (expression_state.as_ref(), rule.expression.as_ref())
                && !evaluate_expression(
                    expr,
                    &state.eval(request_data, host, client_addr),
                )
            {
                continue;
            }
            // A client holding a valid clearance already solved a challenge;
            // challenge rules neither count nor stop it.
            if rule.action == RateAction::Challenge && cleared {
                continue;
            }
            let key = rule.counter_key(request_data, host, asn);
            if counters.len() > RATE_COUNTERS_GC_THRESHOLD {
                counters.retain(|_, entry| now < entry.expires_at);
            }
            let window = now / rule.period_secs;
            let mut entry = counters.entry(key).or_insert(RateCounter {
                window,
                count: 0,
                blocked_until: 0,
                expires_at: 0,
            });
            if entry.window != window {
                entry.window = window;
                entry.count = 0;
                entry.blocked_until = 0;
            }
            let retry_after = if rule.mitigation_secs > 0 {
                rule.mitigation_secs
            } else {
                (window + 1) * rule.period_secs - now
            };
            if now < entry.blocked_until {
                drop(entry);
                let tripped = rate_tripped(rule, retry_after);
                match rule.action {
                    RateAction::Log => logged.push(tripped),
                    _ => {
                        return RateOutcome {
                            deny: Some(tripped),
                            logged,
                        };
                    },
                }
                continue;
            }
            entry.count = entry.count.saturating_add(1);
            entry.expires_at =
                (window + 1) * rule.period_secs + rule.mitigation_secs;
            if entry.count > rule.threshold {
                if rule.mitigation_secs > 0 {
                    entry.blocked_until = now + rule.mitigation_secs;
                }
                drop(entry);
                let tripped = rate_tripped(rule, retry_after);
                match rule.action {
                    RateAction::Log => logged.push(tripped),
                    _ => {
                        return RateOutcome {
                            deny: Some(tripped),
                            logged,
                        };
                    },
                }
            }
        }
        RateOutcome { deny: None, logged }
    }
}

/// Owned per-request data rule expressions evaluate against: the
/// [`EvalContext`] borrows from this state plus the request data.
pub(crate) struct ExpressionState {
    pub(crate) full_uri: String,
    pub(crate) cookies: Vec<(String, String)>,
}

impl ExpressionState {
    pub(crate) fn build(request_data: &RequestData) -> Self {
        let full_uri = if request_data.query.is_empty() {
            request_data.path.clone()
        } else {
            format!("{}?{}", request_data.path, request_data.query)
        };
        Self {
            full_uri,
            cookies: parse_cookies(&request_data.headers),
        }
    }

    pub(crate) fn eval<'a>(
        &'a self,
        request_data: &'a RequestData,
        host: &'a str,
        parsed_ip: Option<IpAddr>,
    ) -> EvalContext<'a> {
        let user_agent = request_data
            .headers
            .iter()
            .find(|(k, _)| k == "user-agent")
            .map(|(_, v)| v.as_str())
            .unwrap_or("");
        EvalContext {
            method: &request_data.method,
            path: &request_data.path,
            full_uri: &self.full_uri,
            host,
            user_agent,
            body: None,
            headers: &request_data.headers,
            cookies: &self.cookies,
            client_ip: &request_data.client_ip,
            parsed_ip,
            country_code: request_data.country_code.as_deref(),
            ssl: request_data.scheme.eq_ignore_ascii_case("https"),
            waf_score: 0,
            waf_score_sqli: 0,
            waf_score_xss: 0,
            waf_score_rce: 0,
        }
    }
}

/// Parses the `Cookie` header into name/value pairs.
pub(crate) fn parse_cookies(
    headers: &[(String, String)],
) -> Vec<(String, String)> {
    let Some(raw) = headers
        .iter()
        .find(|(k, _)| k == "cookie")
        .map(|(_, v)| v.as_str())
    else {
        return Vec::new();
    };
    raw.split(';')
        .filter_map(|pair| {
            let (name, value) = pair.trim().split_once('=')?;
            Some((name.trim().to_string(), value.trim().to_string()))
        })
        .collect()
}

/// Extracts the clearance cookie value, if the client carries one.
pub(crate) fn clearance_cookie(headers: &[(String, String)]) -> Option<String> {
    headers
        .iter()
        .find(|(k, _)| k == "cookie")
        .and_then(|(_, v)| {
            v.split(';').find_map(|pair| {
                let (name, value) = pair.trim().split_once('=')?;
                name.trim()
                    .eq_ignore_ascii_case(CLEARANCE_COOKIE_NAME)
                    .then(|| value.trim().to_string())
            })
        })
}

/// Clearance cookie manager of the challenge system, cached against the agent
/// cache dir it was resolved from so a rebuilt or replaced agent re-resolves
/// its secret instead of reusing a stale one. Holding the constructed manager
/// spares the hot path an HMAC key setup per validated request.
static CLEARANCE_MANAGER: RwLock<Option<(PathBuf, CookieManager)>> =
    RwLock::new(None);

/// Whether `value` (when present) is a valid clearance cookie. A client that
/// solved a challenge once is exempt from challenge-type rate limit rules.
pub(crate) fn clearance_valid(value: Option<String>) -> bool {
    let Some(value) = value else {
        return false;
    };
    let Some(agent) = VarmanAgent::instance() else {
        return false;
    };
    let secret_path =
        Path::new(&agent.config.cache_dir).join("challenge_cookie_secret");
    {
        let cached =
            CLEARANCE_MANAGER.read().unwrap_or_else(|e| e.into_inner());
        if let Some((path, manager)) = cached.as_ref()
            && *path == secret_path
        {
            return manager.validate_clearance(&value).is_ok();
        }
    }
    let secret = resolve_cookie_secret("");
    let manager = CookieManager::new(secret.as_bytes(), 3600);
    let valid = manager.validate_clearance(&value).is_ok();
    *CLEARANCE_MANAGER.write().unwrap_or_else(|e| e.into_inner()) =
        Some((secret_path, manager));
    valid
}
