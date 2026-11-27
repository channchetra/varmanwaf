// Copyright 2024-2025 Tree xie.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//! WAF plugin — inspects every request against the VarmanWAF detection engine.
//!
//! Runs at [`PluginStep::EarlyRequest`], ahead of most other plugins. Rules are
//! resolved per request:
//! * When a [`VarmanAgent`] control-plane instance is running, site rules for
//!   the request's domain are used (cached per-domain and rebuilt when the
//!   agent's config hash changes).
//! * Otherwise (standalone pingap) the locally configured engine is used.
//!
//! Verdicts map onto the proxy pipeline: `Pass`/`Monitor` continue, `Block`
//! returns 403, and `Challenge` delegates to the challenge subsystem.

use super::{Error, get_hash_key, parse_params};
use crate::challenge::{
    ChallengeKind, VERIFY_ENDPOINT, basic_auth_page, block_page,
    build_challenge_response, paused_page, rate_limit_page,
    resolve_cookie_secret,
};
use crate::waf_ato::{FailedAuthTracker, is_state_changing};
use crate::waf_stream::{StreamFinding, StreamInspector, TailWindow};
use async_trait::async_trait;
use bytes::{BufMut, Bytes, BytesMut};
use dashmap::DashMap;
use ipnet::IpNet;
use pingap_config::{PluginCategory, PluginConf};
use pingap_core::{
    Ctx, HTTP_HEADER_NAME_X_REQUEST_ID, HttpResponse, Plugin, PluginStep,
    RequestPluginResult, ResponseBodyPluginResult, ResponsePluginResult,
    constant_time_eq, ensure_client_ip, get_host, new_internal_error,
};
use pingap_util::{IpRules, base64_decode};
use pingora::http::{ResponseHeader, Version};
use pingora::proxy::Session;
use std::borrow::Cow;
use std::collections::{HashMap, HashSet};
use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::sync::{Arc, LazyLock, RwLock};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use tor_geoip::GeoipDb;
use tracing::{debug, warn};
use varman_agent::cache::PathTargetExclusion as CachePathTargetExclusion;
use varman_agent::cache::{
    BasicAuthConfig as CacheBasicAuthConfig,
    BotProtectionConfig as CacheBotProtection, GeoConfig as CacheGeoConfig,
    IpAccessAction as CacheIpAccessAction, RateLimitRule as CacheRateLimitRule,
    SiteRules as CacheSiteRules, SslConfig as CacheSslConfig,
    WafAction as CacheWafAction, WafConfig as CacheWafConfig,
    WafMode as CacheWafMode,
};
use varman_agent::{AccessLogEntry, SecurityEvent, VarmanAgent};
use varman_challenge::{
    CLEARANCE_COOKIE_NAME, CookieManager, generate_request_id,
};
use varman_waf::pipeline::Action;
use varman_waf::rules::{
    EvalContext, Expression, evaluate as evaluate_expression, parse_expression,
};
use varman_waf::{
    CategorySet, CompiledRule, PathTargetExclusion, RequestData, RuleAction,
    ScoreBreakdown, StackSet, WafAction, WafEngine, WafEngineConfig, WafLevel,
    WafMode, WafVerdict,
};

type Result<T, E = Error> = std::result::Result<T, E>;

/// Which engine handles the current request.
enum EngineChoice {
    /// Locally configured engine (standalone mode).
    Base,
    /// Per-domain engine built from agent-supplied site rules.
    Site(Arc<WafEngine>),
    /// WAF explicitly disabled for this site by the control plane.
    Disabled,
}

/// Client certificate policy of a site, built from its SSL posture. The
/// listener verifies the chain against the union of every mTLS site's CA;
/// what is left per site is requiring a certificate at all, rejecting the
/// ones the dashboard revoked and pinning the organization.
struct MtlsPolicy {
    require_client_cert: bool,
    /// Organization every presented certificate must carry; empty skips the
    /// check.
    organization: String,
    /// Lowercase hex SHA-256 fingerprints of revoked certificates.
    revoked: HashSet<String>,
}

impl MtlsPolicy {
    /// `None` when the site does not use mTLS at all.
    fn build(ssl: Option<&CacheSslConfig>) -> Option<Self> {
        let ssl = ssl.filter(|ssl| ssl.mtls_enabled)?;
        Some(Self {
            require_client_cert: ssl.mtls_requires_cert(),
            organization: ssl.mtls_organization.trim().to_string(),
            revoked: ssl
                .mtls_revoked_fingerprints
                .iter()
                .map(|fingerprint| fingerprint.trim().to_lowercase())
                .filter(|fingerprint| !fingerprint.is_empty())
                .collect(),
        })
    }

    /// The reason this request is refused, `None` when the client
    /// certificate — or its absence — is acceptable.
    fn denial_reason(&self, ctx: &Ctx) -> Option<&'static str> {
        let digest = ctx.conn.tls_peer_cert_digest.as_deref();
        let Some(digest) = digest else {
            return self
                .require_client_cert
                .then_some("client certificate required");
        };
        if self.revoked.contains(&digest.to_lowercase()) {
            return Some("client certificate revoked");
        }
        if !self.organization.is_empty()
            && ctx
                .conn
                .tls_peer_organization
                .as_deref()
                .is_none_or(|org| org != self.organization)
        {
            return Some("client certificate organization mismatch");
        }
        None
    }
}

/// The site's HTTP basic authentication credentials and gate.
///
/// The gate sits inside the WAF plugin, which runs ahead of the cache plugin
/// in the chain, so a stored response can never answer a request that has not
/// been authenticated. Credentials reach the data plane pre-encoded; the
/// request payload is decoded once and compared in constant time.
struct BasicAuthGate {
    /// The gate applies to every request, not only to the clients an access
    /// rule with the `basic_auth` action singles out.
    site_wide: bool,
    realm: String,
    /// Decoded `user:password` payloads.
    credentials: Vec<Vec<u8>>,
    delay: Option<std::time::Duration>,
    hide_credentials: bool,
}

/// Realm advertised when the site did not name one.
const DEFAULT_BASIC_REALM: &str = "Restricted";

/// Keeps a configured realm from breaking out of the `WWW-Authenticate`
/// header.
fn sanitise_realm(value: &str) -> String {
    let cleaned: String = value
        .trim()
        .chars()
        .filter(|c| !c.is_control() && *c != '"' && *c != '\\')
        .collect();
    if cleaned.is_empty() {
        DEFAULT_BASIC_REALM.to_string()
    } else {
        cleaned
    }
}

impl BasicAuthGate {
    /// `None` when the site has no usable credential: without one nothing
    /// can pass, so the gate is left out and the operator sees the warning
    /// logged instead. The credentials serve both the site-wide gate and the
    /// `basic_auth` rule action, so they are compiled even while the
    /// site-wide switch is off.
    fn build(cfg: &CacheBasicAuthConfig) -> Option<Self> {
        let credentials: Vec<Vec<u8>> = cfg
            .credentials
            .iter()
            .filter_map(|credential| {
                match base64_decode(&credential.authorization) {
                    Ok(decoded) => Some(decoded),
                    Err(error) => {
                        warn!(
                            username = %credential.username,
                            error = %error,
                            "basic auth credential is not valid base64; entry ignored"
                        );
                        None
                    },
                }
            })
            .collect();
        if credentials.is_empty() {
            if cfg.enabled {
                warn!(
                    "basic auth is enabled without a usable credential; gate disabled"
                );
            }
            return None;
        }
        Some(Self {
            site_wide: cfg.enabled,
            realm: sanitise_realm(&cfg.realm),
            credentials,
            delay: (cfg.delay_seconds > 0).then(|| {
                std::time::Duration::from_secs(u64::from(cfg.delay_seconds))
            }),
            hide_credentials: cfg.hide_credentials,
        })
    }

    /// Whether the request carries a credential this gate accepts.
    fn verify(&self, headers: &[(String, String)]) -> bool {
        let Some(value) = headers
            .iter()
            .find(|(name, _)| name.eq_ignore_ascii_case("authorization"))
            .map(|(_, value)| value.as_str())
        else {
            return false;
        };
        // The scheme is case-insensitive (RFC 7235).
        let Some((scheme, payload)) = value.split_once(' ') else {
            return false;
        };
        if !scheme.eq_ignore_ascii_case("basic") {
            return false;
        }
        let Ok(decoded) = base64_decode(payload.trim()) else {
            return false;
        };
        self.credentials
            .iter()
            .any(|expected| constant_time_eq(expected, &decoded))
    }
}

/// Whether any enabled access rule asks for the basic auth gate.
fn access_rules_require_basic_auth(site_rules: &CacheSiteRules) -> bool {
    let ip_rule = site_rules.ip_access_rules.iter().any(|rule| {
        rule.enabled && matches!(rule.action, CacheIpAccessAction::BasicAuth)
    });
    let geo_rule = site_rules
        .geo_config
        .as_ref()
        .is_some_and(|geo| matches!(geo.action, CacheWafAction::BasicAuth));
    ip_rule || geo_rule
}

/// Site data resolved from the agent cache, compiled once per config
/// fingerprint: the WAF engine, the access restrictions and the custom rule
/// names used to label security events.
struct SiteContext {
    engine: Option<Arc<WafEngine>>,
    policy: AccessPolicy,
    /// Bot protection (UA classification); `None` when disabled.
    bot: Option<BotPolicy>,
    /// Rate limit rules; `None` when the site has none that are enforceable.
    rate_limits: Option<RateLimitPolicy>,
    /// mTLS enforcement; `None` when the site does not use mTLS.
    mtls: Option<MtlsPolicy>,
    /// Site-wide basic auth gate; `None` when the site has none, it is
    /// disabled, or it stores no usable credential.
    basic_auth: Option<BasicAuthGate>,
    /// Custom rule id → name.
    rule_names: HashMap<String, String>,
    /// Observation mode: every protection keeps detecting but only records —
    /// WAF, IP/geo rules, bot protection and rate limiting stop enforcing.
    /// Access control (mTLS, basic auth, a paused site) is never downgraded.
    observation_mode: bool,
    /// Site-level deep body inspection (advanced mode): inspect request
    /// bodies even when the plugin-level `inspect_body` switch is off.
    inspect_body: bool,
    /// Per-site WAF engine mode from `waf_settings.engine_mode`: empty or
    /// `inherit` follows the process-wide `VARMAN_WAF_ENGINE`.
    engine_mode: String,
    /// Per-site enforcement mode from `waf_settings.mode`; `None` when no
    /// site context exists (standalone mode). The mode caps every engine
    /// path after inspection: `monitor` records findings without enforcing
    /// and `off` skips inspection entirely, no matter which engine (legacy,
    /// pipeline, custom layers, processor) escalated the verdict.
    mode: Option<WafMode>,
    /// Per-site monitor-only categories (`waf_settings.monitor_categories`),
    /// applied to the Varman pipeline so both engines agree on the site's
    /// policy.
    monitor_categories: Vec<String>,
    /// Path-scoped target exclusions from exclusion packages. Streams are
    /// body content, so only entries that name the body target apply.
    path_target_exclusions: Vec<CachePathTargetExclusion>,
    /// Compiled per-site custom layers (SecLang virtual patches + OpenAPI
    /// validation); `None` when neither is configured.
    custom: Option<Arc<crate::waf_custom::CustomLayers>>,
}

impl SiteContext {
    fn build(site_rules: &CacheSiteRules) -> Self {
        let waf_cfg = site_rules.waf_config.as_ref();
        let (custom, custom_errors) = waf_cfg
            .map(|cfg| {
                crate::waf_custom::CustomLayers::build(
                    &cfg.virtual_patches,
                    &cfg.openapi_spec,
                    &cfg.api_operations,
                )
            })
            .unwrap_or_default();
        for error in &custom_errors {
            warn!(
                site_id = %site_rules.site_id,
                error,
                "custom WAF layer failed to compile; layer disabled"
            );
        }
        let rate_limits = RateLimitPolicy::build(site_rules);
        let basic_auth = site_rules
            .basic_auth
            .as_ref()
            .and_then(BasicAuthGate::build);
        if basic_auth.is_none() && access_rules_require_basic_auth(site_rules) {
            warn!(
                site_id = %site_rules.site_id,
                "access rule requires basic auth but the site has no usable credentials; matching requests are refused"
            );
        }
        Self {
            engine: waf_cfg
                .filter(|cfg| cfg.enabled)
                .map(|cfg| Arc::new(build_site_engine(cfg))),
            policy: AccessPolicy::build(site_rules),
            bot: site_rules
                .bot_protection
                .as_ref()
                .filter(|cfg| cfg.enabled)
                .map(BotPolicy::build),
            rate_limits: (!rate_limits.rules.is_empty()).then_some(rate_limits),
            mtls: MtlsPolicy::build(site_rules.ssl_config.as_ref()),
            basic_auth,
            rule_names: waf_cfg
                .map(|cfg| {
                    cfg.custom_rules
                        .iter()
                        .map(|r| (r.id.clone(), r.name.clone()))
                        .collect()
                })
                .unwrap_or_default(),
            observation_mode: site_rules.observation_mode,
            inspect_body: waf_cfg
                .filter(|cfg| cfg.enabled)
                .is_some_and(|cfg| cfg.advanced_mode),
            engine_mode: waf_cfg
                .map(|cfg| cfg.engine_mode.clone())
                .unwrap_or_default(),
            mode: waf_cfg.map(site_mode),
            monitor_categories: waf_cfg
                .map(|cfg| cfg.monitor_categories.clone())
                .unwrap_or_default(),
            path_target_exclusions: waf_cfg
                .map(|cfg| cfg.path_target_exclusions.clone())
                .unwrap_or_default(),
            custom,
        }
    }

    /// Resolves the engine choice for the rules this context was built from.
    fn choice(&self, site_rules: &CacheSiteRules) -> EngineChoice {
        match site_rules.waf_config.as_ref() {
            Some(cfg) if cfg.enabled => {
                self.engine.as_ref().map_or(EngineChoice::Base, |engine| {
                    EngineChoice::Site(Arc::clone(engine))
                })
            },
            Some(_) => EngineChoice::Disabled,
            None => EngineChoice::Base,
        }
    }
}

/// A cached per-domain context plus the fingerprint it was built from.
struct CachedSite {
    /// Per-site bundle fingerprint the context was built from. Keying on the
    /// site's own hash (not the agent's global first-site hash) is what makes
    /// a rule or mode change invalidate this context.
    fingerprint: String,
    context: Arc<SiteContext>,
}

/// Everything resolved for one request target.
struct ResolvedSite {
    choice: EngineChoice,
    site_id: String,
    /// Read from the live rule cache, not the compiled context: a status
    /// change is not part of the bundle fingerprint, so caching it would let
    /// a paused site keep serving until the process restarts.
    paused: bool,
    context: Option<Arc<SiteContext>>,
}

mod access;
pub(crate) use access::*;

mod bot;
pub(crate) use bot::*;

mod rate_limit;
pub(crate) use rate_limit::*;

mod inspect;
mod request;
mod request_body;
mod state;
pub(crate) use state::*;
pub use state::{PENDING_ACCESS_SWEEP_TTL, sweep_stale_access};

/// Web Application Firewall plugin.
struct WafPlugin {
    plugin_step: PluginStep,
    /// Locally configured engine; shared and hot-reloadable.
    engine: Arc<RwLock<WafEngine>>,
    mode: WafMode,
    /// Inspect the full request body with the WAF engine. Off by default:
    /// scanning arbitrary bodies is expensive. Independent of this flag the
    /// first KiB of every body is captured for the access log.
    inspect_body: bool,
    max_body_size: usize,
    /// `body_policy = "reject"`: refuse bodies above `max_body_size` (413)
    /// instead of inspecting a prefix and forwarding the rest.
    body_reject: bool,
    /// Deadline for reading the whole request body while inspecting or
    /// logging it; a slow or trickling upload is refused with 408. 0 disables
    /// the deadline.
    body_read_timeout_ms: u64,
    /// `tail_inspection = false` disables the sliding-window scan of body
    /// chunks the early read pass did not consume.
    tail_inspection: bool,
    /// `ws_inspection = false` disables WebSocket frame inspection on
    /// upgraded connections.
    ws_inspection: bool,
    /// Proof-of-work difficulty used when delegating a `Challenge` verdict.
    pow_difficulty: u32,
    hash_value: String,
    /// Per-domain engines built from agent rules, keyed by host.
    site_contexts: DashMap<String, CachedSite>,
    /// Rate limit counters, keyed by rule id and characteristic values. Kept
    /// on the plugin so they survive per-site context rebuilds.
    rate_counters: DashMap<String, RateCounter>,
    /// Failed-authentication streak tracker (Phase 8 ATO defense).
    ato: Arc<FailedAuthTracker>,
}

impl WafPlugin {
    /// Create a new plugin from configuration.
    pub fn new(params: &PluginConf) -> Result<Self> {
        debug!(params = params.to_string(), "new waf plugin");
        // Load the embedded GeoIP database here rather than on the first
        // request: the lookup is on the request path and its parse is not.
        LazyLock::force(&GEO_DB);
        Self::try_from(params)
    }

    /// Resolve the site data for `host`, consulting the agent rule cache when
    /// available and caching compiled contexts per domain.
    fn resolve_site(&self, host: &str) -> ResolvedSite {
        let fallback = |site_id: String| ResolvedSite {
            choice: EngineChoice::Base,
            site_id,
            paused: false,
            context: None,
        };
        let Some(agent) = VarmanAgent::instance() else {
            return fallback(host.to_string());
        };
        if host.is_empty() {
            return fallback(String::new());
        }
        let Some(site_rules) = agent.get_rules_for_domain(host) else {
            return fallback(host.to_string());
        };

        // Prefer the site's own bundle fingerprint. The agent-level hash is
        // the first site's bundle hash and stays put when another site
        // changes, which would leave this domain pinned to an old context.
        let global_hash = agent.config_hash();
        let fingerprint = if site_rules.config_hash.is_empty() {
            global_hash.as_ref()
        } else {
            site_rules.config_hash.as_str()
        };
        let cached = self.site_contexts.get(host).and_then(|cached| {
            (cached.fingerprint.as_str() == fingerprint)
                .then(|| Arc::clone(&cached.context))
        });
        let context = match cached {
            Some(context) => context,
            None => {
                let context = Arc::new(SiteContext::build(&site_rules));
                self.site_contexts.insert(
                    host.to_string(),
                    CachedSite {
                        fingerprint: fingerprint.to_string(),
                        context: Arc::clone(&context),
                    },
                );
                context
            },
        };

        let choice = context.choice(&site_rules);
        ResolvedSite {
            choice,
            site_id: site_rules.site_id.clone(),
            paused: site_rules.is_paused(),
            context: Some(context),
        }
    }

    /// Ship a security event to the control plane (best effort, non-blocking).
    fn log_event(
        site_id: &str,
        request_id: &str,
        host: &str,
        request_data: &RequestData,
        verdict: &WafVerdict,
        rule_name: &str,
    ) {
        let Some(agent) = VarmanAgent::instance() else {
            return;
        };
        let blocked =
            matches!(verdict.action, WafAction::Block | WafAction::Challenge);
        agent.record_request(blocked);
        let user_agent = request_data
            .headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case("user-agent"))
            .map(|(_, v)| v.clone())
            .unwrap_or_default();
        let response_status = match verdict.action {
            WafAction::Block => 403,
            WafAction::Challenge => 503,
            _ => 0,
        };
        agent.log_security_event(SecurityEvent {
            site_id: site_id.to_string(),
            request_id: request_id.to_string(),
            client_ip: request_data.client_ip.clone(),
            method: request_data.method.clone(),
            scheme: request_data.scheme.clone(),
            protocol: request_data.protocol.clone(),
            host: host.to_string(),
            path: request_data.path.clone(),
            query_string: request_data.query.clone(),
            rule_id: verdict.matched_rules.first().cloned().unwrap_or_default(),
            rule_name: rule_name.to_string(),
            event_type: "waf".to_string(),
            action: action_str(&verdict.action).to_string(),
            score: verdict.score as u32,
            details: verdict.details.clone(),
            response_status,
            user_agent,
            country_code: request_data.country_code.clone().unwrap_or_default(),
            matched_tags: verdict.matched_rules.clone(),
        });
    }

    /// Records an access restriction (IP/geo rule, bot or rate limit) that
    /// observation mode refused to enforce. The security event is written as a
    /// `monitor` verdict — nothing was actually blocked or challenged — while
    /// the server log names what enforcement would have done.
    #[allow(clippy::too_many_arguments)]
    fn log_observed(
        site_id: &str,
        request_id: &str,
        host: &str,
        request_data: &RequestData,
        would_have: WafAction,
        rule_id: &str,
        detail: &str,
        rule_name: &str,
    ) {
        tracing::info!(
            site_id,
            request_id,
            rule = rule_id,
            would_have = ?would_have,
            "[observation] detection recorded without enforcing"
        );
        let verdict = WafVerdict {
            action: WafAction::Monitor,
            score: 0,
            matched_rules: (!rule_id.is_empty())
                .then(|| rule_id.to_string())
                .into_iter()
                .collect(),
            details: detail.to_string(),
            breakdown: ScoreBreakdown::clean(),
        };
        Self::log_event(
            site_id,
            request_id,
            host,
            request_data,
            &verdict,
            rule_name,
        );
    }

    /// Answers a request stopped by an access restriction: security event,
    /// access log with the real status, then the block page or the challenge.
    #[allow(clippy::too_many_arguments)]
    fn deny_request(
        agent: Option<&Arc<VarmanAgent>>,
        site_id: &str,
        request_id: &str,
        host: &str,
        request_data: &RequestData,
        denial: &Denial,
        original_url: &str,
        pow_difficulty: u32,
    ) -> RequestPluginResult {
        let verdict = WafVerdict {
            action: if denial.challenge {
                WafAction::Challenge
            } else {
                WafAction::Block
            },
            score: 0,
            matched_rules: vec![denial.rule_id.clone()],
            details: denial.detail.clone(),
            breakdown: ScoreBreakdown::clean(),
        };
        Self::log_event(
            site_id,
            request_id,
            host,
            request_data,
            &verdict,
            &denial.rule_name,
        );
        let response = if denial.challenge {
            build_challenge_response(
                request_id,
                original_url,
                site_id,
                pow_difficulty,
                ChallengeKind::Js,
            )
        } else {
            block_page(request_id, &verdict.details)
        };
        emit_generated_access(agent, request_id, &response);
        RequestPluginResult::Respond(response)
    }
}

/// Typed view of the flat keys of `[plugins.<name>]` for the WAF plugin.
///
/// Site- and rule-level configuration comes from the agent, not from here;
/// every key the standalone constructor reads is listed so a misspelling or a
/// wrong TOML type is rejected at `pingap -t`.
#[derive(Debug, Default, serde::Deserialize)]
#[serde(default, deny_unknown_fields)]
struct WafParams {
    mode: String,
    advanced_mode: bool,
    level: String,
    stacks: Vec<String>,
    #[serde(default = "default_paranoia_level")]
    paranoia_level: i64,
    #[serde(default = "default_anomaly_threshold")]
    anomaly_threshold: i64,
    detections: Vec<String>,
    monitor_categories: Vec<String>,
    monitor_stacks: Vec<String>,
    ml_enabled: bool,
    /// Accepted for compatibility with the documented option set. The
    /// detection engine has no ML scorer, so the value is not read — the same
    /// situation as `ml_enabled`, which is reported at construction time.
    #[allow(dead_code)]
    ml_threshold: f64,
    inspect_body: bool,
    #[serde(default = "default_max_body_size")]
    max_body_size: i64,
    body_policy: String,
    #[serde(default = "default_body_read_timeout_ms")]
    body_read_timeout_ms: i64,
    #[serde(default = "default_true")]
    tail_inspection: bool,
    #[serde(default = "default_true")]
    ws_inspection: bool,
    #[serde(default = "default_waf_pow_difficulty")]
    pow_difficulty: i64,
    #[serde(default = "default_ato_failed_auth_threshold")]
    ato_failed_auth_threshold: i64,
    #[serde(default = "default_ato_window_secs")]
    ato_window_secs: i64,
    #[serde(default = "default_ato_block_secs")]
    ato_block_secs: i64,
}

fn default_paranoia_level() -> i64 {
    2
}

fn default_anomaly_threshold() -> i64 {
    40
}

fn default_max_body_size() -> i64 {
    64 * 1024
}

fn default_body_read_timeout_ms() -> i64 {
    10_000
}

fn default_true() -> bool {
    true
}

fn default_waf_pow_difficulty() -> i64 {
    20
}

fn default_ato_failed_auth_threshold() -> i64 {
    20
}

fn default_ato_window_secs() -> i64 {
    300
}

fn default_ato_block_secs() -> i64 {
    300
}

impl TryFrom<&PluginConf> for WafPlugin {
    type Error = Error;

    fn try_from(value: &PluginConf) -> Result<Self> {
        let hash_value = get_hash_key(value);
        let category = PluginCategory::Waf.to_string();
        let params: WafParams = parse_params(value, "waf")?;

        let mode = parse_mode(&params.mode);
        let advanced_mode = params.advanced_mode;
        let level = if advanced_mode {
            WafLevel::Strict
        } else {
            WafLevel::parse(&params.level).unwrap_or_default()
        };
        let stack_names = params.stacks;
        let stacks = if stack_names.is_empty() {
            StackSet::default()
        } else {
            StackSet::from_names(stack_names.iter().map(String::as_str))
        };
        let paranoia_level = (params.paranoia_level as u8).clamp(1, 4);
        let anomaly_threshold = params.anomaly_threshold as u32;
        let detections = params.detections;
        let mut monitor_categories =
            parse_monitor_categories(&params.monitor_categories);
        // `detections` is a whitelist of attack families allowed to block. The
        // engine cannot disable detection per family, so the faithful
        // semantic is a monitor downgrade for every family *not* listed:
        // detection keeps running (events, telemetry) but only the listed
        // families can block. An absent/empty list changes nothing; unknown
        // names are dropped with a warning (observable, never silent).
        if !detections.is_empty() {
            let mut allowed = CategorySet::EMPTY;
            for name in &detections {
                match CategorySet::parse_name(name) {
                    Some(flag) => allowed = allowed.union(flag),
                    None => warn!(
                        detection = %name,
                        "unknown detection family in the WAF plugin config; \
                         ignored (allowed: sqli, xss, rce, lfi, ssrf, deser, \
                         crlf, xxe, ssti)"
                    ),
                }
            }
            monitor_categories =
                monitor_categories.union(CategorySet::ALL.difference(allowed));
        }
        let monitor_stacks = parse_monitor_stacks(&params.monitor_stacks);
        let ml_enabled = params.ml_enabled;
        if ml_enabled {
            // The engine has no ML scorer; the flag is accepted for
            // configuration compatibility and reported instead of silently
            // doing nothing.
            warn!(
                "ml_enabled is not implemented by the detection engine; the \
                 flag has no effect"
            );
        }
        let inspect_body = advanced_mode || params.inspect_body;
        let configured_body_size = params.max_body_size as usize;
        // Pingora's retry buffer caps replay at 64 KiB: bytes read past that
        // would never reach the upstream, so the inspection window is clamped
        // to the same limit.
        const RETRY_BUFFER_LIMIT: usize = 64 * 1024;
        let max_body_size = configured_body_size.min(RETRY_BUFFER_LIMIT);
        if configured_body_size > RETRY_BUFFER_LIMIT {
            tracing::warn!(
                configured = configured_body_size,
                clamped = max_body_size,
                "max_body_size exceeds the 64 KiB replay limit; clamped"
            );
        }
        // Phase 5 size policy: `process_partial` (default) inspects the head
        // window and forwards the rest; `reject` answers 413 once a body
        // exceeds `max_body_size` instead of inspecting a prefix.
        let body_reject = params.body_policy.eq_ignore_ascii_case("reject");
        // Slow-upload defense: the body read pass gets a total deadline, so a
        // trickling client cannot hold the connection open byte by byte.
        let body_read_timeout_ms = params.body_read_timeout_ms.max(0) as u64;
        // Stream inspection: body tails beyond the early read pass and
        // WebSocket frames on upgraded connections (both default on).
        let tail_inspection = params.tail_inspection;
        let ws_inspection = params.ws_inspection;
        let pow_difficulty = params.pow_difficulty as u32;
        // ATO: repeated upstream authentication failures on state-changing
        // requests from one client block that client for a while. 0 disables.
        let ato = Arc::new(FailedAuthTracker::new(
            params.ato_failed_auth_threshold as u32,
            params.ato_window_secs as u64,
            params.ato_block_secs as u64,
        ));

        let plugin_step = match super::get_step_conf_in(
            value,
            "waf",
            PluginStep::EarlyRequest,
            &[PluginStep::EarlyRequest, PluginStep::Request],
        ) {
            Ok(step) => step,
            Err(e) => {
                return Err(Error::Invalid {
                    category,
                    message: e.to_string(),
                });
            },
        };

        // `WafEngineConfig::default` owns every value the plugin does not
        // deliberately override: three decode layers, managed rules and
        // fast-path blocking on, no monitor/disable/score/exclusion sets.
        let engine_config = WafEngineConfig {
            mode,
            level,
            stacks,
            threshold: anomaly_threshold,
            paranoia_level,
            monitor_categories,
            monitor_stacks,
            ..Default::default()
        };

        Ok(Self {
            plugin_step,
            engine: Arc::new(RwLock::new(WafEngine::new(&engine_config))),
            mode,
            inspect_body,
            max_body_size,
            body_reject,
            body_read_timeout_ms,
            tail_inspection,
            ws_inspection,
            pow_difficulty,
            hash_value,
            site_contexts: DashMap::new(),
            rate_counters: DashMap::new(),
            ato,
        })
    }
}

#[async_trait]
impl Plugin for WafPlugin {
    #[inline]
    fn config_key(&self) -> Cow<'_, str> {
        Cow::Borrowed(&self.hash_value)
    }

    async fn handle_request(
        &self,
        step: PluginStep,
        session: &mut Session,
        ctx: &mut Ctx,
    ) -> pingora::Result<RequestPluginResult> {
        if step != self.plugin_step {
            return Ok(RequestPluginResult::Skipped);
        }
        let mut state = self.begin_request(session, ctx);
        if let Some(result) = self.check_ato(&state) {
            return Ok(result);
        }
        if let Some(result) =
            self.capture_body(session, ctx, &mut state).await?
        {
            return Ok(result);
        }
        if let Some(result) = self.check_paused(&state) {
            return Ok(result);
        }
        if let Some(result) = self.check_ip_block(&state) {
            return Ok(result);
        }
        if let Some(result) = self.check_mtls(&state, ctx) {
            return Ok(result);
        }
        if let Some(result) = self.check_access(&mut state) {
            return Ok(result);
        }
        if let Some(result) = self.check_basic_auth(session, &mut state).await {
            return Ok(result);
        }
        if let Some(result) = self.check_bot(session, &state).await {
            return Ok(result);
        }
        if let Some(result) = self.check_rate_limit(&state) {
            return Ok(result);
        }
        if let Some(result) = self.select_engine(&state) {
            return Ok(result);
        }
        let verdict = self.inspect_request(&mut state).await;
        Ok(self.finalize_response(&state, verdict))
    }

    async fn handle_response(
        &self,
        _session: &mut Session,
        ctx: &mut Ctx,
        upstream_response: &mut ResponseHeader,
    ) -> pingora::Result<ResponsePluginResult> {
        let Some(request_id) = ctx.state.request_id.clone() else {
            return Ok(ResponsePluginResult::Unchanged);
        };
        // Without an agent nothing was registered at request time.
        let Some(agent) = VarmanAgent::instance() else {
            return Ok(ResponsePluginResult::Unchanged);
        };
        let status = upstream_response.status.as_u16();
        // A 101 WebSocket upgrade turns the connection into a frame stream;
        // record it so the stream hooks decode frames instead of skipping
        // the tunnel.
        if status == 101 {
            let websocket = PENDING_ACCESS
                .get(&request_id)
                .map(|entry| {
                    entry.request_headers.iter().any(|(name, value)| {
                        name.eq_ignore_ascii_case("upgrade")
                            && value.to_ascii_lowercase().contains("websocket")
                    })
                })
                .unwrap_or(false);
            if websocket {
                // Snapshot the request identity: the access log consumes the
                // pending entry when the 101 completes, but aborts inside the
                // tunnel still need it for their security event.
                let facts = PENDING_ACCESS
                    .get(&request_id)
                    .map(|entry| StreamFacts {
                        site_id: entry.site_id.clone(),
                        client_ip: entry.client_ip.clone(),
                        method: entry.method.clone(),
                        scheme: entry.scheme.clone(),
                        protocol: entry.protocol.clone(),
                        host: entry.host.clone(),
                        path: entry.path.clone(),
                        query: entry.query.clone(),
                        user_agent: entry.user_agent.clone(),
                        country_code: entry.country_code.clone(),
                    })
                    .unwrap_or_default();
                let policy =
                    Arc::new(self.stream_policy(&facts.host, &facts.path));
                with_stream(&request_id, |state| {
                    state.websocket = true;
                    state.policy = Some(policy);
                    state.facts = facts;
                });
            }
        }
        let upstream_latency_ms =
            ctx.timing.upstream_processing.unwrap_or(0).max(0) as u64;
        let headers = cap_headers(upstream_response.headers.iter().filter_map(
            |(name, value)| {
                value
                    .to_str()
                    .ok()
                    .map(|value| (name.as_str().to_string(), value))
            },
        ));

        // Hold the entry back for body capture when the payload is worth
        // keeping; otherwise the entry is complete now.
        {
            let Some(mut entry) = PENDING_ACCESS.get_mut(&request_id) else {
                return Ok(ResponsePluginResult::Unchanged);
            };
            // ── ATO: upstream authentication failures on state-changing
            // requests feed the failed-auth streak tracker. Credential
            // submissions are state-changing; expired-token polling is not,
            // so ordinary SPAs cannot trip it. ──
            if matches!(status, 401 | 403)
                && is_state_changing(&entry.method)
                && self.ato.enabled()
                && !entry.site_id.is_empty()
            {
                let key = format!("{}|{}", entry.site_id, entry.client_ip);
                self.ato.record_failure(&key);
            }
            if entry.body_limit > 0
                && should_capture_response_body(
                    &entry.method,
                    status,
                    upstream_response,
                )
            {
                entry.response = Some(ResponseFacts {
                    status_code: status as u32,
                    upstream_addr: ctx.upstream.address.clone(),
                    upstream_latency_ms,
                    headers,
                    body: None,
                    body_size: 0,
                    abandoned: false,
                });
                return Ok(ResponsePluginResult::Unchanged);
            }
        }
        let Some((_, pending)) = PENDING_ACCESS.remove(&request_id) else {
            return Ok(ResponsePluginResult::Unchanged);
        };
        emit_access(
            &agent,
            &request_id,
            pending,
            ResponseFacts {
                status_code: status as u32,
                upstream_addr: ctx.upstream.address.clone(),
                upstream_latency_ms,
                headers,
                body: None,
                body_size: announced_body_size(upstream_response),
                abandoned: false,
            },
        );
        Ok(ResponsePluginResult::Unchanged)
    }

    fn handle_response_body(
        &self,
        _session: &mut Session,
        ctx: &mut Ctx,
        body: &mut Option<bytes::Bytes>,
        end_of_stream: bool,
    ) -> pingora::Result<ResponseBodyPluginResult> {
        let Some(request_id) = ctx.state.request_id.clone() else {
            return Ok(ResponseBodyPluginResult::Unchanged);
        };
        if end_of_stream {
            // The response is complete: take the entry and ship it.
            let Some((_, mut pending)) = PENDING_ACCESS.remove(&request_id)
            else {
                return Ok(ResponseBodyPluginResult::Unchanged);
            };
            let Some(agent) = VarmanAgent::instance() else {
                return Ok(ResponseBodyPluginResult::Unchanged);
            };
            let Some(mut facts) = pending.response.take() else {
                return Ok(ResponseBodyPluginResult::Unchanged);
            };
            let limit = pending.body_limit;
            if let Some(chunk) = body.as_ref() {
                facts.absorb(chunk, limit);
            }
            emit_access(&agent, &request_id, pending, facts);
            return Ok(ResponseBodyPluginResult::Unchanged);
        }
        let Some(mut entry) = PENDING_ACCESS.get_mut(&request_id) else {
            return Ok(ResponseBodyPluginResult::Unchanged);
        };
        let limit = entry.body_limit;
        let Some(facts) = entry.response.as_mut() else {
            return Ok(ResponseBodyPluginResult::Unchanged);
        };
        if let Some(chunk) = body.as_ref() {
            facts.absorb(chunk, limit);
        }
        Ok(ResponseBodyPluginResult::Unchanged)
    }

    /// Read-only inspection of forwarded request-body chunks: body tails
    /// beyond the early read pass, and client-to-server frames once the
    /// connection was upgraded. The body is never modified; a tail finding
    /// answers the request with the standard block page (the server writes it
    /// and aborts the upstream exchange), while a tunnel finding aborts the
    /// connection with an error because no HTTP response is possible there.
    fn handle_request_body(
        &self,
        session: &mut Session,
        ctx: &mut Ctx,
        body: &mut Option<Bytes>,
        end_of_stream: bool,
    ) -> pingora::Result<Option<HttpResponse>> {
        let Some(request_id) = ctx.state.request_id.clone() else {
            return Ok(None);
        };
        let Some(bytes) = body.as_ref() else {
            if end_of_stream {
                STREAMS.remove(&request_id);
            }
            return Ok(None);
        };
        if session.was_upgraded() {
            if !self.ws_inspection {
                return Ok(None);
            }
            return self
                .inspect_tunnel(&request_id, true, bytes, end_of_stream)
                .map(|()| None);
        }
        // Staged remainder: withhold chunks up to the cap, scan them before
        // the upstream sees a byte, then let the rest through. Past the cap
        // the tail scan below takes over as before.
        if let Some(mut entry) = DEFERRED_BODY.remove(&request_id).map(|e| e.1)
        {
            if !end_of_stream {
                match stage_chunk(
                    self.max_body_size,
                    &mut entry.passthrough,
                    &mut entry.buffer,
                    Some(bytes),
                ) {
                    StageAction::Withhold => {
                        // An empty chunk: pingora skips it entirely, so the
                        // upstream stays byte-silent and keeps its
                        // end-of-body state. Never `None` - that would
                        // truncate the upstream request.
                        *body = Some(Bytes::new());
                        DEFERRED_BODY.insert(request_id, entry);
                        return Ok(None);
                    },
                    StageAction::Flush(staged) => {
                        // The cap was hit mid-body: scan what is staged
                        // (prefix plus this chunk) once, while the upstream
                        // still has no body byte; the rest then flows
                        // through untouched.
                        if let Some(response) =
                            self.inspect_tail(&request_id, &staged)
                        {
                            return Ok(Some(response));
                        }
                        *body = Some(staged);
                        return Ok(None);
                    },
                    StageAction::PassThrough => {
                        DEFERRED_BODY.insert(request_id.clone(), entry);
                    },
                }
            } else if !entry.passthrough {
                // Completion: scan the staged remainder, then hand it over
                // with the end-of-body flag.
                entry.buffer.extend_from_slice(bytes);
                let staged = std::mem::take(&mut entry.buffer).freeze();
                if let Some(response) = self.inspect_tail(&request_id, &staged)
                {
                    return Ok(Some(response));
                }
                *body = Some(staged);
                return Ok(None);
            }
        }
        if !self.tail_inspection {
            return Ok(None);
        }
        Ok(self.inspect_tail(&request_id, bytes))
    }

    /// Read-only inspection of upgraded traffic flowing from the upstream to
    /// the client (server-to-client WebSocket frames). An error closes the
    /// connection.
    fn handle_upgraded_body(
        &self,
        _session: &mut Session,
        ctx: &mut Ctx,
        body: &Option<Bytes>,
        end_of_stream: bool,
    ) -> pingora::Result<()> {
        if !self.ws_inspection {
            return Ok(());
        }
        let Some(request_id) = ctx.state.request_id.clone() else {
            return Ok(());
        };
        let Some(bytes) = body.as_ref() else {
            if end_of_stream {
                STREAMS.remove(&request_id);
            }
            return Ok(());
        };
        self.inspect_tunnel(&request_id, false, bytes, end_of_stream)
    }
}

impl WafPlugin {
    /// Enforcement policy for one stream.
    ///
    /// Resolved from the same [`ResolvedSite`] the request path uses, so a
    /// disabled WAF ([`EngineChoice::Disabled`]), observation mode, a
    /// non-Block site mode and a non-Varman engine all keep the stream in
    /// monitor-only mode. The engine goes through
    /// [`crate::waf_shadow::resolve_mode`], so the aliases (`enforce`,
    /// `observe`, `base`) and the invalid-value fallback match the request
    /// path exactly.
    fn stream_policy(&self, host: &str, path: &str) -> StreamPolicy {
        let resolved = self.resolve_site(host);
        let Some(context) = resolved.context else {
            // No site context at all: a standalone plugin follows its own
            // mode. In an agent deployment this instead means the domain's
            // bundle has not arrived yet, and enforcing then is how a
            // monitor site gets blocked after a restart.
            return StreamPolicy {
                enforce: VarmanAgent::instance().is_none()
                    && self.mode == WafMode::Block,
                path: path.to_string(),
                ..Default::default()
            };
        };
        let enforce = !matches!(resolved.choice, EngineChoice::Disabled)
            && context.mode == Some(WafMode::Block)
            && !context.observation_mode
            && crate::waf_shadow::resolve_mode(Some(&context.engine_mode))
                == crate::waf_shadow::EngineMode::Varman;
        StreamPolicy {
            enforce,
            monitored: context.monitor_categories.clone(),
            excluded_rules: stream_excluded_rules(
                path,
                &context.path_target_exclusions,
            ),
            path: path.to_string(),
        }
    }

    /// Sliding-window scan of a forwarded body chunk. A payload found here
    /// returns the standard block page only when the finding is enforcing;
    /// a monitor/log finding is recorded and the body continues.
    fn inspect_tail(
        &self,
        request_id: &str,
        bytes: &Bytes,
    ) -> Option<HttpResponse> {
        let (finding, policy) = with_stream(request_id, |state| {
            if state.aborted {
                return (None, state.policy.clone());
            }
            let policy = match state.policy.clone() {
                Some(policy) => policy,
                None => {
                    // Only the first chunk pays for the site lookup; the
                    // resolved policy serves every later chunk.
                    let (host, path) = PENDING_ACCESS
                        .get(request_id)
                        .map(|entry| (entry.host.clone(), entry.path.clone()))
                        .unwrap_or_default();
                    let policy = Arc::new(self.stream_policy(&host, &path));
                    state.policy = Some(Arc::clone(&policy));
                    policy
                },
            };
            (state.tail.push(bytes, &policy.monitored), Some(policy))
        });
        let finding = finding?;
        let policy = policy?;
        let (rule_id, detail, _, _) = finding.parts();
        if self.record_stream_finding(request_id, &finding, &policy) {
            Some(block_page(
                request_id,
                &format!("varman: {rule_id}: {detail}"),
            ))
        } else {
            None
        }
    }

    /// Frame inspection of an upgraded connection, one direction per call.
    /// A finding aborts the connection with an error: no HTTP response is
    /// possible once the tunnel is open.
    fn inspect_tunnel(
        &self,
        request_id: &str,
        from_client: bool,
        bytes: &Bytes,
        end_of_stream: bool,
    ) -> pingora::Result<()> {
        let (finding, policy) = with_stream(request_id, |state| {
            if !state.websocket || state.aborted {
                return (None, state.policy.clone());
            }
            let policy = match state.policy.clone() {
                Some(policy) => policy,
                None => return (None, None),
            };
            (
                state
                    .inspector
                    .inspect(from_client, bytes, &policy.monitored),
                Some(policy),
            )
        });
        if let (Some(finding), Some(policy)) = (finding, policy) {
            let (rule_id, detail, _, _) = finding.parts();
            if self.record_stream_finding(request_id, &finding, &policy) {
                return Err(new_internal_error(
                    403,
                    format!("varman: {rule_id}: {detail}"),
                ));
            }
        }
        if end_of_stream {
            STREAMS.remove(request_id);
        }
        Ok(())
    }

    /// Record a stream finding. Only a `Block`/`Challenge` finding on an
    /// enforcing site closes the stream; a `Log`/`Monitor` finding (or any
    /// finding on a monitor/legacy site) is a monitor event and the stream
    /// continues. Returns whether the caller must abort.
    ///
    /// A path-scoped body exclusion drops the rule before it is recorded or
    /// enforced. A protocol failure is the exception to the mode cap: after
    /// a malformed frame the boundaries are unknown, so the stream cannot be
    /// inspected any further and is closed even in monitor mode. One finding
    /// per rule is recorded per connection; a monitor site otherwise writes
    /// a row for every matching message.
    fn record_stream_finding(
        &self,
        request_id: &str,
        finding: &StreamFinding,
        policy: &StreamPolicy,
    ) -> bool {
        let (rule_id, detail, action, score) = finding.parts();
        let protocol = matches!(finding, StreamFinding::Protocol(_));
        if !protocol && policy.excluded_rules.contains(rule_id.as_str()) {
            tracing::debug!(
                rule_id,
                path = %policy.path,
                "stream finding dropped by a path-scoped body exclusion"
            );
            return false;
        }
        let blocking = protocol
            || (policy.enforce
                && matches!(action, Action::Block | Action::Challenge));
        let (facts, first) = with_stream(request_id, |state| {
            let first = state.reported.insert(rule_id.clone());
            if blocking {
                state.aborted = true;
            }
            (state.facts.clone(), first)
        });
        if !blocking && !first {
            // This rule is already on the connection's record. Do not write
            // one event per matching message.
            return false;
        }
        if blocking {
            tracing::warn!(
                rule_id,
                detail,
                score,
                "stream inspection aborted the connection"
            );
        } else {
            tracing::info!(
                rule_id,
                detail,
                score,
                "stream inspection recorded a monitor-only finding"
            );
        }
        if let Some(agent) = VarmanAgent::instance() {
            let from_pending =
                PENDING_ACCESS.get(request_id).map(|entry| StreamFacts {
                    site_id: entry.site_id.clone(),
                    client_ip: entry.client_ip.clone(),
                    method: entry.method.clone(),
                    scheme: entry.scheme.clone(),
                    protocol: entry.protocol.clone(),
                    host: entry.host.clone(),
                    path: entry.path.clone(),
                    query: entry.query.clone(),
                    user_agent: entry.user_agent.clone(),
                    country_code: entry.country_code.clone(),
                });
            let facts = from_pending.unwrap_or(facts);
            // The request itself is already counted by the access-log path.
            // Only a blocked stream adds to the blocked counter; counting a
            // monitor finding inflated requests_total once per message.
            if blocking {
                agent.record_request(true);
            }
            agent.log_security_event(SecurityEvent {
                site_id: facts.site_id,
                request_id: request_id.to_string(),
                client_ip: facts.client_ip,
                method: facts.method,
                scheme: facts.scheme,
                protocol: facts.protocol,
                host: facts.host,
                path: facts.path,
                query_string: facts.query,
                matched_tags: vec![rule_id.clone()],
                rule_id,
                rule_name: "stream-inspection".to_string(),
                event_type: "waf".to_string(),
                action: if blocking { "block" } else { "monitor" }.to_string(),
                score,
                details: detail,
                response_status: if blocking { 403 } else { 0 },
                user_agent: facts.user_agent,
                country_code: facts.country_code,
            });
        }
        if blocking {
            STREAMS.remove(request_id);
        }
        blocking
    }
}

register_plugin!("waf", WafPlugin);

#[cfg(test)]
pub(crate) mod tests;
