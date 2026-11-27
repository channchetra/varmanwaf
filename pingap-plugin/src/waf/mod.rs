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

use super::{
    Error, get_bool_conf, get_hash_key, get_int_conf_or_default, get_str_conf,
    get_str_slice_conf,
};
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
    fn denial(&self, ctx: &Ctx) -> Option<&'static str> {
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

impl TryFrom<&PluginConf> for WafPlugin {
    type Error = Error;

    fn try_from(value: &PluginConf) -> Result<Self> {
        let hash_value = get_hash_key(value);
        let category = PluginCategory::Waf.to_string();

        let mode = parse_mode(&get_str_conf(value, "mode"));
        let advanced_mode = get_bool_conf(value, "advanced_mode");
        let level = if advanced_mode {
            WafLevel::Strict
        } else {
            WafLevel::parse(&get_str_conf(value, "level")).unwrap_or_default()
        };
        let stack_names = get_str_slice_conf(value, "stacks");
        let stacks = if stack_names.is_empty() {
            StackSet::default()
        } else {
            StackSet::from_names(stack_names.iter().map(String::as_str))
        };
        let paranoia_level =
            (get_int_conf_or_default(value, "paranoia_level", 2) as u8)
                .clamp(1, 4);
        let anomaly_threshold =
            get_int_conf_or_default(value, "anomaly_threshold", 40) as u32;
        let detections = get_str_slice_conf(value, "detections");
        let mut monitor_categories = parse_monitor_categories(
            &get_str_slice_conf(value, "monitor_categories"),
        );
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
        let monitor_stacks =
            parse_monitor_stacks(&get_str_slice_conf(value, "monitor_stacks"));
        let ml_enabled = get_bool_conf(value, "ml_enabled");
        if ml_enabled {
            // The engine has no ML scorer; the flag is accepted for
            // configuration compatibility and reported instead of silently
            // doing nothing.
            warn!(
                "ml_enabled is not implemented by the detection engine; the \
                 flag has no effect"
            );
        }
        let inspect_body =
            advanced_mode || get_bool_conf(value, "inspect_body");
        let configured_body_size =
            get_int_conf_or_default(value, "max_body_size", 64 * 1024) as usize;
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
        let body_reject =
            get_str_conf(value, "body_policy").eq_ignore_ascii_case("reject");
        // Slow-upload defense: the body read pass gets a total deadline, so a
        // trickling client cannot hold the connection open byte by byte.
        let body_read_timeout_ms =
            get_int_conf_or_default(value, "body_read_timeout_ms", 10_000)
                .max(0) as u64;
        // Stream inspection: body tails beyond the early read pass and
        // WebSocket frames on upgraded connections (both default on).
        let tail_inspection = value
            .get("tail_inspection")
            .and_then(|item| item.as_bool())
            .unwrap_or(true);
        let ws_inspection = value
            .get("ws_inspection")
            .and_then(|item| item.as_bool())
            .unwrap_or(true);
        let pow_difficulty =
            get_int_conf_or_default(value, "pow_difficulty", 20) as u32;
        // ATO: repeated upstream authentication failures on state-changing
        // requests from one client block that client for a while. 0 disables.
        let ato = Arc::new(FailedAuthTracker::new(
            get_int_conf_or_default(value, "ato_failed_auth_threshold", 20)
                as u32,
            get_int_conf_or_default(value, "ato_window_secs", 300) as u64,
            get_int_conf_or_default(value, "ato_block_secs", 300) as u64,
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

        // ── Extract immutable request facts (all borrowed data is cloned) ──
        let req_header = session.req_header();
        let method = req_header.method.as_str().to_string();
        let path = req_header.uri.path().to_string();
        let query = req_header.uri.query().unwrap_or_default().to_string();
        let mut headers: Vec<(String, String)> = Vec::new();
        let mut user_agent = String::new();
        let mut referer = String::new();
        for (name, value) in req_header.headers.iter() {
            let Ok(v) = value.to_str() else {
                continue;
            };
            match name.as_str() {
                "user-agent" => user_agent = v.to_string(),
                "referer" => referer = v.to_string(),
                _ => {},
            }
            headers.push((name.as_str().to_string(), v.to_string()));
        }
        let host = get_host(req_header).unwrap_or_default().to_string();
        let scheme = if ctx.conn.tls_version.is_some() {
            "https".to_string()
        } else {
            "http".to_string()
        };
        // Matches http::Version's Debug output without the formatting
        // machinery on the hot path.
        let protocol = match req_header.version {
            Version::HTTP_09 => "HTTP/0.9",
            Version::HTTP_10 => "HTTP/1.0",
            Version::HTTP_11 => "HTTP/1.1",
            Version::HTTP_2 => "HTTP/2.0",
            Version::HTTP_3 => "HTTP/3.0",
            // Hidden `__NonExhaustive` variant; never constructible here.
            _ => "HTTP/1.1",
        }
        .to_string();
        let client_ip = ensure_client_ip(session, ctx).to_string();
        let client_addr: Option<IpAddr> = client_ip.parse().ok();

        // Get or create the request id early so the access log, security
        // events and the X-Request-ID header all share one stable value.
        let request_id = match ctx.state.request_id.clone() {
            Some(id) => id,
            None => {
                let id = generate_request_id();
                ctx.state.request_id = Some(id.clone());
                let _ = session
                    .req_header_mut()
                    .insert_header(&HTTP_HEADER_NAME_X_REQUEST_ID, &id);
                id
            },
        };

        // ── Resolve the engine and access restrictions for this domain ──
        let resolved = self.resolve_site(&host);
        let site_id = resolved.site_id.clone();
        let paused = resolved.paused;
        let context = resolved.context.clone();
        let choice = resolved.choice;
        // Observation mode: detections keep running but nothing is enforced.
        // Access control (mTLS, basic auth, a paused site) is never downgraded.
        let observe =
            context.as_ref().is_some_and(|site| site.observation_mode);

        // Country of the client: it feeds geo restrictions, the
        // `ip.src.country` rule variable and the flag shown with the access
        // log, so it is only resolved when an agent consumes those facts.
        let agent = VarmanAgent::instance();
        let country = if agent.is_some() {
            client_addr.and_then(lookup_country_addr)
        } else {
            None
        };

        // ── ATO: a client serving out a failed-authentication block is
        // refused before any further work happens. ──
        if self.ato.enabled() && !site_id.is_empty() {
            let key = format!("{site_id}|{client_ip}");
            if self.ato.is_blocked(&key) {
                let retry = self.ato.retry_after_secs(&key).unwrap_or(0);
                tracing::info!(
                    site_id = %site_id,
                    client_ip = %client_ip,
                    "request refused: failed-authentication streak"
                );
                let mut response = block_page(
                    &request_id,
                    "too many failed authentication attempts; try again later",
                );
                if retry > 0 {
                    response.headers.get_or_insert_with(Vec::new).push((
                        http::header::RETRY_AFTER,
                        http::HeaderValue::from_str(&retry.to_string())
                            .unwrap_or(http::HeaderValue::from_static("60")),
                    ));
                }
                emit_generated_access(agent.as_ref(), &request_id, &response);
                return Ok(RequestPluginResult::Respond(response));
            }
        }

        // ── Full-request log capture: snapshot headers (capped) and keep the
        // configured body prefix. Pingora's retry buffer replays bytes
        // consumed here to the upstream, so reading does not interfere with
        // forwarding. Skipped for the challenge verify endpoint, whose
        // handler consumes the body itself. WAF body inspection reuses the
        // same read pass. ──
        let body_limit = log_body_limit();
        let log_headers = cap_headers(
            headers
                .iter()
                .map(|(name, value)| (name.clone(), value.as_str())),
        );
        let mut log_body_prefix = LogBodyPrefix::new(body_limit);
        let mut inspect_buf = BytesMut::new();
        // Advanced-mode sites ask for body inspection even when the plugin
        // switch is off; the plugin-level switch stays authoritative for the
        // truncation cap.
        let site_inspect_body =
            context.as_ref().is_some_and(|site| site.inspect_body);
        // Per-site custom layers may need the body (OpenAPI JSON-body
        // schemas) even when generic body inspection is off.
        let site_wants_body = context
            .as_ref()
            .and_then(|site| site.custom.as_ref())
            .is_some_and(|custom| custom.wants_body());
        let should_inspect = self.inspect_body || site_inspect_body;
        let capture_body = should_inspect || site_wants_body;
        // Log capture only matters when an agent consumes it; body inspection
        // works standalone - a static deployment blocks POST payloads just
        // the same.
        let mut body_truncated = false;
        // Set when the early read stopped before the end of the body: the
        // remainder is staged (withheld and scanned) by the body filter.
        let mut stage_remainder = false;
        if (agent.is_some() && body_limit > 0 || capture_body)
            && !(method == "POST" && path == VERIFY_ENDPOINT)
        {
            // Reading the body here consumes it from the downstream stream.
            // Pingora only enables its retry buffer after the request filters
            // have run, so without this call the bytes we read are lost: the
            // proxy replays nothing while the upstream waits for the declared
            // Content-Length and the request stalls. Enabling the buffer
            // first makes every byte we read replayable.
            //
            // The replay buffer is exactly 64 KiB and a single read can return
            // a full 64 KiB, so a second read after any consumed byte can
            // cross the limit, truncate the replay and stall the upstream
            // (observed live as a hang on bodies above 64 KiB). The safe rule:
            // read the whole body only when the declared Content-Length fits
            // the replay window; otherwise read exactly one chunk and let the
            // stream (tail) inspection cover everything after it.
            const REPLAY_LIMIT: usize = 64 * 1024;
            let content_length = headers
                .iter()
                .find(|(name, _)| name.eq_ignore_ascii_case("content-length"))
                .and_then(|(_, value)| value.trim().parse::<usize>().ok());
            let read_whole =
                content_length.is_some_and(|len| len <= REPLAY_LIMIT);
            session.enable_retry_buffering();
            let mut interrupted = false;
            // Slow-upload defense: the whole read pass must finish within the
            // deadline, so a trickling client cannot stretch it byte by byte.
            let deadline = (self.body_read_timeout_ms > 0).then(|| {
                tokio::time::Instant::now()
                    + Duration::from_millis(self.body_read_timeout_ms)
            });
            loop {
                let read = session.read_request_body();
                let chunk = match deadline {
                    Some(deadline) => {
                        match tokio::time::timeout_at(deadline, read).await {
                            Ok(result) => result?,
                            Err(_) => {
                                tracing::info!(
                                    timeout_ms = self.body_read_timeout_ms,
                                    "request body read deadline exceeded; refused"
                                );
                                let mut response = block_page(
                                    &request_id,
                                    &format!(
                                        "request body was not received within {} ms",
                                        self.body_read_timeout_ms
                                    ),
                                );
                                response.status =
                                    http::StatusCode::REQUEST_TIMEOUT;
                                emit_generated_access(
                                    agent.as_ref(),
                                    &request_id,
                                    &response,
                                );
                                return Ok(RequestPluginResult::Respond(
                                    response,
                                ));
                            },
                        }
                    },
                    None => read.await?,
                };
                let Some(chunk) = chunk else {
                    break;
                };
                let chunk = chunk.as_ref();
                log_body_prefix.absorb(chunk);
                if capture_body {
                    inspect_buf.put(chunk);
                }
                // Inspection needs the prefix; the log needs its own. Stop
                // once neither can learn anything from more bytes.
                if capture_body && inspect_buf.len() >= self.max_body_size {
                    interrupted = true;
                    body_truncated = true;
                    break;
                }
                if !read_whole {
                    // A body larger than the replay window: one chunk is all
                    // we can consume without risking a truncated replay; the
                    // stream (tail) inspection covers the remainder.
                    interrupted = true;
                    body_truncated = true;
                    break;
                }
                if !capture_body && log_body_prefix.limit_hit() {
                    interrupted = true;
                    break;
                }
            }
            if session.retry_buffer_truncated() {
                // The replay can no longer be trusted (a content-length that
                // under-declared the body, or an unforeseen read path).
                // Refusing explicitly beats stalling the upstream forever.
                tracing::warn!(
                    limit = REPLAY_LIMIT,
                    "request body exceeded the replay window; refused"
                );
                let mut response = block_page(
                    &request_id,
                    &format!(
                        "request body exceeds the {} byte replay window",
                        REPLAY_LIMIT
                    ),
                );
                response.status = http::StatusCode::PAYLOAD_TOO_LARGE;
                emit_generated_access(agent.as_ref(), &request_id, &response);
                return Ok(RequestPluginResult::Respond(response));
            }
            if interrupted {
                log_body_prefix.interrupted();
                // Explicit size policy: refuse the request rather than
                // inspecting a prefix and forwarding the remainder.
                if self.body_reject {
                    tracing::info!(
                        limit = self.max_body_size,
                        "request body exceeds the inspection limit; rejected"
                    );
                    let mut response = block_page(
                        &request_id,
                        &format!(
                            "request body exceeds the {} byte inspection limit",
                            self.max_body_size
                        ),
                    );
                    response.status = http::StatusCode::PAYLOAD_TOO_LARGE;
                    emit_generated_access(
                        agent.as_ref(),
                        &request_id,
                        &response,
                    );
                    return Ok(RequestPluginResult::Respond(response));
                }
                // Staging policy: withhold and scan the remainder before
                // any of it reaches the upstream.
                if capture_body {
                    stage_remainder = true;
                }
            }
        }
        if stage_remainder && self.tail_inspection {
            DEFERRED_BODY.insert(
                request_id.clone(),
                DeferredBody {
                    buffer: BytesMut::new(),
                    passthrough: false,
                    created_at: Instant::now(),
                },
            );
        }
        let (log_body, log_body_size, log_body_truncated) =
            log_body_prefix.finish();

        // Track the request for access logging until the response phase —
        // including WAF-disabled sites, so traffic data stays complete.
        if agent.is_some() {
            register_pending_access(
                &request_id,
                PendingAccess {
                    site_id: site_id.clone(),
                    client_ip: client_ip.clone(),
                    method: method.clone(),
                    scheme: scheme.clone(),
                    protocol: protocol.clone(),
                    host: host.clone(),
                    path: path.clone(),
                    query: query.clone(),
                    user_agent: user_agent.clone(),
                    referer,
                    tls_version: ctx
                        .conn
                        .tls_version
                        .clone()
                        .unwrap_or_default()
                        .to_string(),
                    country_code: country.clone().unwrap_or_default(),
                    request_headers: log_headers,
                    request_body: log_body,
                    request_body_size: log_body_size,
                    request_body_truncated: log_body_truncated,
                    body_limit,
                    response: None,
                    start: Instant::now(),
                },
            );
        }

        let mut request_data = RequestData {
            method,
            path: path.clone(),
            query: query.clone(),
            headers,
            body: None,
            client_ip,
            country_code: country,
            scheme,
            protocol,
        };

        // ── Paused sites answer with a maintenance page before any other
        // rule runs. TLS termination and the log pipeline stay untouched, so
        // the certificate keeps serving and the traffic remains visible. ──
        if paused {
            let response = paused_page(&request_id);
            emit_generated_access(agent.as_ref(), &request_id, &response);
            return Ok(RequestPluginResult::Respond(response));
        }

        // ── Dynamic IP blocks: an IP the edge already refused (an auto-block
        // from an earlier WAF/rate-limit verdict or a server-issued block
        // command) is rejected before any rule runs. Like the paused-site
        // and mTLS denials this enforces an existing decision, so observation
        // mode never downgrades it. Unknown hosts carry no synced site id and
        // therefore can never match a block. ──
        if !site_id.is_empty()
            && agent.as_ref().is_some_and(|agent| {
                agent.is_ip_blocked(&site_id, &request_data.client_ip)
            })
        {
            let response = block_page(
                &request_id,
                "IP temporarily blocked by WAF defense",
            );
            emit_generated_access(agent.as_ref(), &request_id, &response);
            return Ok(RequestPluginResult::Respond(response));
        }

        // ── mTLS: a site that requires a client certificate refuses the
        // request before any other rule runs. Revoked certificates and
        // organization mismatches are refused here too, since the TLS layer
        // only proves the chain is trusted, not which site it was issued for.
        // The denial is logged as access only - it is not a WAF verdict. ──
        if let Some(mtls) = context.as_ref().and_then(|site| site.mtls.as_ref())
            && let Some(reason) = mtls.denial(ctx)
        {
            let response = block_page(&request_id, reason);
            emit_generated_access(agent.as_ref(), &request_id, &response);
            return Ok(RequestPluginResult::Respond(response));
        }

        // ── Access restrictions: IP rules and geo stop a request before the
        // WAF engine runs, and apply whether or not it is enabled. A rule
        // whose action is `basic_auth` is not an outright denial: it feeds
        // the gate below so the request continues once authenticated ──
        let mut access = PolicyOutcome::NoMatch;
        if let Some(site) = &context {
            access = site.policy.evaluate(
                &request_data.client_ip,
                client_addr,
                request_data.country_code.as_deref(),
            );
            if let Some(denial) =
                access.denial().filter(|denial| !denial.basic_auth)
            {
                if observe || denial.monitor {
                    // Observation mode downgrades every protection; the geo
                    // policy's monitor action downgrades only itself. Both
                    // record without enforcing; the monitor action labels
                    // the event as such.
                    Self::log_observed(
                        &site_id,
                        &request_id,
                        &host,
                        &request_data,
                        if denial.monitor {
                            WafAction::Monitor
                        } else if denial.challenge {
                            WafAction::Challenge
                        } else {
                            WafAction::Block
                        },
                        &denial.rule_id,
                        &denial.detail,
                        &denial.rule_name,
                    );
                } else {
                    let original_url = if query.is_empty() {
                        path
                    } else {
                        format!("{path}?{query}")
                    };
                    return Ok(Self::deny_request(
                        agent.as_ref(),
                        &site_id,
                        &request_id,
                        &host,
                        &request_data,
                        denial,
                        &original_url,
                        self.pow_difficulty,
                    ));
                }
            }
        }

        // ── Basic authentication: the site-wide gate and any access rule
        // with the `basic_auth` action share one credential set. It runs
        // before bot/rate/WAF checks and inside the WAF plugin, which sits
        // ahead of the cache plugin, so neither a cached response nor a
        // later verdict can skip it. An `allow` rule is the one exemption:
        // it means the client is trusted outright ──
        let gate = context.as_ref().and_then(|site| site.basic_auth.as_ref());
        let gate_required = match &access {
            PolicyOutcome::Allowed => false,
            PolicyOutcome::Denied(denial) => denial.basic_auth,
            PolicyOutcome::NoMatch => gate.is_some_and(|gate| gate.site_wide),
        };
        if gate_required {
            let authenticated =
                gate.is_some_and(|gate| gate.verify(&request_data.headers));
            if !authenticated {
                if let Some(delay) = gate.and_then(|gate| gate.delay) {
                    tokio::time::sleep(delay).await;
                }
                let realm = gate
                    .map(|gate| gate.realm.as_str())
                    .unwrap_or(DEFAULT_BASIC_REALM);
                let reason = access
                    .denial()
                    .map(|denial| {
                        format!("{}; authentication required", denial.detail)
                    })
                    .unwrap_or_else(|| {
                        "site-wide basic authentication".to_string()
                    });
                let response = basic_auth_page(&request_id, realm, &reason);
                emit_generated_access(agent.as_ref(), &request_id, &response);
                return Ok(RequestPluginResult::Respond(response));
            }
            if let Some(gate) = gate
                && gate.hide_credentials
            {
                session
                    .req_header_mut()
                    .remove_header(&http::header::AUTHORIZATION);
            }
        }

        // ── Bot protection: UA classification runs after IP/geo and before
        // the engine, applying whether or not the WAF engine is enabled ──
        if let Some(bot) = context.as_ref().and_then(|ctx| ctx.bot.as_ref()) {
            let burst = bot.uses_behavioral()
                && !request_data.client_ip.is_empty()
                && request_burst(&request_data.client_ip);
            match bot
                .evaluate_with_signals(
                    request_data.client_ip.parse::<IpAddr>().ok(),
                    &user_agent,
                    ClientSignals {
                        browser_hints: browser_header_hints(
                            &request_data.headers,
                        ),
                        tls_verified: session
                            .digest()
                            .is_some_and(|d| d.ssl_digest.is_some()),
                        burst,
                    },
                )
                .await
            {
                BotDecision::Pass => {},
                BotDecision::Deny(denial) => {
                    if observe {
                        Self::log_observed(
                            &site_id,
                            &request_id,
                            &host,
                            &request_data,
                            if denial.challenge {
                                WafAction::Challenge
                            } else {
                                WafAction::Block
                            },
                            &denial.rule_id,
                            &denial.detail,
                            &denial.rule_name,
                        );
                    } else {
                        let original_url = if query.is_empty() {
                            path.clone()
                        } else {
                            format!("{path}?{query}")
                        };
                        return Ok(Self::deny_request(
                            agent.as_ref(),
                            &site_id,
                            &request_id,
                            &host,
                            &request_data,
                            &denial,
                            &original_url,
                            self.pow_difficulty,
                        ));
                    }
                },
                BotDecision::LogOnly(denial) => {
                    let verdict = WafVerdict {
                        action: WafAction::Monitor,
                        score: 0,
                        matched_rules: vec![denial.rule_id.clone()],
                        details: denial.detail.clone(),
                        breakdown: ScoreBreakdown::clean(),
                    };
                    Self::log_event(
                        &site_id,
                        &request_id,
                        &host,
                        &request_data,
                        &verdict,
                        &denial.rule_name,
                    );
                },
            }
        }

        // ── Rate limiting: fixed-window counters run after IP/geo/bot and
        // before the engine, applying whether or not the WAF engine is
        // enabled ──
        if let Some(rate) =
            context.as_ref().and_then(|c| c.rate_limits.as_ref())
        {
            let cleared =
                rate.rules.iter().any(|r| r.action == RateAction::Challenge)
                    && clearance_valid(clearance_cookie(&request_data.headers));
            let outcome = rate.evaluate(
                &self.rate_counters,
                &request_data,
                &host,
                cleared,
                client_addr,
            );
            for tripped in &outcome.logged {
                let verdict = WafVerdict {
                    action: WafAction::Monitor,
                    score: 0,
                    matched_rules: vec![tripped.rule_id.clone()],
                    details: tripped.detail.clone(),
                    breakdown: ScoreBreakdown::clean(),
                };
                Self::log_event(
                    &site_id,
                    &request_id,
                    &host,
                    &request_data,
                    &verdict,
                    &tripped.rule_name,
                );
            }
            if let Some(tripped) = outcome.deny {
                if observe {
                    Self::log_observed(
                        &site_id,
                        &request_id,
                        &host,
                        &request_data,
                        if tripped.challenge {
                            WafAction::Challenge
                        } else {
                            WafAction::Block
                        },
                        &tripped.rule_id,
                        &tripped.detail,
                        &tripped.rule_name,
                    );
                } else {
                    let original_url = if query.is_empty() {
                        path.clone()
                    } else {
                        format!("{path}?{query}")
                    };
                    let verdict = WafVerdict {
                        action: if tripped.challenge {
                            WafAction::Challenge
                        } else {
                            WafAction::Block
                        },
                        score: 0,
                        matched_rules: vec![tripped.rule_id.clone()],
                        details: tripped.detail.clone(),
                        breakdown: ScoreBreakdown::clean(),
                    };
                    Self::log_event(
                        &site_id,
                        &request_id,
                        &host,
                        &request_data,
                        &verdict,
                        &tripped.rule_name,
                    );
                    // Defense in depth: refuse the client at the edge for the
                    // mitigation window so a repeat offender never reaches
                    // the counters (or the origin) again in that time.
                    if !tripped.challenge
                        && let Some(agent) = &agent
                    {
                        agent.block_ip(
                            &site_id,
                            &request_data.client_ip,
                            Some(Duration::from_secs(tripped.retry_after)),
                            &format!("rate limit: {}", tripped.rule_name),
                        );
                    }
                    let response = if tripped.challenge {
                        build_challenge_response(
                            &request_id,
                            &original_url,
                            &site_id,
                            self.pow_difficulty,
                            ChallengeKind::Js,
                        )
                    } else {
                        rate_limit_page(
                            &request_id,
                            &tripped.detail,
                            tripped.retry_after,
                        )
                    };
                    emit_generated_access(
                        agent.as_ref(),
                        &request_id,
                        &response,
                    );
                    return Ok(RequestPluginResult::Respond(response));
                }
            }
        }

        if matches!(choice, EngineChoice::Disabled) {
            if let Some(agent) = &agent {
                agent.record_request(false);
            }
            return Ok(RequestPluginResult::Continue);
        }
        if matches!(choice, EngineChoice::Base) && self.mode == WafMode::Off {
            if let Some(agent) = &agent {
                agent.record_request(false);
            }
            return Ok(RequestPluginResult::Skipped);
        }
        // A site-level `off` mode skips enforcement entirely, mirroring the
        // plugin-level switch above: the site is configured to enforce
        // nothing, so neither the legacy engine nor the pipeline runs.
        if context.as_ref().and_then(|site| site.mode) == Some(WafMode::Off) {
            if let Some(agent) = &agent {
                agent.record_request(false);
            }
            return Ok(RequestPluginResult::Skipped);
        }

        // ── Inspect ──
        // The body (if any) was already read during log capture; when body
        // inspection (or a per-site body schema) is enabled the engine sees
        // the same prefix.
        request_data.body = if capture_body && !inspect_buf.is_empty() {
            Some(inspect_buf.to_vec())
        } else {
            None
        };
        let verdict = match &choice {
            EngineChoice::Site(engine) => engine.inspect(&request_data),
            EngineChoice::Base => {
                let guard =
                    self.engine.read().unwrap_or_else(|e| e.into_inner());
                guard.inspect(&request_data)
            },
            EngineChoice::Disabled => unreachable!("handled above"),
        };

        // ── Varman pipeline: shadow comparison, or enforcement when the
        // engine mode is `varman`. The pipeline can only escalate the legacy
        // action, so dashboard-configured custom rules stay effective. The
        // mode comes from the site's `waf_settings.engine_mode` (when it is
        // not `inherit`) and falls back to the process-wide
        // `VARMAN_WAF_ENGINE`. ──
        let engine = crate::waf_shadow::resolve_mode(
            context
                .as_ref()
                .map(|site| site.engine_mode.as_str())
                .filter(|mode| !mode.is_empty()),
        );
        let monitored = context
            .as_ref()
            .map(|site| site.monitor_categories.as_slice())
            .unwrap_or_default();
        // Engine telemetry sink: only meaningful when an agent reports it.
        let metrics = agent.as_ref().map(|agent| agent.metrics.as_ref());
        let mut verdict = match crate::waf_shadow::analyze(
            &request_data,
            &verdict,
            engine,
            monitored,
            metrics,
        ) {
            Some(pipeline)
                if engine == crate::waf_shadow::EngineMode::Varman =>
            {
                crate::waf_shadow::effective_verdict(&verdict, &pipeline)
            },
            _ => verdict,
        };

        // ── Per-site custom layers: SecLang virtual patches (block) and
        // OpenAPI validation (monitor). Compiled once per site context; both
        // escalate only, never weaken the native verdict. ──
        if let Some(custom) =
            context.as_ref().and_then(|site| site.custom.as_ref())
        {
            let canonical = crate::waf_shadow::canonicalize(&request_data);
            if let Some(custom_verdict) =
                custom.evaluate(&canonical, !body_truncated)
            {
                verdict = crate::waf_shadow::effective_verdict(
                    &verdict,
                    &custom_verdict,
                );
            }
        }

        // ── External processor (Phase 9): bounded, policy-resolved and
        // additive. The processor can only escalate the verdict; a failure
        // resolves through its configured policy. ──
        if crate::waf_processor::is_enabled() {
            let findings =
                crate::waf_processor::evaluate(&request_data, metrics)
                    .await
                    .filter(|findings| !findings.is_empty());
            if let Some(findings) = findings {
                let processor_verdict =
                    crate::waf_processor::to_waf_verdict(&findings);
                verdict = crate::waf_shadow::effective_verdict(
                    &verdict,
                    &processor_verdict,
                );
            }
        }

        // ── The site's enforcement mode caps every engine path, including
        // the escalate-only ones (pipeline, custom layers, external
        // processor): `monitor` records findings without enforcing and `off`
        // (handled above) enforces nothing. Access control decided before
        // inspection - mTLS, basic auth, paused sites, dynamic IP blocks -
        // is never downgraded. ──
        if let Some(mode) = context.as_ref().and_then(|site| site.mode) {
            verdict = cap_to_site_mode(verdict, mode);
        }

        // Custom rule ids carry no name of their own; the site context maps
        // the one that fired back to its configured name.
        let rule_name_of = |verdict: &WafVerdict| -> String {
            let Some(id) = verdict.matched_rules.first() else {
                return String::new();
            };
            context
                .as_ref()
                .and_then(|context| context.rule_names.get(id))
                .cloned()
                .unwrap_or_default()
        };

        if verdict.action == WafAction::Pass {
            if let Some(agent) = &agent {
                agent.record_request(false);
            }
            return Ok(RequestPluginResult::Continue);
        }

        // Monitor: log the event but let the request through.
        if verdict.action == WafAction::Monitor {
            let rule_name = rule_name_of(&verdict);
            Self::log_event(
                &site_id,
                &request_id,
                &host,
                &request_data,
                &verdict,
                &rule_name,
            );
            return Ok(RequestPluginResult::Continue);
        }

        // Observation mode: a Block/Challenge verdict is recorded as a
        // monitor event — nothing was actually blocked — and the request
        // proceeds.
        if observe {
            let rule_name = rule_name_of(&verdict);
            tracing::info!(
                site_id = %site_id,
                request_id = %request_id,
                path = %request_data.path,
                would_have = ?verdict.action,
                score = verdict.score,
                "[observation] WAF verdict recorded without enforcing"
            );
            let observed = WafVerdict {
                action: WafAction::Monitor,
                ..verdict.clone()
            };
            Self::log_event(
                &site_id,
                &request_id,
                &host,
                &request_data,
                &observed,
                &rule_name,
            );
            return Ok(RequestPluginResult::Continue);
        }

        // Block / Challenge: log the security event, then emit the access
        // entry with the real status — a Respond result never reaches
        // handle_response, so this is the only chance to log it.
        let rule_name = rule_name_of(&verdict);
        Self::log_event(
            &site_id,
            &request_id,
            &host,
            &request_data,
            &verdict,
            &rule_name,
        );
        let response = if verdict.action == WafAction::Block {
            // Auto-block the client for a grace window: repeat requests are
            // refused at the edge (see the entry check above) instead of
            // running the engine every time.
            if let Some(agent) = &agent {
                agent.block_ip(
                    &site_id,
                    &request_data.client_ip,
                    Some(Duration::from_secs(WAF_AUTO_BLOCK_SECS)),
                    &format!("waf: {rule_name}"),
                );
            }
            block_page(&request_id, &verdict.details)
        } else {
            // Challenge verdict — delegate to the challenge subsystem.
            let original_url = if query.is_empty() {
                path
            } else {
                format!("{path}?{query}")
            };
            build_challenge_response(
                &request_id,
                &original_url,
                &site_id,
                self.pow_difficulty,
                ChallengeKind::Js,
            )
        };
        emit_generated_access(agent.as_ref(), &request_id, &response);
        Ok(RequestPluginResult::Respond(response))
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
