//! Pure edge model: the local mirrors of the control-plane site, WAF, route
//! and cache types, plus the proto conversions that build them.
//!
//! Nothing here touches disk or the [`RuleCache`](super::RuleCache) storage
//! fields; the conversions are associated functions on the cache only because
//! the bundle path calls them.

use std::collections::HashMap;
use std::sync::Arc;

use chrono::{DateTime, Utc};
use pingap_core::normalize_host;
use serde::{Deserialize, Serialize};
use tracing::warn;

use varman_protocol::control_plane as proto;

use super::RuleCache;

// ─────────────────────────────────────────────────────────────
// Serializable cache types (local mirrors of proto types)
// ─────────────────────────────────────────────────────────────

/// Top-level cached state that is swapped atomically.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CachedRules {
    /// Site rules keyed by site_id
    ///
    /// The values are shared via `Arc` so the hot-path lookups
    /// (`get_site_rules`) return a pointer instead of deep-cloning every
    /// rule the site carries. Updates build a new map but reuse the
    /// `Arc`s of untouched sites.
    pub sites: HashMap<String, Arc<SiteRules>>,
    /// Domain → site_id index for fast lookup
    pub domain_index: HashMap<String, String>,
    /// Domain → disconnected (failover) policy, covering every site the
    /// control plane knows about — including ones whose rule bundle this
    /// agent has not (yet) received. Consulted when a host has no synced
    /// rules, which is exactly when `sites` cannot answer.
    #[serde(default)]
    pub failover_registry: HashMap<String, FailoverMode>,
    /// Control-plane-wide default for hosts absent from
    /// `failover_registry`. `None` when the server never sent it (old
    /// control plane), which makes the agent fall back to its local
    /// `config.fail_open`.
    #[serde(default)]
    pub global_fail_open: Option<bool>,
    /// Deployment-wide cache ceiling; `None` when the server never sent it
    /// (old control plane) — the generator and quota logic then fall back to
    /// their built-in defaults.
    #[serde(default)]
    pub global_cache: Option<GlobalCacheSettings>,
    /// When the cache was last updated from the server
    pub updated_at: DateTime<Utc>,
    /// Hash of the configuration (for delta sync). An `Arc` so the hot path
    /// reads it without a heap copy.
    pub config_hash: Arc<str>,
    /// Fingerprint of the whole applied configuration, used by the data-plane
    /// reload watcher. `config_hash` is a per-site bundle hash for delta sync;
    /// an unbound agent receives several sites and the first one's hash does
    /// not move when another site's certificate or origin changes. This value
    /// is the outer `SiteConfig` fingerprint for a full push, and the changed
    /// bundle's hash for a single-site push.
    #[serde(default)]
    pub data_plane_hash: Arc<str>,
    /// Revision of the policy bundle last applied (0 = none / never).
    #[serde(default)]
    pub policy_revision: i32,
}

impl Default for CachedRules {
    fn default() -> Self {
        Self {
            sites: HashMap::new(),
            domain_index: HashMap::new(),
            failover_registry: HashMap::new(),
            global_fail_open: None,
            global_cache: None,
            updated_at: Utc::now(),
            config_hash: Arc::from(""),
            data_plane_hash: Arc::from(""),
            policy_revision: 0,
        }
    }
}

/// Rules for a single site/domain.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SiteRules {
    pub site_id: String,
    pub domain: String,
    pub alternate_domains: Vec<String>,
    /// Fingerprint of the rule bundle this site was built from. The WAF
    /// plugin keys its compiled per-domain context on it, so changing one
    /// site invalidates that site's context without touching the rest.
    /// Empty for caches written before the field existed.
    #[serde(default)]
    pub config_hash: String,
    /// Lifecycle status (`active`/`paused`/`pending`); caches written before
    /// the edge consumed it default to `active`.
    #[serde(default = "default_site_status")]
    pub status: String,
    pub waf_config: Option<WafConfig>,
    pub rate_limit_rules: Vec<RateLimitRule>,
    pub ip_access_rules: Vec<IpAccessRule>,
    pub geo_config: Option<GeoConfig>,
    pub cache_rules: Vec<CacheRule>,
    pub challenge_config: Option<ChallengeConfig>,
    pub rewrite_rules: Vec<RewriteRule>,
    pub error_pages: Vec<CustomErrorPage>,
    pub ssl_config: Option<SslConfig>,
    pub upstreams: Vec<UpstreamConfig>,
    /// Path routes to origin pools; empty for caches written before pools
    /// existed.
    #[serde(default)]
    pub routes: Vec<RouteConfig>,
    #[serde(default)]
    pub bot_protection: Option<BotProtectionConfig>,
    /// Site-wide basic auth gate; `None` when the site has none configured.
    #[serde(default)]
    pub basic_auth: Option<BasicAuthConfig>,
    /// Observation mode: detections keep running but nothing is enforced —
    /// WAF, IP/geo rules, bot protection and rate limiting only record.
    #[serde(default)]
    pub observation_mode: bool,
    /// Site-level cache limits; `None` when the site overrides nothing and
    /// every limit follows the global ceiling.
    #[serde(default)]
    pub cache_settings: Option<SiteCacheSettings>,
    /// Forwarded-header client IP resolution; disabled when the site has no
    /// CDN / reverse proxy in front of it.
    #[serde(default)]
    pub proxy_trust: ProxyTrustConfig,
}

/// Site-level forwarded-header trust: which header carries the real client
/// IP, whether only the nearest proxy's entry is believed, and which peers
/// are allowed to influence the resolution at all.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProxyTrustConfig {
    /// Trust forwarded headers at all.
    #[serde(default)]
    pub enabled: bool,
    /// Lower-case header name; empty means `x-forwarded-for`.
    #[serde(default)]
    pub header: String,
    /// Take the last XFF entry (added by the nearest proxy) instead of the
    /// first one, which the client can spoof.
    #[serde(default = "default_true")]
    pub last_hop_only: bool,
    /// CIDR ranges of proxies allowed to influence the resolved client IP.
    /// Empty = trust nothing (the TCP peer is always used).
    #[serde(default)]
    pub trusted_ranges: Vec<String>,
}

impl Default for ProxyTrustConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            header: String::new(),
            last_hop_only: true,
            trusted_ranges: Vec::new(),
        }
    }
}

fn default_true() -> bool {
    true
}

impl SiteRules {
    /// All domains this site responds to.
    pub fn all_domains(&self) -> impl Iterator<Item = &str> {
        std::iter::once(self.domain.as_str())
            .chain(self.alternate_domains.iter().map(|s| s.as_str()))
    }

    /// Whether the control plane has paused the site.
    pub fn is_paused(&self) -> bool {
        self.status == site_status::PAUSED
    }
}

/// How a host behaves while the control plane is unreachable and it has no
/// synced rule bundle. Local mirror of `proto::FailoverMode`.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default,
)]
#[serde(rename_all = "snake_case")]
pub enum FailoverMode {
    /// Follow the control-plane-wide `global_fail_open` default.
    #[default]
    Inherit,
    /// Keep proxying through the base engine.
    Open,
    /// Answer 503.
    Closed,
}

impl From<i32> for FailoverMode {
    fn from(value: i32) -> Self {
        match value {
            1 => FailoverMode::Open,
            2 => FailoverMode::Closed,
            0 => FailoverMode::Inherit,
            // A newer control plane may know modes this agent does not.
            // Failover is an availability switch, so degrade to the next
            // resolution layer instead of guessing a stricter behaviour.
            other => {
                warn!(
                    value = other,
                    "unknown failover mode from the control plane, treating as inherit"
                );
                FailoverMode::Inherit
            },
        }
    }
}

/// Folds the per-site policy registry of one bundle into a domain-keyed map,
/// covering primary and alternate domains alike. Keys are normalised
/// (lowercase) to match what `pingap_core::get_host` produces on the lookup
/// side, so a `EXAMPLE.com` entry in the control plane still resolves.
pub(super) fn failover_registry_from(
    policies: &[proto::SitePolicy],
) -> HashMap<String, FailoverMode> {
    let mut registry = HashMap::with_capacity(policies.len());
    for policy in policies {
        let mode = FailoverMode::from(policy.mode);
        registry.insert(normalize_host(&policy.domain), mode);
        for alt in &policy.alternate_domains {
            registry.insert(normalize_host(alt), mode);
        }
    }
    registry
}

/// Exact lookup with wildcard fallback, mirroring the routing layer's
/// `HostSelector::Suffix` semantics: `*.example.com` covers strict
/// subdomains only, never the apex itself. `www.a.example.com` tries the
/// exact key first, then `*.a.example.com`, `*.example.com`, … — most
/// specific wildcard wins, so a wildcard site never shadows an exact one
/// and a longer wildcard beats a shorter one.
///
/// Exact hits cost a single lookup and no allocation; the wildcard walk
/// only runs on a miss and reuses one buffer.
pub(super) fn lookup_with_wildcard<'a, V>(
    map: &'a HashMap<String, V>,
    domain: &str,
) -> Option<&'a V> {
    if let Some(value) = map.get(domain) {
        return Some(value);
    }
    let mut buf = String::with_capacity(domain.len() + 2);
    let mut rest = domain;
    while let Some((_, suffix)) = rest.split_once('.') {
        if suffix.is_empty() {
            break;
        }
        buf.clear();
        buf.push_str("*.");
        buf.push_str(suffix);
        if let Some(value) = map.get(&buf) {
            return Some(value);
        }
        rest = suffix;
    }
    None
}

/// The site's effective WAF enforcement state: `(engine mode, observation)`.
/// A missing WAF config means the engine is off.
pub(super) fn site_enforcement(site: Option<&SiteRules>) -> (WafMode, bool) {
    match site {
        Some(s) => (
            s.waf_config
                .as_ref()
                .map(|c| c.mode)
                .unwrap_or(WafMode::Off),
            s.observation_mode,
        ),
        None => (WafMode::Off, false),
    }
}

/// True when the state enforces WAF block verdicts (block mode without
/// observation), i.e. WAF auto-blocks may be produced.
pub(super) fn waf_enforcing(state: (WafMode, bool)) -> bool {
    state.0 == WafMode::Block && !state.1
}

/// Persisted site status values, matching `models::sites::site_status` on the
/// control plane.
pub mod site_status {
    pub const ACTIVE: &str = "active";
    pub const PAUSED: &str = "paused";
    pub const PENDING: &str = "pending";
}

fn default_site_status() -> String {
    site_status::ACTIVE.to_string()
}

/// Maps a `varman.SiteStatusEnum` value onto the persisted string form; the
/// control-plane counterpart is `grpc::config::site_status_proto`, which must
/// stay in sync.
pub fn site_status_str(value: i32) -> String {
    match value {
        1 => site_status::PAUSED,  // SITE_STATUS_PAUSED
        2 => site_status::PENDING, // SITE_STATUS_PENDING
        _ => site_status::ACTIVE,
    }
    .to_string()
}

// ─── WAF ────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WafConfig {
    pub enabled: bool,
    pub mode: WafMode,
    pub paranoia_level: u32,
    pub sqli_detection: bool,
    pub xss_detection: bool,
    pub rce_detection: bool,
    pub lfi_detection: bool,
    pub ssrf_detection: bool,
    pub bot_detection: bool,
    pub custom_rules: Vec<WafRule>,
    pub managed_overrides: Vec<RuleOverride>,
    pub ml_enabled: bool,
    pub ml_model_path: String,
    pub ml_threshold: f64,
    pub anomaly_threshold: u32,
    /// Site-level WAF grading. Defaults keep old on-disk caches (written
    /// before these fields existed) enforcing everything.
    #[serde(default)]
    pub advanced_mode: bool,
    /// Per-site engine mode: `inherit` (process default), `legacy`, `shadow`
    /// or `varman`. Old caches without the field inherit.
    #[serde(default = "default_engine_mode")]
    pub engine_mode: String,
    /// SecLang virtual-patch source (empty = off).
    #[serde(default)]
    pub virtual_patches: String,
    /// OpenAPI document, JSON (empty = off).
    #[serde(default)]
    pub openapi_spec: String,
    #[serde(default)]
    pub monitor_categories: Vec<String>,
    #[serde(default)]
    pub monitor_stacks: Vec<String>,
    #[serde(default)]
    pub monitor_managed_rules: Vec<String>,
    /// Managed rules switched off entirely (no match, no score, no event).
    #[serde(default)]
    pub disabled_rules: Vec<String>,
    /// Per-rule score overrides (`rule id -> points`); the rule's own action
    /// still applies.
    #[serde(default)]
    pub rule_scores: std::collections::HashMap<String, u32>,
    /// Per-rule excluded request targets (`rule id -> targets`).
    #[serde(default)]
    pub rule_target_exclusions: std::collections::HashMap<String, Vec<String>>,
    /// Path-scoped target exclusions (exclusion packages): active only
    /// while the request path starts with `path_prefix`.
    #[serde(default)]
    pub path_target_exclusions: Vec<PathTargetExclusion>,
    /// Per-operation API controls: how the OpenAPI layer treats one
    /// observed endpoint (`off` / `observe` / `enforce`).
    #[serde(default)]
    pub api_operations: Vec<ApiOperationControl>,
}

/// One path-scoped target exclusion from a package binding.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct PathTargetExclusion {
    pub rule_id: String,
    pub targets: Vec<String>,
    pub path_prefix: String,
}

/// One observed endpoint's schema-validation mode.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ApiOperationControl {
    /// Lowercase HTTP method.
    pub method: String,
    /// Path template, e.g. `/orders/{id}`.
    pub path: String,
    /// `off`, `observe` or `enforce`.
    pub mode: String,
}

/// Default for [`WafConfig::engine_mode`]: follow the process-wide
/// `VARMAN_WAF_ENGINE`.
fn default_engine_mode() -> String {
    "inherit".to_string()
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WafMode {
    Off,
    Monitor,
    Block,
}

impl From<i32> for WafMode {
    fn from(v: i32) -> Self {
        match v {
            1 => Self::Monitor,
            2 => Self::Block,
            0 => Self::Off,
            // A newer control plane may know modes this agent does not.
            // Silently treating the site as off would disable its WAF for
            // the whole upgrade window; enforcing (block) matches the
            // fail-close convention used by `WafAction`.
            unknown => {
                warn!(value = unknown, "unknown waf mode; enforcing as block");
                Self::Block
            },
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WafRule {
    pub id: String,
    pub name: String,
    pub description: String,
    pub expression: String,
    pub action: WafAction,
    pub severity: u32,
    pub tags: Vec<String>,
    pub enabled: bool,
    pub mode: WafMode,
    pub priority: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WafAction {
    Block,
    Log,
    Challenge,
    JsChallenge,
    Allow,
    /// Only meaningful where the protocol allows it (the geo policy and the
    /// IP access rules); a WAF engine verdict never carries it.
    BasicAuth,
}

impl From<i32> for WafAction {
    fn from(v: i32) -> Self {
        match v {
            1 => Self::Log,
            2 => Self::Challenge,
            3 => Self::JsChallenge,
            4 => Self::Allow,
            5 => Self::BasicAuth,
            // 0 is the enum's own block value. Anything else comes from a
            // control plane newer than this data plane: warn instead of
            // enforcing an action we do not understand as a block.
            unknown => {
                if unknown != 0 {
                    warn!(
                        value = unknown,
                        "unknown waf action; enforcing as block"
                    );
                }
                Self::Block
            },
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RuleOverride {
    pub rule_id: String,
    pub tag: String,
    pub action: WafAction,
    pub enabled: bool,
}

// ─── Rate Limiting ──────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RateLimitRule {
    pub id: String,
    pub name: String,
    pub expression: String,
    pub characteristics: Vec<String>,
    /// Parameter names for `RateLimitCharHeader/Cookie/Query` characteristics,
    /// parallel to `characteristics`. Older caches without this field load as
    /// empty.
    #[serde(default)]
    pub characteristic_params: Vec<String>,
    pub period_seconds: u32,
    pub threshold: u32,
    pub action: WafAction,
    pub mitigation_timeout_seconds: u32,
    pub enabled: bool,
    pub priority: u32,
}

// ─── IP Access ──────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IpAccessRule {
    pub id: String,
    pub name: String,
    pub ip_ranges: Vec<String>,
    pub action: IpAccessAction,
    pub note: String,
    pub enabled: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum IpAccessAction {
    Block,
    Challenge,
    JsChallenge,
    Allow,
    /// The matching client must pass the site's basic auth gate.
    BasicAuth,
}

impl From<i32> for IpAccessAction {
    fn from(v: i32) -> Self {
        match v {
            1 => Self::Challenge,
            2 => Self::JsChallenge,
            3 => Self::Allow,
            4 => Self::BasicAuth,
            // 0 is the enum's own block value. Anything else comes from a
            // control plane newer than this data plane: warn instead of
            // enforcing an action we do not understand as a block.
            unknown => {
                if unknown != 0 {
                    warn!(
                        value = unknown,
                        "unknown ip access action; enforcing as block"
                    );
                }
                Self::Block
            },
        }
    }
}

// ─── Geo ────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GeoConfig {
    pub enabled: bool,
    pub blocked_countries: Vec<String>,
    pub allowed_countries: Vec<String>,
    pub blocked_asns: Vec<String>,
    pub block_unknown: bool,
    pub action: WafAction,
    /// Ranges synced from ipverse for the listed countries (blocked, or
    /// allowed in whitelist mode).
    pub country_ranges: Vec<String>,
    /// Ranges synced from ipverse for the blocked ASNs.
    pub asn_ranges: Vec<String>,
    /// Listed keys whose dataset is not synced yet.
    pub missing_keys: Vec<String>,
}

// ─── Cache Rules ────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CacheRule {
    pub id: String,
    pub name: String,
    pub match_expression: String,
    pub edge_ttl_seconds: u32,
    pub browser_ttl_seconds: u32,
    pub disk_quota_mb: u32,
    pub cache_eligible: bool,
    pub cache_key_headers: Vec<String>,
    pub respect_origin_headers: bool,
    pub stale_while_revalidate_seconds: u32,
    pub enabled: bool,
}

/// Deployment-wide cache ceiling, mirrored from the control plane's
/// `cache_settings` row. Absent fields fall back to the built-in defaults
/// the agent used before the ceiling existed.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Default)]
pub struct GlobalCacheSettings {
    #[serde(default)]
    pub max_file_size_mb: Option<u32>,
    #[serde(default)]
    pub max_space_mb: Option<u32>,
    #[serde(default)]
    pub master_enabled: Option<bool>,
    #[serde(default)]
    pub default_edge_ttl_seconds: Option<u32>,
}

impl GlobalCacheSettings {
    /// Built-in default: the ceiling the configuration generator hardcoded
    /// before the setting existed.
    pub fn max_file_size_mb(&self) -> u32 {
        self.max_file_size_mb.unwrap_or(16)
    }

    /// `0` = unlimited (no `?max_size=` on the cache directory).
    pub fn max_space_mb(&self) -> u32 {
        self.max_space_mb.unwrap_or(0)
    }

    pub fn master_enabled(&self) -> bool {
        self.master_enabled.unwrap_or(true)
    }

    /// `0` = no fallback TTL for rules without an explicit one.
    pub fn default_edge_ttl_seconds(&self) -> u32 {
        self.default_edge_ttl_seconds.unwrap_or(0)
    }
}

/// Site-level cache limits, mirrored from the `sites` cache columns. `None`
/// fields fall back level by level: type limit → site cap → global cap.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Default)]
pub struct SiteCacheSettings {
    #[serde(default)]
    pub max_file_size_mb: Option<u32>,
    #[serde(default)]
    pub type_max_file_size_mb: HashMap<String, u32>,
}

// ─── Challenge ──────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChallengeConfig {
    pub enabled: bool,
    pub under_attack_mode: bool,
    pub default_level: ChallengeLevel,
    pub clearance_duration_seconds: u32,
    pub exempt_paths: Vec<String>,
    pub request_threshold: u32,
    pub browser_integrity_check: bool,
    pub tls_fingerprint_check: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ChallengeLevel {
    None,
    NonInteractive,
    Managed,
    Interactive,
}

impl From<i32> for ChallengeLevel {
    fn from(v: i32) -> Self {
        match v {
            1 => Self::NonInteractive,
            2 => Self::Managed,
            3 => Self::Interactive,
            0 => Self::None,
            // A newer control plane may know levels this agent does not.
            // Degrading to `None` would silently stop challenging; the
            // strongest level keeps the protection fail-close.
            unknown => {
                warn!(
                    value = unknown,
                    "unknown challenge level; enforcing as interactive"
                );
                Self::Interactive
            },
        }
    }
}

// ─── Bot Protection ─────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BotProtectionConfig {
    pub enabled: bool,
    pub action: WafAction,
    pub known_bots_whitelist: Vec<String>,
    /// Browser-like UAs must also present browser request headers.
    pub js_detection: bool,
    /// Browser-like UAs must arrive over a TLS session.
    pub tls_fingerprint: bool,
    /// Per-IP request bursts receive the configured action.
    pub behavioral_analysis: bool,
    /// Expanded CIDR ranges of the configured verified-bot IP group; a
    /// client IP inside any of them counts as a verified bot.
    pub verified_bot_ranges: Vec<String>,
    /// Verify known crawler user agents by DNS reverse + forward lookups.
    pub dns_verification_enabled: bool,
}

// ─── Basic Auth ─────────────────────────────────────────────

/// Site-wide HTTP basic authentication, enforced by the WAF plugin before the
/// cache plugin can answer from a stored response.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BasicAuthConfig {
    pub enabled: bool,
    /// Realm advertised in `WWW-Authenticate`.
    pub realm: String,
    pub credentials: Vec<BasicAuthCredential>,
    /// Seconds a failed attempt is delayed before the 401 goes out.
    pub delay_seconds: u32,
    /// Strip the `Authorization` header once the request is authenticated.
    pub hide_credentials: bool,
}

/// One accepted credential, pre-encoded by the control plane.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BasicAuthCredential {
    pub username: String,
    /// Base64 of `username:password`, the payload a client sends in the
    /// `Authorization: Basic …` header.
    pub authorization: String,
}

// ─── Rewrite ────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RewriteRule {
    pub id: String,
    pub name: String,
    pub match_expression: String,
    pub direction: RewriteDirection,
    #[serde(default)]
    pub operations: Vec<RewriteOperation>,
    pub enabled: bool,
    pub priority: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RewriteDirection {
    Request,
    Response,
}

impl From<i32> for RewriteDirection {
    fn from(v: i32) -> Self {
        match v {
            1 => Self::Response,
            _ => Self::Request,
        }
    }
}

/// One declarative rewrite operation mirroring the console's operations JSON:
/// `op_type` is one of set_header | add_header | remove_header | set_path |
/// regex_replace_path | set_query_param | remove_query_param | replace_body;
/// `name`/`value` semantics depend on the type.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RewriteOperation {
    #[serde(rename = "type")]
    pub op_type: String,
    #[serde(default)]
    pub name: String,
    #[serde(default)]
    pub value: String,
}

// ─── Error Pages ────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CustomErrorPage {
    pub id: String,
    pub status_code: u32,
    pub content_type: String,
    pub body_template: String,
    pub name: String,
    pub enabled: bool,
}

// ─── SSL ────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SslConfig {
    pub cert_pem: String,
    pub key_pem: String,
    pub acme_enabled: bool,
    pub acme_email: String,
    pub acme_challenge_type: String,
    pub acme_dns_provider: String,
    pub acme_dns_config: HashMap<String, String>,
    pub min_tls_version: String,
    pub hsts_enabled: bool,
    pub hsts_max_age: u32,
    pub always_use_https: bool,
    /// Whether the site serves HTTPS at all.
    pub enabled: bool,
    pub max_tls_version: String,
    /// The edge issues certificates on the fly instead of using `cert_pem`.
    pub self_signed: bool,
    pub mtls_enabled: bool,
    pub mtls_client_ca: String,
    /// Id of the `site_certificates` row this posture selects, when any.
    pub certificate_id: String,
    /// Hostnames the selected certificate covers. Empty keeps the historical
    /// fallback to the site's primary and alternate domains.
    #[serde(default)]
    pub domains: Vec<String>,
    /// Lowercase-hex SHA-256 fingerprints of revoked client certificates.
    #[serde(default)]
    pub mtls_revoked_fingerprints: Vec<String>,
    /// Organization every client certificate must carry; empty skips the
    /// check.
    #[serde(default)]
    pub mtls_organization: String,
    /// Whether a client certificate is required. `None` means the cache
    /// predates the flag, when turning mTLS on always required one.
    #[serde(default)]
    pub mtls_require_client_cert: Option<bool>,
}

impl SslConfig {
    /// Whether clients must present a certificate.
    ///
    /// A site may instead only *trust* client certificates (optional mTLS),
    /// in which case a request without one still passes; caches written
    /// before the dedicated flag existed only stored `mtls_enabled`, which
    /// always meant enforcement.
    pub fn mtls_requires_cert(&self) -> bool {
        self.mtls_require_client_cert.unwrap_or(self.mtls_enabled)
    }
}

// ─── Upstream ───────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UpstreamConfig {
    pub name: String,
    pub peers: Vec<UpstreamPeer>,
    pub algorithm: String,
    pub health_check: Option<HealthCheckConfig>,
    pub connection_timeout_ms: u32,
    pub read_timeout_ms: u32,
    pub write_timeout_ms: u32,
    /// Origin pool identity; empty for caches written before pools existed.
    #[serde(default)]
    pub pool_id: String,
    /// Complete pingap LB spec (`round_robin` or `hash:<type>[:<key>]`),
    /// superseding `algorithm`.
    #[serde(default)]
    pub algo: String,
    /// Non-empty enables TLS to the origin and sets the SNI.
    #[serde(default)]
    pub sni: String,
    /// `None` keeps the proxy default (verification on).
    #[serde(default)]
    pub verify_cert: Option<bool>,
    #[serde(default)]
    pub is_default: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UpstreamPeer {
    pub address: String,
    pub weight: u32,
    pub tls: bool,
}

/// A path-based route directing matching requests to an origin pool.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RouteConfig {
    pub id: String,
    pub name: String,
    /// prefix | exact | regex
    pub match_type: String,
    /// Raw path; the data plane adds the `=`/`~` marker.
    pub path: String,
    /// Manual location weight; `None` uses pingap's auto weight.
    pub priority: Option<i32>,
    pub enabled: bool,
    pub pool_id: String,
    /// CIDR ranges the client IP must fall into; empty matches every client.
    #[serde(default)]
    pub ip_ranges: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HealthCheckConfig {
    pub enabled: bool,
    pub path: String,
    pub interval_seconds: u32,
    pub timeout_ms: u32,
    pub unhealthy_threshold: u32,
    pub healthy_threshold: u32,
}

impl RuleCache {
    /// Convert a proto RuleBundle into local SiteRules.
    pub(super) fn convert_bundle(bundle: &proto::RuleBundle) -> SiteRules {
        SiteRules {
            site_id: bundle.site_id.clone(),
            domain: String::new(), // Will be set from Site if available
            alternate_domains: Vec::new(),
            config_hash: bundle.config_hash.clone(),
            // Set from the owning `Site` in `update_from_site_config`.
            status: default_site_status(),
            waf_config: bundle.waf.as_ref().map(Self::convert_waf_config),
            rate_limit_rules: bundle
                .rate_limit_rules
                .iter()
                .map(Self::convert_rate_limit_rule)
                .collect(),
            ip_access_rules: bundle
                .ip_access_rules
                .iter()
                .map(Self::convert_ip_access_rule)
                .collect(),
            geo_config: bundle.geo.as_ref().map(Self::convert_geo_config),
            cache_rules: bundle
                .cache_rules
                .iter()
                .map(Self::convert_cache_rule)
                .collect(),
            challenge_config: bundle
                .challenge
                .as_ref()
                .map(Self::convert_challenge_config),
            rewrite_rules: bundle
                .rewrite_rules
                .iter()
                .map(Self::convert_rewrite_rule)
                .collect(),
            error_pages: bundle
                .error_pages
                .iter()
                .map(Self::convert_error_page)
                .collect(),
            ssl_config: bundle.ssl.as_ref().map(Self::convert_ssl_config),
            upstreams: bundle
                .upstreams
                .iter()
                .map(Self::convert_upstream_config)
                .collect(),
            routes: bundle
                .routes
                .iter()
                .map(Self::convert_route_config)
                .collect(),
            bot_protection: bundle
                .bot_protection
                .as_ref()
                .map(Self::convert_bot_protection),
            basic_auth: bundle
                .basic_auth
                .as_ref()
                .map(Self::convert_basic_auth),
            observation_mode: bundle.observation_mode,
            proxy_trust: ProxyTrustConfig::default(),
            cache_settings: bundle
                .cache_settings
                .as_ref()
                .map(Self::convert_site_cache_settings),
        }
    }

    pub(super) fn convert_global_cache(
        g: &proto::GlobalCacheSettings,
    ) -> GlobalCacheSettings {
        GlobalCacheSettings {
            max_file_size_mb: g.max_file_size_mb,
            max_space_mb: g.max_space_mb,
            master_enabled: g.master_enabled,
            default_edge_ttl_seconds: g.default_edge_ttl_seconds,
        }
    }

    pub(super) fn convert_site_cache_settings(
        s: &proto::SiteCacheSettings,
    ) -> SiteCacheSettings {
        SiteCacheSettings {
            max_file_size_mb: s.max_file_size_mb,
            type_max_file_size_mb: s.type_max_file_size_mb.clone(),
        }
    }

    pub(super) fn convert_waf_config(w: &proto::WafConfig) -> WafConfig {
        WafConfig {
            enabled: w.enabled,
            mode: WafMode::from(w.mode),
            paranoia_level: w.paranoia_level,
            sqli_detection: w.sqli_detection,
            xss_detection: w.xss_detection,
            rce_detection: w.rce_detection,
            lfi_detection: w.lfi_detection,
            ssrf_detection: w.ssrf_detection,
            bot_detection: w.bot_detection,
            custom_rules: w
                .custom_rules
                .iter()
                .map(|r| WafRule {
                    id: r.id.clone(),
                    name: r.name.clone(),
                    description: r.description.clone(),
                    expression: r.expression.clone(),
                    action: WafAction::from(r.action),
                    severity: r.severity,
                    tags: r.tags.clone(),
                    enabled: r.enabled,
                    mode: WafMode::from(r.mode),
                    priority: r.priority,
                })
                .collect(),
            managed_overrides: w
                .managed_overrides
                .iter()
                .map(|o| RuleOverride {
                    rule_id: o.rule_id.clone(),
                    tag: o.tag.clone(),
                    action: WafAction::from(o.action),
                    enabled: o.enabled,
                })
                .collect(),
            ml_enabled: w.ml_enabled,
            ml_model_path: w.ml_model_path.clone(),
            ml_threshold: w.ml_threshold,
            anomaly_threshold: w.anomaly_threshold,
            advanced_mode: w.advanced_mode,
            engine_mode: if w.engine_mode.is_empty() {
                default_engine_mode()
            } else {
                w.engine_mode.clone()
            },
            virtual_patches: w.virtual_patches.clone(),
            openapi_spec: w.openapi_spec.clone(),
            monitor_categories: w.monitor_categories.clone(),
            monitor_stacks: w.monitor_stacks.clone(),
            monitor_managed_rules: w.monitor_managed_rules.clone(),
            disabled_rules: w.disabled_rules.clone(),
            rule_scores: w.rule_scores.clone(),
            rule_target_exclusions: w
                .rule_target_exclusions
                .iter()
                // Path-scoped entries live in `path_target_exclusions`; a
                // package exclusion must never widen into a site-wide one.
                .filter(|entry| entry.path_prefix.is_empty())
                .map(|entry| (entry.rule_id.clone(), entry.targets.clone()))
                .collect(),
            path_target_exclusions: w
                .rule_target_exclusions
                .iter()
                .filter(|entry| !entry.path_prefix.is_empty())
                .map(|entry| PathTargetExclusion {
                    rule_id: entry.rule_id.clone(),
                    targets: entry.targets.clone(),
                    path_prefix: entry.path_prefix.clone(),
                })
                .collect(),
            api_operations: w
                .api_operations
                .iter()
                .map(|entry| ApiOperationControl {
                    method: entry.method.clone(),
                    path: entry.path.clone(),
                    mode: entry.mode.clone(),
                })
                .collect(),
        }
    }

    pub(super) fn convert_rate_limit_rule(
        r: &proto::RateLimitRule,
    ) -> RateLimitRule {
        RateLimitRule {
            id: r.id.clone(),
            name: r.name.clone(),
            expression: r.expression.clone(),
            characteristics: r
                .characteristics
                .iter()
                .map(|c| {
                    format!(
                        "{:?}",
                        proto::RateLimitCharacteristics::try_from(*c)
                            .unwrap_or(
                            proto::RateLimitCharacteristics::RateLimitCharIp
                        )
                    )
                })
                .collect(),
            characteristic_params: r.characteristic_params.clone(),
            period_seconds: r.period_seconds,
            threshold: r.threshold,
            action: WafAction::from(r.action),
            mitigation_timeout_seconds: r.mitigation_timeout_seconds,
            enabled: r.enabled,
            priority: r.priority,
        }
    }

    pub(super) fn convert_ip_access_rule(
        r: &proto::IpAccessRule,
    ) -> IpAccessRule {
        IpAccessRule {
            id: r.id.clone(),
            name: r.name.clone(),
            ip_ranges: r.ip_ranges.clone(),
            action: IpAccessAction::from(r.action),
            note: r.note.clone(),
            enabled: r.enabled,
        }
    }

    pub(super) fn convert_geo_config(g: &proto::GeoConfig) -> GeoConfig {
        GeoConfig {
            enabled: g.enabled,
            blocked_countries: g.blocked_countries.clone(),
            allowed_countries: g.allowed_countries.clone(),
            blocked_asns: g.blocked_asns.clone(),
            block_unknown: g.block_unknown,
            action: WafAction::from(g.action),
            country_ranges: g.country_ranges.clone(),
            asn_ranges: g.asn_ranges.clone(),
            missing_keys: g.missing_keys.clone(),
        }
    }

    pub(super) fn convert_cache_rule(c: &proto::CacheRule) -> CacheRule {
        CacheRule {
            id: c.id.clone(),
            name: c.name.clone(),
            match_expression: c.match_expression.clone(),
            edge_ttl_seconds: c.edge_ttl_seconds,
            browser_ttl_seconds: c.browser_ttl_seconds,
            disk_quota_mb: c.disk_quota_mb,
            cache_eligible: c.cache_eligible,
            cache_key_headers: c.cache_key_headers.clone(),
            respect_origin_headers: c.respect_origin_headers,
            stale_while_revalidate_seconds: c.stale_while_revalidate_seconds,
            enabled: c.enabled,
        }
    }

    pub(super) fn convert_challenge_config(
        c: &proto::ChallengeConfig,
    ) -> ChallengeConfig {
        ChallengeConfig {
            enabled: c.enabled,
            under_attack_mode: c.under_attack_mode,
            default_level: ChallengeLevel::from(c.default_level),
            clearance_duration_seconds: c.clearance_duration_seconds,
            exempt_paths: c.exempt_paths.clone(),
            request_threshold: c.request_threshold,
            browser_integrity_check: c.browser_integrity_check,
            tls_fingerprint_check: c.tls_fingerprint_check,
        }
    }

    pub(super) fn convert_bot_protection(
        b: &proto::BotProtectionConfig,
    ) -> BotProtectionConfig {
        BotProtectionConfig {
            enabled: b.enabled,
            action: WafAction::from(b.action),
            known_bots_whitelist: b.known_bots_whitelist.clone(),
            js_detection: b.js_detection,
            tls_fingerprint: b.tls_fingerprint,
            behavioral_analysis: b.behavioral_analysis,
            verified_bot_ranges: b.verified_bot_ranges.clone(),
            dns_verification_enabled: b.dns_verification_enabled,
        }
    }

    pub(super) fn convert_basic_auth(
        b: &proto::BasicAuthConfig,
    ) -> BasicAuthConfig {
        BasicAuthConfig {
            enabled: b.enabled,
            realm: b.realm.clone(),
            credentials: b
                .credentials
                .iter()
                .map(|credential| BasicAuthCredential {
                    username: credential.username.clone(),
                    authorization: credential.authorization.clone(),
                })
                .collect(),
            delay_seconds: b.delay_seconds,
            hide_credentials: b.hide_credentials,
        }
    }

    pub(super) fn convert_rewrite_rule(r: &proto::RewriteRule) -> RewriteRule {
        RewriteRule {
            id: r.id.clone(),
            name: r.name.clone(),
            match_expression: r.match_expression.clone(),
            direction: RewriteDirection::from(r.direction),
            operations: r
                .operations
                .iter()
                .map(|o| RewriteOperation {
                    op_type: o.r#type.clone(),
                    name: o.name.clone(),
                    value: o.value.clone(),
                })
                .collect(),
            enabled: r.enabled,
            priority: r.priority,
        }
    }

    pub(super) fn convert_error_page(
        e: &proto::CustomErrorPage,
    ) -> CustomErrorPage {
        CustomErrorPage {
            id: e.id.clone(),
            status_code: e.status_code,
            content_type: e.content_type.clone(),
            body_template: e.body_template.clone(),
            name: e.name.clone(),
            enabled: e.enabled,
        }
    }

    pub(super) fn convert_ssl_config(s: &proto::SslConfig) -> SslConfig {
        SslConfig {
            cert_pem: s.cert_pem.clone(),
            key_pem: s.key_pem.clone(),
            acme_enabled: s.acme_enabled,
            acme_email: s.acme_email.clone(),
            acme_challenge_type: format!(
                "{:?}",
                proto::AcmeChallengeType::try_from(s.acme_challenge_type)
                    .unwrap_or(proto::AcmeChallengeType::AcmeHttp01)
            ),
            acme_dns_provider: s.acme_dns_provider.clone(),
            acme_dns_config: s.acme_dns_config.clone(),
            min_tls_version: s.min_tls_version.clone(),
            hsts_enabled: s.hsts_enabled,
            hsts_max_age: s.hsts_max_age,
            always_use_https: s.always_use_https,
            enabled: s.enabled,
            max_tls_version: s.max_tls_version.clone(),
            self_signed: s.self_signed,
            mtls_enabled: s.mtls_enabled,
            mtls_client_ca: s.mtls_client_ca.clone(),
            certificate_id: s.certificate_id.clone(),
            domains: s.domains.clone(),
            mtls_revoked_fingerprints: s
                .mtls_revoked_fingerprints
                .iter()
                .map(|f| f.to_lowercase())
                .collect(),
            mtls_organization: s.mtls_organization.clone(),
            mtls_require_client_cert: Some(s.mtls_require_client_cert),
        }
    }

    pub(super) fn convert_upstream_config(
        u: &proto::UpstreamConfig,
    ) -> UpstreamConfig {
        UpstreamConfig {
            name: u.name.clone(),
            peers: u
                .peers
                .iter()
                .map(|p| UpstreamPeer {
                    address: p.address.clone(),
                    weight: p.weight,
                    tls: p.tls,
                })
                .collect(),
            // `algo` carries the full pingap spec; the legacy enum is kept for
            // caches that predate it.
            algo: if u.algo.is_empty() {
                format!(
                    "{:?}",
                    proto::LoadBalanceAlgorithm::try_from(u.algorithm)
                        .unwrap_or(proto::LoadBalanceAlgorithm::LbRoundRobin)
                )
                .to_lowercase()
            } else {
                u.algo.clone()
            },
            algorithm: format!(
                "{:?}",
                proto::LoadBalanceAlgorithm::try_from(u.algorithm)
                    .unwrap_or(proto::LoadBalanceAlgorithm::LbRoundRobin)
            ),
            health_check: u.health_check.as_ref().map(|h| HealthCheckConfig {
                enabled: h.enabled,
                path: h.path.clone(),
                interval_seconds: h.interval_seconds,
                timeout_ms: h.timeout_ms,
                unhealthy_threshold: h.unhealthy_threshold,
                healthy_threshold: h.healthy_threshold,
            }),
            connection_timeout_ms: u.connection_timeout_ms,
            read_timeout_ms: u.read_timeout_ms,
            write_timeout_ms: u.write_timeout_ms,
            pool_id: u.pool_id.clone(),
            sni: u.sni.clone(),
            // Verification is opt-in: an unset flag means lenient (do not
            // verify the origin certificate), matching the control plane's
            // default. Explicit true keeps strict validation.
            verify_cert: Some(u.verify_cert.unwrap_or(false)),
            is_default: u.is_default,
        }
    }

    pub(super) fn convert_route_config(r: &proto::RouteConfig) -> RouteConfig {
        RouteConfig {
            id: r.id.clone(),
            name: r.name.clone(),
            match_type: r.match_type.clone(),
            path: r.path.clone(),
            priority: r.priority,
            enabled: r.enabled,
            pool_id: r.pool_id.clone(),
            ip_ranges: r.ip_ranges.clone(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Path-scoped exclusions stay out of the site-wide map: a package
    /// exclusion must never widen beyond its prefix.
    #[test]
    fn path_scoped_exclusions_stay_out_of_the_site_wide_map() {
        let proto_config = proto::WafConfig {
            enabled: true,
            rule_target_exclusions: vec![
                proto::RuleTargetExclusions {
                    rule_id: "VARMAN-1020".to_string(),
                    targets: vec!["path".to_string()],
                    path_prefix: "/.git".to_string(),
                },
                proto::RuleTargetExclusions {
                    rule_id: "VARMAN-1003".to_string(),
                    targets: vec!["body".to_string()],
                    path_prefix: String::new(),
                },
            ],
            ..Default::default()
        };
        let cfg = RuleCache::convert_waf_config(&proto_config);
        assert_eq!(cfg.path_target_exclusions.len(), 1);
        assert_eq!(cfg.path_target_exclusions[0].path_prefix, "/.git");
        assert_eq!(cfg.path_target_exclusions[0].targets, vec!["path"]);
        assert_eq!(
            cfg.rule_target_exclusions.len(),
            1,
            "only the site-wide entry stays in the map"
        );
        assert!(cfg.rule_target_exclusions.contains_key("VARMAN-1003"));
    }

    /// A `sites.json` written before origin pools existed carries none of the
    /// new fields; it must still load.
    #[test]
    fn old_cache_format_still_deserializes() {
        let old = serde_json::json!({
            "sites": {
                "site-1": {
                    "site_id": "site-1",
                    "domain": "example.com",
                    "alternate_domains": [],
                    "rate_limit_rules": [],
                    "ip_access_rules": [],
                    "cache_rules": [],
                    "rewrite_rules": [],
                    "error_pages": [],
                    "upstreams": [
                        {
                            "name": "example.com",
                            "peers": [{"address": "10.0.0.1:80", "weight": 1, "tls": false}],
                            "algorithm": "LbRoundRobin",
                            "connection_timeout_ms": 0,
                            "read_timeout_ms": 0,
                            "write_timeout_ms": 0
                        }
                    ]
                }
            },
            "domain_index": {"example.com": "site-1"},
            "updated_at": "2026-01-01T00:00:00Z",
            "config_hash": "abc"
        });
        let cached: CachedRules =
            serde_json::from_str(&old.to_string()).expect("old format loads");
        let site = cached.sites.get("site-1").expect("site present");
        assert!(site.routes.is_empty());
        assert_eq!(site.upstreams.len(), 1);
        assert!(site.upstreams[0].pool_id.is_empty());
        assert!(!site.upstreams[0].is_default);
        // The failover fields default sensibly on a cache written before
        // they existed: an empty registry and an unsynced global default.
        assert!(cached.failover_registry.is_empty());
        assert_eq!(cached.global_fail_open, None);
    }

    #[test]
    fn failover_registry_covers_alternate_domains() {
        use proto::SitePolicy;
        let policies = [SitePolicy {
            domain: "example.com".to_string(),
            alternate_domains: vec!["m.example.com".to_string()],
            mode: proto::FailoverMode::FailoverClosed as i32,
        }];
        let registry = failover_registry_from(&policies);
        assert_eq!(registry.get("example.com"), Some(&FailoverMode::Closed));
        assert_eq!(registry.get("m.example.com"), Some(&FailoverMode::Closed));
        assert_eq!(registry.get("other.example.com"), None);
    }

    #[test]
    fn unknown_failover_modes_degrade_to_inherit() {
        assert_eq!(FailoverMode::from(0), FailoverMode::Inherit);
        assert_eq!(FailoverMode::from(1), FailoverMode::Open);
        assert_eq!(FailoverMode::from(2), FailoverMode::Closed);
        assert_eq!(FailoverMode::from(99), FailoverMode::Inherit);
    }

    #[test]
    fn unknown_waf_mode_enforces_fail_close() {
        assert_eq!(WafMode::from(0), WafMode::Off);
        assert_eq!(WafMode::from(1), WafMode::Monitor);
        assert_eq!(WafMode::from(2), WafMode::Block);
        // An unknown enum value from a newer control plane must not switch
        // the site's WAF off for the upgrade window.
        assert_eq!(WafMode::from(7), WafMode::Block);
    }

    #[test]
    fn unknown_challenge_level_enforces_fail_close() {
        assert_eq!(ChallengeLevel::from(0), ChallengeLevel::None);
        assert_eq!(ChallengeLevel::from(3), ChallengeLevel::Interactive);
        // Degrading to None would silently stop challenging; the strongest
        // level keeps the protection.
        assert_eq!(ChallengeLevel::from(9), ChallengeLevel::Interactive);
    }

    #[test]
    fn new_format_roundtrips() {
        let cached = CachedRules {
            sites: [(
                "site-1".to_string(),
                Arc::new(SiteRules {
                    site_id: "site-1".to_string(),
                    domain: "example.com".to_string(),
                    alternate_domains: Vec::new(),
                    config_hash: String::new(),
                    status: site_status::PAUSED.to_string(),
                    waf_config: None,
                    rate_limit_rules: Vec::new(),
                    ip_access_rules: Vec::new(),
                    geo_config: None,
                    cache_rules: Vec::new(),
                    challenge_config: None,
                    rewrite_rules: Vec::new(),
                    error_pages: Vec::new(),
                    basic_auth: None,
                    observation_mode: false,
                    proxy_trust: ProxyTrustConfig::default(),
                    cache_settings: None,
                    ssl_config: None,
                    upstreams: vec![UpstreamConfig {
                        name: "default".to_string(),
                        peers: Vec::new(),
                        algorithm: "LbRoundRobin".to_string(),
                        health_check: None,
                        connection_timeout_ms: 0,
                        read_timeout_ms: 0,
                        write_timeout_ms: 0,
                        pool_id: "pool-1".to_string(),
                        algo: "hash:header:x-user".to_string(),
                        sni: "origin.example.com".to_string(),
                        verify_cert: Some(false),
                        is_default: true,
                    }],
                    routes: vec![RouteConfig {
                        id: "route-1".to_string(),
                        name: "api".to_string(),
                        match_type: "exact".to_string(),
                        path: "/api".to_string(),
                        priority: Some(10),
                        enabled: true,
                        pool_id: "pool-1".to_string(),
                        ip_ranges: vec!["10.0.0.0/8".to_string()],
                    }],
                    bot_protection: None,
                }),
            )]
            .into_iter()
            .collect(),
            domain_index: HashMap::new(),
            failover_registry: HashMap::from([(
                "example.com".to_string(),
                FailoverMode::Closed,
            )]),
            global_fail_open: Some(true),
            global_cache: None,
            updated_at: Utc::now(),
            config_hash: "abc".into(),
            data_plane_hash: "abc".into(),
            policy_revision: 0,
        };
        let json = serde_json::to_string(&cached).expect("serialize");
        let back: CachedRules =
            serde_json::from_str(&json).expect("deserialize");
        assert_eq!(
            back.failover_registry.get("example.com"),
            Some(&FailoverMode::Closed)
        );
        assert_eq!(back.global_fail_open, Some(true));
        let site = back.sites.get("site-1").expect("site present");
        assert_eq!(site.routes.len(), 1);
        assert_eq!(site.routes[0].path, "/api");
        assert_eq!(site.routes[0].ip_ranges, vec!["10.0.0.0/8"]);
        assert!(site.is_paused());
        assert_eq!(site.status, site_status::PAUSED);
        assert_eq!(site.upstreams[0].algo, "hash:header:x-user");
        assert_eq!(site.upstreams[0].sni, "origin.example.com");
    }

    #[test]
    fn old_cache_defaults_new_fields() {
        // A cache persisted before `status`/`ip_ranges`/mTLS extras existed.
        let old = serde_json::json!({
            "sites": {
                "site-1": {
                    "site_id": "site-1",
                    "domain": "example.com",
                    "alternate_domains": [],
                    "rate_limit_rules": [],
                    "ip_access_rules": [],
                    "cache_rules": [],
                    "rewrite_rules": [],
                    "error_pages": [],
                    "upstreams": [],
                    "routes": [{
                        "id": "route-1",
                        "name": "api",
                        "match_type": "prefix",
                        "path": "/api",
                        "priority": null,
                        "enabled": true,
                        "pool_id": "pool-1"
                    }],
                    "ssl_config": {
                        "cert_pem": "",
                        "key_pem": "",
                        "acme_enabled": false,
                        "acme_email": "",
                        "acme_challenge_type": "AcmeHttp01",
                        "acme_dns_provider": "",
                        "acme_dns_config": {},
                        "min_tls_version": "",
                        "hsts_enabled": false,
                        "hsts_max_age": 0,
                        "always_use_https": false,
                        "enabled": true,
                        "max_tls_version": "",
                        "self_signed": false,
                        "mtls_enabled": true,
                        "mtls_client_ca": "PEM",
                        "certificate_id": ""
                    }
                }
            },
            "domain_index": {"example.com": "site-1"},
            "updated_at": "2026-01-01T00:00:00Z",
            "config_hash": "abc"
        });
        let cached: CachedRules =
            serde_json::from_str(&old.to_string()).expect("old format loads");
        let site = cached.sites.get("site-1").expect("site present");
        assert_eq!(site.status, site_status::ACTIVE);
        assert!(!site.is_paused());
        assert!(site.routes[0].ip_ranges.is_empty());
        let ssl = site.ssl_config.as_ref().expect("ssl config");
        assert!(ssl.mtls_revoked_fingerprints.is_empty());
        assert!(ssl.mtls_organization.is_empty());
        assert!(ssl.mtls_requires_cert());
        // The cache ceiling fields default when a pre-ceiling cache loads.
        assert!(cached.global_cache.is_none());
        assert!(site.cache_settings.is_none());
    }

    #[test]
    fn proto_conversion_carries_status_and_new_fields() {
        let site = proto::Site {
            id: "site-1".to_string(),
            name: "Example".to_string(),
            domain: "example.com".to_string(),
            alternate_domains: Vec::new(),
            status: 1, // SITE_STATUS_PAUSED
            rules: Some(proto::RuleBundle {
                ssl: Some(proto::SslConfig {
                    mtls_enabled: true,
                    mtls_revoked_fingerprints: vec!["AB".to_string()],
                    mtls_organization: "acme".to_string(),
                    mtls_require_client_cert: true,
                    ..Default::default()
                }),
                routes: vec![proto::RouteConfig {
                    ip_ranges: vec!["10.0.0.0/8".to_string()],
                    ..Default::default()
                }],
                ..Default::default()
            }),
            trust_proxy_headers: false,
            trusted_header: String::new(),
            trust_last_hop: false,
            trusted_proxy_ranges: Vec::new(),
        };
        assert_eq!(site_status_str(site.status), site_status::PAUSED);
        let rules =
            RuleCache::convert_bundle(site.rules.as_ref().expect("bundle"));
        let ssl = rules.ssl_config.as_ref().expect("ssl config");
        assert_eq!(ssl.mtls_revoked_fingerprints, vec!["ab".to_string()]);
        assert_eq!(ssl.mtls_organization, "acme");
        assert!(ssl.mtls_requires_cert());
        assert_eq!(rules.routes[0].ip_ranges, vec!["10.0.0.0/8"]);
        assert_eq!(site_status_str(0), site_status::ACTIVE);
        assert_eq!(site_status_str(2), site_status::PENDING);
        assert_eq!(site_status_str(7), site_status::ACTIVE);
    }

    #[test]
    fn optional_mtls_does_not_require_a_client_certificate() {
        let site = proto::Site {
            id: "site-1".to_string(),
            name: "Example".to_string(),
            domain: "example.com".to_string(),
            alternate_domains: Vec::new(),
            status: 0,
            rules: Some(proto::RuleBundle {
                ssl: Some(proto::SslConfig {
                    mtls_enabled: true,
                    mtls_client_ca: "PEM".to_string(),
                    mtls_require_client_cert: false,
                    ..Default::default()
                }),
                ..Default::default()
            }),
            trust_proxy_headers: false,
            trusted_header: String::new(),
            trust_last_hop: false,
            trusted_proxy_ranges: Vec::new(),
        };
        let rules =
            RuleCache::convert_bundle(site.rules.as_ref().expect("bundle"));
        let ssl = rules.ssl_config.as_ref().expect("ssl config");
        assert!(ssl.mtls_enabled);
        assert!(!ssl.mtls_requires_cert());
    }

    #[test]
    fn proto_algo_supersedes_legacy_algorithm() {
        let mut u = proto::UpstreamConfig {
            algorithm: 1, // LB_CONSISTENT_HASH
            ..Default::default()
        };
        let converted = RuleCache::convert_upstream_config(&u);
        assert_eq!(converted.algo, "lbconsistenthash");

        u.algo = "hash:cookie:session".to_string();
        let converted = RuleCache::convert_upstream_config(&u);
        assert_eq!(converted.algo, "hash:cookie:session");
    }
}
