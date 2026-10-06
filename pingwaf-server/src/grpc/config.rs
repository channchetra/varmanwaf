//! Translates database rows into the protocol messages agents consume.
//!
//! Everything the agents need — WAF rules, rate limits, cache policy, upstreams
//! and TLS material — is assembled here, which keeps the gRPC service layer free
//! of SQL and lets the REST API reuse the exact same builder when it pushes a
//! configuration update to a connected agent.

use std::collections::{HashMap, HashSet};

use base64::engine::general_purpose::STANDARD as BASE64_STANDARD;
use base64::Engine;
use chrono::{DateTime, TimeZone, Utc};
use pingwaf_proto::control_plane::{
    BasicAuthConfig, BasicAuthCredential, BotProtectionConfig, CacheRule,
    ChallengeConfig, CustomErrorPage, GeoConfig, IpAccessRule, RateLimitRule,
    RewriteOperation, RewriteRule, RouteConfig, RuleBundle, Site, SiteConfig,
    SslConfig, UpstreamConfig, UpstreamPeer, WafConfig, WafRule,
};
use prost::Message;
use prost_types::Timestamp;
use sea_orm::{
    ColumnTrait, DatabaseConnection, EntityTrait, QueryFilter, QueryOrder,
    QuerySelect, QueryTrait,
};
use uuid::Uuid;

use crate::api::challenge::challenge_level;
use crate::api::ip_rules::ip_action;
use crate::api::site_basic_auth as site_basic_auth_api;
use crate::models::{
    acme_challenge, action, bot_protection, cache_rules, challenge_settings,
    characteristic, client_cert_status, defense_settings, error_pages,
    geo_rules, ip_access_rules, ip_group_sites, ip_groups, mode,
    mtls_client_certificate, rate_limit_rules, rewrite_rules, rule,
    rule_groups, site, site_basic_auth, site_certificates, site_routes,
    site_ssl, site_status, site_upstream_pools, site_upstreams, waf_settings,
};
use crate::pki::mtls::normalise_fingerprint;

/// `pingwaf.WafMode` values from control_plane.proto.
///
/// The numbers are spelled out instead of referencing the generated enum
/// variants: prost strips a value prefix that matches the enum name, and the
/// control plane should not depend on that naming rule.
const WAF_MODE_OFF: i32 = 0;
const WAF_MODE_MONITOR: i32 = 1;
const WAF_MODE_BLOCK: i32 = 2;

/// Converts a `DateTime<Utc>` into the protocol's timestamp.
pub fn to_timestamp(value: DateTime<Utc>) -> Option<Timestamp> {
    Some(Timestamp {
        seconds: value.timestamp(),
        nanos: value.timestamp_subsec_nanos() as i32,
    })
}

/// `to_timestamp` for "now".
pub fn now_timestamp() -> Option<Timestamp> {
    to_timestamp(Utc::now())
}

/// Converts a protocol timestamp back into a `DateTime<Utc>`, defaulting to the
/// current time when the agent omitted it.
pub fn from_timestamp(value: Option<&Timestamp>) -> DateTime<Utc> {
    match value {
        Some(ts) => Utc
            .timestamp_opt(ts.seconds, ts.nanos.max(0) as u32)
            .single()
            .unwrap_or_else(Utc::now),
        None => Utc::now(),
    }
}

/// Maps the persisted site status onto `pingwaf.SiteStatusEnum`.
///
/// The numeric values are used directly because prost's variant naming for
/// prefixed enum entries is not something the control plane should depend on.
pub fn site_status_proto(status: &str) -> i32 {
    match status {
        site_status::ACTIVE => 0,  // SITE_STATUS_ACTIVE
        site_status::PAUSED => 1,  // SITE_STATUS_PAUSED
        site_status::PENDING => 2, // SITE_STATUS_PENDING
        _ => 0,
    }
}

/// Maps the persisted ACME challenge type onto `pingwaf.AcmeChallengeType`.
pub fn acme_challenge_proto(challenge: Option<&str>) -> i32 {
    match challenge {
        Some(acme_challenge::DNS_01) => 1, // ACME_DNS_01
        _ => 0,                            // ACME_HTTP_01
    }
}

/// FNV-1a over 64 bits; used to fingerprint a configuration without pulling in
/// a hashing crate.
fn fnv1a64(bytes: &[u8]) -> u64 {
    let mut hash: u64 = 0xcbf2_9ce4_8422_2325;
    for byte in bytes {
        hash ^= u64::from(*byte);
        hash = hash.wrapping_mul(0x0000_0100_0000_01b3);
    }
    hash
}

/// Stable 16-hex-character fingerprint of any protobuf message.
pub fn fingerprint<T: Message>(message: &T) -> String {
    let mut buf = Vec::with_capacity(message.encoded_len());
    // `encode` only fails when the buffer is too small, which cannot happen for
    // a `Vec` sized with `encoded_len()`.
    let _ = message.encode(&mut buf);
    format!("{:016x}", fnv1a64(&buf))
}

/// Flattens a JSON object into the `map<string, string>` shape the protocol
/// expects; non-object or non-string values are stringified.
fn json_to_string_map(
    value: &Option<serde_json::Value>,
) -> HashMap<String, String> {
    let mut map = HashMap::new();
    if let Some(serde_json::Value::Object(object)) = value {
        for (key, raw) in object {
            let text = match raw {
                serde_json::Value::String(s) => s.clone(),
                other => other.to_string(),
            };
            map.insert(key.clone(), text);
        }
    }
    map
}

/// Loads the WAF rule rows of a site, ordered by priority then name so that the
/// fingerprint does not change between otherwise identical configurations.
async fn load_rules(
    db: &DatabaseConnection,
    site_id: Uuid,
) -> Result<Vec<rule::Model>, sea_orm::DbErr> {
    rule::Entity::find()
        .filter(rule::Column::SiteId.eq(site_id))
        .order_by_asc(rule::Column::Priority)
        .order_by_asc(rule::Column::Name)
        .all(db)
        .await
}

async fn load_rule_groups(
    db: &DatabaseConnection,
    site_id: Uuid,
) -> Result<Vec<rule_groups::Model>, sea_orm::DbErr> {
    rule_groups::Entity::find()
        .filter(rule_groups::Column::SiteId.eq(site_id))
        .order_by_asc(rule_groups::Column::Priority)
        .all(db)
        .await
}

async fn load_rate_limits(
    db: &DatabaseConnection,
    site_id: Uuid,
) -> Result<Vec<rate_limit_rules::Model>, sea_orm::DbErr> {
    rate_limit_rules::Entity::find()
        .filter(rate_limit_rules::Column::SiteId.eq(site_id))
        .order_by_asc(rate_limit_rules::Column::Priority)
        .all(db)
        .await
}

async fn load_cache_rules(
    db: &DatabaseConnection,
    site_id: Uuid,
) -> Result<Vec<cache_rules::Model>, sea_orm::DbErr> {
    cache_rules::Entity::find()
        .filter(cache_rules::Column::SiteId.eq(site_id))
        .all(db)
        .await
}

async fn load_upstreams(
    db: &DatabaseConnection,
    site_id: Uuid,
) -> Result<Vec<site_upstreams::Model>, sea_orm::DbErr> {
    site_upstreams::Entity::find()
        .filter(site_upstreams::Column::SiteId.eq(site_id))
        .order_by_desc(site_upstreams::Column::Weight)
        .all(db)
        .await
}

async fn load_pools(
    db: &DatabaseConnection,
    site_id: Uuid,
) -> Result<Vec<site_upstream_pools::Model>, sea_orm::DbErr> {
    site_upstream_pools::Entity::find()
        .filter(site_upstream_pools::Column::SiteId.eq(site_id))
        .order_by_desc(site_upstream_pools::Column::IsDefault)
        .order_by_asc(site_upstream_pools::Column::CreatedAt)
        .all(db)
        .await
}

async fn load_routes(
    db: &DatabaseConnection,
    site_id: Uuid,
) -> Result<Vec<site_routes::Model>, sea_orm::DbErr> {
    site_routes::Entity::find()
        .filter(site_routes::Column::SiteId.eq(site_id))
        .order_by_desc(site_routes::Column::Priority)
        .order_by_asc(site_routes::Column::CreatedAt)
        .all(db)
        .await
}

async fn load_ssl(
    db: &DatabaseConnection,
    site_id: Uuid,
) -> Result<Option<site_ssl::Model>, sea_orm::DbErr> {
    site_ssl::Entity::find()
        .filter(site_ssl::Column::SiteId.eq(site_id))
        .one(db)
        .await
}

async fn load_certificates(
    db: &DatabaseConnection,
    site_id: Uuid,
) -> Result<Vec<site_certificates::Model>, sea_orm::DbErr> {
    site_certificates::Entity::find()
        .filter(site_certificates::Column::SiteId.eq(site_id))
        .order_by_desc(site_certificates::Column::UpdatedAt)
        .all(db)
        .await
}

async fn load_ip_access_rules(
    db: &DatabaseConnection,
    site_id: Uuid,
) -> Result<Vec<ip_access_rules::Model>, sea_orm::DbErr> {
    ip_access_rules::Entity::find()
        .filter(ip_access_rules::Column::SiteId.eq(site_id))
        .filter(ip_access_rules::Column::Enabled.eq(true))
        .order_by_asc(ip_access_rules::Column::Priority)
        .all(db)
        .await
}

/// Loads enabled IP groups that apply to a site: all global groups plus any
/// non-global group explicitly linked to the site via `ip_group_sites`.
async fn load_ip_groups(
    db: &DatabaseConnection,
    site_id: Uuid,
) -> Result<Vec<ip_groups::Model>, sea_orm::DbErr> {
    let linked_ids = ip_group_sites::Entity::find()
        .filter(ip_group_sites::Column::SiteId.eq(site_id))
        .select_only()
        .column(ip_group_sites::Column::IpGroupId)
        .into_query();

    ip_groups::Entity::find()
        .filter(ip_groups::Column::Enabled.eq(true))
        .filter(
            ip_groups::Column::IsGlobal
                .eq(true)
                .or(ip_groups::Column::Id.in_subquery(linked_ids)),
        )
        .order_by_asc(ip_groups::Column::Name)
        .all(db)
        .await
}

/// Loads the enabled IP groups referenced by the given access rules.
///
/// Group-backed rules expand against these rows at bundle time, so a group
/// update reaches agents without touching the rules themselves.
async fn load_referenced_groups(
    db: &DatabaseConnection,
    rules: &[ip_access_rules::Model],
) -> Result<HashMap<Uuid, ip_groups::Model>, sea_orm::DbErr> {
    let ids: Vec<Uuid> = rules.iter().filter_map(|r| r.group_id).collect();
    load_enabled_groups(db, ids).await
}

/// Loads the enabled IP groups gating the given routes. A group that is
/// missing or disabled expands to nothing, which drops the route from the
/// pushed config — the API refuses such writes, so this only happens after an
/// out-of-band change.
async fn load_route_groups(
    db: &DatabaseConnection,
    routes: &[site_routes::Model],
) -> Result<HashMap<Uuid, ip_groups::Model>, sea_orm::DbErr> {
    let ids: Vec<Uuid> = routes.iter().filter_map(|r| r.ip_group_id).collect();
    load_enabled_groups(db, ids).await
}

async fn load_enabled_groups(
    db: &DatabaseConnection,
    ids: Vec<Uuid>,
) -> Result<HashMap<Uuid, ip_groups::Model>, sea_orm::DbErr> {
    if ids.is_empty() {
        return Ok(HashMap::new());
    }
    let rows = ip_groups::Entity::find()
        .filter(ip_groups::Column::Enabled.eq(true))
        .filter(ip_groups::Column::Id.is_in(ids))
        .all(db)
        .await?;
    Ok(rows.into_iter().map(|g| (g.id, g)).collect())
}

async fn load_geo_rules(
    db: &DatabaseConnection,
    site_id: Uuid,
) -> Result<Option<geo_rules::Model>, sea_orm::DbErr> {
    geo_rules::Entity::find()
        .filter(geo_rules::Column::SiteId.eq(site_id))
        .one(db)
        .await
}

async fn load_challenge_settings(
    db: &DatabaseConnection,
    site_id: Uuid,
) -> Result<Option<challenge_settings::Model>, sea_orm::DbErr> {
    challenge_settings::Entity::find()
        .filter(challenge_settings::Column::SiteId.eq(site_id))
        .one(db)
        .await
}

async fn load_waf_settings(
    db: &DatabaseConnection,
    site_id: Uuid,
) -> Result<Option<waf_settings::Model>, sea_orm::DbErr> {
    waf_settings::Entity::find()
        .filter(waf_settings::Column::SiteId.eq(site_id))
        .one(db)
        .await
}

async fn load_basic_auth(
    db: &DatabaseConnection,
    site_id: Uuid,
) -> Result<Option<site_basic_auth::Model>, sea_orm::DbErr> {
    site_basic_auth::Entity::find()
        .filter(site_basic_auth::Column::SiteId.eq(site_id))
        .one(db)
        .await
}

async fn load_rewrite_rules(
    db: &DatabaseConnection,
    site_id: Uuid,
) -> Result<Vec<rewrite_rules::Model>, sea_orm::DbErr> {
    rewrite_rules::Entity::find()
        .filter(rewrite_rules::Column::SiteId.eq(site_id))
        .filter(rewrite_rules::Column::Enabled.eq(true))
        .order_by_asc(rewrite_rules::Column::Priority)
        .all(db)
        .await
}

/// Loads the enabled global error pages.
///
/// Error pages are deployment-wide, so every site's bundle carries the same
/// list; the data plane picks the template matching the status code it is about
/// to return.
async fn load_error_pages(
    db: &DatabaseConnection,
) -> Result<Vec<error_pages::Model>, sea_orm::DbErr> {
    error_pages::Entity::find()
        .filter(error_pages::Column::Enabled.eq(true))
        .order_by_asc(error_pages::Column::StatusCode)
        .all(db)
        .await
}

/// Turns a stored WAF rule into its protocol representation.
pub fn rule_to_proto(row: &rule::Model) -> WafRule {
    WafRule {
        id: row.id.to_string(),
        name: row.name.clone(),
        description: row.description.clone().unwrap_or_default(),
        expression: row.expression.clone(),
        action: action::to_proto(&row.action),
        severity: row.severity.max(0) as u32,
        tags: row.tags.clone(),
        enabled: row.enabled,
        mode: mode::to_proto(&row.mode),
        priority: row.priority.max(0) as u32,
    }
}

fn rate_limit_to_proto(row: &rate_limit_rules::Model) -> RateLimitRule {
    RateLimitRule {
        id: row.id.to_string(),
        name: row.name.clone(),
        expression: row.expression.clone(),
        characteristics: row
            .characteristics
            .iter()
            .map(|value| characteristic::to_proto(value))
            .collect(),
        characteristic_params: row
            .characteristics
            .iter()
            .map(|value| characteristic::to_param(value))
            .collect(),
        period_seconds: row.period_seconds.max(0) as u32,
        threshold: row.threshold.max(0) as u32,
        action: action::to_proto(&row.action),
        mitigation_timeout_seconds: row.mitigation_timeout_seconds.max(0)
            as u32,
        enabled: row.enabled,
        priority: row.priority.max(0) as u32,
    }
}

/// Turns a stored cache rule into its protocol representation.
///
/// `site_quota_mb` is the disk budget the agent enforces for the site; it is
/// carried on every rule because the budget is site-wide, and the agent applies
/// what it reads per hostname.
fn cache_rule_to_proto(
    row: &cache_rules::Model,
    site_quota_mb: i32,
) -> CacheRule {
    CacheRule {
        id: row.id.to_string(),
        name: row.name.clone(),
        match_expression: row.match_expression.clone(),
        edge_ttl_seconds: row.edge_ttl_seconds.max(0) as u32,
        browser_ttl_seconds: row.browser_ttl_seconds.max(0) as u32,
        disk_quota_mb: site_quota_mb.max(0) as u32,
        cache_eligible: row.cache_eligible,
        cache_key_headers: Vec::new(),
        respect_origin_headers: row.respect_origin,
        stale_while_revalidate_seconds: 0,
        enabled: row.enabled,
    }
}

fn ssl_to_proto(
    row: &site_ssl::Model,
    certs: &[site_certificates::Model],
    mtls: &MtlsPush,
) -> SslConfig {
    // The posture row selects a certificate but does not copy its material:
    // the PEM of an uploaded certificate and every ACME setting (email,
    // challenge type, DNS provider config) live on the `site_certificates`
    // row only, so they are backfilled here for the agent.
    let selected = row
        .certificate_id
        .and_then(|id| certs.iter().find(|cert| cert.id == id));
    let uploaded_pem = row.cert_pem.as_deref().is_some_and(|p| !p.is_empty());
    let cert_pem = if uploaded_pem {
        row.cert_pem.clone().unwrap_or_default()
    } else {
        selected
            .and_then(|cert| cert.cert_pem.clone())
            .unwrap_or_default()
    };
    let uploaded_key = row.key_pem.as_deref().is_some_and(|p| !p.is_empty());
    let key_pem = if uploaded_key {
        row.key_pem.clone().unwrap_or_default()
    } else {
        selected
            .and_then(|cert| cert.key_pem.clone())
            .unwrap_or_default()
    };
    let acme_email = row
        .acme_email
        .clone()
        .or_else(|| selected.and_then(|cert| cert.acme_email.clone()))
        .unwrap_or_default();
    let auto_renew =
        row.auto_renew || selected.is_some_and(|cert| cert.auto_renew);
    let acme_enabled = auto_renew && !acme_email.is_empty();
    let acme_challenge_type = acme_challenge_proto(
        row.acme_challenge_type.as_deref().or_else(|| {
            selected
                .as_ref()
                .map(|cert| cert.acme_challenge_type.as_str())
        }),
    );
    let acme_dns_provider = row
        .acme_dns_provider
        .clone()
        .or_else(|| selected.and_then(|cert| cert.acme_dns_provider.clone()))
        .unwrap_or_default();
    let acme_dns_config =
        json_to_string_map(&row.acme_dns_config.clone().or_else(|| {
            selected.and_then(|cert| cert.acme_dns_config.clone())
        }));
    let certificate_id = row
        .certificate_id
        .or(selected.map(|cert| cert.id))
        .map(|id| id.to_string())
        .unwrap_or_default();
    SslConfig {
        cert_pem,
        key_pem,
        acme_enabled,
        acme_email,
        acme_challenge_type,
        acme_dns_provider,
        acme_dns_config,
        min_tls_version: row.min_tls_version.clone(),
        hsts_enabled: row.hsts_enabled,
        hsts_max_age: row.hsts_max_age.max(0) as u32,
        always_use_https: row.always_use_https,
        enabled: row.https_enabled,
        max_tls_version: row.max_tls_version.clone().unwrap_or_default(),
        self_signed: row.self_signed,
        mtls_enabled: row.mtls_enabled,
        mtls_client_ca: row.mtls_client_ca.clone().unwrap_or_default(),
        certificate_id,
        // Revocations and the expected organization come from the managed-CA
        // tables loaded by the caller.
        mtls_revoked_fingerprints: mtls.revoked_fingerprints.clone(),
        mtls_organization: row.mtls_organization.clone().unwrap_or_default(),
        // Turning mTLS on means clients must present a certificate.
        mtls_require_client_cert: row.mtls_enabled
            && row.mtls_require_client_cert,
    }
}

/// The mTLS material a site adds to the pushed configuration that is not stored
/// on `site_ssl`: the fingerprints the edge rejects.
///
/// The trust anchor itself travels as `SslConfig.mtls_client_ca`; the edge
/// unions the anchors of every mTLS site into the shared TLS listener.
#[derive(Debug, Default, Clone)]
pub struct MtlsPush {
    pub revoked_fingerprints: Vec<String>,
}

/// Loads the mTLS material pushed to agents for one site.
///
/// Only revoked certificates are pushed: the edge compares the fingerprint of
/// whatever the client presents against this list, so it stays small.
async fn load_mtls(
    db: &DatabaseConnection,
    site_id: Uuid,
) -> Result<MtlsPush, sea_orm::DbErr> {
    let revoked = mtls_client_certificate::Entity::find()
        .filter(mtls_client_certificate::Column::SiteId.eq(site_id))
        .filter(
            mtls_client_certificate::Column::Status
                .eq(client_cert_status::REVOKED),
        )
        .all(db)
        .await?;
    Ok(MtlsPush {
        revoked_fingerprints: revoked
            .into_iter()
            .map(|row| normalise_fingerprint(&row.fingerprint_sha256))
            .collect(),
    })
}

/// Turns origin pools into one `UpstreamConfig` per pool.
///
/// Pools without nodes are skipped: an empty upstream would make the agent
/// build a proxy with no peers to send traffic to.
fn pools_to_proto(
    pools: &[site_upstream_pools::Model],
    upstreams: &[site_upstreams::Model],
) -> Vec<UpstreamConfig> {
    let mut configs = Vec::with_capacity(pools.len());
    for pool in pools {
        let peers: Vec<UpstreamPeer> = upstreams
            .iter()
            .filter(|row| row.pool_id == pool.id)
            .map(|row| UpstreamPeer {
                address: row.address.clone(),
                weight: row.weight.max(0) as u32,
                tls: row.tls,
            })
            .collect();
        if peers.is_empty() {
            continue;
        }
        configs.push(UpstreamConfig {
            name: pool.name.clone(),
            peers,
            // LB_ROUND_ROBIN — the legacy enum, superseded by `algo`.
            algorithm: 0,
            health_check: None,
            connection_timeout_ms: 0,
            read_timeout_ms: 0,
            write_timeout_ms: 0,
            pool_id: pool.id.to_string(),
            algo: pool.lb_algorithm.clone(),
            sni: pool.sni.clone().unwrap_or_default(),
            verify_cert: pool.verify_cert,
            is_default: pool.is_default,
        });
    }
    configs
}

/// Turns stored routes into their protocol representation, dropping routes
/// that are disabled or point at a pool without nodes (the agent would have
/// no upstream to serve them with). The path is passed through verbatim; the
/// data plane adds the `=`/`~` marker pingap's location syntax expects.
///
/// A route gated on an IP group carries the group's ranges; a gate that no
/// longer resolves (group deleted or disabled behind the API's back) drops the
/// route rather than turning it into a match-everything location.
fn routes_to_proto(
    routes: &[site_routes::Model],
    pools: &[site_upstream_pools::Model],
    upstreams: &[site_upstreams::Model],
    groups: &HashMap<Uuid, ip_groups::Model>,
) -> Vec<RouteConfig> {
    let served: HashSet<Uuid> = pools
        .iter()
        .filter(|pool| upstreams.iter().any(|row| row.pool_id == pool.id))
        .map(|pool| pool.id)
        .collect();
    routes
        .iter()
        .filter(|route| route.enabled && served.contains(&route.pool_id))
        .filter_map(|route| {
            let ip_ranges = match route.ip_group_id {
                Some(group_id) => match groups.get(&group_id) {
                    Some(group) => group.ip_ranges.clone(),
                    None => {
                        tracing::warn!(
                            route = %route.id,
                            group = %group_id,
                            "route IP group is missing or disabled; route dropped",
                        );
                        return None;
                    },
                },
                None => Vec::new(),
            };
            Some(RouteConfig {
                id: route.id.to_string(),
                name: route.name.clone(),
                match_type: route.match_type.clone(),
                path: route.path.clone(),
                priority: route.priority,
                enabled: route.enabled,
                pool_id: route.pool_id.to_string(),
                ip_ranges,
            })
        })
        .collect()
}

/// Derives the site-wide WAF switches from the rules that are actually enabled,
/// merged with the site's `waf_settings` posture row when present. A missing
/// row keeps the historical behavior: everything enforced at the normal level.
fn waf_config_to_proto(
    rules: &[WafRule],
    groups: &[rule_groups::Model],
    settings: Option<&waf_settings::Model>,
) -> WafConfig {
    let active: Vec<&WafRule> = rules.iter().filter(|r| r.enabled).collect();

    // Blocking wins over monitoring, monitoring wins over off.
    let mode = if active.iter().any(|r| r.mode == WAF_MODE_BLOCK) {
        WAF_MODE_BLOCK
    } else if active.iter().any(|r| r.mode == WAF_MODE_MONITOR) {
        WAF_MODE_MONITOR
    } else {
        WAF_MODE_OFF
    };

    let has_tag = |needle: &str| {
        active.iter().any(|rule| {
            rule.tags
                .iter()
                .any(|tag| tag.to_ascii_lowercase().contains(needle))
        })
    };

    let any_group_enabled =
        groups.is_empty() || groups.iter().any(|group| group.enabled);

    let (advanced_mode, monitor_categories, monitor_stacks) = settings
        .map(|s| {
            (
                s.advanced_mode,
                s.monitor_categories.clone(),
                s.monitor_stacks.clone(),
            )
        })
        .unwrap_or_else(|| (false, Vec::new(), Vec::new()));

    // Advanced mode (strict + body inspection) and monitor downgrades are
    // meaningful only with the WAF on; a site with no custom rules but an
    // explicit posture still gets the managed ruleset.
    let enabled = (!active.is_empty()
        || advanced_mode
        || !monitor_categories.is_empty()
        || !monitor_stacks.is_empty())
        && any_group_enabled;

    WafConfig {
        enabled,
        mode,
        // Paranoia level is derived from the highest severity in use (1-5 maps
        // onto the 1-4 range the protocol allows).
        paranoia_level: active
            .iter()
            .map(|rule| rule.severity)
            .max()
            .map(|severity| severity.clamp(1, 4))
            .unwrap_or(1),
        sqli_detection: has_tag("sqli") || has_tag("sql-injection"),
        xss_detection: has_tag("xss"),
        rce_detection: has_tag("rce") || has_tag("command-injection"),
        lfi_detection: has_tag("lfi") || has_tag("file-inclusion"),
        ssrf_detection: has_tag("ssrf"),
        bot_detection: has_tag("bot"),
        custom_rules: rules.to_vec(),
        managed_overrides: Vec::new(),
        ml_enabled: false,
        ml_model_path: String::new(),
        ml_threshold: 0.0,
        anomaly_threshold: 0,
        advanced_mode,
        monitor_categories,
        monitor_stacks,
    }
}

/// Converts a stored IP access rule into its protocol representation.
///
/// Group-backed rules expand to the referenced group's live ranges while
/// keeping the rule's own action and note; rules with neither a resolvable
/// group nor their own ranges are skipped (they would match nothing).
fn ip_access_rule_to_proto(
    row: &ip_access_rules::Model,
    groups: &HashMap<Uuid, ip_groups::Model>,
) -> Option<IpAccessRule> {
    let mut ip_ranges = row.ip_ranges.clone();
    if let Some(group) = row.group_id.and_then(|gid| groups.get(&gid)) {
        ip_ranges = group.ip_ranges.clone();
    } else if ip_ranges.is_empty() {
        return None;
    }
    Some(IpAccessRule {
        id: row.id.to_string(),
        name: row.name.clone(),
        ip_ranges,
        action: ip_action::to_proto(&row.action),
        note: row.note.clone().unwrap_or_default(),
        enabled: row.enabled,
    })
}

/// Converts an IP group row into the same `IpAccessRule` proto message so that
/// agents can apply group-level allow/block lists alongside per-site rules.
fn ip_group_to_proto(row: &ip_groups::Model) -> IpAccessRule {
    IpAccessRule {
        id: row.id.to_string(),
        name: row.name.clone(),
        ip_ranges: row.ip_ranges.clone(),
        action: ip_action::to_proto(&row.action),
        note: row.description.clone().unwrap_or_default(),
        enabled: row.enabled,
    }
}

/// Converts stored geo rules into the protocol representation.
fn geo_to_proto(row: Option<&geo_rules::Model>) -> GeoConfig {
    match row {
        Some(g) => GeoConfig {
            enabled: g.enabled,
            blocked_countries: if g.mode == "block_list" {
                g.countries.clone()
            } else {
                Vec::new()
            },
            allowed_countries: if g.mode == "allow_list" {
                g.countries.clone()
            } else {
                Vec::new()
            },
            blocked_asns: g.blocked_asns.clone(),
            block_unknown: g.block_unknown,
            action: action::to_proto(&g.action),
        },
        None => GeoConfig {
            enabled: false,
            blocked_countries: Vec::new(),
            allowed_countries: Vec::new(),
            blocked_asns: Vec::new(),
            block_unknown: false,
            action: action::to_proto(action::BLOCK),
        },
    }
}

/// Converts stored challenge settings into the protocol representation.
fn challenge_to_proto(
    row: Option<&challenge_settings::Model>,
) -> ChallengeConfig {
    match row {
        Some(c) => ChallengeConfig {
            enabled: c.enabled,
            under_attack_mode: c.under_attack_mode,
            default_level: challenge_level::to_proto(&c.default_level),
            clearance_duration_seconds: c.clearance_duration_secs.max(0) as u32,
            exempt_paths: c.exempt_paths.clone(),
            request_threshold: c.rate_threshold.max(0) as u32,
            browser_integrity_check: c.browser_integrity_check,
            tls_fingerprint_check: c.tls_fingerprint_check,
        },
        None => ChallengeConfig {
            enabled: false,
            under_attack_mode: false,
            default_level: 0,
            clearance_duration_seconds: 0,
            exempt_paths: Vec::new(),
            request_threshold: 0,
            browser_integrity_check: false,
            tls_fingerprint_check: false,
        },
    }
}

/// Converts the site's basic auth row into the protocol representation.
///
/// The agent receives `Authorization` payloads the way a client would send
/// them — `Basic <base64(user:password)>` — so the password never has to be
/// encoded on the request path. A row that cannot be decoded ships disabled
/// rather than failing the whole bundle: an unreadable credential list must
/// not lock the site out.
fn basic_auth_to_proto(
    row: Option<&site_basic_auth::Model>,
) -> Option<BasicAuthConfig> {
    let row = row?;
    let credentials = match site_basic_auth_api::stored_credentials(row) {
        Ok(credentials) => credentials,
        Err(error) => {
            tracing::warn!(
                site_id = %row.site_id,
                error = %error,
                "basic auth credentials are unreadable; shipping the gate disabled"
            );
            Vec::new()
        },
    };
    let credentials: Vec<BasicAuthCredential> = credentials
        .iter()
        .map(|credential| BasicAuthCredential {
            username: credential.username.clone(),
            authorization: BASE64_STANDARD.encode(format!(
                "{}:{}",
                credential.username, credential.password
            )),
        })
        .collect();
    Some(BasicAuthConfig {
        enabled: row.enabled && !credentials.is_empty(),
        realm: row.realm.clone(),
        credentials,
        delay_seconds: row.delay_seconds.max(0) as u32,
        hide_credentials: row.hide_credentials,
    })
}

async fn load_bot_protection(
    db: &DatabaseConnection,
    site_id: Uuid,
) -> Result<Option<bot_protection::Model>, sea_orm::DbErr> {
    bot_protection::Entity::find()
        .filter(bot_protection::Column::SiteId.eq(site_id))
        .one(db)
        .await
}

/// Converts stored bot protection settings into the protocol representation.
///
/// The whitelist is stored as a JSON array of strings; malformed entries are
/// skipped so a bad edit in the control plane can never break agent config.
fn bot_protection_to_proto(
    row: Option<&bot_protection::Model>,
) -> BotProtectionConfig {
    let Some(row) = row else {
        return BotProtectionConfig {
            enabled: false,
            action: 0,
            known_bots_whitelist: Vec::new(),
        };
    };

    let known_bots_whitelist = row
        .known_bots_whitelist
        .as_array()
        .map(|items| {
            items
                .iter()
                .filter_map(|item| item.as_str().map(str::to_string))
                .collect::<Vec<String>>()
        })
        .unwrap_or_default();

    BotProtectionConfig {
        enabled: row.enabled && row.ua_analysis,
        action: action::to_proto(&row.action),
        known_bots_whitelist,
    }
}

/// Converts a stored rewrite rule into its protocol representation.
fn rewrite_rule_to_proto(row: &rewrite_rules::Model) -> RewriteRule {
    RewriteRule {
        id: row.id.to_string(),
        name: row.name.clone(),
        match_expression: row.condition_expr.clone().unwrap_or_default(),
        direction: if row.direction == "response" { 1 } else { 0 },
        operations: parse_operations(&row.operations),
        enabled: row.enabled,
        priority: row.priority.max(0) as u32,
    }
}

/// Parses the stored operations JSON array into proto operations. The console
/// stores `{type, name, value}` objects whose semantics depend on the type
/// (pattern/replacement for `regex_replace_path` and `replace_body`); they
/// pass through verbatim so the data plane sees exactly what was configured.
fn parse_operations(ops: &serde_json::Value) -> Vec<RewriteOperation> {
    let Some(items) = ops.as_array() else {
        return Vec::new();
    };
    items
        .iter()
        .filter_map(|item| {
            let obj = item.as_object()?;
            let r#type = obj
                .get("type")
                .and_then(|v| v.as_str())
                .unwrap_or_default()
                .to_string();
            if r#type.is_empty() {
                return None;
            }
            Some(RewriteOperation {
                r#type,
                name: obj
                    .get("name")
                    .and_then(|v| v.as_str())
                    .unwrap_or_default()
                    .to_string(),
                value: obj
                    .get("value")
                    .and_then(|v| v.as_str())
                    .unwrap_or_default()
                    .to_string(),
            })
        })
        .collect()
}

/// Converts a stored error page into its protocol representation.
fn error_page_to_proto(row: &error_pages::Model) -> CustomErrorPage {
    CustomErrorPage {
        id: row.id.to_string(),
        status_code: row.status_code.max(0) as u32,
        content_type: row.content_type.clone(),
        body_template: row.body_template.clone(),
        name: row.name.clone(),
        enabled: row.enabled,
    }
}

/// Builds the complete [`RuleBundle`] for one site.
pub async fn build_rule_bundle(
    db: &DatabaseConnection,
    site_row: &site::Model,
) -> Result<RuleBundle, sea_orm::DbErr> {
    let rules_rows = load_rules(db, site_row.id).await?;
    let groups = load_rule_groups(db, site_row.id).await?;
    let rate_limits = load_rate_limits(db, site_row.id).await?;
    let caches = load_cache_rules(db, site_row.id).await?;
    let upstreams = load_upstreams(db, site_row.id).await?;
    let pools = load_pools(db, site_row.id).await?;
    let routes = load_routes(db, site_row.id).await?;
    let route_groups = load_route_groups(db, &routes).await?;
    let ssl = load_ssl(db, site_row.id).await?;
    let ip_rules = load_ip_access_rules(db, site_row.id).await?;
    let ip_groups = load_ip_groups(db, site_row.id).await?;
    let referenced_groups = load_referenced_groups(db, &ip_rules).await?;
    let geo = load_geo_rules(db, site_row.id).await?;
    let challenge = load_challenge_settings(db, site_row.id).await?;
    let waf_settings = load_waf_settings(db, site_row.id).await?;
    let basic_auth = load_basic_auth(db, site_row.id).await?;
    let rewrites = load_rewrite_rules(db, site_row.id).await?;
    let err_pages = load_error_pages(db).await?;
    let certificates = load_certificates(db, site_row.id).await?;
    let bot = load_bot_protection(db, site_row.id).await?;
    let mtls = load_mtls(db, site_row.id).await?;
    // A missing settings row means observation mode was never switched on, so
    // the data plane keeps enforcing.
    let observation_mode = defense_settings::Entity::find_by_id(1)
        .one(db)
        .await?
        .is_some_and(|row| row.observation_mode);

    let custom_rules: Vec<WafRule> =
        rules_rows.iter().map(rule_to_proto).collect();

    let mut bundle = RuleBundle {
        site_id: site_row.id.to_string(),
        // Filled in below, once every other field is final.
        config_hash: String::new(),
        updated_at: to_timestamp(site_row.updated_at),
        waf: Some(waf_config_to_proto(
            &custom_rules,
            &groups,
            waf_settings.as_ref(),
        )),
        rate_limit_rules: rate_limits.iter().map(rate_limit_to_proto).collect(),
        ip_access_rules: ip_rules
            .iter()
            .filter_map(|row| ip_access_rule_to_proto(row, &referenced_groups))
            .chain(ip_groups.iter().map(ip_group_to_proto))
            .collect(),
        geo: Some(geo_to_proto(geo.as_ref())),
        cache_rules: caches
            .iter()
            .map(|row| cache_rule_to_proto(row, site_row.cache_quota_mb))
            .collect(),
        challenge: Some(challenge_to_proto(challenge.as_ref())),
        rewrite_rules: rewrites.iter().map(rewrite_rule_to_proto).collect(),
        error_pages: err_pages.iter().map(error_page_to_proto).collect(),
        ssl: ssl
            .as_ref()
            .map(|row| ssl_to_proto(row, &certificates, &mtls)),
        upstreams: pools_to_proto(&pools, &upstreams),
        routes: routes_to_proto(&routes, &pools, &upstreams, &route_groups),
        bot_protection: Some(bot_protection_to_proto(bot.as_ref())),
        basic_auth: basic_auth_to_proto(basic_auth.as_ref()),
        observation_mode,
    };

    bundle.config_hash = fingerprint(&bundle);
    Ok(bundle)
}

/// Builds a [`SiteConfig`] for the given sites, or for every site when
/// `site_ids` is `None`.
pub async fn build_site_config(
    db: &DatabaseConnection,
    site_ids: Option<&[Uuid]>,
) -> Result<SiteConfig, sea_orm::DbErr> {
    let mut query = site::Entity::find().order_by_asc(site::Column::Domain);
    if let Some(ids) = site_ids {
        if ids.is_empty() {
            // Nothing requested: return an empty configuration instead of
            // accidentally serving every site.
            let mut config = SiteConfig {
                sites: Vec::new(),
                updated_at: to_timestamp(Utc.timestamp_opt(0, 0).unwrap()),
                config_hash: String::new(),
            };
            config.config_hash = fingerprint(&config);
            return Ok(config);
        }
        query = query.filter(site::Column::Id.is_in(ids.iter().copied()));
    }
    let rows = query.all(db).await?;

    let mut sites = Vec::with_capacity(rows.len());
    let mut updated_at = Utc.timestamp_opt(0, 0).unwrap();
    for row in &rows {
        let bundle = build_rule_bundle(db, row).await?;
        if row.updated_at > updated_at {
            updated_at = row.updated_at;
        }
        sites.push(Site {
            id: row.id.to_string(),
            name: row.name.clone(),
            domain: row.domain.clone(),
            alternate_domains: row.alternate_domains.clone(),
            status: site_status_proto(&row.status),
            rules: Some(bundle),
        });
    }

    let mut config = SiteConfig {
        sites,
        updated_at: to_timestamp(updated_at),
        config_hash: String::new(),
    };
    config.config_hash = fingerprint(&config);
    Ok(config)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::route_match_type;

    #[test]
    fn timestamps_roundtrip() {
        let value = Utc::now();
        let ts = to_timestamp(value).expect("timestamp");
        let back = from_timestamp(Some(&ts));
        assert_eq!(back.timestamp(), value.timestamp());
        assert!(from_timestamp(None) <= Utc::now());
    }

    #[test]
    fn status_mappings_match_the_proto() {
        assert_eq!(site_status_proto(site_status::ACTIVE), 0);
        assert_eq!(site_status_proto(site_status::PAUSED), 1);
        assert_eq!(site_status_proto(site_status::PENDING), 2);
        assert_eq!(acme_challenge_proto(Some(acme_challenge::DNS_01)), 1);
        assert_eq!(acme_challenge_proto(Some(acme_challenge::HTTP_01)), 0);
        assert_eq!(acme_challenge_proto(None), 0);
    }

    #[test]
    fn fingerprints_are_stable_and_order_sensitive() {
        let bundle = RuleBundle {
            site_id: Uuid::nil().to_string(),
            ..Default::default()
        };
        assert_eq!(fingerprint(&bundle), fingerprint(&bundle));
        assert_eq!(fingerprint(&bundle).len(), 16);

        let mut other = bundle.clone();
        other.site_id = Uuid::new_v4().to_string();
        assert_ne!(fingerprint(&bundle), fingerprint(&other));
    }

    #[test]
    fn json_objects_become_string_maps() {
        let value = serde_json::json!({ "token": "abc", "retries": 3 });
        let map = json_to_string_map(&Some(value));
        assert_eq!(map.get("token").map(String::as_str), Some("abc"));
        assert_eq!(map.get("retries").map(String::as_str), Some("3"));
        assert!(json_to_string_map(&None).is_empty());
    }

    fn bot_row(enabled: bool, ua_analysis: bool) -> bot_protection::Model {
        bot_protection::Model {
            id: Uuid::new_v4(),
            site_id: Uuid::nil(),
            enabled,
            ua_analysis,
            js_detection: true,
            tls_fingerprint: false,
            behavioral_analysis: false,
            action: "challenge".to_string(),
            known_bots_whitelist: serde_json::json!([
                "Googlebot",
                1,
                "bingbot"
            ]),
            updated_at: Utc::now(),
        }
    }

    #[test]
    fn bot_protection_proto_skips_malformed_whitelist_entries() {
        let row = bot_row(true, true);
        let proto = bot_protection_to_proto(Some(&row));
        assert!(proto.enabled);
        assert_eq!(proto.action, action::to_proto("challenge"));
        assert_eq!(
            proto.known_bots_whitelist,
            vec!["Googlebot".to_string(), "bingbot".to_string()]
        );

        // UA analysis disabled means the data plane has nothing to enforce.
        let row = bot_row(true, false);
        assert!(!bot_protection_to_proto(Some(&row)).enabled);

        // No row yet: disabled defaults.
        let proto = bot_protection_to_proto(None);
        assert!(!proto.enabled);
        assert!(proto.known_bots_whitelist.is_empty());
    }

    #[test]
    fn waf_mode_follows_the_strongest_rule() {
        let base = rule::Model {
            id: Uuid::new_v4(),
            group_id: None,
            site_id: Uuid::nil(),
            name: "r".into(),
            description: None,
            expression: "true".into(),
            action: action::BLOCK.into(),
            severity: 3,
            tags: vec!["sqli".into()],
            enabled: true,
            mode: mode::MONITOR.into(),
            priority: 0,
            created_at: Utc::now(),
            updated_at: Utc::now(),
        };
        let monitoring = vec![rule_to_proto(&base)];
        let config = waf_config_to_proto(&monitoring, &[], None);
        assert!(config.enabled);
        assert_eq!(config.mode, WAF_MODE_MONITOR);
        assert!(config.sqli_detection);
        assert_eq!(config.paranoia_level, 3);
        assert!(!config.advanced_mode);
        assert!(config.monitor_categories.is_empty());
        assert!(config.monitor_stacks.is_empty());

        let mut blocking = base.clone();
        blocking.mode = mode::BLOCK.into();
        let config =
            waf_config_to_proto(&[rule_to_proto(&blocking)], &[], None);
        assert_eq!(config.mode, WAF_MODE_BLOCK);

        let mut disabled = base.clone();
        disabled.enabled = false;
        let config =
            waf_config_to_proto(&[rule_to_proto(&disabled)], &[], None);
        assert!(!config.enabled);
        assert_eq!(config.mode, WAF_MODE_OFF);
    }

    fn waf_settings_row(
        site_id: Uuid,
        advanced_mode: bool,
        categories: Vec<String>,
        stacks: Vec<String>,
    ) -> waf_settings::Model {
        waf_settings::Model {
            id: Uuid::new_v4(),
            site_id,
            advanced_mode,
            monitor_categories: categories,
            monitor_stacks: stacks,
            created_at: Utc::now(),
            updated_at: Utc::now(),
        }
    }

    #[test]
    fn waf_config_merges_site_settings() {
        let base = rule::Model {
            id: Uuid::new_v4(),
            group_id: None,
            site_id: Uuid::nil(),
            name: "r".into(),
            description: None,
            expression: "true".into(),
            action: action::BLOCK.into(),
            severity: 2,
            tags: vec!["sql-injection".into()],
            enabled: true,
            mode: mode::MONITOR.into(),
            priority: 0,
            created_at: Utc::now(),
            updated_at: Utc::now(),
        };
        let rules = vec![rule_to_proto(&base)];

        // A lone advanced-mode switch must still yield an enabled config so
        // the data plane spins up the strict managed engine.
        let advanced =
            waf_settings_row(Uuid::nil(), true, Vec::new(), Vec::new());
        let config = waf_config_to_proto(&rules, &[], Some(&advanced));
        assert!(config.enabled);
        assert!(config.advanced_mode);

        // Monitor lists flow through verbatim; the data plane ignores
        // unknown names.
        let monitored = waf_settings_row(
            Uuid::nil(),
            false,
            vec!["sqli".into(), "ssti".into()],
            vec!["java".into()],
        );
        let config = waf_config_to_proto(&rules, &[], Some(&monitored));
        assert!(config.enabled);
        assert!(!config.advanced_mode);
        assert_eq!(config.monitor_categories, vec!["sqli", "ssti"]);
        assert_eq!(config.monitor_stacks, vec!["java"]);

        // No rules and no settings row: the pre-existing disabled default.
        let config = waf_config_to_proto(&[], &[], None);
        assert!(!config.enabled);
    }

    fn pool_model(
        name: &str,
        lb_algorithm: &str,
        sni: Option<&str>,
        is_default: bool,
    ) -> site_upstream_pools::Model {
        site_upstream_pools::Model {
            id: Uuid::new_v4(),
            site_id: Uuid::nil(),
            name: name.into(),
            lb_algorithm: lb_algorithm.into(),
            sni: sni.map(Into::into),
            verify_cert: None,
            is_default,
            created_at: Utc::now(),
        }
    }

    fn node_model(
        pool_id: Uuid,
        address: &str,
        weight: i32,
    ) -> site_upstreams::Model {
        site_upstreams::Model {
            id: Uuid::new_v4(),
            site_id: Uuid::nil(),
            pool_id,
            name: "origin".into(),
            address: address.into(),
            weight,
            tls: false,
            health_status: "unknown".into(),
            created_at: Utc::now(),
        }
    }

    #[test]
    fn pools_group_their_nodes_and_skip_empty_ones() {
        let default_pool = pool_model("default", "round_robin", None, true);
        let tls_pool =
            pool_model("static", "hash:path", Some("cdn.example.com"), false);
        let empty_pool = pool_model("empty", "round_robin", None, false);

        let nodes = vec![
            node_model(default_pool.id, "10.0.0.1:8080", 3),
            node_model(default_pool.id, "10.0.0.2:8080", 1),
            node_model(tls_pool.id, "10.0.0.3:9090", 2),
        ];

        let configs = pools_to_proto(
            &[default_pool.clone(), tls_pool, empty_pool],
            &nodes,
        );
        assert_eq!(configs.len(), 2);

        assert_eq!(configs[0].name, "default");
        assert_eq!(configs[0].pool_id, default_pool.id.to_string());
        assert!(configs[0].is_default);
        assert_eq!(configs[0].algo, "round_robin");
        assert_eq!(configs[0].algorithm, 0);
        assert_eq!(configs[0].peers.len(), 2);
        assert_eq!(configs[0].peers[0].weight, 3);
        assert_eq!(configs[0].sni, "");

        assert_eq!(configs[1].name, "static");
        assert_eq!(configs[1].algo, "hash:path");
        assert_eq!(configs[1].sni, "cdn.example.com");
        assert_eq!(configs[1].peers.len(), 1);
        assert!(!configs[1].is_default);

        assert!(pools_to_proto(&[], &nodes).is_empty());
    }

    #[test]
    fn pools_pass_verify_cert_through() {
        let mut pool = pool_model("default", "round_robin", None, true);
        pool.verify_cert = Some(false);
        let nodes = vec![node_model(pool.id, "10.0.0.1:8080", 1)];
        let configs = pools_to_proto(&[pool], &nodes);
        assert_eq!(configs[0].verify_cert, Some(false));
    }

    fn route_model(
        enabled: bool,
        priority: Option<i32>,
        pool_id: Uuid,
    ) -> site_routes::Model {
        site_routes::Model {
            id: Uuid::new_v4(),
            site_id: Uuid::nil(),
            name: "r".into(),
            match_type: route_match_type::EXACT.into(),
            path: "/api".into(),
            priority,
            enabled,
            pool_id,
            ip_group_id: None,
            created_at: Utc::now(),
        }
    }

    #[test]
    fn routes_skip_disabled_and_nodeless_pools() {
        let pool = pool_model("default", "round_robin", None, true);
        let empty = pool_model("empty", "round_robin", None, false);
        let nodes = vec![node_model(pool.id, "10.0.0.1:8080", 1)];

        let routes = vec![
            route_model(true, Some(10), pool.id),
            route_model(false, None, pool.id),
            route_model(true, None, empty.id),
        ];
        let protos = routes_to_proto(
            &routes,
            &[pool.clone(), empty.clone()],
            &nodes,
            &HashMap::new(),
        );
        assert_eq!(protos.len(), 1);
        assert_eq!(protos[0].pool_id, routes[0].pool_id.to_string());
        assert_eq!(protos[0].match_type, route_match_type::EXACT);
        assert_eq!(protos[0].path, "/api");
        assert_eq!(protos[0].priority, Some(10));

        // Losing the last node drops the route along with the pool.
        let protos =
            routes_to_proto(&routes, &[pool, empty], &[], &HashMap::new());
        assert!(protos.is_empty());
    }

    #[test]
    fn route_gates_expand_from_their_ip_group() {
        let pool = pool_model("default", "round_robin", None, true);
        let nodes = vec![node_model(pool.id, "10.0.0.1:8080", 1)];
        let group_id = Uuid::new_v4();
        let group = ip_groups::Model {
            id: group_id,
            name: "internal".into(),
            description: None,
            ip_ranges: vec!["10.0.0.0/8".into(), "192.168.0.0/16".into()],
            action: "allow".into(),
            is_global: false,
            source_url: None,
            sync_interval_minutes: None,
            last_synced_at: None,
            last_sync_error: None,
            enabled: true,
            created_at: Utc::now(),
            updated_at: Utc::now(),
        };

        let mut gated = route_model(true, None, pool.id);
        gated.ip_group_id = Some(group_id);
        let open = route_model(true, None, pool.id);

        let groups: HashMap<Uuid, ip_groups::Model> =
            [(group_id, group)].into_iter().collect();
        let protos = routes_to_proto(
            &[gated.clone(), open],
            std::slice::from_ref(&pool),
            &nodes,
            &groups,
        );
        assert_eq!(protos.len(), 2);
        assert_eq!(
            protos[0].ip_ranges,
            vec!["10.0.0.0/8".to_string(), "192.168.0.0/16".to_string()]
        );
        // An ungated route keeps matching every client.
        assert!(protos[1].ip_ranges.is_empty());

        // A gate the control plane can no longer resolve drops the route
        // instead of publishing it as match-everything.
        let protos = routes_to_proto(
            &[gated],
            std::slice::from_ref(&pool),
            &nodes,
            &HashMap::new(),
        );
        assert!(protos.is_empty());
    }

    fn ip_rule_model(
        group_id: Option<Uuid>,
        ip_ranges: Vec<String>,
    ) -> ip_access_rules::Model {
        ip_access_rules::Model {
            id: Uuid::new_v4(),
            site_id: Uuid::nil(),
            name: "rule".into(),
            ip_ranges,
            action: "block".into(),
            note: None,
            enabled: true,
            priority: 0,
            group_id,
            created_at: Utc::now(),
            updated_at: Utc::now(),
        }
    }

    fn ip_group_model(id: Uuid, ranges: &[&str]) -> ip_groups::Model {
        ip_groups::Model {
            id,
            name: "group".into(),
            description: None,
            ip_ranges: ranges.iter().map(|r| r.to_string()).collect(),
            action: "allow".into(),
            is_global: false,
            source_url: None,
            sync_interval_minutes: None,
            last_synced_at: None,
            last_sync_error: None,
            enabled: true,
            created_at: Utc::now(),
            updated_at: Utc::now(),
        }
    }

    #[test]
    fn group_backed_rules_expand_to_live_group_ranges() {
        let group_id = Uuid::new_v4();
        let group =
            ip_group_model(group_id, &["203.0.113.0/24", "198.51.100.7"]);

        // The rule keeps its own action; the ranges come from the group.
        let grouped = ip_rule_model(Some(group_id), Vec::new());
        let mut groups = HashMap::new();
        groups.insert(group_id, group.clone());
        let proto =
            ip_access_rule_to_proto(&grouped, &groups).expect("expands");
        assert_eq!(proto.ip_ranges, group.ip_ranges);
        assert_eq!(proto.action, ip_action::to_proto("block"));
        assert_eq!(proto.name, "rule");

        // A group-backed rule whose group is missing or disabled is skipped
        // when it has no ranges of its own.
        assert!(ip_access_rule_to_proto(&grouped, &HashMap::new()).is_none());

        // A manual rule keeps its own ranges and ignores groups entirely.
        let manual = ip_rule_model(None, vec!["10.0.0.0/8".to_string()]);
        let proto = ip_access_rule_to_proto(&manual, &groups).expect("manual");
        assert_eq!(proto.ip_ranges, vec!["10.0.0.0/8".to_string()]);

        // A rule with neither group nor ranges matches nothing and is skipped.
        let empty = ip_rule_model(None, Vec::new());
        assert!(ip_access_rule_to_proto(&empty, &groups).is_none());
    }
}
