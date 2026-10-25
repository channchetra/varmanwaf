//! Control plane self-protection: the 9080 listener's own access log, IP
//! allowlist and WAF.
//!
//! Three middlewares guard the console and REST API, outermost first:
//!
//! 1. [`access_log`] — records one row per request into
//!    `control_plane_access_logs` (when enabled) and stamps a request id on
//!    the response.
//! 2. [`ip_allowlist`] — refuses callers outside the configured ranges and
//!    the referenced `ip_groups` row.
//! 3. [`waf_guard`] — inspects the request with the embedded
//!    [`varman_waf`] engine and blocks (or only records, in `monitor` mode).
//!
//! Health probes (`/healthz`, `/api/v1/health`) are exempt from all three so
//! container and load balancer probes keep working. The policy is loaded from
//! `api_protection_settings` at boot and refreshed by a background task, so a
//! change made through the API — or by the `varman security` CLI on another
//! process — takes effect within [`REFRESH_INTERVAL`] without a restart.
//!
//! The middlewares never trust forwarding headers for the client address:
//! the allowlist and the log use the TCP peer. A console behind a reverse
//! proxy therefore sees the proxy's address, and the proxy's range must be
//! allowlisted.

use std::net::IpAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use axum::extract::connect_info::ConnectInfo;
use axum::extract::{Request, State};
use axum::http::header::{HeaderMap, AUTHORIZATION, HOST, REFERER, USER_AGENT};
use axum::http::{HeaderName, HeaderValue, StatusCode};
use axum::middleware::Next;
use axum::response::Response;
use chrono::{DateTime, Utc};
use sea_orm::sea_query::OnConflict;
use sea_orm::{
    ColumnTrait, DatabaseConnection, DbErr, EntityTrait, QueryFilter,
    QuerySelect, QueryTrait, Set,
};
use uuid::Uuid;

use varman_waf::{
    CategorySet, RequestData, StackSet, WafAction, WafEngine, WafEngineConfig,
    WafLevel, WafMode,
};

use crate::api::error::error_response;
use crate::api::state::AppState;
use crate::auth::jwt::verify_user_token;
use crate::models::api_protection::{action, waf_mode};
use crate::models::{
    api_protection_setting, control_plane_access_log, ip_groups,
};
pub use crate::self_protection::{
    normalize_ip, Allowlist, LogRecord, ProtectionPolicy, SelfProtection,
};
use crate::tls::ConnInfo;

/// Primary key of the single settings row.
const SETTINGS_ID: i32 = 1;

/// How often the background task re-reads the settings row.
pub const REFRESH_INTERVAL: Duration = Duration::from_secs(15);

/// Request-body prefix the WAF inspects. Bodies above this are refused with
/// `413` while the WAF is enabled, so a truncated body can never slip past
/// inspection.
const WAF_BODY_LIMIT: usize = 128 * 1024;

/// Correlation header stamped on every response.
const REQUEST_ID_HEADER: &str = "x-request-id";

// ─────────────────────────────────────────────────────────────
// Settings
// ─────────────────────────────────────────────────────────────

/// Reads the settings row, creating it with the defaults if it is missing.
pub async fn load_settings(
    db: &DatabaseConnection,
) -> Result<api_protection_setting::Model, DbErr> {
    if let Some(row) = api_protection_setting::Entity::find_by_id(SETTINGS_ID)
        .one(db)
        .await?
    {
        return Ok(row);
    }

    let now = Utc::now();
    let insert = api_protection_setting::ActiveModel {
        id: Set(SETTINGS_ID),
        access_log_enabled: Set(true),
        access_log_retention_days: Set(
            crate::models::api_protection::DEFAULT_RETENTION_DAYS,
        ),
        ip_allowlist_enabled: Set(false),
        ip_allowlist_ranges: Set(Vec::new()),
        ip_allowlist_group_id: Set(None),
        ip_denylist_enabled: Set(false),
        ip_denylist_ranges: Set(Vec::new()),
        waf_enabled: Set(false),
        waf_mode: Set(waf_mode::BLOCK.to_string()),
        updated_at: Set(now),
    };
    let ignore_conflict =
        OnConflict::column(api_protection_setting::Column::Id)
            .do_nothing()
            .to_owned();
    match api_protection_setting::Entity::insert(insert)
        .on_conflict(ignore_conflict)
        .exec(db)
        .await
    {
        Ok(_) | Err(DbErr::RecordNotInserted) => {},
        Err(err) => return Err(err),
    }

    api_protection_setting::Entity::find_by_id(SETTINGS_ID)
        .one(db)
        .await?
        .ok_or_else(|| {
            DbErr::RecordNotFound(
                "api protection settings row vanished".to_string(),
            )
        })
}

/// The effective allowlist of a settings row: inline ranges plus the ranges
/// of the referenced group (when it exists and is enabled — a disabled group
/// is not deployed anywhere, so it contributes nothing here either).
pub async fn effective_allowlist(
    db: &DatabaseConnection,
    settings: &api_protection_setting::Model,
) -> Result<(Allowlist, Option<DateTime<Utc>>), DbErr> {
    let mut ranges = settings.ip_allowlist_ranges.clone();
    let mut group_updated_at = None;
    if let Some(group_id) = settings.ip_allowlist_group_id {
        let group = ip_groups::Entity::find_by_id(group_id).one(db).await?;
        match group {
            Some(group) => {
                // Track the row even while it is disabled: enabling or
                // editing the group later must rebuild the policy. Before
                // this timestamp was compared, the policy only rebuilt when
                // the *settings* row changed, so a group enabled after the
                // save kept being ignored until the next save or restart.
                group_updated_at = Some(group.updated_at);
                if group.enabled {
                    ranges.extend(group.ip_ranges);
                } else {
                    tracing::warn!(
                        group_id = %group_id,
                        "API allowlist references a disabled ip group; only the inline ranges apply"
                    );
                }
            },
            None => tracing::warn!(
                group_id = %group_id,
                "API allowlist references a missing ip group; only the inline ranges apply"
            ),
        }
    }
    let (allowlist, invalid) = Allowlist::parse(ranges);
    if !invalid.is_empty() {
        tracing::warn!(
            invalid = ?invalid,
            "ignoring invalid API allowlist entries"
        );
    }
    Ok((allowlist, group_updated_at))
}

/// Builds the enforcement policy from the current settings row.
pub async fn refresh(
    db: &DatabaseConnection,
) -> Result<ProtectionPolicy, DbErr> {
    let settings = load_settings(db).await?;
    let (allowlist, group_updated_at) =
        effective_allowlist(db, &settings).await?;
    let (denylist, invalid_deny) =
        Allowlist::parse(&settings.ip_denylist_ranges);
    if !invalid_deny.is_empty() {
        tracing::warn!(
            invalid = ?invalid_deny,
            "ignoring invalid API denylist entries"
        );
    }
    let waf_blocking = settings.waf_mode == waf_mode::BLOCK;
    let waf = settings.waf_enabled.then(|| {
        Arc::new(WafEngine::new(&WafEngineConfig {
            mode: if waf_blocking {
                WafMode::Block
            } else {
                WafMode::Monitor
            },
            level: WafLevel::default(),
            stacks: StackSet::default(),
            monitor_categories: CategorySet::EMPTY,
            monitor_stacks: StackSet::EMPTY,
            monitor_managed_rules: std::collections::HashSet::new(),
            monitor_custom_rules: std::collections::HashSet::new(),
            disabled_rules: std::collections::HashSet::new(),
            rule_scores: std::collections::HashMap::new(),
            rule_target_exclusions: std::collections::HashMap::new(),
            path_target_exclusions: Vec::new(),
            threshold: 40,
            paranoia_level: 2,
            max_decode_layers: 3,
            rules: Vec::new(),
            enable_managed_rules: true,
            fast_path_block_on_critical: true,
        }))
    });

    Ok(ProtectionPolicy {
        access_log_enabled: settings.access_log_enabled,
        allowlist_enabled: settings.ip_allowlist_enabled,
        allowlist,
        denylist_enabled: settings.ip_denylist_enabled,
        denylist,
        waf,
        waf_blocking,
        settings_updated_at: settings.updated_at,
        group_updated_at,
    })
}

/// Whether a freshly built policy differs from the one in force.
///
/// Both inputs matter: the settings row *and* the referenced IP group. The
/// group is edited on its own page (and enabled by its own switch), so
/// comparing only the settings timestamp left a group enabled after the save
/// out of the enforced policy until something else touched the settings.
fn inputs_changed(
    current: &ProtectionPolicy,
    fresh: &ProtectionPolicy,
) -> bool {
    fresh.settings_updated_at != current.settings_updated_at
        || fresh.group_updated_at != current.group_updated_at
}

/// Background task: re-read the settings every [`REFRESH_INTERVAL`] and swap
/// the policy in when the row changed. Failures keep the previous policy.
pub fn start_refresh_task(state: AppState) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        loop {
            tokio::time::sleep(REFRESH_INTERVAL).await;
            match refresh(&state.db).await {
                Ok(policy) => {
                    let current = state.protection.policy();
                    if inputs_changed(&current, &policy) {
                        tracing::info!(
                            allowlist_enabled = policy.allowlist_enabled,
                            allowlist_entries = policy.allowlist.len(),
                            group_updated_at = ?policy.group_updated_at,
                            waf_enabled = policy.waf.is_some(),
                            "control plane protection settings reloaded"
                        );
                        state.protection.store(policy);
                    }
                },
                Err(err) => tracing::warn!(
                    error = %err,
                    "could not reload control plane protection settings"
                ),
            }
        }
    })
}

/// Marker the inner middlewares leave on the response, read back by
/// [`access_log`] once the response is on its way out.
#[derive(Debug, Clone)]
pub struct ProtectionOutcome {
    pub action: &'static str,
    pub reason: Option<String>,
}

/// Rows deleted per statement by [`purge_access_logs`].
const LOG_PURGE_BATCH_SIZE: u64 = 10_000;

/// Deletes control plane log rows older than the given window, in bounded
/// batches — the same shape as the site log sweep, so one statement never
/// holds locks on the whole table.
pub async fn purge_access_logs(
    db: &DatabaseConnection,
    older_than_days: i64,
) -> Result<u64, DbErr> {
    let cutoff = Utc::now() - chrono::Duration::days(older_than_days);
    let mut deleted_total = 0_u64;
    loop {
        let batch = control_plane_access_log::Entity::find()
            .select_only()
            .column(control_plane_access_log::Column::Id)
            .filter(control_plane_access_log::Column::Timestamp.lt(cutoff))
            .limit(LOG_PURGE_BATCH_SIZE);
        let deleted = control_plane_access_log::Entity::delete_many()
            .filter(
                control_plane_access_log::Column::Id
                    .in_subquery(batch.into_query()),
            )
            .exec(db)
            .await?;
        deleted_total += deleted.rows_affected;
        if deleted.rows_affected < LOG_PURGE_BATCH_SIZE {
            break;
        }
    }
    Ok(deleted_total)
}

/// `is_health_probe` decides exemption; shared so the middlewares agree with
/// the redirect layer.
fn exempt(path: &str) -> bool {
    crate::api::is_health_probe(path)
}

/// The peer address of the connection, when the serve layer provided one.
pub(crate) fn peer_addr(request: &Request) -> Option<std::net::SocketAddr> {
    request
        .extensions()
        .get::<ConnectInfo<ConnInfo>>()
        .map(|info| info.0.peer_addr)
}

/// Best-effort caller identity: a valid Bearer token on the request is
/// decoded for the log only. The handler performs the real authentication.
fn log_identity(
    state: &AppState,
    headers: &HeaderMap,
) -> (Option<Uuid>, Option<String>) {
    let Some(token) = headers
        .get(AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.strip_prefix("Bearer "))
    else {
        return (None, None);
    };
    match verify_user_token(token, state.jwt_secret()) {
        Ok(claims) => (claims.subject_id().ok(), Some(claims.email)),
        Err(_) => (None, None),
    }
}

fn header_text<K: axum::http::header::AsHeaderName>(
    headers: &HeaderMap,
    name: K,
) -> Option<String> {
    headers
        .get(name)
        .and_then(|value| value.to_str().ok())
        .map(|value| value.to_string())
}

/// Middleware 1/3: request/response logging for the control plane itself.
pub async fn access_log(
    State(state): State<AppState>,
    mut request: Request,
    next: Next,
) -> Response {
    if exempt(request.uri().path()) {
        return next.run(request).await;
    }

    let started = Instant::now();
    let request_id = header_text(request.headers(), REQUEST_ID_HEADER)
        .filter(|value| !value.is_empty())
        .unwrap_or_else(|| Uuid::new_v4().to_string());
    if let Ok(value) = HeaderValue::from_str(&request_id) {
        request
            .headers_mut()
            .insert(HeaderName::from_static(REQUEST_ID_HEADER), value);
    }

    let enabled = state.protection.policy().access_log_enabled;
    // Identity is decoded before the request moves on; the body never needs
    // it, so this stays on the cheap side of the middleware.
    let (user_id, user_email) = if enabled {
        log_identity(&state, request.headers())
    } else {
        (None, None)
    };
    let method = request.method().as_str().to_string();
    let path = request.uri().path().to_string();
    let query = request.uri().query().map(|value| value.to_string());
    let host = header_text(request.headers(), HOST);
    let user_agent = header_text(request.headers(), USER_AGENT);
    let referer = header_text(request.headers(), REFERER);
    let scheme = if request
        .extensions()
        .get::<ConnectInfo<ConnInfo>>()
        .is_some_and(|info| info.0.tls)
    {
        "https"
    } else {
        "http"
    };
    let protocol = format!("{:?}", request.version());
    let client_ip = peer_addr(&request)
        .map(|addr| addr.ip().to_string())
        .unwrap_or_default();

    let mut response = next.run(request).await;

    if let Ok(value) = HeaderValue::from_str(&request_id) {
        response
            .headers_mut()
            .insert(HeaderName::from_static(REQUEST_ID_HEADER), value);
    }
    if !enabled {
        return response;
    }

    let outcome = response
        .extensions()
        .get::<ProtectionOutcome>()
        .cloned()
        .unwrap_or(ProtectionOutcome {
            action: action::ALLOWED,
            reason: None,
        });
    state.protection.record(LogRecord {
        request_id: Some(request_id),
        timestamp: Utc::now(),
        client_ip,
        method,
        host,
        path,
        query_string: query,
        scheme: Some(scheme.to_string()),
        protocol: Some(protocol),
        status_code: Some(response.status().as_u16() as i32),
        latency_ms: Some(started.elapsed().as_millis() as i64),
        user_agent,
        referer,
        user_id,
        user_email,
        action: outcome.action.to_string(),
        reason: outcome.reason,
    });
    response
}

// ─────────────────────────────────────────────────────────────
// IP allowlist + denylist
// ─────────────────────────────────────────────────────────────

/// What the IP gates decide for one peer address.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum IpGate {
    /// The request may proceed.
    Allow,
    /// An explicit denylist match: refuse even when allowlisted.
    Deny,
    /// The allowlist is enabled and does not cover the address.
    NotAllowlisted,
}

/// The allow/deny decision, in one place so it is testable without a request.
fn ip_gate(policy: &ProtectionPolicy, ip: &IpAddr) -> IpGate {
    if policy.denylist_enabled && policy.denylist.contains(ip) {
        return IpGate::Deny;
    }
    if !policy.allowlist_enabled || policy.allowlist.contains(ip) {
        return IpGate::Allow;
    }
    IpGate::NotAllowlisted
}

/// Middleware 2/3: applies the IP gates - the denylist first (an explicit
/// refusal wins over the allowlist), then the allowlist.
pub async fn ip_allowlist(
    State(state): State<AppState>,
    request: Request,
    next: Next,
) -> Response {
    let policy = state.protection.policy();
    if (!policy.allowlist_enabled && !policy.denylist_enabled)
        || exempt(request.uri().path())
    {
        return next.run(request).await;
    }

    let Some(addr) = peer_addr(&request) else {
        // No peer information means the serve layer was not wired with
        // connect info; refusing nothing would silently disable the gate, so
        // refuse the request and say why.
        tracing::error!(
            "an API IP gate is enabled but the connection carries no peer address"
        );
        let mut response = error_response(
            StatusCode::INTERNAL_SERVER_ERROR,
            "no_peer_address",
            "the control plane cannot determine your address",
        );
        response.extensions_mut().insert(ProtectionOutcome {
            action: action::BLOCKED_ALLOWLIST,
            reason: Some("peer address unavailable".to_string()),
        });
        return response;
    };
    let ip = addr.ip();

    match ip_gate(&policy, &ip) {
        IpGate::Allow => next.run(request).await,
        IpGate::Deny => {
            tracing::warn!(
                client_ip = %ip,
                path = %request.uri().path(),
                "control plane request refused by the IP denylist"
            );
            let mut response = error_response(
                StatusCode::FORBIDDEN,
                "ip_denied",
                "your address is blocked by the control plane denylist",
            );
            response.extensions_mut().insert(ProtectionOutcome {
                action: action::BLOCKED_DENYLIST,
                reason: Some(format!("client ip {ip} is on the denylist")),
            });
            response
        },
        IpGate::NotAllowlisted => {
            tracing::warn!(
                client_ip = %ip,
                path = %request.uri().path(),
                "control plane request refused by the IP allowlist"
            );
            let mut response = error_response(
                StatusCode::FORBIDDEN,
                "ip_not_allowed",
                "your address is not in the control plane allowlist",
            );
            response.extensions_mut().insert(ProtectionOutcome {
                action: action::BLOCKED_ALLOWLIST,
                reason: Some(format!("client ip {ip} is not allowlisted")),
            });
            response
        },
    }
}

// ─────────────────────────────────────────────────────────────
// WAF
// ─────────────────────────────────────────────────────────────

/// Middleware 3/3: inspects API requests with the embedded WAF engine.
pub async fn waf_guard(
    State(state): State<AppState>,
    request: Request,
    next: Next,
) -> Response {
    let policy = state.protection.policy();
    let Some(engine) = policy.waf.clone() else {
        return next.run(request).await;
    };
    if exempt(request.uri().path()) {
        return next.run(request).await;
    }

    // Read the connection facts before the request is split: `Parts` is not
    // cloneable, so this is the last chance to look at the extensions.
    let client_ip = peer_addr(&request)
        .map(|addr| addr.ip().to_string())
        .unwrap_or_default();
    let scheme = if request
        .extensions()
        .get::<ConnectInfo<ConnInfo>>()
        .is_some_and(|info| info.0.tls)
    {
        "https".to_string()
    } else {
        "http".to_string()
    };

    let (parts, body) = request.into_parts();
    let bytes = match axum::body::to_bytes(body, WAF_BODY_LIMIT).await {
        Ok(bytes) => bytes,
        Err(err) => {
            tracing::warn!(error = %err, "control plane request body exceeded the WAF inspection limit");
            let mut response = error_response(
                StatusCode::PAYLOAD_TOO_LARGE,
                "request_body_too_large",
                "request body exceeds the control plane WAF inspection limit",
            );
            response.extensions_mut().insert(ProtectionOutcome {
                action: action::BLOCKED_WAF,
                reason: Some(format!(
                    "body larger than {WAF_BODY_LIMIT} bytes was not inspected"
                )),
            });
            return response;
        },
    };

    let request_data = RequestData {
        method: parts.method.as_str().to_string(),
        path: parts.uri.path().to_string(),
        query: parts.uri.query().unwrap_or_default().to_string(),
        headers: parts
            .headers
            .iter()
            .filter_map(|(name, value)| {
                value
                    .to_str()
                    .ok()
                    .map(|value| (name.as_str().to_string(), value.to_string()))
            })
            .collect(),
        body: (!bytes.is_empty()).then(|| bytes.to_vec()),
        client_ip,
        country_code: None,
        scheme,
        protocol: format!("{:?}", parts.version),
    };
    let verdict = engine.inspect(&request_data);

    let request = Request::from_parts(parts, axum::body::Body::from(bytes));
    let blocking = policy.waf_blocking
        && matches!(verdict.action, WafAction::Block | WafAction::Challenge);
    if blocking {
        tracing::warn!(
            client_ip = %request_data.client_ip,
            path = %request_data.path,
            score = verdict.score,
            rules = ?verdict.matched_rules,
            "control plane WAF blocked a request"
        );
        let mut response = error_response(
            StatusCode::FORBIDDEN,
            "blocked_by_waf",
            &format!(
                "request blocked by the control plane WAF: {}",
                verdict.details
            ),
        );
        response.extensions_mut().insert(ProtectionOutcome {
            action: action::BLOCKED_WAF,
            reason: Some(verdict.details.clone()),
        });
        return response;
    }

    let mut response = next.run(request).await;
    if verdict.action != WafAction::Pass {
        tracing::info!(
            client_ip = %request_data.client_ip,
            path = %request_data.path,
            score = verdict.score,
            rules = ?verdict.matched_rules,
            "control plane WAF match (not enforced)"
        );
        response.extensions_mut().insert(ProtectionOutcome {
            action: action::OBSERVED_WAF,
            reason: Some(format!(
                "{} ({})",
                verdict.details,
                if policy.waf_blocking {
                    "monitor verdict"
                } else {
                    "monitor mode"
                }
            )),
        });
    }
    response
}

#[cfg(test)]
mod tests {
    use super::*;

    fn policy(
        allow: bool,
        deny: bool,
        allow_ranges: &[&str],
        deny_ranges: &[&str],
    ) -> ProtectionPolicy {
        let (allowlist, _) = Allowlist::parse(allow_ranges);
        let (denylist, _) = Allowlist::parse(deny_ranges);
        ProtectionPolicy {
            allowlist_enabled: allow,
            allowlist,
            denylist_enabled: deny,
            denylist,
            ..Default::default()
        }
    }

    fn ip(value: &str) -> IpAddr {
        value.parse().expect("ip")
    }

    #[test]
    fn the_denylist_wins_over_the_allowlist() {
        let p = policy(true, true, &["10.0.0.0/8"], &["10.1.2.3"]);
        assert_eq!(ip_gate(&p, &ip("10.1.2.3")), IpGate::Deny);
        assert_eq!(ip_gate(&p, &ip("10.9.9.9")), IpGate::Allow);
        assert_eq!(ip_gate(&p, &ip("192.0.2.7")), IpGate::NotAllowlisted);
    }

    #[test]
    fn the_denylist_works_without_the_allowlist() {
        let p = policy(false, true, &[], &["203.0.113.0/24"]);
        assert_eq!(ip_gate(&p, &ip("203.0.113.7")), IpGate::Deny);
        assert_eq!(ip_gate(&p, &ip("198.51.100.7")), IpGate::Allow);
    }

    #[test]
    fn both_gates_off_allow_everything() {
        let p = policy(false, false, &[], &[]);
        assert_eq!(ip_gate(&p, &ip("203.0.113.7")), IpGate::Allow);
    }

    #[test]
    fn the_allowlist_alone_still_gates() {
        let p = policy(true, false, &["192.0.2.0/24"], &[]);
        assert_eq!(ip_gate(&p, &ip("192.0.2.5")), IpGate::Allow);
        assert_eq!(ip_gate(&p, &ip("203.0.113.7")), IpGate::NotAllowlisted);
    }

    #[test]
    fn an_ipv4_cidr_covers_addresses_inside_it() {
        // The exact shape an ipverse country group carries: a /22 that must
        // cover a client address (this was reported from a live deployment
        // where the range was present but the policy was stale).
        let (allowlist, invalid) =
            Allowlist::parse(["116.197.152.0/22", "103.16.60.21"]);
        assert!(invalid.is_empty());
        assert!(allowlist.contains(&ip("116.197.152.21")));
        assert!(allowlist.contains(&ip("116.197.155.255")));
        assert!(!allowlist.contains(&ip("116.197.156.1")));
        assert!(allowlist.contains(&ip("103.16.60.21")));
        assert!(!allowlist.contains(&ip("103.16.60.22")));
    }

    #[test]
    fn a_referenced_group_edit_rebuilds_the_policy() {
        let base = Utc::now();
        let current = ProtectionPolicy {
            settings_updated_at: base,
            group_updated_at: Some(base),
            ..Default::default()
        };

        // Unchanged inputs: no rebuild.
        let same = ProtectionPolicy {
            settings_updated_at: base,
            group_updated_at: Some(base),
            ..Default::default()
        };
        assert!(!inputs_changed(&current, &same));

        // The group was enabled/edited after the settings save: rebuild.
        let group_edited = ProtectionPolicy {
            settings_updated_at: base,
            group_updated_at: Some(base + chrono::Duration::seconds(1)),
            ..Default::default()
        };
        assert!(inputs_changed(&current, &group_edited));

        // A group appearing or disappearing also rebuilds.
        let group_cleared = ProtectionPolicy {
            settings_updated_at: base,
            group_updated_at: None,
            ..Default::default()
        };
        assert!(inputs_changed(&current, &group_cleared));

        // A settings save still rebuilds.
        let settings_saved = ProtectionPolicy {
            settings_updated_at: base + chrono::Duration::seconds(1),
            group_updated_at: Some(base),
            ..Default::default()
        };
        assert!(inputs_changed(&current, &settings_saved));
    }
}
