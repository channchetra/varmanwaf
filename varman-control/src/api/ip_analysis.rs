//! Client IP analysis: why would this address be allowed or blocked?
//!
//! The answer is computed from the same stored configuration the control
//! plane compiles into the site bundle - the site's IP access rules in
//! priority order, then the enabled IP groups that apply to the site, then
//! the geo policy - resolved against the same embedded geo database the
//! edge uses. What this cannot see is stated explicitly in `limitations`
//! rather than guessed at.

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::{Arc, LazyLock};

use axum::extract::{Path, Query, State};
use axum::routing::get;
use axum::{Json, Router};
use ipnet::IpNet;
use sea_orm::{ColumnTrait, EntityTrait, QueryFilter};
use serde::{Deserialize, Serialize};
use tor_geoip::GeoipDb;
use uuid::Uuid;

use crate::api::error::ApiError;
use crate::api::state::AppState;
use crate::auth::AuthUser;
use crate::models::{defense_settings, geo_rules, ip_groups, site};

/// The embedded geo database - the same data the edge resolves with.
static GEO_DB: LazyLock<Arc<GeoipDb>> = LazyLock::new(GeoipDb::new_embedded);

/// Routes contributed to `/api/v1`.
pub fn routes() -> Router<AppState> {
    Router::new().route("/sites/{site_id}/ip-analysis", get(analyze))
}

#[derive(Debug, Deserialize)]
struct AnalysisQuery {
    /// The address to analyse.
    ip: String,
}

/// The full answer: what the address resolves to, which rules match it, and
/// what the edge would do - plus what this tool cannot see.
#[derive(Debug, Serialize)]
pub struct IpAnalysis {
    ip: String,
    /// ISO 3166-1 alpha-2, from the embedded database the edge uses.
    country: Option<String>,
    asn: Option<u32>,
    geo: GeoAnalysis,
    /// The first matching IP access rule: site rules first (priority
    /// order), then groups - the order the compiled policy evaluates.
    ip_rule: Option<RuleMatch>,
    /// Every enabled group that applies to the site, with whether it
    /// contains the address.
    groups: Vec<GroupContext>,
    verdict: Verdict,
    limitations: Vec<String>,
}

#[derive(Debug, Serialize)]
pub struct GeoAnalysis {
    enabled: bool,
    /// `block_list` or `allow_list`.
    mode: String,
    /// The configured action: `block`, `challenge`, `js_challenge`,
    /// `basic_auth` or `log` (monitor).
    action: String,
    matched: bool,
    /// Why the policy matched (or did not).
    reason: String,
}

#[derive(Debug, Serialize)]
pub struct RuleMatch {
    id: String,
    name: String,
    action: String,
    /// `site` (an IP access rule) or `group` (an IP group).
    source: String,
}

#[derive(Debug, Serialize)]
pub struct GroupContext {
    id: String,
    name: String,
    action: String,
    matched: bool,
}

#[derive(Debug, Serialize)]
pub struct Verdict {
    /// `pass`, `allow`, `block`, `challenge`, `basic_auth` or `monitor`.
    action: String,
    /// Which layer decided: `ip_rule`, `group`, `geo` or `none`.
    decided_by: String,
    /// Observation mode is on: the decision is recorded, not enforced.
    observed: bool,
}

/// `GET /api/v1/sites/{site_id}/ip-analysis?ip=...` - administrators only.
async fn analyze(
    State(state): State<AppState>,
    current: AuthUser,
    Path(site_id): Path<Uuid>,
    Query(query): Query<AnalysisQuery>,
) -> Result<Json<IpAnalysis>, ApiError> {
    current.require_admin().map_err(ApiError::from)?;

    let raw = query.ip.trim();
    let ip: IpAddr = raw.parse().map_err(|_| {
        ApiError::BadRequest(format!("'{raw}' is not an IP address"))
    })?;

    let exists = site::Entity::find_by_id(site_id)
        .one(&state.db)
        .await?
        .is_some();
    if !exists {
        return Err(ApiError::NotFound("site not found".to_string()));
    }

    let country = lookup_country(ip);
    let asn = lookup_asn(ip);

    // ── IP access rules and groups, in the compiled evaluation order ──
    let rules =
        crate::grpc::config::load_ip_access_rules(&state.db, site_id).await?;
    let groups =
        crate::grpc::config::load_ip_groups(&state.db, site_id).await?;
    let group_map: HashMap<Uuid, &ip_groups::Model> =
        groups.iter().map(|group| (group.id, group)).collect();

    let mut ip_rule: Option<RuleMatch> = None;
    for rule in &rules {
        let ranges = match rule.group_id.and_then(|id| group_map.get(&id)) {
            Some(group) => group.ip_ranges.clone(),
            None if rule.ip_ranges.is_empty() => continue,
            None => rule.ip_ranges.clone(),
        };
        if ranges.iter().any(|range| range_contains(range, ip)) {
            ip_rule = Some(RuleMatch {
                id: rule.id.to_string(),
                name: rule.name.clone(),
                action: rule.action.clone(),
                source: "site".to_string(),
            });
            break;
        }
    }
    if ip_rule.is_none() {
        if let Some(group) = groups
            .iter()
            .find(|group| group.ip_ranges.iter().any(|r| range_contains(r, ip)))
        {
            ip_rule = Some(RuleMatch {
                id: group.id.to_string(),
                name: group.name.clone(),
                action: group.action.clone(),
                source: "group".to_string(),
            });
        }
    }

    let group_context: Vec<GroupContext> = groups
        .iter()
        .map(|group| GroupContext {
            id: group.id.to_string(),
            name: group.name.clone(),
            action: group.action.clone(),
            matched: group
                .ip_ranges
                .iter()
                .any(|range| range_contains(range, ip)),
        })
        .collect();

    // ── Geo policy ──
    let geo_row = geo_rules::Entity::find()
        .filter(geo_rules::Column::SiteId.eq(site_id))
        .one(&state.db)
        .await?;
    let geo = geo_analysis(geo_row.as_ref(), country.as_deref(), asn);

    // ── Verdict: IP rules decide first; geo only when none matched ──
    let (mut action, decided_by) = match &ip_rule {
        Some(rule) if rule.source == "group" => (rule.action.clone(), "group"),
        Some(rule) => (rule.action.clone(), "ip_rule"),
        None if geo.matched => (geo.action.clone(), "geo"),
        None => ("pass".to_string(), "none"),
    };
    // `log` is the monitor action: show what it does.
    if action == crate::models::action::LOG {
        action = "monitor".to_string();
    }

    let observed = action != "pass"
        && defense_settings::Entity::find_by_id(1)
            .one(&state.db)
            .await?
            .is_some_and(|row| row.observation_mode);

    let mut limitations = vec![
        "The embedded geo database carries country data only, so ASN \
         lookups and ASN block lists cannot match."
            .to_string(),
        "Policy-layer IP rules (Policies) are not simulated here; the \
         verdict covers this site's IP rules, IP groups and geo policy."
            .to_string(),
        "Live state (active challenges, clearance cookies, connection \
         tracking) is not visible to the control plane."
            .to_string(),
    ];
    if observed {
        limitations.push(
            "Observation mode is on: the edge records decisions without \
             enforcing them."
                .to_string(),
        );
    }

    Ok(Json(IpAnalysis {
        ip: ip.to_string(),
        country,
        asn,
        geo,
        ip_rule,
        groups: group_context,
        verdict: Verdict {
            action,
            decided_by: decided_by.to_string(),
            observed,
        },
        limitations,
    }))
}

/// Mirrors the edge's geo evaluation exactly (see the WAF plugin).
fn geo_analysis(
    row: Option<&geo_rules::Model>,
    country: Option<&str>,
    asn: Option<u32>,
) -> GeoAnalysis {
    let Some(geo) = row else {
        return GeoAnalysis {
            enabled: false,
            mode: "block_list".to_string(),
            action: crate::models::action::BLOCK.to_string(),
            matched: false,
            reason: "no geo policy is configured for this site".to_string(),
        };
    };
    if !geo.enabled {
        return GeoAnalysis {
            enabled: false,
            mode: geo.mode.clone(),
            action: geo.action.clone(),
            matched: false,
            reason: "the geo policy is disabled".to_string(),
        };
    }

    let blocked: Vec<String> = geo
        .countries
        .iter()
        .map(|code| code.trim().to_uppercase())
        .collect();
    let asn_denied = !geo.blocked_asns.is_empty()
        && asn.is_some_and(|asn| {
            geo.blocked_asns
                .iter()
                .filter_map(|entry| parse_asn(entry))
                .any(|blocked| blocked == asn)
        });
    let country_denied = match country {
        Some(code) => {
            let code = code.to_uppercase();
            if geo.mode == "allow_list" {
                !blocked.contains(&code)
            } else {
                blocked.contains(&code)
            }
        },
        None => geo.block_unknown,
    };

    let matched = asn_denied || country_denied;
    let reason = match (country, asn_denied, country_denied) {
        (Some(code), true, _) => {
            format!("country {code} and its network are restricted")
        },
        (Some(code), false, true) if geo.mode == "allow_list" => {
            format!("country {code} is not on the allow list")
        },
        (Some(code), false, true) => {
            format!("country {code} is on the block list")
        },
        (Some(code), false, false) if geo.mode == "allow_list" => {
            format!("country {code} is on the allow list")
        },
        (Some(code), false, false) => {
            format!("country {code} is not restricted")
        },
        (None, true, _) => "the client network is restricted".to_string(),
        (None, false, true) => {
            "the country of the client could not be determined and unknown \
             countries are blocked"
                .to_string()
        },
        (None, false, false) => {
            "the country of the client could not be determined".to_string()
        },
    };

    GeoAnalysis {
        enabled: true,
        mode: geo.mode.clone(),
        action: geo.action.clone(),
        matched,
        reason,
    }
}

/// Resolves the country with the embedded database the edge uses.
fn lookup_country(ip: IpAddr) -> Option<String> {
    GEO_DB
        .lookup_country_code(ip)
        .map(|code| code.as_ref().to_uppercase())
}

fn lookup_asn(ip: IpAddr) -> Option<u32> {
    GEO_DB.lookup_asn(ip)
}

/// Parses an ASN written bare or with an `AS` prefix (`13335`, `AS13335`).
fn parse_asn(value: &str) -> Option<u32> {
    let trimmed = value.trim();
    let digits = trimmed
        .strip_prefix("AS")
        .or_else(|| trimmed.strip_prefix("as"))
        .unwrap_or(trimmed);
    digits.parse::<u32>().ok()
}

/// Whether a configured range (CIDR or a bare address) contains the IP.
fn range_contains(range: &str, ip: IpAddr) -> bool {
    let trimmed = range.trim();
    trimmed
        .parse::<IpNet>()
        .map(|net| net.contains(&ip))
        .or_else(|_| trimmed.parse::<IpAddr>().map(|addr| addr == ip))
        .unwrap_or(false)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ranges_accept_cidr_and_bare_addresses() {
        let ip: IpAddr = "203.0.113.7".parse().unwrap();
        assert!(range_contains("203.0.113.0/24", ip));
        assert!(range_contains("203.0.113.7", ip));
        assert!(!range_contains("198.51.100.0/24", ip));
        assert!(!range_contains("not-a-range", ip));
    }

    #[test]
    fn asns_parse_with_and_without_prefix() {
        assert_eq!(parse_asn("AS13335"), Some(13335));
        assert_eq!(parse_asn("as13335"), Some(13335));
        assert_eq!(parse_asn("13335"), Some(13335));
        assert_eq!(parse_asn("nope"), None);
    }

    #[test]
    fn geo_analysis_matches_the_edge_semantics() {
        let row = geo_rules::Model {
            id: Uuid::new_v4(),
            site_id: Uuid::new_v4(),
            enabled: true,
            mode: "block_list".to_string(),
            countries: vec!["RU".to_string()],
            blocked_asns: vec!["AS13335".to_string()],
            block_unknown: false,
            action: "log".to_string(),
            updated_at: chrono::Utc::now(),
        };
        let blocked = geo_analysis(Some(&row), Some("ru"), None);
        assert!(blocked.matched);
        assert_eq!(blocked.action, "log");

        let asn_blocked = geo_analysis(Some(&row), Some("US"), Some(13335));
        assert!(asn_blocked.matched);

        let clean = geo_analysis(Some(&row), Some("US"), Some(15169));
        assert!(!clean.matched);

        let unknown = geo_analysis(Some(&row), None, None);
        assert!(!unknown.matched);

        let allow_row = geo_rules::Model {
            mode: "allow_list".to_string(),
            block_unknown: true,
            ..row
        };
        let outside = geo_analysis(Some(&allow_row), Some("US"), None);
        assert!(outside.matched);
        assert!(outside.reason.contains("allow list"));
    }
}
