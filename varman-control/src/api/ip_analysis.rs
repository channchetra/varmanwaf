//! Client IP analysis: why would this address be allowed or blocked?
//!
//! The answer is computed from the same stored configuration the control
//! plane compiles into the site bundle - the site's IP access rules in
//! priority order, then the enabled IP groups that apply to the site, then
//! the geo policy - with the geo side matching the **ipverse-synced ranges**
//! exactly as the edge does. Country codes shown here are display labels
//! from the built-in table; they play no part in enforcement. What this
//! cannot see is stated explicitly in `limitations` rather than guessed at.

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
use crate::ipverse::{self, KIND_ASN, KIND_COUNTRY};
use crate::models::{defense_settings, geo_rules, ip_groups, site};

/// The embedded country table - display labels only, never enforcement.
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
    /// Display label from the built-in table (not used for enforcement).
    country: Option<String>,
    /// Blocked ASNs whose synced ranges contain the address.
    asn_matches: Vec<String>,
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
    /// Where the enforcement data comes from: always `ipverse`.
    source: String,
    /// False when a listed country/ASN has no synced dataset.
    synced: bool,
    /// Listed keys whose dataset is missing: not enforced until synced.
    missing_keys: Vec<String>,
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
    Path(site_id): Path<String>,
    Query(query): Query<AnalysisQuery>,
) -> Result<Json<IpAnalysis>, ApiError> {
    current.require_admin().map_err(ApiError::from)?;

    let raw = query.ip.trim();
    let ip: IpAddr = raw.parse().map_err(|_| {
        ApiError::BadRequest(format!("'{raw}' is not an IP address"))
    })?;

    let exists = site::Entity::find_by_id(parse_uuid(&site_id)?)
        .one(&state.db)
        .await?
        .is_some();
    if !exists {
        return Err(ApiError::NotFound("site not found".to_string()));
    }
    let site_id = parse_uuid(&site_id)?;

    let country = lookup_country(ip);

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

    // ── Geo policy, matched against the ipverse-synced ranges ──
    let geo_row = geo_rules::Entity::find()
        .filter(geo_rules::Column::SiteId.eq(site_id))
        .one(&state.db)
        .await?;
    let (geo, asn_matches) =
        geo_analysis(&state.db, geo_row.as_ref(), ip).await?;

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
        "Enforcement uses the ipverse ranges synced on the Access control \
         page; the country shown here is a display label from the built-in \
         table and plays no part in the decision."
            .to_string(),
        "Policy-layer IP rules (Policies) are not simulated here; the \
         verdict covers this site's IP rules, IP groups and geo policy."
            .to_string(),
        "Live state (active challenges, clearance cookies, connection \
         tracking) is not visible to the control plane."
            .to_string(),
    ];
    if !geo.missing_keys.is_empty() {
        limitations.push(format!(
            "Not enforced until synced from ipverse: {}.",
            geo.missing_keys.join(", ")
        ));
    }
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
        asn_matches,
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

/// Mirrors the edge's geo evaluation exactly: the listed countries and ASNs
/// resolve to their synced ipverse ranges, and the same range logic decides.
async fn geo_analysis(
    db: &sea_orm::DatabaseConnection,
    row: Option<&geo_rules::Model>,
    ip: IpAddr,
) -> Result<(GeoAnalysis, Vec<String>), ApiError> {
    let Some(geo) = row else {
        return Ok((
            GeoAnalysis {
                enabled: false,
                mode: "block_list".to_string(),
                action: crate::models::action::BLOCK.to_string(),
                matched: false,
                reason: "no geo policy is configured for this site".to_string(),
                source: "ipverse".to_string(),
                synced: true,
                missing_keys: Vec::new(),
            },
            Vec::new(),
        ));
    };
    if !geo.enabled {
        return Ok((
            GeoAnalysis {
                enabled: false,
                mode: geo.mode.clone(),
                action: geo.action.clone(),
                matched: false,
                reason: "the geo policy is disabled".to_string(),
                source: "ipverse".to_string(),
                synced: true,
                missing_keys: Vec::new(),
            },
            Vec::new(),
        ));
    }

    let country_map =
        ipverse::load_map(db, KIND_COUNTRY, &geo.countries).await?;
    let asn_map = ipverse::load_map(db, KIND_ASN, &geo.blocked_asns).await?;

    let mut country_ranges = Vec::new();
    let mut missing_keys = Vec::new();
    for key in &geo.countries {
        match ipverse::normalise_key(KIND_COUNTRY, key)
            .ok()
            .and_then(|key| country_map.get(&key))
        {
            Some(dataset) => country_ranges.extend(dataset.all()),
            None => missing_keys.push(key.clone()),
        }
    }

    let mut asn_ranges = Vec::new();
    let mut asn_matches = Vec::new();
    for key in &geo.blocked_asns {
        match ipverse::normalise_key(KIND_ASN, key)
            .ok()
            .and_then(|key| asn_map.get(&key))
        {
            Some(dataset) => {
                let ranges = dataset.all();
                let normalised = ipverse::normalise_key(KIND_ASN, key)
                    .unwrap_or_else(|_| key.clone());
                if ranges.iter().any(|range| range_contains(range, ip)) {
                    asn_matches.push(format!("AS{normalised}"));
                }
                asn_ranges.extend(ranges);
            },
            None => missing_keys.push(format!(
                "AS{}",
                key.trim_start_matches(['A', 'S', 'a', 's'])
            )),
        }
    }

    let in_country =
        country_ranges.iter().any(|range| range_contains(range, ip));
    let in_asn = asn_ranges.iter().any(|range| range_contains(range, ip));
    let allow_list = geo.mode == "allow_list";
    let matched = if allow_list {
        !in_country
    } else {
        in_country || in_asn || (geo.block_unknown && !in_country)
    };
    let reason = if allow_list {
        if in_country {
            "the client address is inside the allowed countries".to_string()
        } else {
            "the client address is outside the allowed countries".to_string()
        }
    } else if in_country {
        "the client address is inside a blocked country's ranges".to_string()
    } else if in_asn {
        "the client address is inside a blocked ASN's ranges".to_string()
    } else if geo.block_unknown {
        "the client address is outside every listed country (block \
         unknown is on)"
            .to_string()
    } else {
        "the client address is not inside any listed range".to_string()
    };

    Ok((
        GeoAnalysis {
            enabled: true,
            mode: geo.mode.clone(),
            action: geo.action.clone(),
            matched,
            reason,
            source: "ipverse".to_string(),
            synced: missing_keys.is_empty(),
            missing_keys,
        },
        asn_matches,
    ))
}

/// Resolves the display country label with the built-in table.
fn lookup_country(ip: IpAddr) -> Option<String> {
    GEO_DB
        .lookup_country_code(ip)
        .map(|code| code.as_ref().to_uppercase())
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

fn parse_uuid(raw: &str) -> Result<Uuid, ApiError> {
    raw.parse::<Uuid>()
        .map_err(|_| ApiError::BadRequest(format!("'{raw}' is not a uuid")))
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
}
