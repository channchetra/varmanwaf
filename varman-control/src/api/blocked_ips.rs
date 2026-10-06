//! Auto-blocked IP dashboard: lists the dynamic blocks the edge currently
//! enforces for a site (WAF/rate-limit auto-blocks and server-issued block
//! commands) and offers a one-click unblock that fans out to every agent
//! reporting the block.

use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use chrono::{DateTime, Utc};
use sea_orm::{
    ColumnTrait, EntityTrait, FromQueryResult, QueryFilter, QueryOrder,
    QuerySelect,
};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::api::common::{load_site_read, load_site_write, parse_uuid};
use crate::api::error::ApiError;
use crate::api::state::AppState;
use crate::auth::AuthUser;
use crate::models::{agent_blocked_ip, security_event};

/// Per-IP attack rollup over `security_events`, grouped by client IP.
#[derive(Debug, FromQueryResult)]
struct AttackStats {
    client_ip: String,
    attack_count: i64,
    last_attack_at: Option<DateTime<Utc>>,
}

/// One blocked IP as shown on the dashboard: the edge-side block merged with
/// the attack history that led to it. Multiple agents may enforce the same IP;
/// the counts and timestamps are folded into a single row.
#[derive(Debug, Serialize)]
pub struct BlockedIpResponse {
    pub ip: String,
    pub reason: Option<String>,
    pub blocked_at: DateTime<Utc>,
    /// None = permanent block (no automatic expiry).
    pub expires_at: Option<DateTime<Utc>>,
    pub agent_count: usize,
    pub attack_count: i64,
    pub last_attack_at: Option<DateTime<Utc>>,
}

#[derive(Debug, Deserialize)]
pub struct UnblockRequest {
    pub ip: String,
}

/// Routes contributed to `/api/v1`.
pub fn routes() -> Router<AppState> {
    Router::new()
        .route("/sites/{site_id}/blocked-ips", get(list))
        .route("/sites/{site_id}/blocked-ips/unblock", post(unblock))
}

/// `GET /api/v1/sites/{site_id}/blocked-ips` — dynamic blocks in force,
/// newest first, each merged with its attack stats from `security_events`.
/// Lapsed blocks are hidden: the agent stops reporting them and the next
/// heartbeat reconciles the mirror, but a just-expired row may still be
/// visible between heartbeats.
async fn list(
    State(state): State<AppState>,
    current: AuthUser,
    Path(site_id): Path<String>,
) -> Result<Json<Vec<BlockedIpResponse>>, ApiError> {
    let id = parse_uuid(&site_id, "site id")?;
    load_site_read(&state.db, id, &current).await?;

    let now = Utc::now();
    let rows = agent_blocked_ip::Entity::find()
        .filter(agent_blocked_ip::Column::SiteId.eq(id))
        .filter(
            sea_orm::Condition::any()
                .add(agent_blocked_ip::Column::ExpiresAt.is_null())
                .add(agent_blocked_ip::Column::ExpiresAt.gt(now)),
        )
        .order_by_desc(agent_blocked_ip::Column::BlockedAt)
        .all(&state.db)
        .await?;

    let stats = security_event::Entity::find()
        .select_only()
        .column(security_event::Column::ClientIp)
        .column_as(security_event::Column::Id.count(), "attack_count")
        .column_as(security_event::Column::Timestamp.max(), "last_attack_at")
        .filter(security_event::Column::SiteId.eq(id))
        .group_by(security_event::Column::ClientIp)
        .into_model::<AttackStats>()
        .all(&state.db)
        .await?;
    let stat_map: std::collections::HashMap<String, AttackStats> = stats
        .into_iter()
        .map(|s| (s.client_ip.clone(), s))
        .collect();

    let mut by_ip: std::collections::HashMap<String, BlockedIpResponse> =
        std::collections::HashMap::new();
    for row in rows {
        let entry = by_ip.entry(row.ip.clone()).or_insert_with(|| {
            let stat = stat_map.get(&row.ip);
            BlockedIpResponse {
                ip: row.ip.clone(),
                reason: row.reason.clone(),
                blocked_at: row.blocked_at,
                expires_at: row.expires_at,
                agent_count: 0,
                attack_count: stat.map_or(0, |s| s.attack_count),
                last_attack_at: stat.and_then(|s| s.last_attack_at),
            }
        });
        entry.agent_count += 1;
        // The most recent report wins for reason/timestamps; expiry shows the
        // soonest automatic unblock across enforcing agents.
        if row.blocked_at >= entry.blocked_at {
            entry.blocked_at = row.blocked_at;
            if row.reason.is_some() {
                entry.reason = row.reason.clone();
            }
        }
        entry.expires_at = match (entry.expires_at, row.expires_at) {
            (Some(a), Some(b)) => Some(a.min(b)),
            (None, Some(b)) => Some(b),
            (a, None) => a,
        };
    }

    let mut out: Vec<BlockedIpResponse> = by_ip.into_values().collect();
    out.sort_by_key(|ip| std::cmp::Reverse(ip.blocked_at));
    Ok(Json(out))
}

/// `POST /api/v1/sites/{site_id}/blocked-ips/unblock` — lifts a dynamic block:
/// an `UnblockIp` command goes to every agent still enforcing it (queued when
/// disconnected) and the mirror rows are removed so the dashboard reflects
/// the unblock immediately.
async fn unblock(
    State(state): State<AppState>,
    current: AuthUser,
    Path(site_id): Path<String>,
    Json(payload): Json<UnblockRequest>,
) -> Result<Response, ApiError> {
    let id = parse_uuid(&site_id, "site id")?;
    load_site_write(&state.db, id, &current).await?;
    let ip = payload.ip.trim().to_string();
    if ip.is_empty() || ip.parse::<std::net::IpAddr>().is_err() {
        return Err(ApiError::BadRequest(format!(
            "invalid IP address: '{ip}'"
        )));
    }

    let rows = agent_blocked_ip::Entity::find()
        .filter(agent_blocked_ip::Column::SiteId.eq(id))
        .filter(agent_blocked_ip::Column::Ip.eq(&ip))
        .all(&state.db)
        .await?;
    let agent_ids: std::collections::BTreeSet<Uuid> =
        rows.iter().map(|row| row.agent_id).collect();

    let request = crate::api::agents::CommandRequest {
        command: "unblock_ip".to_string(),
        site_id: Some(id.to_string()),
        ip_addresses: vec![ip.clone()],
        urls: Vec::new(),
        tags: Vec::new(),
        duration_seconds: None,
        reason: Some("unblocked from dashboard".to_string()),
        graceful: true,
    };
    let mut delivered = 0usize;
    for agent_id in &agent_ids {
        let command = crate::api::agents::build_command(&request, Some(id))?;
        if state.agents.send_command(agent_id, command).await {
            delivered += 1;
        }
    }

    agent_blocked_ip::Entity::delete_many()
        .filter(agent_blocked_ip::Column::SiteId.eq(id))
        .filter(agent_blocked_ip::Column::Ip.eq(&ip))
        .exec(&state.db)
        .await?;

    tracing::info!(
        %id,
        %ip,
        agents = agent_ids.len(),
        delivered,
        requested_by = %current.id,
        "dynamic IP block lifted"
    );

    Ok((
        StatusCode::ACCEPTED,
        Json(serde_json::json!({
            "ip": ip,
            "agents": agent_ids.len(),
            "delivered": delivered,
        })),
    )
        .into_response())
}
