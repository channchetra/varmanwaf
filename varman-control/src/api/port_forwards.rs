//! TCP port forwards: expose a private `host:port` on an edge listen port.
//!
//! Forwards are per-site so they follow site ownership. The control plane
//! validates the port range, target and allowlist; the agent opens the actual
//! listener and enforces `allowed_cidrs` per accepted connection.

use axum::extract::{Path, State};
use axum::routing::{get, put};
use axum::{Json, Router};
use chrono::Utc;
use ipnet::IpNet;
use sea_orm::{ActiveModelTrait, ColumnTrait, EntityTrait, QueryFilter, Set};
use serde::Deserialize;
use std::net::IpAddr;
use uuid::Uuid;

use crate::api::common::{load_site_read, load_site_write, parse_uuid};
use crate::api::error::ApiError;
use crate::api::state::AppState;
use crate::auth::AuthUser;
use crate::grpc::notify_all_config_changed;
use crate::models::port_forward;

/// The public listen ports reserved for port forwarding. The deployment must
/// publish the same range (see docker-compose.yml).
pub const LISTEN_PORT_MIN: i32 = 10_000;
pub const LISTEN_PORT_MAX: i32 = 10_099;

pub fn routes() -> Router<AppState> {
    Router::new()
        .route("/sites/{site_id}/port-forwards", get(list).post(create))
        .route(
            "/sites/{site_id}/port-forwards/{forward_id}",
            put(update).delete(remove),
        )
}

#[derive(Debug, Deserialize)]
pub struct CreatePortForwardRequest {
    pub name: String,
    pub listen_port: i32,
    pub target_host: String,
    pub target_port: i32,
    /// At least one address/CIDR; an empty list would expose the target to the
    /// whole internet by accident.
    #[serde(default)]
    pub allowed_cidrs: Vec<String>,
    #[serde(default)]
    pub enabled: Option<bool>,
}

#[derive(Debug, Deserialize)]
pub struct UpdatePortForwardRequest {
    #[serde(default)]
    pub name: Option<String>,
    #[serde(default)]
    pub listen_port: Option<i32>,
    #[serde(default)]
    pub target_host: Option<String>,
    #[serde(default)]
    pub target_port: Option<i32>,
    #[serde(default)]
    pub allowed_cidrs: Option<Vec<String>>,
    #[serde(default)]
    pub enabled: Option<bool>,
}

/// `GET /api/v1/sites/{site_id}/port-forwards`
async fn list(
    State(state): State<AppState>,
    current: AuthUser,
    Path(site_id): Path<String>,
) -> Result<Json<Vec<port_forward::Model>>, ApiError> {
    let site = parse_uuid(&site_id, "site id")?;
    load_site_read(&state.db, site, &current).await?;
    let rows = port_forward::Entity::find()
        .filter(port_forward::Column::SiteId.eq(site))
        .all(&state.db)
        .await?;
    Ok(Json(rows))
}

/// `POST /api/v1/sites/{site_id}/port-forwards`
async fn create(
    State(state): State<AppState>,
    current: AuthUser,
    Path(site_id): Path<String>,
    Json(payload): Json<CreatePortForwardRequest>,
) -> Result<Json<port_forward::Model>, ApiError> {
    let site = parse_uuid(&site_id, "site id")?;
    load_site_write(&state.db, site, &current).await?;

    let name = validate_name(&payload.name)?;
    let listen_port = validate_listen_port(payload.listen_port)?;
    let target_host = validate_target_host(&payload.target_host)?;
    let target_port = validate_target_port(payload.target_port)?;
    if target_is_waf_listener(&target_host, target_port) {
        return Err(ApiError::BadRequest(
            "target points at the WAF listener (loopback on 80/443/9080/9090); use the service's private address".to_string(),
        ));
    }
    let allowed = validate_allowed_cidrs(&payload.allowed_cidrs)?;
    ensure_listen_port_free(&state, listen_port, None).await?;

    let now = Utc::now();
    let model = port_forward::ActiveModel {
        id: Set(Uuid::new_v4()),
        site_id: Set(site),
        name: Set(name),
        listen_port: Set(listen_port),
        target_host: Set(target_host),
        target_port: Set(target_port),
        allowed_cidrs: Set(allowed),
        enabled: Set(payload.enabled.unwrap_or(true)),
        created_at: Set(now),
        updated_at: Set(now),
    }
    .insert(&state.db)
    .await?;

    tracing::info!(
        %site,
        forward = %model.id,
        listen_port,
        target = %format!("{}:{}", model.target_host, model.target_port),
        "port forward created"
    );
    notify_all_config_changed(&state, Some(&current.email)).await;
    Ok(Json(model))
}

/// `PUT /api/v1/sites/{site_id}/port-forwards/{forward_id}`
async fn update(
    State(state): State<AppState>,
    current: AuthUser,
    Path((site_id, forward_id)): Path<(String, String)>,
    Json(payload): Json<UpdatePortForwardRequest>,
) -> Result<Json<port_forward::Model>, ApiError> {
    let site = parse_uuid(&site_id, "site id")?;
    let target = parse_uuid(&forward_id, "port forward id")?;
    load_site_write(&state.db, site, &current).await?;

    let row = port_forward::Entity::find_by_id(target)
        .filter(port_forward::Column::SiteId.eq(site))
        .one(&state.db)
        .await?
        .ok_or_else(|| {
            ApiError::NotFound(format!("port forward {target} not found"))
        })?;

    let listen_port = match payload.listen_port {
        Some(port) => validate_listen_port(port)?,
        None => row.listen_port,
    };
    ensure_listen_port_free(&state, listen_port, Some(target)).await?;

    let mut effective_host = row.target_host.clone();
    let mut effective_port = row.target_port;
    let mut active: port_forward::ActiveModel = row.into();
    if let Some(name) = payload.name {
        active.name = Set(validate_name(&name)?);
    }
    active.listen_port = Set(listen_port);
    if let Some(host) = payload.target_host {
        effective_host = validate_target_host(&host)?;
        active.target_host = Set(effective_host.clone());
    }
    if let Some(port) = payload.target_port {
        effective_port = validate_target_port(port)?;
        active.target_port = Set(effective_port);
    }
    // Validate the effective target after applying the patch: changing only
    // the host or only the port must still not point at the WAF listener.
    if target_is_waf_listener(&effective_host, effective_port) {
        return Err(ApiError::BadRequest(
            "target points at the WAF listener (loopback on 80/443/9080/9090); use the service's private address".to_string(),
        ));
    }
    if let Some(cidrs) = payload.allowed_cidrs {
        active.allowed_cidrs = Set(validate_allowed_cidrs(&cidrs)?);
    }
    if let Some(enabled) = payload.enabled {
        active.enabled = Set(enabled);
    }
    active.updated_at = Set(Utc::now());
    let updated = active.update(&state.db).await?;

    tracing::info!(
        %site,
        forward = %target,
        "port forward updated"
    );
    notify_all_config_changed(&state, Some(&current.email)).await;
    Ok(Json(updated))
}

/// `DELETE /api/v1/sites/{site_id}/port-forwards/{forward_id}`
async fn remove(
    State(state): State<AppState>,
    current: AuthUser,
    Path((site_id, forward_id)): Path<(String, String)>,
) -> Result<axum::http::StatusCode, ApiError> {
    let site = parse_uuid(&site_id, "site id")?;
    let target = parse_uuid(&forward_id, "port forward id")?;
    load_site_write(&state.db, site, &current).await?;

    let result = port_forward::Entity::delete_many()
        .filter(port_forward::Column::Id.eq(target))
        .filter(port_forward::Column::SiteId.eq(site))
        .exec(&state.db)
        .await?;
    if result.rows_affected == 0 {
        return Err(ApiError::NotFound(format!(
            "port forward {target} not found"
        )));
    }
    tracing::info!(%site, forward = %target, "port forward removed");
    notify_all_config_changed(&state, Some(&current.email)).await;
    Ok(axum::http::StatusCode::NO_CONTENT)
}

fn target_is_waf_listener(host: &str, port: i32) -> bool {
    if !matches!(port, 80 | 443 | 9080 | 9090) {
        return false;
    }
    host.eq_ignore_ascii_case("localhost")
        || host
            .parse::<IpAddr>()
            .is_ok_and(|ip| ip.is_loopback() || ip.is_unspecified())
}

fn validate_name(raw: &str) -> Result<String, ApiError> {
    let name = raw.trim().to_string();
    if name.is_empty() || name.len() > 100 {
        return Err(ApiError::BadRequest(
            "port forward name must be 1-100 characters".to_string(),
        ));
    }
    Ok(name)
}

fn validate_listen_port(port: i32) -> Result<i32, ApiError> {
    if (LISTEN_PORT_MIN..=LISTEN_PORT_MAX).contains(&port) {
        Ok(port)
    } else {
        Err(ApiError::BadRequest(format!(
            "listen port must be between {LISTEN_PORT_MIN} and {LISTEN_PORT_MAX}"
        )))
    }
}

fn validate_target_port(port: i32) -> Result<i32, ApiError> {
    if (1..=65_535).contains(&port) {
        Ok(port)
    } else {
        Err(ApiError::BadRequest(
            "target port must be between 1 and 65535".to_string(),
        ))
    }
}

fn validate_target_host(raw: &str) -> Result<String, ApiError> {
    let host = raw.trim().to_string();
    if host.is_empty() || host.len() > 253 {
        return Err(ApiError::BadRequest(
            "target host must be 1-253 characters".to_string(),
        ));
    }
    if host.parse::<IpAddr>().is_err() {
        let valid = host.chars().all(|c| {
            c.is_ascii_alphanumeric() || c == '.' || c == '-' || c == '_'
        });
        if !valid {
            return Err(ApiError::BadRequest(
                "target host must be an IP address or hostname".to_string(),
            ));
        }
    }
    Ok(host)
}

/// Validates and normalizes the allowlist. At least one entry is required: a
/// forward with no allowlist would be reachable by every client that can see
/// the listen port.
fn validate_allowed_cidrs(raw: &[String]) -> Result<Vec<String>, ApiError> {
    let mut out = Vec::new();
    for entry in raw {
        let value = entry.trim();
        if value.is_empty() {
            continue;
        }
        if value.parse::<IpNet>().is_err() && value.parse::<IpAddr>().is_err() {
            return Err(ApiError::BadRequest(format!(
                "invalid allowed address or CIDR '{value}'"
            )));
        }
        if !out.iter().any(|existing| existing == value) {
            out.push(value.to_string());
        }
    }
    if out.is_empty() {
        return Err(ApiError::BadRequest(
            "at least one allowed address or CIDR is required".to_string(),
        ));
    }
    Ok(out)
}

/// The listen port is a deployment-wide resource: two sites cannot bind the
/// same port on the same edge.
async fn ensure_listen_port_free(
    state: &AppState,
    port: i32,
    except: Option<Uuid>,
) -> Result<(), ApiError> {
    let mut condition = port_forward::Column::ListenPort.eq(port);
    if let Some(id) = except {
        condition = condition.and(port_forward::Column::Id.ne(id));
    }
    let exists = port_forward::Entity::find()
        .filter(condition)
        .one(&state.db)
        .await?;
    if exists.is_some() {
        return Err(ApiError::Conflict(format!(
            "listen port {port} is already used by another forward"
        )));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn listen_ports_are_limited_to_the_published_range() {
        assert_eq!(validate_listen_port(10_000).unwrap(), 10_000);
        assert_eq!(validate_listen_port(10_099).unwrap(), 10_099);
        assert!(validate_listen_port(9_999).is_err());
        assert!(validate_listen_port(10_100).is_err());
        assert!(validate_listen_port(80).is_err());
    }

    #[test]
    fn allowlists_must_be_valid_and_non_empty() {
        let values = vec![
            "203.0.113.7".to_string(),
            "10.0.0.0/8".to_string(),
            "203.0.113.7".to_string(),
        ];
        assert_eq!(
            validate_allowed_cidrs(&values).unwrap(),
            vec!["203.0.113.7".to_string(), "10.0.0.0/8".to_string()]
        );
        assert!(validate_allowed_cidrs(&[]).is_err());
        assert!(validate_allowed_cidrs(&["not-an-ip".to_string()]).is_err());
    }

    #[test]
    fn waf_listener_targets_are_rejected() {
        assert!(target_is_waf_listener("localhost", 80));
        assert!(target_is_waf_listener("127.0.0.1", 443));
        assert!(target_is_waf_listener("::1", 9080));
        assert!(target_is_waf_listener("0.0.0.0", 9090));
        assert!(!target_is_waf_listener("10.1.18.5", 80));
        assert!(!target_is_waf_listener("127.0.0.1", 3001));
    }

    #[test]
    fn target_host_and_port_are_validated() {
        assert_eq!(validate_target_host(" 10.1.18.5 ").unwrap(), "10.1.18.5");
        assert_eq!(validate_target_host("db.internal").unwrap(), "db.internal");
        assert!(validate_target_host("http://x").is_err());
        assert!(validate_target_port(0).is_err());
        assert!(validate_target_port(65_536).is_err());
        assert_eq!(validate_target_port(22).unwrap(), 22);
    }
}
