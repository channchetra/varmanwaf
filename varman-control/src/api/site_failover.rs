//! Site-level disconnected (failover) policy.
//!
//! `sites.failover_policy` decides how the site behaves while the control
//! plane is unreachable and the host has no synced rule bundle: `inherit`
//! (follow `defense_settings.default_fail_open`), `open` (keep proxying
//! through the base engine) or `closed` (answer 503). The value rides in the
//! per-site failover registry inside every `RuleBundle`, so a change here is
//! pushed to the agents like any other configuration edit.

use axum::extract::{Path, State};
use axum::routing::get;
use axum::{Json, Router};
use sea_orm::{ActiveModelTrait, Set};
use serde::{Deserialize, Serialize};
use serde_json::json;

use crate::api::common::{load_site_read, load_site_write, parse_uuid};
use crate::api::error::ApiError;
use crate::api::sites::touch_site;
use crate::api::state::AppState;
use crate::auth::AuthUser;
use crate::grpc::notify_config_changed;
use crate::models::site;

/// Accepted `failover_policy` values.
pub const POLICIES: [&str; 3] = ["inherit", "open", "closed"];

#[derive(Debug, Deserialize)]
pub struct UpdateFailoverRequest {
    /// `inherit`, `open` or `closed`.
    pub policy: String,
}

/// The site's policy plus the global default it inherits from, so the
/// console can render "follow global (currently: fail open)".
#[derive(Debug, Serialize)]
pub struct FailoverSettings {
    pub failover_policy: String,
    pub default_fail_open: bool,
}

/// Routes contributed to `/api/v1`.
pub fn routes() -> Router<AppState> {
    Router::new().route(
        "/sites/{site_id}/failover",
        get(get_failover).put(update_failover),
    )
}

/// `GET /api/v1/sites/{site_id}/failover`
async fn get_failover(
    State(state): State<AppState>,
    current: AuthUser,
    Path(site_id): Path<String>,
) -> Result<Json<FailoverSettings>, ApiError> {
    let id = parse_uuid(&site_id, "site id")?;
    let site_row = load_site_read(&state.db, id, &current).await?;
    let default_fail_open = crate::api::defense::load(&state.db)
        .await?
        .default_fail_open;
    Ok(Json(FailoverSettings {
        failover_policy: site_row.failover_policy,
        default_fail_open,
    }))
}

/// `PUT /api/v1/sites/{site_id}/failover`
async fn update_failover(
    State(state): State<AppState>,
    current: AuthUser,
    Path(site_id): Path<String>,
    Json(payload): Json<UpdateFailoverRequest>,
) -> Result<Json<FailoverSettings>, ApiError> {
    let id = parse_uuid(&site_id, "site id")?;
    let site_row = load_site_write(&state.db, id, &current).await?;

    let policy = payload.policy.trim().to_ascii_lowercase();
    if !POLICIES.contains(&policy.as_str()) {
        return Err(ApiError::BadRequest(format!(
            "unknown policy '{}'; allowed: {}",
            payload.policy.trim(),
            POLICIES.join(", ")
        )));
    }

    let previous_policy = site_row.failover_policy.clone();
    let mut active: site::ActiveModel = site_row.into();
    active.failover_policy = Set(policy);
    active.updated_at = Set(chrono::Utc::now());
    let updated = active.update(&state.db).await?;

    tracing::info!(site_id = %id, policy = %updated.failover_policy, "failover policy updated");
    // The switch decides whether a disconnected site keeps serving or
    // answers 503 — an availability/security decision the dashboard must
    // surface, so it lands in the notification history (and any channel
    // subscribed to it) even though it is not a fault.
    if previous_policy != updated.failover_policy {
        let severity = if updated.failover_policy == "closed" {
            crate::models::severity::WARNING
        } else {
            crate::models::severity::INFO
        };
        crate::notify::emit(crate::notify::AlertEvent {
            event_type: crate::models::event_type::SITE_FAILOVER_CHANGED
                .to_string(),
            severity,
            title: format!(
                "Failover policy of '{}' changed to {}",
                updated.domain, updated.failover_policy
            ),
            message: format!(
                "'{}' changed the disconnected-policy of site '{}' \
                 (id {id}) from '{}' to '{}'.",
                current.email,
                updated.domain,
                previous_policy,
                updated.failover_policy
            ),
            details: Some(json!({
                "site_id": id.to_string(),
                "domain": updated.domain,
                "from": previous_policy,
                "to": updated.failover_policy,
                "actor": current.email,
            })),
            dedup_key: None,
        })
        .await;
    }
    touch_site(&state, id).await?;
    notify_config_changed(&state, id, Some(&current.email)).await;

    Ok(Json(FailoverSettings {
        failover_policy: updated.failover_policy,
        default_fail_open: crate::api::defense::load(&state.db)
            .await?
            .default_fail_open,
    }))
}
