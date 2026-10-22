//! Routes for the dashboard's own ACME certificate.
//!
//! `/system/tls/acme` stores the identity (domain name or IP) and the ACME
//! contact, arms issuance and exposes the lifecycle state; the installer in
//! [`crate::management_cert`] installs the certificate the edge issues on
//! the 9080 listener. A manual upload on `/system/tls/certificate` keeps
//! working and simply replaces the active certificate.

use axum::extract::State;
use axum::routing::{get, post};
use axum::{Json, Router};
use chrono::{DateTime, Utc};
use sea_orm::{
    ColumnTrait, EntityTrait, QueryFilter, QueryOrder,
};
use serde::{Deserialize, Serialize};

use crate::api::error::ApiError;
use crate::api::state::AppState;
use crate::auth::AuthUser;
use crate::management_cert;
use crate::models::control_plane_certificate;

/// Routes contributed to `/api/v1`.
pub fn routes() -> Router<AppState> {
    Router::new()
        .route("/system/tls/acme", get(show).put(update))
        .route("/system/tls/acme/retry", post(retry))
}

/// The dashboard-facing view of the request and the active certificate.
#[derive(Serialize)]
pub struct AcmeView {
    /// Whether an edge shares this process, i.e. auto-issue can complete.
    pub available: bool,
    pub identity: String,
    pub email: String,
    pub enabled: bool,
    pub status: String,
    pub failure_reason: Option<String>,
    /// Fingerprint of the certificate the control plane last installed.
    pub installed_fingerprint: Option<String>,
    /// The certificate the 9080 listener presents right now.
    pub active: Option<ActiveCertificate>,
}

#[derive(Serialize)]
pub struct ActiveCertificate {
    pub source: String,
    pub sans: Vec<String>,
    pub not_after: DateTime<Utc>,
    pub fingerprint_sha256: String,
}

#[derive(Deserialize)]
pub struct UpdateAcmeRequest {
    pub identity: String,
    pub email: String,
    pub enabled: bool,
}

/// `GET /api/v1/system/tls/acme` - current request and active certificate.
async fn show(
    State(state): State<AppState>,
    current: AuthUser,
) -> Result<Json<AcmeView>, ApiError> {
    current.require_admin().map_err(ApiError::from)?;
    build_view(&state).await.map(Json)
}

/// `PUT /api/v1/system/tls/acme` - set the identity/contact and arm or
/// disarm issuance.
async fn update(
    State(state): State<AppState>,
    current: AuthUser,
    Json(payload): Json<UpdateAcmeRequest>,
) -> Result<Json<AcmeView>, ApiError> {
    current.require_admin().map_err(ApiError::from)?;
    if payload.enabled && !management_cert::available() {
        return Err(ApiError::BadRequest(
            "auto-issue needs the edge on the management host (all-in-one \
             mode); upload a certificate under System TLS instead"
                .to_string(),
        ));
    }
    let identity = management_cert::normalize_identity(&payload.identity)
        .map_err(ApiError::BadRequest)?;
    let email = management_cert::normalize_email(&payload.email)
        .map_err(ApiError::BadRequest)?;
    let row = management_cert::load(&state.db)
        .await
        .map_err(ApiError::from)?;
    let row = management_cert::apply(
        &state.db,
        row,
        identity.clone(),
        email,
        payload.enabled,
    )
    .await
    .map_err(ApiError::from)?;

    tracing::info!(
        actor = %current.email,
        identity = %row.identity,
        enabled = row.enabled,
        "management certificate request updated"
    );
    write_event(
        &state,
        if payload.enabled {
            "management_requested"
        } else {
            "management_disabled"
        },
        format!(
            "Management certificate for {} {}",
            row.identity,
            if payload.enabled {
                "requested (Let's Encrypt, HTTP-01)"
            } else {
                "disabled"
            }
        ),
    )
    .await;
    build_view(&state).await.map(Json)
}

/// `POST /api/v1/system/tls/acme/retry` - re-arm a failed or stuck request.
async fn retry(
    State(state): State<AppState>,
    current: AuthUser,
) -> Result<Json<AcmeView>, ApiError> {
    current.require_admin().map_err(ApiError::from)?;
    if !management_cert::available() {
        return Err(ApiError::BadRequest(
            "auto-issue needs the edge on the management host (all-in-one \
             mode); upload a certificate under System TLS instead"
                .to_string(),
        ));
    }
    let row = management_cert::load(&state.db)
        .await
        .map_err(ApiError::from)?;
    let row = management_cert::retry(&state.db, row)
        .await
        .map_err(ApiError::from)?;
    tracing::info!(actor = %current.email, identity = %row.identity, "management certificate retried");
    write_event(
        &state,
        "management_requested",
        format!("Management certificate for {} retried", row.identity),
    )
    .await;
    build_view(&state).await.map(Json)
}

/// Builds the response from the settings row and the active certificate.
async fn build_view(state: &AppState) -> Result<AcmeView, ApiError> {
    let row = management_cert::load(&state.db)
        .await
        .map_err(ApiError::from)?;
    let active = control_plane_certificate::Entity::find()
        .filter(control_plane_certificate::Column::IsActive.eq(true))
        .order_by_desc(control_plane_certificate::Column::CreatedAt)
        .one(&state.db)
        .await?;
    Ok(AcmeView {
        available: management_cert::available(),
        identity: row.identity.clone(),
        email: row.email.clone(),
        enabled: row.enabled,
        status: row.status.clone(),
        failure_reason: row.failure_reason.clone(),
        installed_fingerprint: row.installed_fingerprint.clone(),
        active: active.map(|row| ActiveCertificate {
            source: row.source,
            sans: row
                .sans
                .as_array()
                .map(|items| {
                    items
                        .iter()
                        .filter_map(|item| item.as_str().map(str::to_string))
                        .collect()
                })
                .unwrap_or_default(),
            not_after: row.not_after.with_timezone(&Utc),
            fingerprint_sha256: row.fingerprint_sha256,
        }),
    })
}

/// Records the change in the certificate event log (the SSL Application log).
async fn write_event(state: &AppState, event_type: &str, message: String) {
    let event = crate::models::certificate_events::ActiveModel {
        id: sea_orm::Set(uuid::Uuid::new_v4()),
        certificate_id: sea_orm::Set(None),
        site_id: sea_orm::Set(None),
        event_type: sea_orm::Set(event_type.to_string()),
        message: sea_orm::Set(message),
        details: sea_orm::Set(None),
        created_at: sea_orm::Set(Utc::now()),
    };
    if let Err(err) = sea_orm::ActiveModelTrait::insert(event, &state.db).await
    {
        tracing::warn!(%err, "failed to write management certificate event");
    }
}
