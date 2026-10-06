//! The control plane's own HTTPS certificate.
//!
//! The dashboard is served over HTTPS so browsers treat it as a secure origin
//! (WebAuthn passkeys refuse plain `http://` outside localhost), and that means
//! an operator has to be able to see and replace the certificate without
//! editing files: a self-signed pair is generated on first boot, and a real
//! certificate can be uploaded here. Uploads take effect immediately — the
//! running listener picks the new pair up through its reloadable resolver — so
//! this module is the only place that keeps the database and the listener in
//! sync.
//!
//! Everything here is administrator-only: the private key never leaves the
//! server, and the certificate describes how the console itself is secured.

use axum::extract::State;
use axum::http::{header, HeaderMap, HeaderValue, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use chrono::{DateTime, Utc};
use sea_orm::{
    ActiveModelTrait, ColumnTrait, EntityTrait, QueryFilter, QueryOrder, Set,
};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::api::common::host_without_port;
use crate::api::error::ApiError;
use crate::api::mtls::to_utc;
use crate::api::state::AppState;
use crate::auth::AuthUser;
use crate::config::DEFAULT_TLS_COMMON_NAME;
use crate::models::{control_plane_certificate, tls_source};
use crate::pki::tls::{describe, generate_self_signed, MAX_SERVER_CERT_DAYS};

/// Validity of a generated self-signed certificate, in days. Long enough that
/// an operator does not have to regenerate it, short enough that it is not
/// mistaken for a long-lived trust anchor.
const DEFAULT_SELF_SIGNED_DAYS: i64 = 825;

/// Routes contributed to `/api/v1`.
pub fn routes() -> Router<AppState> {
    Router::new()
        .route("/system/tls", get(show))
        .route("/system/tls/certificate", get(download).put(upload))
        .route("/system/tls/certificate/self-signed", post(generate))
}

/// The certificate as the dashboard sees it. The private key is never
/// included in a JSON response.
#[derive(Debug, Serialize)]
pub struct TlsCertificateView {
    pub id: Uuid,
    /// `self_signed` or `uploaded`.
    pub source: String,
    pub subject_dn: String,
    pub common_name: Option<String>,
    pub sans: Vec<String>,
    pub serial: String,
    pub fingerprint_sha256: String,
    pub not_before: DateTime<Utc>,
    pub not_after: DateTime<Utc>,
    pub created_at: DateTime<Utc>,
    /// Days until `not_after`, negative once the certificate has expired.
    pub expires_in_days: i64,
}

impl From<control_plane_certificate::Model> for TlsCertificateView {
    fn from(model: control_plane_certificate::Model) -> Self {
        let sans = serde_json::from_value(model.sans).unwrap_or_default();
        Self {
            id: model.id,
            source: model.source,
            subject_dn: model.subject_dn,
            common_name: model.common_name,
            sans,
            serial: model.serial,
            fingerprint_sha256: model.fingerprint_sha256,
            not_before: model.not_before,
            not_after: model.not_after,
            created_at: model.created_at,
            expires_in_days: (model.not_after - Utc::now()).num_days(),
        }
    }
}

/// `GET /api/v1/system/tls` — administrators only.
#[derive(Debug, Serialize)]
pub struct TlsStatusView {
    /// `--tls-enabled`: whether this process terminates TLS.
    pub enabled: bool,
    /// Whether a certificate is loaded in the running listener.
    pub has_certificate: bool,
    /// The active certificate, when one has been stored.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub certificate: Option<TlsCertificateView>,
    /// Names the self-signed generator uses for this deployment.
    pub default_sans: Vec<String>,
    /// Longest accepted lifetime for a generated certificate, in days.
    pub max_validity_days: i64,
}

#[derive(Debug, Deserialize)]
pub struct UploadRequest {
    /// PEM certificate, chain included when the issuer is not a root.
    pub cert_pem: String,
    /// PEM private key (PKCS#8, PKCS#1 or SEC1), matching the certificate.
    pub key_pem: String,
}

#[derive(Debug, Deserialize)]
pub struct SelfSignedRequest {
    /// Subject common name; defaults to this deployment's console name.
    #[serde(default)]
    pub common_name: Option<String>,
    /// Subject alternative names; defaults to the names the control plane
    /// answers on (configured list plus the host name and the relying party).
    #[serde(default)]
    pub sans: Option<Vec<String>>,
    #[serde(default)]
    pub validity_days: Option<i64>,
}

/// `GET /api/v1/system/tls`
async fn show(
    State(state): State<AppState>,
    current: AuthUser,
    headers: HeaderMap,
) -> Result<Json<TlsStatusView>, ApiError> {
    current.require_admin().map_err(ApiError::from)?;
    Ok(Json(status(&state, &headers).await?))
}

/// `GET /api/v1/system/tls/certificate` — downloads the served certificate.
async fn download(
    State(state): State<AppState>,
    current: AuthUser,
) -> Result<Response, ApiError> {
    current.require_admin().map_err(ApiError::from)?;
    let Some(row) = active_certificate(&state).await? else {
        return Err(ApiError::NotFound(
            "no control plane certificate has been stored yet".to_string(),
        ));
    };

    let filename = if row.source == tls_source::SELF_SIGNED {
        "pingwaf-control-plane-self-signed.crt"
    } else {
        "pingwaf-control-plane.crt"
    };
    let disposition =
        HeaderValue::from_str(&format!("attachment; filename=\"{filename}\""))
            .unwrap_or_else(|_| HeaderValue::from_static("attachment"));

    Ok((
        StatusCode::OK,
        [
            (
                header::CONTENT_TYPE,
                HeaderValue::from_static("application/x-pem-file"),
            ),
            (header::CONTENT_DISPOSITION, disposition),
        ],
        row.cert_pem,
    )
        .into_response())
}

/// `PUT /api/v1/system/tls/certificate`
///
/// The pair is validated before anything is written: a mismatched key or an
/// unparsable chain is rejected with `400` and the running listener keeps
/// serving the previous certificate.
async fn upload(
    State(state): State<AppState>,
    current: AuthUser,
    headers: HeaderMap,
    Json(payload): Json<UploadRequest>,
) -> Result<Json<TlsStatusView>, ApiError> {
    current.require_admin().map_err(ApiError::from)?;

    let (meta, sans) = describe(&payload.cert_pem)
        .map_err(|err| ApiError::BadRequest(err.to_string()))?;

    store_and_activate(
        &state,
        Some(current.id),
        tls_source::UPLOADED,
        &payload.cert_pem,
        &payload.key_pem,
        &meta,
        sans,
    )
    .await?;

    tracing::info!(
        requested_by = %current.email,
        subject = %meta.subject_dn,
        fingerprint = %meta.fingerprint_sha256,
        "control plane certificate replaced"
    );
    Ok(Json(status(&state, &headers).await?))
}

/// `POST /api/v1/system/tls/certificate/self-signed`
async fn generate(
    State(state): State<AppState>,
    current: AuthUser,
    headers: HeaderMap,
    Json(payload): Json<SelfSignedRequest>,
) -> Result<Json<TlsStatusView>, ApiError> {
    current.require_admin().map_err(ApiError::from)?;

    let common_name = payload
        .common_name
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .unwrap_or(DEFAULT_TLS_COMMON_NAME)
        .to_string();
    let sans = payload
        .sans
        .unwrap_or_else(|| default_sans(&state, &headers));
    let days = payload.validity_days.unwrap_or(DEFAULT_SELF_SIGNED_DAYS);

    let material = generate_self_signed(&common_name, &sans, days)
        .map_err(|err| ApiError::BadRequest(err.to_string()))?;
    let key_pem = material.key_pem.clone().ok_or_else(|| {
        ApiError::Internal("the generated key is missing".to_string())
    })?;

    store_and_activate(
        &state,
        Some(current.id),
        tls_source::SELF_SIGNED,
        &material.cert_pem,
        &key_pem,
        &material.meta,
        sans,
    )
    .await?;

    tracing::info!(
        requested_by = %current.email,
        valid_days = days,
        "generated a self-signed control plane certificate"
    );
    Ok(Json(status(&state, &headers).await?))
}

/// Persists a certificate as the active one and hands it to the listener.
///
/// The previous rows are kept (only deactivated) so an operator can see what
/// was served before; a restart always picks the newest active row. `actor` is
/// `None` for the certificate generated at boot, which no account asked for —
/// `created_by` is a foreign key, so a placeholder id would be rejected.
async fn store_and_activate(
    state: &AppState,
    actor: Option<Uuid>,
    source: &str,
    cert_pem: &str,
    key_pem: &str,
    meta: &crate::pki::mtls::CertMeta,
    sans: Vec<String>,
) -> Result<(), ApiError> {
    // The same builder the listener uses, so an upload that passes here can
    // never fail to load later.
    state
        .control_tls
        .activate(cert_pem, key_pem)
        .map_err(|err| ApiError::BadRequest(err.to_string()))?;

    let row = control_plane_certificate::ActiveModel {
        id: Set(Uuid::new_v4()),
        source: Set(source.to_string()),
        cert_pem: Set(cert_pem.to_string()),
        key_pem: Set(key_pem.to_string()),
        subject_dn: Set(meta.subject_dn.clone()),
        common_name: Set(meta.common_name.clone()),
        sans: Set(serde_json::json!(sans)),
        serial: Set(meta.serial.clone()),
        fingerprint_sha256: Set(meta.fingerprint_sha256.clone()),
        not_before: Set(to_utc(meta.not_before)),
        not_after: Set(to_utc(meta.not_after)),
        is_active: Set(true),
        created_by: Set(actor),
        created_at: Set(Utc::now()),
    }
    .insert(&state.db)
    .await?;

    // Deactivate the previously active rows only once the new one is stored:
    // a failure in between leaves two active rows, and `active_certificate`
    // reads the newest, so the listener and the database still agree.
    control_plane_certificate::Entity::update_many()
        .set(control_plane_certificate::ActiveModel {
            is_active: Set(false),
            ..Default::default()
        })
        .filter(control_plane_certificate::Column::IsActive.eq(true))
        .filter(control_plane_certificate::Column::Id.ne(row.id))
        .exec(&state.db)
        .await?;

    Ok(())
}

/// Builds the status the dashboard renders.
async fn status(
    state: &AppState,
    headers: &HeaderMap,
) -> Result<TlsStatusView, ApiError> {
    let certificate = active_certificate(state).await?.map(Into::into);
    Ok(TlsStatusView {
        enabled: state.control_tls.is_enabled(),
        has_certificate: state.control_tls.has_certificate(),
        certificate,
        default_sans: default_sans(state, headers),
        max_validity_days: MAX_SERVER_CERT_DAYS,
    })
}

/// The names a generated certificate covers.
///
/// The configured list (host name, relying party id, localhost) plus the name
/// the operator actually reached the console under, which is the one a
/// mismatch would break first.
fn default_sans(state: &AppState, headers: &HeaderMap) -> Vec<String> {
    let mut sans = state.config.effective_tls_sans();
    let host = headers
        .get(header::HOST)
        .and_then(|value| value.to_str().ok())
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(host_without_port);
    if let Some(host) = host {
        if !sans.iter().any(|san| san == host) {
            sans.push(host.to_string());
        }
    }
    sans
}

/// The newest active certificate, if any.
async fn active_certificate(
    state: &AppState,
) -> Result<Option<control_plane_certificate::Model>, ApiError> {
    Ok(control_plane_certificate::Entity::find()
        .filter(control_plane_certificate::Column::IsActive.eq(true))
        .order_by_desc(control_plane_certificate::Column::CreatedAt)
        .one(&state.db)
        .await?)
}

/// Loads the stored certificate into a listener at boot.
///
/// Returns the certificate that was loaded, if one was on file. Called before
/// the listener starts, so failures are fatal for a TLS deployment: serving
/// plaintext after the operator asked for HTTPS would be worse than not
/// starting.
pub async fn load_active_certificate(
    state: &AppState,
) -> Result<Option<control_plane_certificate::Model>, ApiError> {
    let Some(row) = active_certificate(state).await? else {
        return Ok(None);
    };
    state
        .control_tls
        .activate(&row.cert_pem, &row.key_pem)
        .map_err(|err| {
            ApiError::Internal(format!(
                "the stored control plane certificate cannot be loaded: {err}"
            ))
        })?;
    Ok(Some(row))
}

/// Regenerates and stores a self-signed certificate at boot.
///
/// Used on the very first start, and whenever the stored certificate cannot be
/// loaded while the operator asked for TLS.
pub async fn bootstrap_self_signed(
    state: &AppState,
) -> Result<control_plane_certificate::Model, ApiError> {
    let sans = state.config.effective_tls_sans();
    let material = generate_self_signed(
        DEFAULT_TLS_COMMON_NAME,
        &sans,
        DEFAULT_SELF_SIGNED_DAYS,
    )
    .map_err(|err| ApiError::Internal(err.to_string()))?;
    let key_pem = material.key_pem.clone().ok_or_else(|| {
        ApiError::Internal("the generated key is missing".to_string())
    })?;

    store_and_activate(
        state,
        None,
        tls_source::SELF_SIGNED,
        &material.cert_pem,
        &key_pem,
        &material.meta,
        sans,
    )
    .await?;

    tracing::info!(
        common_name = ?material.meta.common_name,
        expires = %material.meta.not_after,
        "generated the first self-signed control plane certificate"
    );

    active_certificate(state).await?.ok_or_else(|| {
        ApiError::Internal("the new certificate was not stored".to_string())
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_validity_is_accepted_by_the_generator() {
        // A self-signed pair must be generatable with the module's defaults,
        // otherwise a fresh deployment could not boot.
        let material = generate_self_signed(
            DEFAULT_TLS_COMMON_NAME,
            &["localhost".to_string()],
            DEFAULT_SELF_SIGNED_DAYS,
        )
        .unwrap();
        assert!(material.meta.not_after > time::OffsetDateTime::now_utc());
    }
}
