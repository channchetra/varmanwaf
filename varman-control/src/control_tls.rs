//! The control plane's own HTTPS certificate: storage and boot-time install.
//!
//! The dashboard is served over HTTPS so browsers treat it as a secure origin
//! (WebAuthn passkeys refuse plain `http://` outside localhost), and that means
//! an operator has to be able to see and replace the certificate without
//! editing files: a self-signed pair is generated on first boot, and a real
//! certificate can be uploaded. This module owns the stored material and the
//! listener hand-off; the administrator-only routes live in
//! [`crate::api::system_tls`].
//!
//! Uploads take effect immediately — the running listener picks the new pair
//! up through its reloadable resolver — so every write goes through
//! [`store_and_activate`], which is what keeps the database and the listener
//! in sync.

use chrono::Utc;
use sea_orm::{
    ActiveModelTrait, ColumnTrait, EntityTrait, QueryFilter, QueryOrder, Set,
};
use uuid::Uuid;

use crate::app_state::AppState;
use crate::config::DEFAULT_TLS_COMMON_NAME;
use crate::error::ApiError;
use crate::models::{control_plane_certificate, tls_source};
use crate::pki::tls::generate_self_signed;
use crate::time_util::to_utc;

/// Validity of a generated self-signed certificate, in days. Long enough that
/// an operator does not have to regenerate it, short enough that it is not
/// mistaken for a long-lived trust anchor.
pub const DEFAULT_SELF_SIGNED_DAYS: i64 = 825;

/// Persists a certificate as the active one and hands it to the listener.
///
/// The previous rows are kept (only deactivated) so an operator can see what
/// was served before; a restart always picks the newest active row. `actor` is
/// `None` for the certificate generated at boot, which no account asked for —
/// `created_by` is a foreign key, so a placeholder id would be rejected.
pub(crate) async fn store_and_activate(
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

    // Only after the row is durable: a failed insert must not make the next
    // config rebuild advertise a pair the database does not know about.
    if source == tls_source::ACME {
        crate::management_cert::set_seed(cert_pem, key_pem);
    }
    Ok(())
}

/// The newest active certificate, if any.
pub(crate) async fn active_certificate(
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
    if row.source == tls_source::ACME {
        crate::management_cert::set_seed(&row.cert_pem, &row.key_pem);
    }
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
