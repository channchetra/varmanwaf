//! Per-site HTTP basic authentication.
//!
//! The gate itself is enforced by the WAF plugin on the data plane; this module
//! owns the stored credentials. Passwords are kept in the clear, like the mTLS
//! private keys and the Elasticsearch password elsewhere in this project, and
//! the API masks them on the way out: a client sends back the mask to keep a
//! stored password unchanged.

use axum::extract::{Path, State};
use axum::routing::get;
use axum::Json;
use axum::Router;
use sea_orm::{ActiveModelTrait, ColumnTrait, EntityTrait, QueryFilter, Set};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::api::common::{load_site_read, load_site_write, parse_uuid};
use crate::api::error::ApiError;
use crate::api::sites::touch_site;
use crate::api::state::AppState;
use crate::auth::AuthUser;
use crate::grpc::notify_config_changed;
use crate::models::site_basic_auth;

/// Substituted for a stored password in responses. A `PUT` that sends it back
/// keeps the stored password instead of overwriting it.
pub const SECRET_MASK: &str = "***";

/// Delay bounds, mirrored by the dashboard. The ceiling keeps a failed login
/// from holding a connection for long enough to pile up.
pub const MIN_DELAY_SECONDS: i32 = 0;
pub const MAX_DELAY_SECONDS: i32 = 10;

const MAX_REALM_LEN: usize = 200;
const MAX_USERNAME_LEN: usize = 100;
const MAX_CREDENTIALS: usize = 100;

/// One accepted credential pair.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct BasicAuthCredential {
    pub username: String,
    /// Stored in the clear; masked in responses.
    pub password: String,
}

/// What the dashboard receives: credentials with masked passwords.
#[derive(Debug, Serialize)]
pub struct BasicAuthView {
    pub id: Uuid,
    pub site_id: Uuid,
    pub enabled: bool,
    pub realm: String,
    pub credentials: Vec<BasicAuthCredential>,
    pub delay_seconds: i32,
    pub hide_credentials: bool,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub updated_at: chrono::DateTime<chrono::Utc>,
}

#[derive(Debug, Deserialize, Default)]
pub struct UpdateBasicAuthRequest {
    #[serde(default)]
    pub enabled: Option<bool>,
    #[serde(default)]
    pub realm: Option<String>,
    /// Replaces the whole list when present.
    #[serde(default)]
    pub credentials: Option<Vec<BasicAuthCredential>>,
    #[serde(default)]
    pub delay_seconds: Option<i32>,
    #[serde(default)]
    pub hide_credentials: Option<bool>,
}

/// Routes contributed to `/api/v1`.
pub fn routes() -> Router<AppState> {
    Router::new().route("/sites/{site_id}/basic-auth", get(show).put(update))
}

/// `GET /api/v1/sites/{site_id}/basic-auth`
async fn show(
    State(state): State<AppState>,
    current: AuthUser,
    Path(site_id): Path<String>,
) -> Result<Json<BasicAuthView>, ApiError> {
    let id = parse_uuid(&site_id, "site id")?;
    load_site_read(&state.db, id, &current).await?;

    let row = find_or_create(&state, id).await?;
    Ok(Json(to_view(&row)?))
}

/// `PUT /api/v1/sites/{site_id}/basic-auth`
async fn update(
    State(state): State<AppState>,
    current: AuthUser,
    Path(site_id): Path<String>,
    Json(payload): Json<UpdateBasicAuthRequest>,
) -> Result<Json<BasicAuthView>, ApiError> {
    let id = parse_uuid(&site_id, "site id")?;
    load_site_write(&state.db, id, &current).await?;

    let row = find_or_create(&state, id).await?;
    let stored = stored_credentials(&row)?;
    let stored_enabled = row.enabled;
    let mut active: site_basic_auth::ActiveModel = row.into();

    if let Some(enabled) = payload.enabled {
        active.enabled = Set(enabled);
    }
    if let Some(realm) = payload.realm {
        active.realm = Set(validate_realm(&realm)?);
    }
    if let Some(delay) = payload.delay_seconds {
        if !(MIN_DELAY_SECONDS..=MAX_DELAY_SECONDS).contains(&delay) {
            return Err(ApiError::BadRequest(format!(
                "delay_seconds must be between {MIN_DELAY_SECONDS} and {MAX_DELAY_SECONDS}"
            )));
        }
        active.delay_seconds = Set(delay);
    }
    if let Some(hide) = payload.hide_credentials {
        active.hide_credentials = Set(hide);
    }
    if let Some(submitted) = payload.credentials {
        let merged = merge_credentials(submitted, &stored)?;
        active.credentials =
            Set(serde_json::to_value(&merged).map_err(|err| {
                ApiError::Internal(format!(
                    "failed to encode credentials: {err}"
                ))
            })?);
    }

    // An enabled gate with nothing to accept would lock everyone out.
    let resulting: Vec<BasicAuthCredential> = match &active.credentials {
        sea_orm::ActiveValue::Set(value) => decode_credentials(value)?,
        _ => stored.clone(),
    };
    let enabled_after = match &active.enabled {
        sea_orm::ActiveValue::Set(value) => *value,
        _ => stored_enabled,
    };
    guard_enabled_state(enabled_after, &resulting)?;

    active.updated_at = Set(chrono::Utc::now());
    let updated = active.update(&state.db).await?;

    tracing::info!(
        site_id = %id,
        enabled = updated.enabled,
        credentials = resulting.len(),
        "site basic auth updated"
    );
    touch_site(&state, id).await?;
    notify_config_changed(&state, id, Some(&current.email)).await;

    Ok(Json(to_view(&updated)?))
}

fn validate_realm(value: &str) -> Result<String, ApiError> {
    let realm = value.trim();
    if realm.is_empty() || realm.len() > MAX_REALM_LEN {
        return Err(ApiError::BadRequest(format!(
            "realm must be 1-{MAX_REALM_LEN} characters"
        )));
    }
    Ok(realm.to_string())
}

/// Rejects a state where the gate is on but nothing can pass it.
fn guard_enabled_state(
    enabled: bool,
    credentials: &[BasicAuthCredential],
) -> Result<(), ApiError> {
    if enabled && credentials.is_empty() {
        return Err(ApiError::BadRequest(
            "at least one credential is required while basic auth is enabled"
                .to_string(),
        ));
    }
    Ok(())
}

/// Applies the submitted list onto the stored one.
///
/// A password equal to [`SECRET_MASK`] means "keep the stored one for this
/// username"; anything else replaces it. Usernames must be non-empty and
/// unique in the resulting list.
fn merge_credentials(
    submitted: Vec<BasicAuthCredential>,
    stored: &[BasicAuthCredential],
) -> Result<Vec<BasicAuthCredential>, ApiError> {
    if submitted.len() > MAX_CREDENTIALS {
        return Err(ApiError::BadRequest(format!(
            "at most {MAX_CREDENTIALS} credentials are supported"
        )));
    }

    let mut merged = Vec::with_capacity(submitted.len());
    let mut seen = std::collections::HashSet::new();
    for credential in submitted {
        let username = credential.username.trim().to_string();
        if username.is_empty() || username.len() > MAX_USERNAME_LEN {
            return Err(ApiError::BadRequest(format!(
                "username must be 1-{MAX_USERNAME_LEN} characters"
            )));
        }
        if !seen.insert(username.clone()) {
            return Err(ApiError::BadRequest(format!(
                "duplicate username '{username}'"
            )));
        }

        let password = if credential.password == SECRET_MASK {
            let previous = stored
                .iter()
                .find(|existing| existing.username == username)
                .ok_or_else(|| {
                    ApiError::BadRequest(format!(
                        "no stored password for '{username}'; send a password instead of the mask"
                    ))
                })?;
            previous.password.clone()
        } else {
            if credential.password.is_empty() {
                return Err(ApiError::BadRequest(format!(
                    "password must not be empty for '{username}'"
                )));
            }
            credential.password
        };

        merged.push(BasicAuthCredential { username, password });
    }
    Ok(merged)
}

/// Reads the stored credentials back out of the JSON column.
pub fn stored_credentials(
    row: &site_basic_auth::Model,
) -> Result<Vec<BasicAuthCredential>, ApiError> {
    decode_credentials(&row.credentials)
}

/// Decodes a credentials JSON value, rejecting a shape we did not write.
pub fn decode_credentials(
    value: &serde_json::Value,
) -> Result<Vec<BasicAuthCredential>, ApiError> {
    serde_json::from_value(value.clone()).map_err(|err| {
        ApiError::Internal(format!(
            "stored basic auth credentials are invalid: {err}"
        ))
    })
}

fn to_view(row: &site_basic_auth::Model) -> Result<BasicAuthView, ApiError> {
    let credentials = stored_credentials(row)?
        .into_iter()
        .map(|mut credential| {
            credential.password = SECRET_MASK.to_string();
            credential
        })
        .collect();

    Ok(BasicAuthView {
        id: row.id,
        site_id: row.site_id,
        enabled: row.enabled,
        realm: row.realm.clone(),
        credentials,
        delay_seconds: row.delay_seconds,
        hide_credentials: row.hide_credentials,
        created_at: row.created_at,
        updated_at: row.updated_at,
    })
}

/// Finds the row for a site, creating a disabled default when absent.
async fn find_or_create(
    state: &AppState,
    site_id: Uuid,
) -> Result<site_basic_auth::Model, ApiError> {
    if let Some(row) = site_basic_auth::Entity::find()
        .filter(site_basic_auth::Column::SiteId.eq(site_id))
        .one(&state.db)
        .await?
    {
        return Ok(row);
    }

    let now = chrono::Utc::now();
    let model = site_basic_auth::ActiveModel {
        id: Set(Uuid::new_v4()),
        site_id: Set(site_id),
        enabled: Set(false),
        realm: Set("Restricted".to_string()),
        credentials: Set(serde_json::json!([])),
        delay_seconds: Set(1),
        hide_credentials: Set(false),
        created_at: Set(now),
        updated_at: Set(now),
    }
    .insert(&state.db)
    .await?;

    Ok(model)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn credential(username: &str, password: &str) -> BasicAuthCredential {
        BasicAuthCredential {
            username: username.to_string(),
            password: password.to_string(),
        }
    }

    #[test]
    fn the_mask_keeps_the_stored_password() {
        let stored = vec![credential("alice", "hunter2")];
        let merged = merge_credentials(
            vec![credential("alice", SECRET_MASK), credential("bob", "pw")],
            &stored,
        )
        .unwrap();

        assert_eq!(merged[0].password, "hunter2");
        assert_eq!(merged[1].password, "pw");
    }

    #[test]
    fn a_mask_without_a_stored_password_is_rejected() {
        let stored = vec![credential("alice", "hunter2")];
        assert!(merge_credentials(
            vec![credential("carol", SECRET_MASK)],
            &stored
        )
        .is_err());
    }

    #[test]
    fn duplicate_or_empty_usernames_are_rejected() {
        let stored = Vec::new();
        assert!(merge_credentials(
            vec![credential("alice", "a"), credential("alice", "b")],
            &stored
        )
        .is_err());
        assert!(
            merge_credentials(vec![credential("  ", "a")], &stored).is_err()
        );
        assert!(
            merge_credentials(vec![credential("bob", "")], &stored).is_err()
        );
    }

    #[test]
    fn an_enabled_gate_needs_a_credential() {
        let alice = [credential("alice", "pw")];
        assert!(guard_enabled_state(true, &[]).is_err());
        assert!(guard_enabled_state(false, &[]).is_ok());
        assert!(guard_enabled_state(true, &alice).is_ok());
    }

    #[test]
    fn stored_json_roundtrips_and_a_foreign_shape_fails() {
        let value = json!([{ "username": "alice", "password": "pw" }]);
        let decoded = decode_credentials(&value).unwrap();
        assert_eq!(decoded.len(), 1);
        assert_eq!(decoded[0].username, "alice");
        assert!(decode_credentials(&json!({ "nope": true })).is_err());
    }
}
