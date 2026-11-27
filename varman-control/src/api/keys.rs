//! API key management.
//!
//! Agents authenticate with an API key rather than a user password. Keys are
//! stored as bcrypt hashes, so the plaintext value is only ever returned once —
//! at creation time — and the row keeps an 8 character prefix for display.

use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use axum::Json;
use axum::Router;
use chrono::{DateTime, Utc};
use sea_orm::{
    ActiveModelTrait, ColumnTrait, Condition, EntityTrait, PaginatorTrait,
    QueryFilter, QueryOrder, Set,
};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::api::common::{
    non_empty, parse_datetime, parse_uuid, require_password_changed, Page,
    Pagination,
};
use crate::api::error::ApiError;
use crate::api::state::AppState;
use crate::auth::password::hash_password_with_cost;
use crate::auth::AuthUser;
use crate::key_auth::{generate_key, is_system_key, KEY_PREFIX_LENGTH};
use crate::models::{api_key, permission, user};

pub use crate::key_auth::{AGENT_ENROLLMENT_PREFIX, BOOTSTRAP_KEY_NAME};

/// bcrypt cost used for API keys. Keys are verified on every agent
/// registration, so this is deliberately lower than the interactive default.
const KEY_HASH_COST: u32 = 10;

/// Key metadata; the hash itself is skipped by serde at the model level.
#[derive(Debug, Clone, Serialize)]
pub struct ApiKeyResponse {
    pub id: Uuid,
    pub user_id: Uuid,
    pub name: String,
    pub key_prefix: String,
    pub permissions: Vec<String>,
    pub expires_at: Option<DateTime<Utc>>,
    pub last_used_at: Option<DateTime<Utc>>,
    pub created_at: DateTime<Utc>,
    /// Owning account's email; `None` for system-minted keys.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub creator: Option<String>,
    /// True when the key was minted by the system (bootstrap, enrollment).
    pub is_system: bool,
    /// Only populated by `POST /keys`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub key: Option<String>,
}

impl From<api_key::Model> for ApiKeyResponse {
    fn from(model: api_key::Model) -> Self {
        Self {
            id: model.id,
            user_id: model.user_id,
            name: model.name,
            key_prefix: model.key_prefix,
            permissions: model.permissions,
            expires_at: model.expires_at,
            last_used_at: model.last_used_at,
            created_at: model.created_at,
            creator: None,
            is_system: false,
            key: None,
        }
    }
}

#[derive(Debug, Deserialize)]
pub struct ListQuery {
    #[serde(flatten)]
    pub pagination: Pagination,
}

#[derive(Debug, Deserialize)]
pub struct CreateKeyRequest {
    pub name: String,
    #[serde(default = "default_permissions")]
    pub permissions: Vec<String>,
    /// RFC 3339 instant after which the key stops working; `None` = never.
    #[serde(default)]
    pub expires_at: Option<String>,
}

fn default_permissions() -> Vec<String> {
    vec![permission::AGENT.to_string(), permission::READ.to_string()]
}

/// Routes contributed to `/api/v1`.
pub fn routes() -> Router<AppState> {
    Router::new()
        .route("/keys", get(list).post(create))
        .route("/keys/{key_id}", axum::routing::delete(remove))
}

/// `GET /api/v1/keys`
async fn list(
    State(state): State<AppState>,
    current: AuthUser,
    Query(query): Query<ListQuery>,
) -> Result<Json<Page<ApiKeyResponse>>, ApiError> {
    let pagination = query.pagination.normalise();
    let mut condition = Condition::all();
    if !current.is_admin() {
        condition = condition.add(api_key::Column::UserId.eq(current.id));
    }

    let paginator = api_key::Entity::find()
        .filter(condition)
        .order_by_desc(api_key::Column::CreatedAt)
        .paginate(&state.db, pagination.limit());

    let total = paginator.num_items().await?;
    let rows = paginator.fetch_page(pagination.index()).await?;

    // Batch-resolve owners for the creator column. System-minted keys keep
    // `creator: None`: the attribution row is incidental (bootstrap lands on
    // the first admin), and the UI labels them "system" instead.
    let owner_ids: Vec<Uuid> = {
        let mut ids: Vec<Uuid> = rows.iter().map(|k| k.user_id).collect();
        ids.sort();
        ids.dedup();
        ids
    };
    let owners: std::collections::HashMap<Uuid, String> =
        if owner_ids.is_empty() {
            std::collections::HashMap::new()
        } else {
            user::Entity::find()
                .filter(user::Column::Id.is_in(owner_ids))
                .all(&state.db)
                .await?
                .into_iter()
                .map(|u| (u.id, u.email))
                .collect()
        };

    let items: Vec<ApiKeyResponse> = rows
        .into_iter()
        .map(|model| {
            let is_system = is_system_key(&model.name);
            let creator = if is_system {
                None
            } else {
                owners.get(&model.user_id).cloned()
            };
            let mut body = ApiKeyResponse::from(model);
            body.creator = creator;
            body.is_system = is_system;
            body
        })
        .collect();

    Ok(Json(Page::new(items, total, pagination)))
}

/// `POST /api/v1/keys`
async fn create(
    State(state): State<AppState>,
    current: AuthUser,
    Json(payload): Json<CreateKeyRequest>,
) -> Result<Response, ApiError> {
    // Every account may mint its own keys; the permissions granted are
    // capped at the caller's own power (see below). A flagged account must
    // replace its temporary password first, administrators included.
    require_password_changed(&current)?;

    let name = payload.name.trim().to_string();
    if name.is_empty() || name.len() > 100 {
        return Err(ApiError::BadRequest(
            "key name must be 1-100 characters".to_string(),
        ));
    }

    let mut permissions = normalise_permissions(&payload.permissions)?;
    if permissions.is_empty() {
        return Err(ApiError::BadRequest(
            "at least one permission is required".to_string(),
        ));
    }
    // Self-service keys for read-only roles never exceed read: agents need
    // the `agent` permission, which only admins may delegate.
    if !current.is_admin() {
        permissions = vec![permission::READ.to_string()];
    }

    let expires_at = match non_empty(&payload.expires_at) {
        Some(raw) => {
            let instant = parse_datetime(&raw, "expires_at")?;
            if instant <= Utc::now() {
                return Err(ApiError::BadRequest(
                    "expires_at must be in the future".to_string(),
                ));
            }
            Some(instant)
        },
        None => None,
    };

    let (model, plaintext) =
        mint_key(&state, current.id, name, permissions, expires_at).await?;

    let mut body = ApiKeyResponse::from(model);
    // A user-minted key may borrow a system-looking name; surface what the
    // name implies so the strong-delete guard matches what the list shows.
    body.is_system = is_system_key(&body.name);
    if !body.is_system {
        body.creator = Some(current.email.clone());
    }
    body.key = Some(plaintext);
    Ok((StatusCode::CREATED, Json(body)).into_response())
}

/// `DELETE /api/v1/keys/{key_id}`
async fn remove(
    State(state): State<AppState>,
    current: AuthUser,
    Path(key_id): Path<String>,
) -> Result<Response, ApiError> {
    // Any account may revoke its own keys; the filter below already restricts
    // non-admins to their own rows.
    require_password_changed(&current)?;
    let id = parse_uuid(&key_id, "key id")?;

    let mut query = api_key::Entity::delete_by_id(id);
    if !current.is_admin() {
        query = query.filter(api_key::Column::UserId.eq(current.id));
    }
    let result = query.exec(&state.db).await?;
    if result.rows_affected == 0 {
        return Err(ApiError::NotFound(format!("API key {id} not found")));
    }

    tracing::info!(key_id = %id, "API key revoked");
    Ok(StatusCode::NO_CONTENT.into_response())
}

/// Stores a new API key and hands back the plaintext, which the caller shows
/// once and nothing persists.
pub(crate) async fn mint_key(
    state: &AppState,
    user_id: Uuid,
    name: String,
    permissions: Vec<String>,
    expires_at: Option<DateTime<Utc>>,
) -> Result<(api_key::Model, String), ApiError> {
    let plaintext = generate_key();
    let key_hash = hash_password_with_cost(&plaintext, KEY_HASH_COST)
        .map_err(ApiError::internal)?;

    let model = api_key::ActiveModel {
        id: Set(Uuid::new_v4()),
        user_id: Set(user_id),
        name: Set(name),
        key_hash: Set(key_hash),
        key_prefix: Set(plaintext[..KEY_PREFIX_LENGTH].to_string()),
        permissions: Set(permissions),
        expires_at: Set(expires_at),
        last_used_at: Set(None),
        created_at: Set(Utc::now()),
    }
    .insert(&state.db)
    .await?;

    tracing::info!(key_id = %model.id, owner = %user_id, "API key created");
    Ok((model, plaintext))
}

/// Validates, de-duplicates and sorts the requested permission set.
fn normalise_permissions(raw: &[String]) -> Result<Vec<String>, ApiError> {
    let mut out: Vec<String> = Vec::new();
    for value in raw {
        let trimmed = value.trim().to_lowercase();
        if trimmed.is_empty() {
            continue;
        }
        if !permission::is_valid(&trimmed) {
            return Err(ApiError::BadRequest(format!(
                "unknown permission '{trimmed}'"
            )));
        }
        if !out.contains(&trimmed) {
            out.push(trimmed);
        }
    }
    out.sort();
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn permissions_are_normalised() {
        let out = normalise_permissions(&[
            "AGENT".into(),
            " agent ".into(),
            "read".into(),
        ])
        .unwrap();
        assert_eq!(out, vec!["agent".to_string(), "read".to_string()]);
        assert!(normalise_permissions(&["admin-all".into()]).is_err());
        assert!(normalise_permissions(&[]).unwrap().is_empty());
    }
}
