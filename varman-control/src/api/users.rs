//! Dashboard user administration.
//!
//! Every route requires the `admin` role. Operators may create accounts,
//! change roles, and disable accounts; self-lockout is prevented (an admin
//! can neither disable nor downgrade themselves, and the last enabled
//! administrator can never lose admin access).

use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post, put};
use axum::{Json, Router};
use chrono::Utc;
use sea_orm::{
    ActiveModelTrait, ColumnTrait, EntityTrait, PaginatorTrait, QueryFilter,
    QueryOrder, Set,
};
use serde::Deserialize;
use uuid::Uuid;

use crate::api::auth::{
    create_user, normalize_email, user_write_error, UserResponse,
};
use crate::api::common::{parse_uuid, require_write, Page, Pagination};
use crate::api::error::ApiError;
use crate::api::state::AppState;
use crate::auth::middleware::AdminUser;
use crate::auth::password::validate_password;
use crate::models::{login_history, role, user};

#[derive(Debug, Deserialize)]
pub struct ListQuery {
    #[serde(flatten)]
    pub pagination: Pagination,
}

#[derive(Debug, Deserialize)]
pub struct CreateUserRequest {
    pub email: String,
    pub password: String,
    #[serde(default)]
    pub name: Option<String>,
    /// Defaults to `viewer`.
    #[serde(default)]
    pub role: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct UpdateUserRequest {
    #[serde(default)]
    pub name: Option<String>,
    /// The login name. Changing it revokes the account's outstanding tokens
    /// (their e-mail claim goes stale); no password confirmation is needed
    /// because only administrators reach this endpoint.
    #[serde(default)]
    pub email: Option<String>,
    #[serde(default)]
    pub role: Option<String>,
    #[serde(default)]
    pub disabled: Option<bool>,
}

/// Routes contributed to `/api/v1`.
pub fn routes() -> Router<AppState> {
    Router::new()
        .route("/users", get(list).post(create))
        .route("/users/{user_id}", put(update))
        .route("/users/{user_id}/reset-password", post(reset_password))
}

/// `GET /api/v1/users`
async fn list(
    State(state): State<AppState>,
    _admin: AdminUser,
    Query(query): Query<ListQuery>,
) -> Result<Json<Page<UserResponse>>, ApiError> {
    let pagination = query.pagination.normalize();
    let paginator = user::Entity::find()
        .order_by_asc(user::Column::CreatedAt)
        .paginate(&state.db, pagination.limit());
    let total = paginator.num_items().await?;
    let rows = paginator.fetch_page(pagination.page - 1).await?;

    // Most recent successful login per account, resolved from the login
    // history (both password and passkey logins are recorded there), so the
    // admin list can show "last seen" without denormalizing onto the user
    // row. Newest-first iteration keeps the first hit per user the latest.
    let ids: Vec<Uuid> = rows.iter().map(|u| u.id).collect();
    let mut latest: std::collections::HashMap<
        Uuid,
        (chrono::DateTime<chrono::Utc>, String),
    > = std::collections::HashMap::new();
    if !ids.is_empty() {
        let histories = login_history::Entity::find()
            .filter(login_history::Column::UserId.is_in(ids))
            .order_by_desc(login_history::Column::CreatedAt)
            .all(&state.db)
            .await?;
        for entry in histories {
            latest
                .entry(entry.user_id)
                .or_insert((entry.created_at, entry.ip));
        }
    }

    let items = rows
        .into_iter()
        .map(|account| {
            let mut body = UserResponse::from(account);
            if let Some((at, ip)) = latest.get(&body.id) {
                body.last_login_at = Some(*at);
                body.last_login_ip = Some(ip.clone());
            }
            body
        })
        .collect();
    Ok(Json(Page::new(items, total, pagination)))
}

/// `POST /api/v1/users`
async fn create(
    State(state): State<AppState>,
    admin: AdminUser,
    Json(payload): Json<CreateUserRequest>,
) -> Result<Response, ApiError> {
    require_write(&admin)?;
    let email = normalize_email(&payload.email)?;
    validate_password(&payload.password)
        .map_err(|err| ApiError::BadRequest(err.to_string()))?;
    let assigned_role = payload.role.as_deref().unwrap_or(role::VIEWER);
    if !role::is_valid(assigned_role) {
        return Err(ApiError::BadRequest(format!(
            "unknown role '{assigned_role}'"
        )));
    }

    let taken = user::Entity::find()
        .filter(user::Column::Email.eq(email.clone()))
        .one(&state.db)
        .await?;
    if taken.is_some() {
        return Err(ApiError::Conflict(format!(
            "an account for {email} already exists"
        )));
    }

    let account = create_user(
        &state.db,
        &email,
        &payload.password,
        payload.name.clone(),
        assigned_role,
        // The administrator typed this password: it is temporary, and the
        // console forces a replacement at first sign-in.
        true,
    )
    .await?;

    tracing::info!(
        %email,
        user_id = %account.id,
        role = %account.role,
        "account created by administrator"
    );
    Ok(
        (StatusCode::CREATED, Json(UserResponse::from(account)))
            .into_response(),
    )
}

/// `PUT /api/v1/users/{user_id}`
async fn update(
    State(state): State<AppState>,
    admin: AdminUser,
    Path(user_id): Path<String>,
    Json(payload): Json<UpdateUserRequest>,
) -> Result<Json<UserResponse>, ApiError> {
    require_write(&admin)?;
    let id = parse_uuid(&user_id, "user id")?;
    let account = user::Entity::find_by_id(id)
        .one(&state.db)
        .await?
        .ok_or_else(|| ApiError::NotFound(format!("user {id} not found")))?;

    // Self-service profile changes go through `/auth/me`; role and status
    // changes on the caller's own account could lock the operator out.
    if id == admin.id()
        && (payload.role.is_some() || payload.disabled.is_some())
    {
        return Err(ApiError::BadRequest(
            "cannot change your own role or disabled state".to_string(),
        ));
    }

    let new_role = match payload.role.as_deref() {
        Some(raw) if raw != account.role => {
            if !role::is_valid(raw) {
                return Err(ApiError::BadRequest(format!(
                    "unknown role '{raw}'"
                )));
            }
            Some(raw.to_string())
        },
        _ => None,
    };
    let new_email = match payload.email.as_deref() {
        Some(raw) => {
            let email = normalize_email(raw)?;
            (email != account.email).then_some(email)
        },
        None => None,
    };
    if let Some(email) = &new_email {
        let taken = user::Entity::find()
            .filter(user::Column::Email.eq(email.clone()))
            .filter(user::Column::Id.ne(id))
            .one(&state.db)
            .await?;
        if taken.is_some() {
            return Err(ApiError::Conflict(format!(
                "an account for {email} already exists"
            )));
        }
    }
    let disabling = payload.disabled.unwrap_or(false);
    // A role change, a disable or a login-name change revokes the account's
    // outstanding tokens; renames and re-enables do not.
    let revoking = new_role.is_some()
        || (disabling && !account.disabled)
        || new_email.is_some();
    let loses_admin = account.role == role::ADMIN
        && !account.disabled
        && ((new_role.is_some() && new_role.as_deref() != Some(role::ADMIN))
            || disabling);
    if loses_admin {
        ensure_other_enabled_admin(&state, id).await?;
    }

    let mut active: user::ActiveModel = account.into();
    if let Some(name) = payload.name {
        let trimmed = name.trim();
        if trimmed.len() > 100 {
            return Err(ApiError::BadRequest(
                "name must be at most 100 characters".to_string(),
            ));
        }
        active.name = Set(if trimmed.is_empty() {
            None
        } else {
            Some(trimmed.to_string())
        });
    }
    if let Some(new_role) = new_role {
        active.role = Set(new_role);
    }
    if let Some(email) = new_email {
        active.email = Set(email);
        tracing::info!(user_id = %id, "login name changed by administrator");
    }
    if let Some(disabled) = payload.disabled {
        active.disabled = Set(disabled);
        if disabled {
            tracing::info!(user_id = %id, "account disabled by administrator");
        }
    }
    if revoking {
        active.token_version = Set(active.token_version.unwrap() + 1);
    }
    active.updated_at = Set(Utc::now());

    let updated = active.update(&state.db).await?;
    Ok(Json(UserResponse::from(updated)))
}

#[derive(Debug, Deserialize)]
pub struct ResetPasswordRequest {
    /// The temporary password; the account must replace it at first sign-in.
    pub password: String,
}

/// `POST /api/v1/users/{user_id}/reset-password` — administrators only.
///
/// Sets a temporary password for the account: the first-sign-in flag forces
/// a replacement, and the token version bump revokes every outstanding
/// session (the account's own sign-ins included). Resetting one's own
/// password stays on `/auth/password`, where the current password is
/// required — this route must not become a self-service bypass.
async fn reset_password(
    State(state): State<AppState>,
    admin: AdminUser,
    Path(user_id): Path<String>,
    Json(payload): Json<ResetPasswordRequest>,
) -> Result<Json<UserResponse>, ApiError> {
    require_write(&admin)?;
    let id = parse_uuid(&user_id, "user id")?;
    if id == admin.id() {
        return Err(ApiError::BadRequest(
            "use your own password change to replace your password".to_string(),
        ));
    }
    validate_password(&payload.password)
        .map_err(|err| ApiError::BadRequest(err.to_string()))?;

    let updated = crate::users::set_password(&state.db, id, &payload.password)
        .await
        .map_err(user_write_error)?;

    tracing::info!(
        user_id = %id,
        admin = %admin.email,
        "password reset by administrator"
    );
    Ok(Json(UserResponse::from(updated)))
}

/// Fails with `400` when `except` is the only enabled administrator left.
async fn ensure_other_enabled_admin(
    state: &AppState,
    except: Uuid,
) -> Result<(), ApiError> {
    let count = user::Entity::find()
        .filter(user::Column::Role.eq(role::ADMIN))
        .filter(user::Column::Disabled.eq(false))
        .filter(user::Column::Id.ne(except))
        .count(&state.db)
        .await?;
    if count == 0 {
        return Err(ApiError::BadRequest(
            "the last enabled administrator cannot be downgraded or disabled"
                .to_string(),
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::collections::{BTreeMap, VecDeque};
    use std::sync::{Arc, Mutex};

    use chrono::Utc;
    use sea_orm::{
        Database, DatabaseBackend, DbErr, EntityTrait, IdenStatic, Iterable,
        ModelTrait, ProxyDatabaseTrait, ProxyExecResult, ProxyRow, Statement,
        Value,
    };
    use uuid::Uuid;

    use super::*;
    use crate::auth::AuthUser;
    use crate::config::ServerConfig;
    use crate::grpc::registry::AgentRegistry;

    /// Answers each query with the next queued batch of rows, in order.
    #[derive(Debug, Default)]
    struct QueryQueue {
        batches: Mutex<VecDeque<Vec<ProxyRow>>>,
    }

    impl QueryQueue {
        fn boxed(
            batches: Vec<Vec<ProxyRow>>,
        ) -> Arc<Box<dyn ProxyDatabaseTrait>> {
            Arc::new(Box::new(Self {
                batches: Mutex::new(batches.into_iter().collect()),
            }))
        }
    }

    #[async_trait::async_trait]
    impl ProxyDatabaseTrait for QueryQueue {
        async fn query(
            &self,
            _statement: Statement,
        ) -> Result<Vec<ProxyRow>, DbErr> {
            let mut batches = self.batches.lock().expect("query queue lock");
            batches.pop_front().ok_or_else(|| {
                DbErr::Custom("no queued query result".to_string())
            })
        }

        async fn execute(
            &self,
            _statement: Statement,
        ) -> Result<ProxyExecResult, DbErr> {
            Ok(ProxyExecResult::new(0, 0))
        }
    }

    /// SeaORM's `count` selects the count as `num_items`.
    fn count_row(count: i64) -> ProxyRow {
        ProxyRow::new(BTreeMap::from([(
            "num_items".to_string(),
            Value::BigInt(Some(count)),
        )]))
    }

    fn encode_row<M>(model: &M) -> ProxyRow
    where
        M: ModelTrait,
    {
        let values = <<M::Entity as EntityTrait>::Column as Iterable>::iter()
            .map(|column| (column.as_str().to_string(), model.get(column)))
            .collect::<BTreeMap<String, Value>>();
        ProxyRow::new(values)
    }

    async fn state_with(batches: Vec<Vec<ProxyRow>>) -> AppState {
        let db = Database::connect_proxy(
            DatabaseBackend::Postgres,
            QueryQueue::boxed(batches),
        )
        .await
        .expect("the proxy connection cannot fail");
        AppState::new(db, ServerConfig::default(), AgentRegistry::new())
    }

    fn user_row(id: Uuid, role_name: &str, disabled: bool) -> user::Model {
        let now = Utc::now();
        user::Model {
            id,
            email: format!("{id}@example.com"),
            password_hash: String::new(),
            name: None,
            role: role_name.to_string(),
            disabled,
            must_change_password: false,
            token_version: 1,
            created_at: now,
            updated_at: now,
        }
    }

    fn admin_caller(id: Uuid) -> AdminUser {
        AdminUser(AuthUser::new(id, "admin@example.com", role::ADMIN))
    }

    #[tokio::test]
    async fn the_last_enabled_administrator_cannot_be_demoted_or_disabled() {
        // Arrange: the target is the only administrator, and the caller is
        // somebody else (self-lockout is rejected earlier).
        let caller = Uuid::new_v4();
        let target = Uuid::new_v4();

        for payload in [
            UpdateUserRequest {
                name: None,
                email: None,
                role: Some(role::VIEWER.to_string()),
                disabled: None,
            },
            UpdateUserRequest {
                name: None,
                email: None,
                role: None,
                disabled: Some(true),
            },
        ] {
            let state = state_with(vec![
                vec![encode_row(&user_row(target, role::ADMIN, false))],
                vec![count_row(0)],
            ])
            .await;

            // Act
            let err = update(
                State(state),
                admin_caller(caller),
                Path(target.to_string()),
                Json(payload),
            )
            .await
            .expect_err("the last enabled administrator must not lose access");

            // Assert
            assert!(
                matches!(&err, ApiError::BadRequest(_)),
                "expected ApiError::BadRequest, got {err:?}"
            );
            assert!(
                err.to_string().contains("last enabled administrator"),
                "unexpected error: {err}"
            );
        }
    }

    #[tokio::test]
    async fn demoting_an_administrator_is_allowed_when_another_admin_exists() {
        // Arrange: one other enabled administrator remains.
        let caller = Uuid::new_v4();
        let target = Uuid::new_v4();
        let mut demoted = user_row(target, role::VIEWER, false);
        demoted.token_version += 1;
        let state = state_with(vec![
            vec![encode_row(&user_row(target, role::ADMIN, false))],
            vec![count_row(1)],
            vec![encode_row(&demoted)],
        ])
        .await;

        // Act
        let updated = update(
            State(state),
            admin_caller(caller),
            Path(target.to_string()),
            Json(UpdateUserRequest {
                name: None,
                email: None,
                role: Some(role::VIEWER.to_string()),
                disabled: None,
            }),
        )
        .await
        .expect("another enabled administrator remains");

        // Assert
        assert_eq!(role::VIEWER, updated.0.role);

        // Disabling is the other way to lose admin access, and follows the
        // same rule.
        let target = Uuid::new_v4();
        let mut disabled = user_row(target, role::ADMIN, true);
        disabled.token_version += 1;
        let state = state_with(vec![
            vec![encode_row(&user_row(target, role::ADMIN, false))],
            vec![count_row(1)],
            vec![encode_row(&disabled)],
        ])
        .await;

        let updated = update(
            State(state),
            admin_caller(caller),
            Path(target.to_string()),
            Json(UpdateUserRequest {
                name: None,
                email: None,
                role: None,
                disabled: Some(true),
            }),
        )
        .await
        .expect("another enabled administrator remains");

        assert!(updated.0.disabled);
    }
}
