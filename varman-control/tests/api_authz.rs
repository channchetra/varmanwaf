//! Executable tests for the site-authorization helpers in `api::common`.
//!
//! The contract under test is the one documented on `load_site`: administrators
//! and auditors see every site, other roles only the sites they own, and a site
//! owned by somebody else is reported as `404` (never `403`) so the API does not
//! leak which domains exist. Mutations stay administrator-only, IP-group
//! mutations included, and an API key without the `agent` permission cannot
//! enrol agents.
//!
//! SeaORM's `mock` feature cannot be enabled here: it drops
//! `DatabaseConnection`'s `Clone` impl (`#[cfg_attr(not(feature = "mock"), ...)]`),
//! which the control plane relies on in production code. The `proxy` feature
//! provides the same queued-row test double without touching that: every test
//! queues the rows its `find_by_id` returns, and no PostgreSQL is needed.

use std::collections::{BTreeMap, VecDeque};
use std::sync::{Arc, Mutex};

use axum::body::Body;
use axum::http::{header, Method, Request, StatusCode};
use axum::Router;
use chrono::Utc;
use sea_orm::{
    Database, DatabaseBackend, DatabaseConnection, DbErr, EntityTrait,
    IdenStatic, Iterable, ModelTrait, ProxyDatabaseTrait, ProxyExecResult,
    ProxyRow, Statement, Value,
};
use tower::ServiceExt;
use uuid::Uuid;

use varman_control::api::common::{
    load_site_read, load_site_write, scope_site,
};
use varman_control::api::{auth, ip_groups, notifications};
use varman_control::app_state::AppState;
use varman_control::auth::{create_token, hash_password, AuthUser};
use varman_control::config::ServerConfig;
use varman_control::error::ApiError;
use varman_control::grpc::registry::AgentRegistry;
use varman_control::key_auth::key_allows_agent;
use varman_control::models::{
    api_key, permission, role, site, site_status, trusted_header, user,
};

/// A `sites` row with `id` as its primary key, owned by `owner`.
fn site_owned_by(id: Uuid, owner: Uuid) -> site::Model {
    let now = Utc::now();
    site::Model {
        id,
        user_id: owner,
        name: "shop".to_string(),
        domain: "shop.example.com".to_string(),
        alternate_domains: Vec::new(),
        status: site_status::ACTIVE.to_string(),
        plan: "free".to_string(),
        cache_quota_mb: 1024,
        cache_max_file_size_mb: None,
        cache_type_limits_mb: None,
        trust_proxy_headers: false,
        trusted_header: trusted_header::DEFAULT.to_string(),
        trust_last_hop: true,
        failover_policy: "inherit".to_string(),
        trusted_proxy_ranges: Vec::new(),
        trusted_proxy_group_ids: Vec::new(),
        created_at: now,
        updated_at: now,
    }
}

/// Encodes one model as the row a query would return.
fn encode_row<M>(model: &M) -> ProxyRow
where
    M: ModelTrait,
{
    let values = <<M::Entity as EntityTrait>::Column as Iterable>::iter()
        .map(|column| (column.as_str().to_string(), model.get(column)))
        .collect::<BTreeMap<String, Value>>();
    ProxyRow::new(values)
}

/// Encodes one `sites` row as the row a query would return.
fn proxy_row(model: site::Model) -> ProxyRow {
    encode_row(&model)
}

/// Answers each query with the next queued batch of rows, in order.
#[derive(Debug, Default)]
struct QueryQueue {
    batches: Mutex<VecDeque<Vec<ProxyRow>>>,
}

impl QueryQueue {
    fn boxed(batches: Vec<Vec<ProxyRow>>) -> Arc<Box<dyn ProxyDatabaseTrait>> {
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
        batches
            .pop_front()
            .ok_or_else(|| DbErr::Custom("no queued query result".to_string()))
    }

    async fn execute(
        &self,
        _statement: Statement,
    ) -> Result<ProxyExecResult, DbErr> {
        Ok(ProxyExecResult::new(0, 0))
    }
}

/// A connection that answers the queued reads in order.
async fn database_with_rows(batches: Vec<Vec<ProxyRow>>) -> DatabaseConnection {
    Database::connect_proxy(
        DatabaseBackend::Postgres,
        QueryQueue::boxed(batches),
    )
    .await
    .expect("the proxy connection cannot fail")
}

/// A connection that answers the queued `find_by_id` calls in order.
async fn database_returning(
    batches: Vec<Vec<site::Model>>,
) -> DatabaseConnection {
    let batches = batches
        .into_iter()
        .map(|batch| batch.into_iter().map(proxy_row).collect())
        .collect();
    database_with_rows(batches).await
}

/// An account with the given role and no forced password change.
fn account(role_name: &str) -> AuthUser {
    AuthUser::new(Uuid::new_v4(), "operator@example.com", role_name)
}

/// A `users` row as the auth extractor reads it back.
fn user_row(id: Uuid, role_name: &str, token_version: i64) -> user::Model {
    let now = Utc::now();
    user::Model {
        id,
        email: "operator@example.com".to_string(),
        password_hash: String::new(),
        name: None,
        role: role_name.to_string(),
        disabled: false,
        must_change_password: false,
        token_version,
        created_at: now,
        updated_at: now,
    }
}

/// The real IP-group router over a proxy connection that answers `requests`
/// account lookups, plus a dashboard token for `account`.
async fn ip_group_app(
    account: &user::Model,
    requests: usize,
) -> (Router, String) {
    app_for(ip_groups::routes(), account, requests).await
}

/// Builds `routes` over a proxy connection that answers `requests` account
/// lookups, plus a dashboard token for `account`.
async fn app_for(
    routes: Router<AppState>,
    account: &user::Model,
    requests: usize,
) -> (Router, String) {
    let config = ServerConfig::default();
    let token = create_token(
        account.id,
        &account.email,
        &account.role,
        account.token_version,
        &config.jwt_secret,
        1,
    )
    .expect("the access token cannot fail to sign");
    let db =
        database_with_rows(vec![vec![encode_row(account)]; requests]).await;
    let state = AppState::new(db, config, AgentRegistry::new());
    (routes.with_state(state), token)
}

/// A bearer-authenticated request, with an optional JSON body.
fn bearer_request(
    method: Method,
    uri: &str,
    token: &str,
    body: Option<&str>,
) -> Request<Body> {
    let mut builder = Request::builder()
        .method(method)
        .uri(uri)
        .header(header::AUTHORIZATION, format!("Bearer {token}"));
    let body = match body {
        Some(json) => {
            builder = builder.header(header::CONTENT_TYPE, "application/json");
            Body::from(json.to_string())
        },
        None => Body::empty(),
    };
    builder.body(body).expect("the request is well formed")
}

#[tokio::test]
async fn admin_reads_any_site() {
    // Arrange: the admin does not own the site.
    let admin = account(role::ADMIN);
    let site_id = Uuid::new_v4();
    let site = site_owned_by(site_id, Uuid::new_v4());
    let owner = site.user_id;
    let db = database_returning(vec![vec![site]]).await;

    // Act
    let loaded = load_site_read(&db, site_id, &admin)
        .await
        .expect("administrators must see every site");

    // Assert
    assert_eq!(loaded.id, site_id);
    assert_eq!(loaded.user_id, owner);
}

#[tokio::test]
async fn owner_reads_own_site() {
    // Arrange: a non-admin account owns the site.
    let owner = account(role::VIEWER);
    let site_id = Uuid::new_v4();
    let db =
        database_returning(vec![vec![site_owned_by(site_id, owner.id)]]).await;

    // Act
    let loaded = load_site_read(&db, site_id, &owner)
        .await
        .expect("an owner must see their own site");

    // Assert
    assert_eq!(loaded.id, site_id);
    assert_eq!(loaded.user_id, owner.id);
}

#[tokio::test]
async fn non_owner_gets_not_found() {
    // Arrange: the site belongs to somebody else.
    let stranger = account(role::VIEWER);
    let site_id = Uuid::new_v4();
    let db =
        database_returning(vec![vec![site_owned_by(site_id, Uuid::new_v4())]])
            .await;

    // Act
    let err = load_site_read(&db, site_id, &stranger)
        .await
        .expect_err("a non-owner must not see the site");

    // Assert: the variant is NotFound, not Forbidden, so domains do not leak.
    assert_eq!(err.code(), "not_found");
    assert!(
        matches!(&err, ApiError::NotFound(_)),
        "expected ApiError::NotFound, got {err:?}"
    );
}

#[tokio::test]
async fn non_admin_write_is_forbidden() {
    // Arrange: an owner without the admin role.
    let owner = account(role::VIEWER);
    let site_id = Uuid::new_v4();
    let db =
        database_returning(vec![vec![site_owned_by(site_id, owner.id)]]).await;

    // Act
    let err = load_site_write(&db, site_id, &owner)
        .await
        .expect_err("read-only roles must not modify a site");

    // Assert
    assert!(
        matches!(&err, ApiError::Forbidden(_)),
        "expected ApiError::Forbidden, got {err:?}"
    );
}

#[tokio::test]
async fn non_owner_write_is_not_found() {
    // Arrange: a non-admin writing to somebody else's site.
    let stranger = account(role::VIEWER);
    let site_id = Uuid::new_v4();
    let db =
        database_returning(vec![vec![site_owned_by(site_id, Uuid::new_v4())]])
            .await;

    // Act
    let err = load_site_write(&db, site_id, &stranger)
        .await
        .expect_err("a non-owner must not modify the site");

    // Assert: ownership is checked before the write gate, so this stays a 404
    // rather than leaking the site's existence with a 403.
    assert!(
        matches!(&err, ApiError::NotFound(_)),
        "expected ApiError::NotFound, got {err:?}"
    );
}

#[tokio::test]
async fn must_change_password_blocks_write() {
    // Arrange: an admin still flagged by the forced-password-change flow.
    let mut admin = account(role::ADMIN);
    admin.must_change_password = true;
    let site_id = Uuid::new_v4();
    let site = site_owned_by(site_id, Uuid::new_v4());
    let db = database_returning(vec![vec![site.clone()], vec![site]]).await;

    // Act: the write path is gated for administrators too.
    let err = load_site_write(&db, site_id, &admin)
        .await
        .expect_err("a flagged administrator must not write");

    // Assert
    assert!(
        matches!(&err, ApiError::Forbidden(_)),
        "expected ApiError::Forbidden, got {err:?}"
    );

    // Reading still works for the same account.
    let loaded = load_site_read(&db, site_id, &admin)
        .await
        .expect("a forced password change must not block reads");
    assert_eq!(loaded.id, site_id);
}

#[tokio::test]
async fn scope_site_requires_an_id_for_non_admins() {
    // Arrange
    let viewer = account(role::VIEWER);
    let admin = account(role::ADMIN);
    let site_id = Uuid::new_v4();

    // Act & Assert: a non-admin asking for "all sites" is a client error.
    let scoped = scope_site(None, &viewer);
    assert!(
        matches!(&scoped, Err(ApiError::BadRequest(_))),
        "expected ApiError::BadRequest, got {scoped:?}"
    );

    // An admin asking for "all sites" gets no filter.
    assert_eq!(
        scope_site(None, &admin).expect("an admin may query all sites"),
        None
    );

    // An explicit site id is passed through for both roles.
    assert_eq!(
        scope_site(Some(site_id), &viewer).expect("an explicit id is accepted"),
        Some(site_id)
    );
    assert_eq!(
        scope_site(Some(site_id), &admin).expect("an explicit id is accepted"),
        Some(site_id)
    );
}

#[tokio::test]
async fn missing_site_is_not_found() {
    // Arrange: the queue returns no row for the lookup.
    let viewer = account(role::VIEWER);
    let site_id = Uuid::new_v4();
    let db = database_returning(vec![Vec::new()]).await;

    // Act
    let err = load_site_read(&db, site_id, &viewer)
        .await
        .expect_err("a missing site must not load");

    // Assert
    assert!(
        matches!(&err, ApiError::NotFound(_)),
        "expected ApiError::NotFound, got {err:?}"
    );
}

#[tokio::test]
async fn auditor_reads_foreign_site() {
    // Arrange: an auditor with global read access who owns nothing.
    let auditor = account(role::AUDITOR);
    let site_id = Uuid::new_v4();
    let owner = Uuid::new_v4();
    let db =
        database_returning(vec![vec![site_owned_by(site_id, owner)]]).await;

    // Act
    let loaded = load_site_read(&db, site_id, &auditor)
        .await
        .expect("auditors must see every site");

    // Assert
    assert_eq!(loaded.id, site_id);
    assert_eq!(loaded.user_id, owner);
}

#[tokio::test]
async fn auditor_write_is_forbidden() {
    // Arrange: an auditor owning the site still must not mutate it.
    let auditor = account(role::AUDITOR);
    let site_id = Uuid::new_v4();
    let db = database_returning(vec![vec![site_owned_by(site_id, auditor.id)]])
        .await;

    // Act
    let err = load_site_write(&db, site_id, &auditor)
        .await
        .expect_err("auditors must not modify a site");

    // Assert: the ownership check passes, the write gate is what refuses.
    assert!(
        matches!(&err, ApiError::Forbidden(_)),
        "expected ApiError::Forbidden, got {err:?}"
    );
}

#[test]
fn scope_site_allows_auditor_all_sites() {
    // Arrange
    let auditor = account(role::AUDITOR);
    let site_id = Uuid::new_v4();

    // Act & Assert: no site filter is a global read, which auditors may do.
    assert_eq!(
        scope_site(None, &auditor).expect("an auditor may query all sites"),
        None
    );
    // An explicit id still passes through.
    assert_eq!(
        scope_site(Some(site_id), &auditor)
            .expect("an explicit id is accepted"),
        Some(site_id)
    );
}

#[test]
fn empty_key_permissions_do_not_allow_agents() {
    // Arrange: a legacy key with no permissions recorded.
    let key = api_key::Model {
        id: Uuid::new_v4(),
        user_id: Uuid::new_v4(),
        name: "legacy".to_string(),
        key_hash: String::new(),
        key_prefix: "pwk_abcd".to_string(),
        permissions: Vec::new(),
        expires_at: None,
        last_used_at: None,
        created_at: Utc::now(),
    };

    // Act & Assert: fail closed; the key must be re-granted explicitly.
    assert!(!key_allows_agent(&key));

    let mut with_agent = key.clone();
    with_agent.permissions = vec![permission::AGENT.to_string()];
    assert!(key_allows_agent(&with_agent));

    let mut read_only = key;
    read_only.permissions = vec![permission::READ.to_string()];
    assert!(!key_allows_agent(&read_only));
}

#[tokio::test]
async fn ip_group_mutations_require_admin() {
    // Arrange: a viewer token through the real router and auth extractor. The
    // single queued row is the account the extractor reads back; the handler
    // must refuse before touching the group table, so a 403 (not a 500 from an
    // exhausted queue) proves `require_admin` runs first.
    let viewer = user_row(Uuid::new_v4(), role::VIEWER, 1);
    let (app, token) = ip_group_app(&viewer, 1).await;

    // Act
    let response = app
        .oneshot(bearer_request(
            Method::POST,
            "/ip-groups",
            &token,
            Some(r#"{"name":"office","ip_ranges":["10.0.0.0/8"]}"#),
        ))
        .await
        .expect("the router is infallible");

    // Assert
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn ip_group_delete_requires_admin() {
    // Arrange: same seam as the create test, with a path parameter.
    let viewer = user_row(Uuid::new_v4(), role::VIEWER, 1);
    let (app, token) = ip_group_app(&viewer, 1).await;
    let group_id = Uuid::new_v4();

    // Act
    let response = app
        .oneshot(bearer_request(
            Method::DELETE,
            &format!("/ip-groups/{group_id}"),
            &token,
            None,
        ))
        .await
        .expect("the router is infallible");

    // Assert
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn must_change_password_blocks_notification_settings() {
    // Arrange: a flagged administrator through the real notification router.
    // Only the account lookup is queued; the handler must refuse before any
    // settings query, so a 403 (not a 500 from an exhausted queue) proves the
    // write gate runs first.
    let mut admin = user_row(Uuid::new_v4(), role::ADMIN, 1);
    admin.must_change_password = true;
    let (app, token) = app_for(notifications::routes(), &admin, 1).await;

    // Act
    let response = app
        .oneshot(bearer_request(
            Method::PUT,
            "/notifications/settings",
            &token,
            Some(r#"{"enabled":false}"#),
        ))
        .await
        .expect("the router is infallible");

    // Assert: the forced-change message, not a database failure.
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .expect("the body is readable");
    let body = String::from_utf8(body.to_vec()).expect("the body is UTF-8");
    assert!(
        body.contains("change your password before making changes"),
        "unexpected body: {body}"
    );
}

#[tokio::test]
async fn forced_password_change_does_not_block_the_password_change_itself() {
    // Arrange: a flagged administrator whose stored hash matches a different
    // password. The extractor and the handler each load the account, hence
    // two queued rows.
    let mut flagged = user_row(Uuid::new_v4(), role::ADMIN, 1);
    flagged.must_change_password = true;
    flagged.password_hash = hash_password("the real current password")
        .expect("hashing a test password cannot fail");
    let (app, token) = app_for(auth::routes(), &flagged, 2).await;

    // Act
    let response = app
        .oneshot(bearer_request(
            Method::PUT,
            "/auth/password",
            &token,
            Some(
                r#"{"current_password":"not the real password","new_password":"a much longer new password"}"#,
            ),
        ))
        .await
        .expect("the router is infallible");

    // Assert: the handler ran and rejected the current password (400), rather
    // than the forced-change gate answering 403.
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
}
