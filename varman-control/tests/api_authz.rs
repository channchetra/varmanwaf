//! Executable tests for the site-authorization helpers in `api::common`.
//!
//! The contract under test is the one documented on `load_site`: administrators
//! see every site, other roles only the sites they own, and a site owned by
//! somebody else is reported as `404` (never `403`) so the API does not leak
//! which domains exist.
//!
//! SeaORM's `mock` feature cannot be enabled here: it drops
//! `DatabaseConnection`'s `Clone` impl (`#[cfg_attr(not(feature = "mock"), ...)]`),
//! which the control plane relies on in production code. The `proxy` feature
//! provides the same queued-row test double without touching that: every test
//! queues the rows its `find_by_id` returns, and no PostgreSQL is needed.

use std::collections::{BTreeMap, VecDeque};
use std::sync::{Arc, Mutex};

use chrono::Utc;
use sea_orm::{
    Database, DatabaseBackend, DatabaseConnection, DbErr, IdenStatic, Iterable,
    ModelTrait, ProxyDatabaseTrait, ProxyExecResult, ProxyRow, Statement,
    Value,
};
use uuid::Uuid;

use varman_control::api::common::{
    load_site_read, load_site_write, scope_site,
};
use varman_control::auth::AuthUser;
use varman_control::error::ApiError;
use varman_control::models::{role, site, site_status, trusted_header};

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
fn proxy_row(model: site::Model) -> ProxyRow {
    let values = site::Column::iter()
        .map(|column| (column.as_str().to_string(), model.get(column)))
        .collect::<BTreeMap<String, Value>>();
    ProxyRow::new(values)
}

/// Answers each query with the next queued batch of rows, in order.
#[derive(Debug, Default)]
struct QueryQueue {
    batches: Mutex<VecDeque<Vec<ProxyRow>>>,
}

impl QueryQueue {
    fn boxed(
        batches: Vec<Vec<site::Model>>,
    ) -> Arc<Box<dyn ProxyDatabaseTrait>> {
        let batches = batches
            .into_iter()
            .map(|batch| batch.into_iter().map(proxy_row).collect())
            .collect();
        Arc::new(Box::new(Self {
            batches: Mutex::new(batches),
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

/// A connection that answers the queued `find_by_id` calls in order.
async fn database_returning(
    batches: Vec<Vec<site::Model>>,
) -> DatabaseConnection {
    Database::connect_proxy(
        DatabaseBackend::Postgres,
        QueryQueue::boxed(batches),
    )
    .await
    .expect("the proxy connection cannot fail")
}

/// An account with the given role and no forced password change.
fn account(role_name: &str) -> AuthUser {
    AuthUser::new(Uuid::new_v4(), "operator@example.com", role_name)
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
