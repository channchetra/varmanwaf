//! Tenant-scope contract of the MCP tools.
//!
//! Every MCP read runs through [`varman_control::mcp::tools`] with a
//! [`ToolContext`] carrying the caller's `subject` and `can_read_all`. A
//! caller without `can_read_all` (the `viewer` role) must only see its own
//! sites, logs, certificates and control-plane activity; administrators and
//! the read-only `auditor` role keep the instance-wide view.
//!
//! SeaORM's `mock` feature cannot be enabled (it removes `Clone` from
//! `DatabaseConnection`, which production code relies on), so these tests use
//! the `proxy` backend from `tests/api_authz.rs`: each query pops a queued
//! batch of rows, and every `Statement` is recorded so the SQL tenant
//! predicates can be asserted directly. The proxy cannot apply filters itself,
//! so a filtered query still needs its predicate checked here.

use std::collections::{BTreeMap, VecDeque};
use std::sync::{Arc, Mutex};

use chrono::Utc;
use sea_orm::{
    Database, DatabaseBackend, DatabaseConnection, DbErr, IdenStatic, Iterable,
    ModelTrait, ProxyDatabaseTrait, ProxyExecResult, ProxyRow, Statement,
    Value,
};
use serde_json::json;
use uuid::Uuid;

use varman_control::app_state::AppState;
use varman_control::config::ServerConfig;
use varman_control::grpc::AgentRegistry;
use varman_control::mcp::auth::role_can_read_all;
use varman_control::mcp::tools::{self, ToolContext, SITE_NOT_VISIBLE};
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
fn site_row(model: site::Model) -> ProxyRow {
    let values = site::Column::iter()
        .map(|column| (column.as_str().to_string(), model.get(column)))
        .collect::<BTreeMap<String, Value>>();
    ProxyRow::new(values)
}

/// A one-column row, e.g. the `id` of a `SELECT id FROM sites` query.
fn uuid_row(column: &str, id: Uuid) -> ProxyRow {
    ProxyRow::new(BTreeMap::from([(
        column.to_string(),
        Value::Uuid(Some(Box::new(id))),
    )]))
}

/// The row a `Paginator::count` reads (`num_items`).
fn count_row(total: i64) -> ProxyRow {
    ProxyRow::new(BTreeMap::from([(
        "num_items".to_string(),
        Value::BigInt(Some(total)),
    )]))
}

/// Records the statements a tool issued.
#[derive(Debug, Default)]
struct Recorder {
    queries: Mutex<Vec<Statement>>,
    executions: Mutex<Vec<Statement>>,
}

impl Recorder {
    fn queries(&self) -> Vec<Statement> {
        self.queries.lock().expect("recorder lock").clone()
    }

    fn executions(&self) -> usize {
        self.executions.lock().expect("recorder lock").len()
    }
}

/// Answers each query with the next queued batch of rows, in order.
#[derive(Debug)]
struct RecordingQueue {
    batches: Mutex<VecDeque<Vec<ProxyRow>>>,
    recorder: Arc<Recorder>,
}

#[async_trait::async_trait]
impl ProxyDatabaseTrait for RecordingQueue {
    async fn query(
        &self,
        statement: Statement,
    ) -> Result<Vec<ProxyRow>, DbErr> {
        self.recorder
            .queries
            .lock()
            .expect("recorder lock")
            .push(statement);
        self.batches
            .lock()
            .expect("query queue lock")
            .pop_front()
            .ok_or_else(|| DbErr::Custom("no queued query result".to_string()))
    }

    async fn execute(
        &self,
        statement: Statement,
    ) -> Result<ProxyExecResult, DbErr> {
        self.recorder
            .executions
            .lock()
            .expect("recorder lock")
            .push(statement);
        Ok(ProxyExecResult::new(0, 0))
    }
}

/// A proxy connection that answers the queued queries in order and records
/// every statement it was asked to run.
async fn database(
    batches: Vec<Vec<ProxyRow>>,
) -> (DatabaseConnection, Arc<Recorder>) {
    let recorder = Arc::new(Recorder::default());
    let queue = RecordingQueue {
        batches: Mutex::new(batches.into()),
        recorder: Arc::clone(&recorder),
    };
    let db = Database::connect_proxy(
        DatabaseBackend::Postgres,
        Arc::new(Box::new(queue)),
    )
    .await
    .expect("the proxy connection cannot fail");
    (db, recorder)
}

fn app_state(db: DatabaseConnection) -> AppState {
    AppState::new(db, ServerConfig::default(), AgentRegistry::new())
}

fn context<'a>(
    state: &'a AppState,
    subject: Uuid,
    can_read_all: bool,
) -> ToolContext<'a> {
    ToolContext {
        state,
        actor: "test",
        subject,
        can_read_all,
        // `set_site_status` sits behind the write gate, so the ownership
        // check needs it open; the read tools ignore the flag.
        can_write: true,
    }
}

/// True when `statement` binds `id` as a parameter.
fn has_uuid(statement: &Statement, id: Uuid) -> bool {
    statement.values.as_ref().is_some_and(|values| {
        values.0.iter().any(
            |value| matches!(value, Value::Uuid(Some(bound)) if **bound == id),
        )
    })
}

/// True when the SQL narrows on a `site_id` parameter (`IN ($n…)`). Column
/// lists also name `site_id`, so a substring check is not enough.
fn has_site_predicate(sql: &str) -> bool {
    sql.contains("site_id\" IN ($") || sql.contains("site_id IN ($")
}

/// True when the SQL compares `user_id` to a bound parameter.
fn has_user_predicate(sql: &str) -> bool {
    sql.contains("user_id\" = $")
}

// ─────────────────────────────────────────────────────────────
// list_sites
// ─────────────────────────────────────────────────────────────

#[tokio::test]
async fn viewer_list_sites_filters_by_owner() {
    let viewer = Uuid::new_v4();
    let site_id = Uuid::new_v4();
    let (db, recorder) = database(vec![
        vec![site_row(site_owned_by(site_id, viewer))],
        Vec::new(),
    ])
    .await;
    let state = app_state(db);

    let result =
        tools::call(&context(&state, viewer, false), "list_sites", &json!({}))
            .await
            .expect("list_sites must succeed");

    let queries = recorder.queries();
    assert_eq!(queries.len(), 2, "sites page + online-agent count");
    assert!(queries[0].sql.contains("sites"), "{}", queries[0].sql);
    assert!(has_user_predicate(&queries[0].sql), "{}", queries[0].sql);
    assert!(has_uuid(&queries[0], viewer));
    // The agent count is scoped to the page's sites.
    assert!(has_site_predicate(&queries[1].sql), "{}", queries[1].sql);
    assert!(has_uuid(&queries[1], site_id));
    assert_eq!(result["count"], 1);
}

#[tokio::test]
async fn admin_and_auditor_list_every_site() {
    // Both read-all roles keep the instance-wide view.
    for role_name in [role::ADMIN, role::AUDITOR] {
        let can_read_all = role_can_read_all(role_name);
        assert!(can_read_all, "{role_name} must read every tenant");
        let caller = Uuid::new_v4();
        let (db, recorder) = database(vec![Vec::new(), Vec::new()]).await;
        let state = app_state(db);

        tools::call(
            &context(&state, caller, can_read_all),
            "list_sites",
            &json!({}),
        )
        .await
        .expect("list_sites must succeed");

        let queries = recorder.queries();
        assert_eq!(queries.len(), 2);
        assert!(
            !has_user_predicate(&queries[0].sql),
            "read-all callers must not be narrowed: {}",
            queries[0].sql
        );
        assert!(!has_uuid(&queries[0], caller));
    }
}

#[tokio::test]
async fn role_can_read_all_matches_the_rest_rule() {
    assert!(role_can_read_all(role::ADMIN));
    assert!(role_can_read_all(role::AUDITOR));
    assert!(!role_can_read_all(role::VIEWER));
}

// ─────────────────────────────────────────────────────────────
// visible_site_ids
// ─────────────────────────────────────────────────────────────

#[tokio::test]
async fn visible_site_ids_is_none_for_read_all_and_owned_ids_otherwise() {
    // Read-all: no query is needed and every site is visible.
    let (db, recorder) = database(Vec::new()).await;
    let state = app_state(db);
    let visible =
        tools::visible_site_ids(&context(&state, Uuid::new_v4(), true))
            .await
            .expect("read-all must resolve");
    assert!(visible.is_none());
    assert!(recorder.queries().is_empty());

    // Viewer: exactly the queued owned id.
    let viewer = Uuid::new_v4();
    let site_id = Uuid::new_v4();
    let (db, recorder) = database(vec![vec![uuid_row("id", site_id)]]).await;
    let state = app_state(db);
    let visible = tools::visible_site_ids(&context(&state, viewer, false))
        .await
        .expect("a viewer's sites must resolve");
    assert_eq!(visible, Some(vec![site_id]));
    let queries = recorder.queries();
    assert_eq!(queries.len(), 1);
    assert!(queries[0].sql.contains("user_id"), "{}", queries[0].sql);
    assert!(has_uuid(&queries[0], viewer));
}

// ─────────────────────────────────────────────────────────────
// Log and certificate reads
// ─────────────────────────────────────────────────────────────

#[tokio::test]
async fn viewer_access_logs_are_scoped_to_owned_sites() {
    let viewer = Uuid::new_v4();
    let site_id = Uuid::new_v4();
    let (db, recorder) = database(vec![
        vec![uuid_row("id", site_id)],
        vec![count_row(0)],
        Vec::new(),
    ])
    .await;
    let state = app_state(db);

    tools::call(
        &context(&state, viewer, false),
        "query_access_logs",
        &json!({}),
    )
    .await
    .expect("query_access_logs must succeed");

    let queries = recorder.queries();
    assert_eq!(queries.len(), 3, "visible sites, count, rows");
    assert!(queries[1].sql.contains("access_logs"), "{}", queries[1].sql);
    assert!(has_site_predicate(&queries[1].sql), "{}", queries[1].sql);
    assert!(has_uuid(&queries[1], site_id));
    assert!(!queries[1].sql.contains("IN ()"), "{}", queries[1].sql);
}

#[tokio::test]
async fn viewer_waf_events_are_scoped_to_owned_sites() {
    let viewer = Uuid::new_v4();
    let site_id = Uuid::new_v4();
    let (db, recorder) = database(vec![
        vec![uuid_row("id", site_id)],
        vec![count_row(0)],
        Vec::new(),
    ])
    .await;
    let state = app_state(db);

    tools::call(
        &context(&state, viewer, false),
        "query_waf_events",
        &json!({}),
    )
    .await
    .expect("query_waf_events must succeed");

    let queries = recorder.queries();
    assert_eq!(queries.len(), 3);
    assert!(
        queries[1].sql.contains("security_events"),
        "{}",
        queries[1].sql
    );
    assert!(has_site_predicate(&queries[1].sql), "{}", queries[1].sql);
    assert!(has_uuid(&queries[1], site_id));
}

#[tokio::test]
async fn an_explicit_foreign_site_id_is_not_visible() {
    let viewer = Uuid::new_v4();
    let foreign = Uuid::new_v4();
    let (db, recorder) =
        database(vec![vec![site_row(site_owned_by(foreign, Uuid::new_v4()))]])
            .await;
    let state = app_state(db);

    let error = tools::call(
        &context(&state, viewer, false),
        "query_access_logs",
        &json!({ "site_id": foreign }),
    )
    .await
    .expect_err("a foreign site must not be readable");

    assert_eq!(error, SITE_NOT_VISIBLE);
    assert_eq!(recorder.queries().len(), 1, "only the visibility lookup");
}

#[tokio::test]
async fn viewer_certificate_summary_excludes_foreign_certificates() {
    let viewer = Uuid::new_v4();
    let site_id = Uuid::new_v4();
    let (db, recorder) =
        database(vec![vec![uuid_row("id", site_id)], Vec::new()]).await;
    let state = app_state(db);

    tools::call(
        &context(&state, viewer, false),
        "certificate_summary",
        &json!({}),
    )
    .await
    .expect("certificate_summary must succeed");

    let queries = recorder.queries();
    assert_eq!(queries.len(), 2);
    assert!(
        queries[1].sql.contains("site_certificates"),
        "{}",
        queries[1].sql
    );
    assert!(has_site_predicate(&queries[1].sql), "{}", queries[1].sql);
    assert!(has_uuid(&queries[1], site_id));
}

// ─────────────────────────────────────────────────────────────
// Traffic summary
// ─────────────────────────────────────────────────────────────

#[tokio::test]
async fn viewer_traffic_summary_filters_both_raw_queries() {
    let viewer = Uuid::new_v4();
    let site_id = Uuid::new_v4();
    let (db, recorder) =
        database(vec![vec![uuid_row("id", site_id)], Vec::new(), Vec::new()])
            .await;
    let state = app_state(db);

    tools::call(
        &context(&state, viewer, false),
        "get_traffic_summary",
        &json!({}),
    )
    .await
    .expect("get_traffic_summary must succeed");

    let queries = recorder.queries();
    assert_eq!(queries.len(), 3, "visible sites plus the two aggregates");
    assert!(queries[1].sql.contains("access_logs"), "{}", queries[1].sql);
    assert!(has_site_predicate(&queries[1].sql), "{}", queries[1].sql);
    assert!(has_uuid(&queries[1], site_id));
    assert!(
        queries[2].sql.contains("security_events"),
        "{}",
        queries[2].sql
    );
    assert!(has_site_predicate(&queries[2].sql), "{}", queries[2].sql);
    assert!(has_uuid(&queries[2], site_id));
}

#[tokio::test]
async fn viewer_without_sites_gets_false_not_an_empty_in_list() {
    let viewer = Uuid::new_v4();
    let (db, recorder) =
        database(vec![Vec::new(), Vec::new(), Vec::new()]).await;
    let state = app_state(db);

    let result = tools::call(
        &context(&state, viewer, false),
        "get_traffic_summary",
        &json!({}),
    )
    .await
    .expect("get_traffic_summary must succeed");

    let queries = recorder.queries();
    assert_eq!(queries.len(), 3);
    for query in &queries[1..] {
        assert!(query.sql.contains("AND FALSE"), "{}", query.sql);
        assert!(!query.sql.contains("IN ()"), "{}", query.sql);
    }
    assert_eq!(result["requests"], 0);
}

// ─────────────────────────────────────────────────────────────
// Agents, IP groups and control-plane logs
// ─────────────────────────────────────────────────────────────

#[tokio::test]
async fn viewer_agents_follow_the_canonical_visibility_rule() {
    let viewer = Uuid::new_v4();
    let site_id = Uuid::new_v4();
    let key_id = Uuid::new_v4();
    let (db, recorder) = database(vec![
        vec![uuid_row("id", site_id)],
        vec![uuid_row("id", key_id)],
        Vec::new(),
    ])
    .await;
    let state = app_state(db);

    tools::call(&context(&state, viewer, false), "list_agents", &json!({}))
        .await
        .expect("list_agents must succeed");

    let queries = recorder.queries();
    assert_eq!(queries.len(), 3, "owned sites, owned keys, agents");
    let agents = &queries[2].sql;
    assert!(agents.contains("site_id"), "{agents}");
    assert!(agents.contains("api_key_id"), "{agents}");
    assert!(agents.contains("IS NULL"), "{agents}");
    assert!(has_uuid(&queries[2], site_id));
    assert!(has_uuid(&queries[2], key_id));
}

#[tokio::test]
async fn viewer_ip_groups_are_global_plus_linked_to_owned_sites() {
    let viewer = Uuid::new_v4();
    let (db, recorder) = database(vec![Vec::new()]).await;
    let state = app_state(db);

    tools::call(
        &context(&state, viewer, false),
        "list_ip_groups",
        &json!({}),
    )
    .await
    .expect("list_ip_groups must succeed");

    let queries = recorder.queries();
    assert_eq!(queries.len(), 1);
    let sql = &queries[0].sql;
    assert!(sql.contains("is_global"), "{sql}");
    assert!(sql.contains("ip_group_sites"), "{sql}");
    assert!(has_user_predicate(sql), "{sql}");
    assert!(has_uuid(&queries[0], viewer));
}

#[tokio::test]
async fn viewer_control_plane_logs_only_show_own_activity() {
    let viewer = Uuid::new_v4();
    let (db, recorder) = database(vec![vec![count_row(0)], Vec::new()]).await;
    let state = app_state(db);

    tools::call(
        &context(&state, viewer, false),
        "query_control_plane_logs",
        &json!({}),
    )
    .await
    .expect("query_control_plane_logs must succeed");

    let queries = recorder.queries();
    assert_eq!(queries.len(), 2);
    let count = &queries[0].sql;
    assert!(count.contains("control_plane_access_logs"), "{count}");
    assert!(has_user_predicate(count), "{count}");
    assert!(has_uuid(&queries[0], viewer));
}

#[tokio::test]
async fn admin_control_plane_logs_are_not_narrowed() {
    let admin = Uuid::new_v4();
    let (db, recorder) = database(vec![vec![count_row(0)], Vec::new()]).await;
    let state = app_state(db);

    tools::call(
        &context(&state, admin, true),
        "query_control_plane_logs",
        &json!({}),
    )
    .await
    .expect("query_control_plane_logs must succeed");

    let queries = recorder.queries();
    assert!(!has_user_predicate(&queries[0].sql), "{}", queries[0].sql);
}

// ─────────────────────────────────────────────────────────────
// set_site_status
// ─────────────────────────────────────────────────────────────

#[tokio::test]
async fn a_foreign_site_cannot_be_paused() {
    let caller = Uuid::new_v4();
    let foreign = Uuid::new_v4();
    let (db, recorder) =
        database(vec![vec![site_row(site_owned_by(foreign, Uuid::new_v4()))]])
            .await;
    let state = app_state(db);

    let error = tools::call(
        &context(&state, caller, false),
        "set_site_status",
        &json!({ "site_id": foreign, "status": "paused" }),
    )
    .await
    .expect_err("a foreign site must not be mutable");

    assert_eq!(error, SITE_NOT_VISIBLE);
    assert_eq!(
        recorder.executions(),
        0,
        "no UPDATE, touch or config push may happen"
    );
}

#[tokio::test]
async fn a_missing_site_is_reported_like_a_foreign_one() {
    let caller = Uuid::new_v4();
    let (db, recorder) = database(vec![Vec::new()]).await;
    let state = app_state(db);

    let error = tools::call(
        &context(&state, caller, false),
        "set_site_status",
        &json!({ "site_id": Uuid::new_v4(), "status": "paused" }),
    )
    .await
    .expect_err("a missing site must not be mutable");

    assert_eq!(error, SITE_NOT_VISIBLE);
    assert_eq!(recorder.executions(), 0);
}

#[tokio::test]
async fn an_auditor_still_fails_the_write_gate() {
    let (db, recorder) = database(Vec::new()).await;
    let state = app_state(db);
    let mut ctx = context(&state, Uuid::new_v4(), true);
    ctx.can_write = false;

    let error = tools::call(
        &ctx,
        "set_site_status",
        &json!({ "site_id": Uuid::new_v4(), "status": "paused" }),
    )
    .await
    .expect_err("auditors are read-only");

    assert!(error.contains("write permission"), "{error}");
    assert!(
        recorder.queries().is_empty(),
        "the write gate runs before any query"
    );
    assert_eq!(recorder.executions(), 0);
}
