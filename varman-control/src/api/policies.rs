//! WAF policy management: policy documents, their layers, site assignments
//! and per-site overrides.
//!
//! A policy is a named document shared by sites; each site either follows
//! one policy or keeps its own `waf_settings` / rules. `GET .../effective-config`
//! resolves the exact posture the next bundle will carry (policy layers with
//! the site overlay applied, then the site's own settings as the fallback),
//! which is what the dashboard preview and the tests assert against.

use std::collections::HashMap;

use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use axum::routing::{get, post, put};
use axum::Json;
use axum::Router;
use chrono::{DateTime, Utc};
use sea_orm::{
    ActiveModelTrait, ColumnTrait, EntityTrait, QueryFilter, QueryOrder, Set,
};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use uuid::Uuid;

use crate::api::common::{load_site_read, load_site_write, parse_uuid};
use crate::api::error::ApiError;
use crate::api::sites::touch_site;
use crate::api::state::AppState;
use crate::auth::AuthUser;
use crate::grpc::notify_config_changed;
use crate::models::{
    agent, api_key, config_version, site, site_waf_policy,
    site_waf_policy_override, waf_policy, waf_policy_layer, waf_policy_version,
    waf_settings,
};
use crate::policy::{self, LAYER_KINDS};

/// Routes contributed to `/api/v1`.
pub fn routes() -> Router<AppState> {
    Router::new()
        .route("/policies", get(list_policies).post(create_policy))
        .route("/policies/preview", post(preview_policy))
        .route(
            "/policies/{id}",
            get(get_policy).put(update_policy).delete(delete_policy),
        )
        .route(
            "/policies/{id}/layers/{kind}",
            put(put_layer).delete(delete_layer),
        )
        .route("/policies/{id}/versions", get(list_versions))
        .route("/policies/{id}/versions/diff", get(diff_versions))
        .route(
            "/policies/{id}/versions/{version_id}",
            get(get_version),
        )
        .route("/policies/{id}/rollback", post(rollback_policy))
        .route(
            "/sites/{site_id}/policy",
            get(get_site_policy).put(set_site_policy),
        )
        .route(
            "/sites/{site_id}/policy-override",
            get(get_site_override)
                .put(put_site_override)
                .delete(delete_site_override),
        )
        .route(
            "/sites/{site_id}/effective-config",
            get(get_effective_config),
        )
        .route(
            "/sites/{site_id}/apply-status",
            get(get_apply_status),
        )
}

/* ── Views ─────────────────────────────────────────────────────────────── */

/// Lightweight reference to a policy (assignments, effective config).
#[derive(Debug, Serialize)]
pub struct PolicyRef {
    pub id: Uuid,
    pub name: String,
    pub revision: i32,
    pub enabled: bool,
}

/// One stored layer.
#[derive(Debug, Serialize)]
pub struct LayerView {
    pub kind: String,
    pub config: Value,
    pub updated_at: DateTime<Utc>,
}

/// A policy as shown in the list, with how widely it is used.
#[derive(Debug, Serialize)]
pub struct PolicySummary {
    pub id: Uuid,
    pub name: String,
    pub description: String,
    pub enabled: bool,
    pub revision: i32,
    pub layer_kinds: Vec<String>,
    pub site_count: u64,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

/// A policy with its layers and the sites following it.
#[derive(Debug, Serialize)]
pub struct PolicyDetail {
    #[serde(flatten)]
    pub policy: PolicySummary,
    pub layers: Vec<LayerView>,
    pub sites: Vec<SiteRef>,
}

/// Minimal site identity for assignment lists.
#[derive(Debug, Serialize)]
pub struct SiteRef {
    pub id: Uuid,
    pub domain: String,
}

/// A site's policy assignment.
#[derive(Debug, Serialize)]
pub struct SitePolicyView {
    pub site_id: Uuid,
    pub policy: Option<PolicyRef>,
    pub overridden: bool,
    pub override_kinds: Vec<String>,
}

/// A site's overlay patch.
#[derive(Debug, Serialize)]
pub struct SiteOverrideView {
    pub site_id: Uuid,
    pub config: Value,
}

/// One version in the history list.
#[derive(Debug, Serialize)]
pub struct VersionView {
    pub id: i64,
    pub revision: i32,
    pub config_hash: String,
    pub source: String,
    pub actor: Option<String>,
    pub summary: Option<Value>,
    pub created_at: DateTime<Utc>,
}

/// Full version, including the snapshot.
#[derive(Debug, Serialize)]
pub struct VersionDetail {
    #[serde(flatten)]
    pub version: VersionView,
    pub snapshot: Value,
}

/// Human-readable diff between two versions.
#[derive(Debug, Serialize)]
pub struct VersionDiffView {
    pub from: i64,
    pub to: i64,
    pub fields: Vec<String>,
    pub layers: Vec<policy::LayerDiff>,
}

#[derive(Debug, Deserialize)]
pub struct DiffQuery {
    pub from: i64,
    pub to: i64,
}

#[derive(Debug, Deserialize)]
pub struct RollbackRequest {
    pub version_id: i64,
    #[serde(default)]
    pub expected_revision: Option<i32>,
}

/// The fully resolved posture of one site.
#[derive(Debug, Serialize)]
pub struct EffectiveConfigView {
    pub site_id: Uuid,
    pub policy: Option<PolicyRef>,
    /// `policy` when a policy contributes, `site` otherwise.
    pub source: &'static str,
    pub overridden: bool,
    pub override_kinds: Vec<String>,
    /// Effective raw `engine` layer (policy + overlay).
    pub engine: Value,
    /// Effective raw `crs` layer (policy + overlay).
    pub crs: Value,
    /// Policy custom rules (policy layer first, overlay rules after).
    pub rules: Vec<policy::PolicyRule>,
    /// Effective managed-rule overrides (policy first, overlay on top).
    pub overrides: Vec<policy::RuleOverrideEntry>,
    /// What the next bundle will carry, layer applied over the site row.
    pub effective: policy::EffectiveEngine,
    /// The compiled managed-rule plan (enforce/monitor/disabled, score,
    /// exclusions) for the effective engine.
    pub plan: Vec<policy::RulePlan>,
}

/* ── Requests ──────────────────────────────────────────────────────────── */

#[derive(Debug, Deserialize)]
pub struct CreatePolicyRequest {
    pub name: String,
    #[serde(default)]
    pub description: String,
    #[serde(default)]
    pub enabled: Option<bool>,
    /// Optional initial layers, keyed by kind.
    #[serde(default)]
    pub layers: HashMap<String, Value>,
}

#[derive(Debug, Deserialize)]
pub struct UpdatePolicyRequest {
    #[serde(default)]
    pub name: Option<String>,
    #[serde(default)]
    pub description: Option<String>,
    #[serde(default)]
    pub enabled: Option<bool>,
    /// Optimistic concurrency token: when present and stale, the update is
    /// rejected with 409 instead of silently overwriting someone else.
    #[serde(default)]
    pub expected_revision: Option<i32>,
}

#[derive(Debug, Deserialize)]
pub struct LayerRequest {
    pub config: Value,
    /// Optimistic concurrency: when present and stale, the write is
    /// rejected with 409 instead of silently overwriting someone else.
    #[serde(default)]
    pub expected_revision: Option<i32>,
}

#[derive(Debug, Deserialize)]
pub struct SetSitePolicyRequest {
    /// `null` clears the assignment (the site keeps its own settings).
    pub policy_id: Option<Uuid>,
}

#[derive(Debug, Deserialize)]
pub struct SiteOverrideRequest {
    pub config: Value,
}

/* ── Helpers ───────────────────────────────────────────────────────────── */

fn validate_name(name: &str) -> Result<String, ApiError> {
    let trimmed = name.trim();
    if trimmed.is_empty() {
        return Err(ApiError::bad_request("policy name must not be empty"));
    }
    if trimmed.chars().count() > 120 {
        return Err(ApiError::bad_request(
            "policy name must be at most 120 characters",
        ));
    }
    Ok(trimmed.to_string())
}

fn validate_layer_payload(kind: &str, config: &Value) -> Result<(), ApiError> {
    policy::validate_layer(kind, config)
        .map_err(|err| ApiError::bad_request(format!("layer '{kind}': {err}")))
}

async fn load_policy(
    state: &AppState,
    id: Uuid,
) -> Result<waf_policy::Model, ApiError> {
    waf_policy::Entity::find_by_id(id)
        .one(&state.db)
        .await?
        .ok_or_else(|| ApiError::not_found("policy not found"))
}

async fn load_layers(
    state: &AppState,
    policy_id: Uuid,
) -> Result<Vec<waf_policy_layer::Model>, ApiError> {
    let mut rows = waf_policy_layer::Entity::find()
        .filter(waf_policy_layer::Column::PolicyId.eq(policy_id))
        .all(&state.db)
        .await?;
    // Deterministic, kind-first order for the dashboard tabs.
    rows.sort_by_key(|row| {
        LAYER_KINDS
            .iter()
            .position(|kind| *kind == row.kind)
            .unwrap_or(LAYER_KINDS.len())
    });
    Ok(rows)
}

fn policy_ref(row: &waf_policy::Model) -> PolicyRef {
    PolicyRef {
        id: row.id,
        name: row.name.clone(),
        revision: row.revision,
        enabled: row.enabled,
    }
}

/// Layer kinds present on a policy, in [`LAYER_KINDS`] order.
fn layer_kinds_of(rows: &[waf_policy_layer::Model]) -> Vec<String> {
    let mut kinds: Vec<String> = LAYER_KINDS
        .iter()
        .filter(|kind| rows.iter().any(|row| row.kind == **kind))
        .map(|kind| kind.to_string())
        .collect();
    kinds.dedup();
    kinds
}

async fn assigned_sites(
    state: &AppState,
    policy_id: Uuid,
) -> Result<Vec<SiteRef>, ApiError> {
    let assignments = site_waf_policy::Entity::find()
        .filter(site_waf_policy::Column::PolicyId.eq(policy_id))
        .all(&state.db)
        .await?;
    let ids: Vec<Uuid> = assignments.iter().map(|row| row.site_id).collect();
    if ids.is_empty() {
        return Ok(Vec::new());
    }
    let mut rows = site::Entity::find()
        .filter(site::Column::Id.is_in(ids))
        .order_by_asc(site::Column::Domain)
        .all(&state.db)
        .await?;
    rows.sort_by(|a, b| a.domain.cmp(&b.domain));
    Ok(rows
        .into_iter()
        .map(|row| SiteRef {
            id: row.id,
            domain: row.domain,
        })
        .collect())
}

/// Bumps a policy's revision after a change.
async fn bump_revision(
    state: &AppState,
    policy: &waf_policy::Model,
) -> Result<waf_policy::Model, ApiError> {
    let mut active: waf_policy::ActiveModel = policy.clone().into();
    active.revision = Set(policy.revision + 1);
    active.updated_at = Set(Utc::now());
    Ok(active.update(&state.db).await?)
}

/// Marks every site following the policy for re-sync and pushes the new
/// configuration to connected agents.
async fn resync_assigned_sites(
    state: &AppState,
    policy_id: Uuid,
    actor: &str,
) -> Result<(), ApiError> {
    let assignments = site_waf_policy::Entity::find()
        .filter(site_waf_policy::Column::PolicyId.eq(policy_id))
        .all(&state.db)
        .await?;
    for assignment in assignments {
        touch_site(state, assignment.site_id).await?;
        notify_config_changed(state, assignment.site_id, Some(actor)).await;
    }
    Ok(())
}

/* ── Policy CRUD ───────────────────────────────────────────────────────── */

/// `GET /api/v1/policies` - every policy with usage counts.
async fn list_policies(
    State(state): State<AppState>,
    _current: AuthUser,
) -> Result<Json<Vec<PolicySummary>>, ApiError> {
    let rows = waf_policy::Entity::find()
        .order_by_asc(waf_policy::Column::Name)
        .all(&state.db)
        .await?;
    let layers = waf_policy_layer::Entity::find().all(&state.db).await?;
    let assignments = site_waf_policy::Entity::find().all(&state.db).await?;
    let mut counts: HashMap<Uuid, u64> = HashMap::new();
    for assignment in &assignments {
        *counts.entry(assignment.policy_id).or_default() += 1;
    }
    let items = rows
        .iter()
        .map(|row| {
            let own: Vec<waf_policy_layer::Model> = layers
                .iter()
                .filter(|layer| layer.policy_id == row.id)
                .cloned()
                .collect();
            PolicySummary {
                id: row.id,
                name: row.name.clone(),
                description: row.description.clone(),
                enabled: row.enabled,
                revision: row.revision,
                layer_kinds: layer_kinds_of(&own),
                site_count: counts.get(&row.id).copied().unwrap_or(0),
                created_at: row.created_at,
                updated_at: row.updated_at,
            }
        })
        .collect();
    Ok(Json(items))
}

/// `POST /api/v1/policies` - creates a policy, optionally with layers.
async fn create_policy(
    State(state): State<AppState>,
    current: AuthUser,
    Json(payload): Json<CreatePolicyRequest>,
) -> Result<Json<PolicyDetail>, ApiError> {
    current.require_admin().map_err(ApiError::from)?;
    let name = validate_name(&payload.name)?;
    for (kind, config) in &payload.layers {
        validate_layer_payload(kind, config)?;
    }
    if waf_policy::Entity::find()
        .filter(waf_policy::Column::Name.eq(name.clone()))
        .one(&state.db)
        .await?
        .is_some()
    {
        return Err(ApiError::Conflict(format!(
            "a policy named '{name}' already exists"
        )));
    }

    let now = Utc::now();
    let id = Uuid::new_v4();
    let policy = waf_policy::ActiveModel {
        id: Set(id),
        name: Set(name),
        description: Set(payload.description),
        enabled: Set(payload.enabled.unwrap_or(true)),
        revision: Set(1),
        created_at: Set(now),
        updated_at: Set(now),
    }
    .insert(&state.db)
    .await?;

    // Store layers in a deterministic order so timestamps never race.
    let mut kinds: Vec<&String> = payload.layers.keys().collect();
    kinds.sort();
    for kind in kinds {
        let config = payload.layers.get(kind).expect("key from keys()");
        insert_layer(&state, id, kind, config).await?;
    }
    policy::record_version(
        &state.db,
        id,
        Some(&current.email),
        waf_policy_version::source::API,
    )
    .await?;

    tracing::info!(policy_id = %id, name = %policy.name, "waf policy created");
    respond_with_detail(&state, &policy).await
}

/// `GET /api/v1/policies/{id}` - one policy with layers and sites.
async fn get_policy(
    State(state): State<AppState>,
    _current: AuthUser,
    Path(id): Path<String>,
) -> Result<Json<PolicyDetail>, ApiError> {
    let id = parse_uuid(&id, "policy id")?;
    let policy = load_policy(&state, id).await?;
    respond_with_detail(&state, &policy).await
}

/// `PUT /api/v1/policies/{id}` - renames/re-toggles a policy.
async fn update_policy(
    State(state): State<AppState>,
    current: AuthUser,
    Path(id): Path<String>,
    Json(payload): Json<UpdatePolicyRequest>,
) -> Result<Json<PolicyDetail>, ApiError> {
    current.require_admin().map_err(ApiError::from)?;
    let id = parse_uuid(&id, "policy id")?;
    let policy = load_policy(&state, id).await?;

    if let Some(expected) = payload.expected_revision {
        if expected != policy.revision {
            return Err(ApiError::Conflict(format!(
                "policy revision changed (expected {expected}, current {})",
                policy.revision
            )));
        }
    }

    let mut active: waf_policy::ActiveModel = policy.clone().into();
    if let Some(name) = payload.name {
        let name = validate_name(&name)?;
        if name != policy.name {
            let clash = waf_policy::Entity::find()
                .filter(waf_policy::Column::Name.eq(name.clone()))
                .filter(waf_policy::Column::Id.ne(policy.id))
                .one(&state.db)
                .await?;
            if clash.is_some() {
                return Err(ApiError::Conflict(format!(
                    "a policy named '{name}' already exists"
                )));
            }
            active.name = Set(name);
        }
    }
    if let Some(description) = payload.description {
        active.description = Set(description);
    }
    if let Some(enabled) = payload.enabled {
        active.enabled = Set(enabled);
    }
    active.revision = Set(policy.revision + 1);
    active.updated_at = Set(Utc::now());
    let updated = active.update(&state.db).await?;
    policy::record_version(
        &state.db,
        id,
        Some(&current.email),
        waf_policy_version::source::API,
    )
    .await?;

    tracing::info!(policy_id = %id, "waf policy updated");
    resync_assigned_sites(&state, id, &current.email).await?;
    respond_with_detail(&state, &updated).await
}

/// `DELETE /api/v1/policies/{id}` - removes the policy and its assignments.
async fn delete_policy(
    State(state): State<AppState>,
    current: AuthUser,
    Path(id): Path<String>,
) -> Result<StatusCode, ApiError> {
    current.require_admin().map_err(ApiError::from)?;
    let id = parse_uuid(&id, "policy id")?;
    let policy = load_policy(&state, id).await?;

    // Collect the affected sites before the cascade removes the rows.
    let assignments = site_waf_policy::Entity::find()
        .filter(site_waf_policy::Column::PolicyId.eq(id))
        .all(&state.db)
        .await?;

    waf_policy::Entity::delete_by_id(policy.id).exec(&state.db).await?;
    tracing::info!(policy_id = %id, name = %policy.name, "waf policy deleted");

    for assignment in assignments {
        touch_site(&state, assignment.site_id).await?;
        notify_config_changed(&state, assignment.site_id, Some(&current.email))
            .await;
    }
    Ok(StatusCode::NO_CONTENT)
}

/* ── Layers ────────────────────────────────────────────────────────────── */

/// `PUT /api/v1/policies/{id}/layers/{kind}` - replaces one layer.
async fn put_layer(
    State(state): State<AppState>,
    current: AuthUser,
    Path((id, kind)): Path<(String, String)>,
    Json(payload): Json<LayerRequest>,
) -> Result<Json<LayerView>, ApiError> {
    current.require_admin().map_err(ApiError::from)?;
    let id = parse_uuid(&id, "policy id")?;
    let policy = load_policy(&state, id).await?;
    validate_layer_payload(&kind, &payload.config)?;
    if let Some(expected) = payload.expected_revision {
        if expected != policy.revision {
            return Err(ApiError::Conflict(format!(
                "policy revision changed (expected {expected}, current {})",
                policy.revision
            )));
        }
    }

    let row = insert_layer(&state, id, &kind, &payload.config).await?;
    bump_revision(&state, &policy).await?;
    policy::record_version(
        &state.db,
        id,
        Some(&current.email),
        waf_policy_version::source::API,
    )
    .await?;
    tracing::info!(policy_id = %id, kind = %kind, "policy layer stored");
    resync_assigned_sites(&state, id, &current.email).await?;

    Ok(Json(LayerView {
        kind: row.kind,
        config: row.config,
        updated_at: row.updated_at,
    }))
}

/// `DELETE /api/v1/policies/{id}/layers/{kind}` - removes one layer.
async fn delete_layer(
    State(state): State<AppState>,
    current: AuthUser,
    Path((id, kind)): Path<(String, String)>,
) -> Result<StatusCode, ApiError> {
    current.require_admin().map_err(ApiError::from)?;
    let id = parse_uuid(&id, "policy id")?;
    let policy = load_policy(&state, id).await?;
    if !policy::is_layer_kind(&kind) {
        return Err(ApiError::bad_request(format!(
            "unknown layer kind '{kind}' (expected one of: {})",
            LAYER_KINDS.join(", ")
        )));
    }

    let deleted = waf_policy_layer::Entity::delete_many()
        .filter(waf_policy_layer::Column::PolicyId.eq(id))
        .filter(waf_policy_layer::Column::Kind.eq(kind.clone()))
        .exec(&state.db)
        .await?
        .rows_affected;
    if deleted > 0 {
        bump_revision(&state, &policy).await?;
        policy::record_version(
            &state.db,
            id,
            Some(&current.email),
            waf_policy_version::source::API,
        )
        .await?;
        tracing::info!(policy_id = %id, kind = %kind, "policy layer removed");
        resync_assigned_sites(&state, id, &current.email).await?;
    }
    Ok(StatusCode::NO_CONTENT)
}

/// Inserts or replaces one layer row and returns the stored row.
async fn insert_layer(
    state: &AppState,
    policy_id: Uuid,
    kind: &str,
    config: &Value,
) -> Result<waf_policy_layer::Model, ApiError> {
    let existing = waf_policy_layer::Entity::find()
        .filter(waf_policy_layer::Column::PolicyId.eq(policy_id))
        .filter(waf_policy_layer::Column::Kind.eq(kind.to_string()))
        .one(&state.db)
        .await?;
    let now = Utc::now();
    match existing {
        Some(row) => {
            let mut active: waf_policy_layer::ActiveModel = row.into();
            active.config = Set(config.clone());
            active.updated_at = Set(now);
            Ok(active.update(&state.db).await?)
        }
        None => Ok(waf_policy_layer::ActiveModel {
            id: Set(Uuid::new_v4()),
            policy_id: Set(policy_id),
            kind: Set(kind.to_string()),
            config: Set(config.clone()),
            updated_at: Set(now),
        }
        .insert(&state.db)
        .await?),
    }
}

/* ── Version history ───────────────────────────────────────────────────── */

fn version_view(row: waf_policy_version::Model) -> VersionView {
    VersionView {
        id: row.id,
        revision: row.revision,
        config_hash: row.config_hash,
        source: row.source,
        actor: row.actor,
        summary: row.summary,
        created_at: row.created_at,
    }
}

/// `GET /api/v1/policies/{id}/versions` - the policy's version history.
async fn list_versions(
    State(state): State<AppState>,
    _current: AuthUser,
    Path(id): Path<String>,
) -> Result<Json<Vec<VersionView>>, ApiError> {
    let id = parse_uuid(&id, "policy id")?;
    load_policy(&state, id).await?;
    let rows = waf_policy_version::Entity::find()
        .filter(waf_policy_version::Column::PolicyId.eq(id))
        .order_by_desc(waf_policy_version::Column::Id)
        .all(&state.db)
        .await?;
    Ok(Json(rows.into_iter().map(version_view).collect()))
}

/// `GET /api/v1/policies/{id}/versions/{version_id}` - one version with its
/// snapshot.
async fn get_version(
    State(state): State<AppState>,
    _current: AuthUser,
    Path((id, version_id)): Path<(String, i64)>,
) -> Result<Json<VersionDetail>, ApiError> {
    let id = parse_uuid(&id, "policy id")?;
    load_policy(&state, id).await?;
    let row = waf_policy_version::Entity::find_by_id(version_id)
        .filter(waf_policy_version::Column::PolicyId.eq(id))
        .one(&state.db)
        .await?
        .ok_or_else(|| ApiError::not_found("policy version not found"))?;
    Ok(Json(VersionDetail {
        version: version_view(row.clone()),
        snapshot: row.snapshot,
    }))
}

/// `GET /api/v1/policies/{id}/versions/diff?from=&to=`
async fn diff_versions(
    State(state): State<AppState>,
    _current: AuthUser,
    Path(id): Path<String>,
    Query(query): Query<DiffQuery>,
) -> Result<Json<VersionDiffView>, ApiError> {
    let id = parse_uuid(&id, "policy id")?;
    load_policy(&state, id).await?;
    let from = waf_policy_version::Entity::find_by_id(query.from)
        .filter(waf_policy_version::Column::PolicyId.eq(id))
        .one(&state.db)
        .await?
        .ok_or_else(|| ApiError::not_found("policy version not found"))?;
    let to = waf_policy_version::Entity::find_by_id(query.to)
        .filter(waf_policy_version::Column::PolicyId.eq(id))
        .one(&state.db)
        .await?
        .ok_or_else(|| ApiError::not_found("policy version not found"))?;
    let diff = policy::version_diff(&from.snapshot, &to.snapshot);
    Ok(Json(VersionDiffView {
        from: from.id,
        to: to.id,
        fields: diff.fields,
        layers: diff.layers,
    }))
}

/// `POST /api/v1/policies/{id}/rollback` - restores a version's content as
/// a new revision and pushes the change to assigned sites.
async fn rollback_policy(
    State(state): State<AppState>,
    current: AuthUser,
    Path(id): Path<String>,
    Json(payload): Json<RollbackRequest>,
) -> Result<Json<PolicyDetail>, ApiError> {
    current.require_admin().map_err(ApiError::from)?;
    let id = parse_uuid(&id, "policy id")?;
    let policy = load_policy(&state, id).await?;
    if let Some(expected) = payload.expected_revision {
        if expected != policy.revision {
            return Err(ApiError::Conflict(format!(
                "policy revision changed (expected {expected}, current {})",
                policy.revision
            )));
        }
    }
    let version = waf_policy_version::Entity::find_by_id(payload.version_id)
        .filter(waf_policy_version::Column::PolicyId.eq(id))
        .one(&state.db)
        .await?
        .ok_or_else(|| ApiError::not_found("policy version not found"))?;

    let updated =
        policy::restore_version(&state.db, &policy, &version.snapshot).await?;
    policy::record_version(
        &state.db,
        id,
        Some(&current.email),
        waf_policy_version::source::ROLLBACK,
    )
    .await?;
    tracing::info!(
        policy_id = %id,
        version = version.id,
        revision = updated.revision,
        "policy rolled back"
    );
    resync_assigned_sites(&state, id, &current.email).await?;
    respond_with_detail(&state, &updated).await
}

/* ── Assignment + overlay ──────────────────────────────────────────────── */

/// `GET /api/v1/sites/{site_id}/policy` - the site's assignment.
async fn get_site_policy(
    State(state): State<AppState>,
    current: AuthUser,
    Path(site_id): Path<String>,
) -> Result<Json<SitePolicyView>, ApiError> {
    let id = parse_uuid(&site_id, "site id")?;
    load_site_read(&state.db, id, &current).await?;

    let assignment =
        site_waf_policy::Entity::find_by_id(id).one(&state.db).await?;
    let mut policy = None;
    if let Some(assignment) = &assignment {
        if let Some(row) = waf_policy::Entity::find_by_id(assignment.policy_id)
            .one(&state.db)
            .await?
        {
            policy = Some(policy_ref(&row));
        }
    }
    let override_row = site_waf_policy_override::Entity::find_by_id(id)
        .one(&state.db)
        .await?;
    let override_kinds = override_row
        .as_ref()
        .and_then(|row| row.config.as_object())
        .map(|map| {
            LAYER_KINDS
                .iter()
                .filter(|kind| map.contains_key(**kind))
                .map(|kind| kind.to_string())
                .collect()
        })
        .unwrap_or_default();

    Ok(Json(SitePolicyView {
        site_id: id,
        policy,
        overridden: override_row.is_some(),
        override_kinds,
    }))
}

/// `PUT /api/v1/sites/{site_id}/policy` - assigns or clears the policy.
async fn set_site_policy(
    State(state): State<AppState>,
    current: AuthUser,
    Path(site_id): Path<String>,
    Json(payload): Json<SetSitePolicyRequest>,
) -> Result<Json<SitePolicyView>, ApiError> {
    let id = parse_uuid(&site_id, "site id")?;
    load_site_write(&state.db, id, &current).await?;

    match payload.policy_id {
        Some(policy_id) => {
            let policy = load_policy(&state, policy_id).await?;
            if !policy.enabled {
                return Err(ApiError::bad_request(
                    "policy is disabled; enable it before assigning",
                ));
            }
            let existing = site_waf_policy::Entity::find_by_id(id)
                .one(&state.db)
                .await?;
            let now = Utc::now();
            match existing {
                Some(row) => {
                    let mut active: site_waf_policy::ActiveModel = row.into();
                    active.policy_id = Set(policy_id);
                    active.updated_at = Set(now);
                    active.update(&state.db).await?;
                }
                None => {
                    site_waf_policy::ActiveModel {
                        site_id: Set(id),
                        policy_id: Set(policy_id),
                        updated_at: Set(now),
                    }
                    .insert(&state.db)
                    .await?;
                }
            }
            tracing::info!(site_id = %id, policy_id = %policy_id, "site policy assigned");
        }
        None => {
            site_waf_policy::Entity::delete_by_id(id).exec(&state.db).await?;
            tracing::info!(site_id = %id, "site policy cleared");
        }
    }

    touch_site(&state, id).await?;
    notify_config_changed(&state, id, Some(&current.email)).await;
    get_site_policy(State(state), current, Path(id.to_string())).await
}

/// `GET /api/v1/sites/{site_id}/policy-override` - the overlay patch.
async fn get_site_override(
    State(state): State<AppState>,
    current: AuthUser,
    Path(site_id): Path<String>,
) -> Result<Json<SiteOverrideView>, ApiError> {
    let id = parse_uuid(&site_id, "site id")?;
    load_site_read(&state.db, id, &current).await?;
    let row = site_waf_policy_override::Entity::find_by_id(id)
        .one(&state.db)
        .await?;
    Ok(Json(SiteOverrideView {
        site_id: id,
        config: row.map(|row| row.config).unwrap_or_else(|| serde_json::json!({})),
    }))
}

/// `PUT /api/v1/sites/{site_id}/policy-override` - replaces the overlay.
async fn put_site_override(
    State(state): State<AppState>,
    current: AuthUser,
    Path(site_id): Path<String>,
    Json(payload): Json<SiteOverrideRequest>,
) -> Result<Json<SiteOverrideView>, ApiError> {
    let id = parse_uuid(&site_id, "site id")?;
    load_site_write(&state.db, id, &current).await?;

    let Some(map) = payload.config.as_object() else {
        return Err(ApiError::bad_request(
            "override config must be a JSON object keyed by layer kind",
        ));
    };
    for (kind, config) in map {
        validate_layer_payload(kind, config)?;
    }

    let existing = site_waf_policy_override::Entity::find_by_id(id)
        .one(&state.db)
        .await?;
    let now = Utc::now();
    let config = payload.config.clone();
    match existing {
        Some(row) => {
            let mut active: site_waf_policy_override::ActiveModel = row.into();
            active.config = Set(config.clone());
            active.updated_at = Set(now);
            active.update(&state.db).await?;
        }
        None => {
            site_waf_policy_override::ActiveModel {
                site_id: Set(id),
                config: Set(config.clone()),
                updated_at: Set(now),
            }
            .insert(&state.db)
            .await?;
        }
    }

    tracing::info!(site_id = %id, "site policy override stored");
    touch_site(&state, id).await?;
    notify_config_changed(&state, id, Some(&current.email)).await;
    Ok(Json(SiteOverrideView {
        site_id: id,
        config,
    }))
}

/// `DELETE /api/v1/sites/{site_id}/policy-override` - clears the overlay.
async fn delete_site_override(
    State(state): State<AppState>,
    current: AuthUser,
    Path(site_id): Path<String>,
) -> Result<StatusCode, ApiError> {
    let id = parse_uuid(&site_id, "site id")?;
    load_site_write(&state.db, id, &current).await?;

    let deleted = site_waf_policy_override::Entity::delete_by_id(id)
        .exec(&state.db)
        .await?
        .rows_affected;
    if deleted > 0 {
        tracing::info!(site_id = %id, "site policy override cleared");
        touch_site(&state, id).await?;
        notify_config_changed(&state, id, Some(&current.email)).await;
    }
    Ok(StatusCode::NO_CONTENT)
}

/* ── Effective configuration ───────────────────────────────────────────── */

/// `GET /api/v1/sites/{site_id}/effective-config` - what the next bundle
/// will carry, with the policy layers applied over the site's own row.
async fn get_effective_config(
    State(state): State<AppState>,
    current: AuthUser,
    Path(site_id): Path<String>,
) -> Result<Json<EffectiveConfigView>, ApiError> {
    let id = parse_uuid(&site_id, "site id")?;
    load_site_read(&state.db, id, &current).await?;

    let resolved = policy::resolve(&state.db, id).await?;
    let settings = waf_settings::Entity::find()
        .filter(waf_settings::Column::SiteId.eq(id))
        .one(&state.db)
        .await?;
    let effective = resolved.effective_engine(settings.as_ref());
    let plan = policy::rule_plan(&effective);

    let policy_ref = match (resolved.policy_id, &resolved.policy_name) {
        (Some(policy_id), Some(name)) => Some(PolicyRef {
            id: policy_id,
            name: name.clone(),
            revision: resolved.revision,
            enabled: true,
        }),
        _ => None,
    };

    Ok(Json(EffectiveConfigView {
        site_id: id,
        source: if policy_ref.is_some() { "policy" } else { "site" },
        overridden: resolved.overridden(),
        override_kinds: resolved.override_kinds.clone(),
        policy: policy_ref,
        engine: Value::Object(resolved.engine.clone()),
        crs: Value::Object(resolved.crs.clone()),
        rules: resolved.rules.clone(),
        overrides: resolved.overrides.clone(),
        effective,
        plan,
    }))
}

/* ── Apply status ──────────────────────────────────────────────────────── */

/// Published vs applied state for one site.
#[derive(Debug, Serialize)]
pub struct ApplyStatusView {
    pub site_id: Uuid,
    pub published: PublishedState,
    pub policy: Option<PolicyRef>,
    pub agents: Vec<AgentApplyState>,
}

/// The configuration the control plane would serve right now.
#[derive(Debug, Serialize)]
pub struct PublishedState {
    pub config_hash: String,
    pub policy_revision: i32,
    /// Latest recorded configuration version for the site, when any.
    pub version_id: Option<i64>,
    pub recorded_at: Option<DateTime<Utc>>,
}

/// One agent's applied state for the site.
#[derive(Debug, Serialize)]
pub struct AgentApplyState {
    pub id: Uuid,
    pub hostname: String,
    pub status: String,
    pub applied_config_hash: Option<String>,
    pub applied_policy_revision: Option<i32>,
    pub last_heartbeat: Option<DateTime<Utc>>,
    pub last_config_sync_at: Option<DateTime<Utc>>,
    /// `applied` (hash + revision match), `pending` (agent is fresh but has
    /// not caught up) or `unknown` (no fresh evidence).
    pub state: &'static str,
}

/// `GET /api/v1/sites/{site_id}/apply-status` - published != applied stays
/// visible: a node that never reported is `unknown`, never assumed applied.
async fn get_apply_status(
    State(state): State<AppState>,
    current: AuthUser,
    Path(site_id): Path<String>,
) -> Result<Json<ApplyStatusView>, ApiError> {
    let id = parse_uuid(&site_id, "site id")?;
    let site_row = load_site_read(&state.db, id, &current).await?;

    let bundle =
        crate::grpc::config::build_rule_bundle(&state.db, &site_row).await?;
    let resolved = policy::resolve(&state.db, id).await?;
    let version = config_version::Entity::find()
        .filter(config_version::Column::SiteId.eq(id))
        .order_by_desc(config_version::Column::Id)
        .one(&state.db)
        .await?;

    let policy_ref = match (resolved.policy_id, &resolved.policy_name) {
        (Some(policy_id), Some(name)) => Some(PolicyRef {
            id: policy_id,
            name: name.clone(),
            revision: resolved.revision,
            enabled: true,
        }),
        _ => None,
    };

    // Agents serving this site: the ones bound to it, plus unbound agents of
    // the site owner's keys (an unbound agent serves every site of its
    // owner).
    let mut rows = agent::Entity::find()
        .filter(agent::Column::SiteId.eq(id))
        .all(&state.db)
        .await?;
    if current.is_admin() || current.id == site_row.user_id {
        let keys: Vec<Uuid> = api_key::Entity::find()
            .filter(api_key::Column::UserId.eq(site_row.user_id))
            .all(&state.db)
            .await?
            .into_iter()
            .map(|key| key.id)
            .collect();
        if !keys.is_empty() {
            rows.extend(
                agent::Entity::find()
                    .filter(agent::Column::SiteId.is_null())
                    .filter(agent::Column::ApiKeyId.is_in(keys))
                    .all(&state.db)
                    .await?,
            );
        }
    }

    let now = Utc::now();
    let agents = rows
        .into_iter()
        .map(|row| {
            let hash_matches = row
                .config_hash
                .as_deref()
                .is_some_and(|hash| hash == bundle.config_hash);
            let revision_matches =
                row.policy_revision.unwrap_or(0) == bundle.policy_revision;
            let fresh = row
                .last_heartbeat
                .is_some_and(|ts| (now - ts).num_seconds() < 90);
            let state = if hash_matches && revision_matches {
                "applied"
            } else if fresh {
                "pending"
            } else {
                "unknown"
            };
            AgentApplyState {
                id: row.id,
                hostname: row.hostname,
                status: row.status,
                applied_config_hash: row.config_hash,
                applied_policy_revision: row.policy_revision,
                last_heartbeat: row.last_heartbeat,
                last_config_sync_at: row.last_config_sync_at,
                state,
            }
        })
        .collect();

    Ok(Json(ApplyStatusView {
        site_id: id,
        published: PublishedState {
            config_hash: bundle.config_hash,
            policy_revision: bundle.policy_revision,
            version_id: version.as_ref().map(|row| row.id),
            recorded_at: version.map(|row| row.created_at),
        },
        policy: policy_ref,
        agents,
    }))
}

/* ── Preview ───────────────────────────────────────────────────────────── */

#[derive(Debug, Deserialize)]
pub struct PreviewRequest {
    /// Base policy whose stored layers seed the preview.
    #[serde(default)]
    pub policy_id: Option<Uuid>,
    /// When set, the site's overlay applies and its own settings feed the
    /// fallback knobs.
    #[serde(default)]
    pub site_id: Option<Uuid>,
    /// Draft layers keyed by kind; they replace the base layer of the same
    /// kind for the preview only.
    #[serde(default)]
    pub layers: HashMap<String, Value>,
}

#[derive(Debug, Serialize)]
pub struct PreviewView {
    pub engine: Value,
    pub crs: Value,
    pub rules: Vec<policy::PolicyRule>,
    pub overrides: Vec<policy::RuleOverrideEntry>,
    pub effective: policy::EffectiveEngine,
    pub plan: Vec<policy::RulePlan>,
}

/// `POST /api/v1/policies/preview` - compiles a draft without saving it.
async fn preview_policy(
    State(state): State<AppState>,
    current: AuthUser,
    Json(payload): Json<PreviewRequest>,
) -> Result<Json<PreviewView>, ApiError> {
    let mut layers: std::collections::BTreeMap<String, Value> =
        std::collections::BTreeMap::new();
    let mut policy_name = None;
    let mut revision = 0;
    if let Some(policy_id) = payload.policy_id {
        let policy = load_policy(&state, policy_id).await?;
        policy_name = Some(policy.name.clone());
        revision = policy.revision;
        for row in load_layers(&state, policy_id).await? {
            layers.insert(row.kind, row.config);
        }
    }
    for (kind, config) in &payload.layers {
        validate_layer_payload(kind, config)?;
        layers.insert(kind.clone(), config.clone());
    }
    let mut overlay = None;
    let mut settings = None;
    if let Some(site_id) = payload.site_id {
        load_site_read(&state.db, site_id, &current).await?;
        overlay = site_waf_policy_override::Entity::find_by_id(site_id)
            .one(&state.db)
            .await?
            .map(|row| row.config);
        settings = waf_settings::Entity::find()
            .filter(waf_settings::Column::SiteId.eq(site_id))
            .one(&state.db)
            .await?;
    }

    let resolved = policy::resolve_maps(
        payload.policy_id,
        policy_name,
        revision,
        &layers,
        overlay.as_ref(),
    );
    let effective = resolved.effective_engine(settings.as_ref());
    let plan = policy::rule_plan(&effective);
    Ok(Json(PreviewView {
        engine: Value::Object(resolved.engine.clone()),
        crs: Value::Object(resolved.crs.clone()),
        rules: resolved.rules.clone(),
        overrides: resolved.overrides.clone(),
        effective,
        plan,
    }))
}

async fn respond_with_detail(
    state: &AppState,
    policy: &waf_policy::Model,
) -> Result<Json<PolicyDetail>, ApiError> {
    let layers = load_layers(state, policy.id).await?;
    let sites = assigned_sites(state, policy.id).await?;
    let layer_kinds = layer_kinds_of(&layers);
    let site_count = sites.len() as u64;
    Ok(Json(PolicyDetail {
        policy: PolicySummary {
            id: policy.id,
            name: policy.name.clone(),
            description: policy.description.clone(),
            enabled: policy.enabled,
            revision: policy.revision,
            layer_kinds,
            site_count,
            created_at: policy.created_at,
            updated_at: policy.updated_at,
        },
        layers: layers
            .into_iter()
            .map(|row| LayerView {
                kind: row.kind,
                config: row.config,
                updated_at: row.updated_at,
            })
            .collect(),
        sites,
    }))
}
