//! WAF policy management: policy documents, their layers, site assignments
//! and per-site overrides.
//!
//! A policy is a named document shared by sites; each site either follows
//! one policy or keeps its own `waf_settings` / rules. `GET .../effective-config`
//! resolves the exact posture the next bundle will carry (policy layers with
//! the site overlay applied, then the site's own settings as the fallback),
//! which is what the dashboard preview and the tests assert against.

use std::collections::HashMap;

use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::routing::{get, put};
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
    site, site_waf_policy, site_waf_policy_override, waf_policy, waf_policy_layer,
    waf_settings,
};
use crate::policy::{self, LAYER_KINDS};

/// Routes contributed to `/api/v1`.
pub fn routes() -> Router<AppState> {
    Router::new()
        .route("/policies", get(list_policies).post(create_policy))
        .route(
            "/policies/{id}",
            get(get_policy).put(update_policy).delete(delete_policy),
        )
        .route(
            "/policies/{id}/layers/{kind}",
            put(put_layer).delete(delete_layer),
        )
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

    let row = insert_layer(&state, id, &kind, &payload.config).await?;
    bump_revision(&state, &policy).await?;
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
