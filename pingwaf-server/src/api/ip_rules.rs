//! IP access rules management: allow, block, challenge specific IPs/CIDRs.

use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use axum::Json;
use axum::Router;
use sea_orm::{
    ActiveModelTrait, ColumnTrait, DatabaseConnection, EntityTrait,
    PaginatorTrait, QueryFilter, QueryOrder, Set,
};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::api::common::{
    load_site_read, load_site_write, non_empty, parse_uuid, Page, Pagination,
};
use crate::api::error::ApiError;
use crate::api::sites::touch_site;
use crate::api::state::AppState;
use crate::auth::AuthUser;
use crate::grpc::notify_config_changed;
use crate::models::{ip_access_rules, ip_groups};

/// Valid IP access actions.
pub mod ip_action {
    pub const BLOCK: &str = "block";
    pub const CHALLENGE: &str = "challenge";
    pub const JS_CHALLENGE: &str = "js_challenge";
    pub const ALLOW: &str = "allow";
    /// Ask for basic authentication; the credentials come from the site's
    /// basic auth settings.
    pub const BASIC_AUTH: &str = "basic_auth";

    pub fn is_valid(action: &str) -> bool {
        matches!(
            action,
            BLOCK | CHALLENGE | JS_CHALLENGE | ALLOW | BASIC_AUTH
        )
    }

    /// Maps to the proto `IpAccessAction` enum.
    pub fn to_proto(action: &str) -> i32 {
        match action {
            BLOCK => 0,
            CHALLENGE => 1,
            JS_CHALLENGE => 2,
            ALLOW => 3,
            BASIC_AUTH => 4,
            _ => 0,
        }
    }
}

fn default_action() -> String {
    ip_action::BLOCK.to_string()
}

fn default_true() -> bool {
    true
}

#[derive(Debug, Deserialize)]
pub struct ListQuery {
    #[serde(flatten)]
    pub pagination: Pagination,
    pub enabled: Option<bool>,
}

#[derive(Debug, Deserialize)]
pub struct CreateRequest {
    pub name: String,
    /// Explicit ranges. Required unless `group_id` references an IP group;
    /// the two are mutually exclusive.
    #[serde(default)]
    pub ip_ranges: Vec<String>,
    /// When set, the rule matches the referenced IP group's ranges (kept in
    /// sync with the group) instead of its own `ip_ranges`.
    #[serde(default)]
    pub group_id: Option<String>,
    #[serde(default = "default_action")]
    pub action: String,
    #[serde(default)]
    pub note: Option<String>,
    #[serde(default = "default_true")]
    pub enabled: bool,
    #[serde(default)]
    pub priority: i32,
}

#[derive(Debug, Deserialize, Default)]
pub struct UpdateRequest {
    #[serde(default)]
    pub name: Option<String>,
    /// Sending ranges switches the rule to manual mode (clearing any group
    /// reference); sending `group_id` switches it to group mode.
    #[serde(default)]
    pub ip_ranges: Option<Vec<String>>,
    #[serde(default)]
    pub group_id: Option<String>,
    #[serde(default)]
    pub action: Option<String>,
    #[serde(default)]
    pub note: Option<String>,
    #[serde(default)]
    pub enabled: Option<bool>,
    #[serde(default)]
    pub priority: Option<i32>,
}

/// Response body: the rule row plus the name of the referenced group (when
/// the rule targets an IP group).
#[derive(Debug, Serialize)]
pub struct IpRuleResponse {
    #[serde(flatten)]
    pub rule: ip_access_rules::Model,
    pub group_name: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct BulkImportRequest {
    pub ip_ranges: Vec<String>,
    #[serde(default = "default_action")]
    pub action: String,
    #[serde(default)]
    pub note: Option<String>,
    #[serde(default = "default_true")]
    pub enabled: bool,
}

/// Routes contributed to `/api/v1`.
pub fn routes() -> Router<AppState> {
    Router::new()
        .route("/sites/{site_id}/ip-rules", get(list).post(create))
        .route(
            "/sites/{site_id}/ip-rules/{rule_id}",
            axum::routing::put(update).delete(remove),
        )
        .route(
            "/sites/{site_id}/ip-rules/bulk",
            axum::routing::post(bulk_import),
        )
}

/// Validates IP/CIDR ranges (basic format check).
fn validate_ip_ranges(ranges: &[String]) -> Result<Vec<String>, ApiError> {
    if ranges.is_empty() {
        return Err(ApiError::BadRequest(
            "at least one IP range is required".to_string(),
        ));
    }
    if ranges.len() > 1000 {
        return Err(ApiError::BadRequest(
            "a rule may contain at most 1000 IP ranges".to_string(),
        ));
    }
    let mut out = Vec::with_capacity(ranges.len());
    for range in ranges {
        let trimmed = range.trim();
        if trimmed.is_empty() {
            continue;
        }
        // Basic validation: must look like an IP or CIDR
        let base = trimmed.split('/').next().unwrap_or(trimmed);
        if base.parse::<std::net::IpAddr>().is_err() {
            return Err(ApiError::BadRequest(format!(
                "invalid IP address or CIDR: '{trimmed}'"
            )));
        }
        if !out.contains(&trimmed.to_string()) {
            out.push(trimmed.to_string());
        }
    }
    if out.is_empty() {
        return Err(ApiError::BadRequest(
            "at least one valid IP range is required".to_string(),
        ));
    }
    Ok(out)
}

fn validate(name: &str, action: &str) -> Result<(), ApiError> {
    if name.trim().is_empty() || name.len() > 200 {
        return Err(ApiError::BadRequest(
            "name must be 1-200 characters".to_string(),
        ));
    }
    if !ip_action::is_valid(action) {
        return Err(ApiError::BadRequest(format!("unknown action '{action}'")));
    }
    Ok(())
}

/// True when `ranges` carries at least one non-blank entry.
fn has_ranges(ranges: &[String]) -> bool {
    ranges.iter().any(|r| !r.trim().is_empty())
}

/// True when a request tries to target both an IP group and its own ranges:
/// a rule matches exactly one of the two, never both.
fn mode_conflict(group_id: &Option<String>, ip_ranges: &[String]) -> bool {
    group_id
        .as_deref()
        .map(str::trim)
        .is_some_and(|v| !v.is_empty())
        && has_ranges(ip_ranges)
}

/// Resolves the create request's mode: a group reference or an explicit
/// range list — exactly one of the two. Returns the validated pair.
async fn resolve_create_mode(
    state: &AppState,
    group_id: &Option<String>,
    ip_ranges: &[String],
) -> Result<(Option<Uuid>, Vec<String>), ApiError> {
    if mode_conflict(group_id, ip_ranges) {
        return Err(ApiError::BadRequest(
            "set either group_id or ip_ranges, not both".to_string(),
        ));
    }
    let raw = group_id.as_deref().map(str::trim).filter(|v| !v.is_empty());
    match raw {
        Some(raw) => {
            let gid = parse_uuid(raw, "IP group id")?;
            ensure_group_exists(state, gid).await?;
            Ok((Some(gid), Vec::new()))
        },
        None => {
            let ranges = validate_ip_ranges(ip_ranges)?;
            Ok((None, ranges))
        },
    }
}

async fn ensure_group_exists(
    state: &AppState,
    group_id: Uuid,
) -> Result<(), ApiError> {
    ip_groups::Entity::find_by_id(group_id)
        .one(&state.db)
        .await?
        .map(|_| ())
        .ok_or_else(|| {
            ApiError::NotFound(format!("IP group {group_id} not found"))
        })
}

/// Group names for the rules of one page, keyed by group id.
async fn group_names(
    db: &DatabaseConnection,
    rules: &[ip_access_rules::Model],
) -> Result<std::collections::HashMap<Uuid, String>, sea_orm::DbErr> {
    let ids: Vec<Uuid> = rules.iter().filter_map(|r| r.group_id).collect();
    if ids.is_empty() {
        return Ok(std::collections::HashMap::new());
    }
    let rows = ip_groups::Entity::find()
        .filter(ip_groups::Column::Id.is_in(ids))
        .all(db)
        .await?;
    Ok(rows.into_iter().map(|g| (g.id, g.name)).collect())
}

fn to_response(
    rule: ip_access_rules::Model,
    names: &std::collections::HashMap<Uuid, String>,
) -> IpRuleResponse {
    let group_name = rule
        .group_id
        .as_ref()
        .and_then(|gid| names.get(gid))
        .cloned();
    IpRuleResponse { rule, group_name }
}

/// `GET /api/v1/sites/{site_id}/ip-rules`
async fn list(
    State(state): State<AppState>,
    current: AuthUser,
    Path(site_id): Path<String>,
    Query(query): Query<ListQuery>,
) -> Result<Json<Page<IpRuleResponse>>, ApiError> {
    let id = parse_uuid(&site_id, "site id")?;
    load_site_read(&state.db, id, &current).await?;
    let pagination = query.pagination.normalise();

    let mut condition =
        sea_orm::Condition::all().add(ip_access_rules::Column::SiteId.eq(id));
    if let Some(enabled) = query.enabled {
        condition = condition.add(ip_access_rules::Column::Enabled.eq(enabled));
    }

    let paginator = ip_access_rules::Entity::find()
        .filter(condition)
        .order_by_asc(ip_access_rules::Column::Priority)
        .order_by_asc(ip_access_rules::Column::Name)
        .paginate(&state.db, pagination.limit());

    let total = paginator.num_items().await?;
    let rows = paginator.fetch_page(pagination.index()).await?;
    let names = group_names(&state.db, &rows).await?;
    let items: Vec<IpRuleResponse> =
        rows.into_iter().map(|r| to_response(r, &names)).collect();
    Ok(Json(Page::new(items, total, pagination)))
}

/// `POST /api/v1/sites/{site_id}/ip-rules`
async fn create(
    State(state): State<AppState>,
    current: AuthUser,
    Path(site_id): Path<String>,
    Json(payload): Json<CreateRequest>,
) -> Result<Response, ApiError> {
    let id = parse_uuid(&site_id, "site id")?;
    load_site_write(&state.db, id, &current).await?;
    validate(&payload.name, &payload.action)?;
    let (group_id, ip_ranges) =
        resolve_create_mode(&state, &payload.group_id, &payload.ip_ranges)
            .await?;

    let timestamp = chrono::Utc::now();
    let model = ip_access_rules::ActiveModel {
        id: Set(Uuid::new_v4()),
        site_id: Set(id),
        name: Set(payload.name.trim().to_string()),
        ip_ranges: Set(ip_ranges),
        action: Set(payload.action),
        note: Set(non_empty(&payload.note)),
        enabled: Set(payload.enabled),
        priority: Set(payload.priority),
        group_id: Set(group_id),
        created_at: Set(timestamp),
        updated_at: Set(timestamp),
    }
    .insert(&state.db)
    .await?;

    tracing::info!(site_id = %id, rule_id = %model.id, "IP access rule created");
    touch_site(&state, id).await?;
    notify_config_changed(&state, id).await;

    let names = group_names(&state.db, std::slice::from_ref(&model)).await?;
    Ok((StatusCode::CREATED, Json(to_response(model, &names))).into_response())
}

/// `PUT /api/v1/sites/{site_id}/ip-rules/{rule_id}`
async fn update(
    State(state): State<AppState>,
    current: AuthUser,
    Path((site_id, rule_id)): Path<(String, String)>,
    Json(payload): Json<UpdateRequest>,
) -> Result<Json<IpRuleResponse>, ApiError> {
    let id = parse_uuid(&site_id, "site id")?;
    let target = parse_uuid(&rule_id, "IP rule id")?;
    load_site_write(&state.db, id, &current).await?;

    let row = find(&state, id, target).await?;
    let mut active: ip_access_rules::ActiveModel = row.into();

    if let Some(name) = non_empty(&payload.name) {
        if name.len() > 200 {
            return Err(ApiError::BadRequest(
                "name must be at most 200 characters".to_string(),
            ));
        }
        active.name = Set(name);
    }
    // A rule targets exactly one of a group or its own ranges: sending
    // `group_id` switches to group mode, sending `ip_ranges` switches to
    // manual mode (and clears the group reference).
    if mode_conflict(
        &payload.group_id,
        payload.ip_ranges.as_deref().unwrap_or_default(),
    ) {
        return Err(ApiError::BadRequest(
            "set either group_id or ip_ranges, not both".to_string(),
        ));
    }
    if let Some(raw) = payload
        .group_id
        .as_deref()
        .map(str::trim)
        .filter(|v| !v.is_empty())
    {
        let gid = parse_uuid(raw, "IP group id")?;
        ensure_group_exists(&state, gid).await?;
        active.group_id = Set(Some(gid));
        active.ip_ranges = Set(Vec::new());
    } else if let Some(ranges) = payload.ip_ranges {
        active.ip_ranges = Set(validate_ip_ranges(&ranges)?);
        active.group_id = Set(None);
    }
    if let Some(action) = non_empty(&payload.action) {
        if !ip_action::is_valid(&action) {
            return Err(ApiError::BadRequest(format!(
                "unknown action '{action}'"
            )));
        }
        active.action = Set(action);
    }
    if let Some(note) = payload.note {
        active.note = Set(non_empty(&Some(note)));
    }
    if let Some(enabled) = payload.enabled {
        active.enabled = Set(enabled);
    }
    if let Some(priority) = payload.priority {
        active.priority = Set(priority);
    }
    active.updated_at = Set(chrono::Utc::now());

    let updated = active.update(&state.db).await?;
    tracing::info!(site_id = %id, rule_id = %target, "IP access rule updated");
    touch_site(&state, id).await?;
    notify_config_changed(&state, id).await;

    let names = group_names(&state.db, std::slice::from_ref(&updated)).await?;
    Ok(Json(to_response(updated, &names)))
}

/// `DELETE /api/v1/sites/{site_id}/ip-rules/{rule_id}`
async fn remove(
    State(state): State<AppState>,
    current: AuthUser,
    Path((site_id, rule_id)): Path<(String, String)>,
) -> Result<Response, ApiError> {
    let id = parse_uuid(&site_id, "site id")?;
    let target = parse_uuid(&rule_id, "IP rule id")?;
    load_site_write(&state.db, id, &current).await?;
    find(&state, id, target).await?;

    ip_access_rules::Entity::delete_by_id(target)
        .exec(&state.db)
        .await?;

    tracing::info!(site_id = %id, rule_id = %target, "IP access rule deleted");
    touch_site(&state, id).await?;
    notify_config_changed(&state, id).await;

    Ok(StatusCode::NO_CONTENT.into_response())
}

/// `POST /api/v1/sites/{site_id}/ip-rules/bulk`
async fn bulk_import(
    State(state): State<AppState>,
    current: AuthUser,
    Path(site_id): Path<String>,
    Json(payload): Json<BulkImportRequest>,
) -> Result<Response, ApiError> {
    let id = parse_uuid(&site_id, "site id")?;
    load_site_write(&state.db, id, &current).await?;

    if !ip_action::is_valid(&payload.action) {
        return Err(ApiError::BadRequest(format!(
            "unknown action '{}'",
            payload.action
        )));
    }
    let ip_ranges = validate_ip_ranges(&payload.ip_ranges)?;

    let timestamp = chrono::Utc::now();
    let model = ip_access_rules::ActiveModel {
        id: Set(Uuid::new_v4()),
        site_id: Set(id),
        name: Set(format!("bulk-import-{}", timestamp.format("%Y%m%d%H%M%S"))),
        ip_ranges: Set(ip_ranges.clone()),
        action: Set(payload.action),
        note: Set(non_empty(&payload.note)),
        enabled: Set(payload.enabled),
        priority: Set(0),
        group_id: Set(None),
        created_at: Set(timestamp),
        updated_at: Set(timestamp),
    }
    .insert(&state.db)
    .await?;

    tracing::info!(site_id = %id, rule_id = %model.id, count = ip_ranges.len(), "bulk IP import");
    touch_site(&state, id).await?;
    notify_config_changed(&state, id).await;

    Ok((
        StatusCode::CREATED,
        Json(serde_json::json!({
            "id": model.id,
            "imported": ip_ranges.len(),
        })),
    )
        .into_response())
}

async fn find(
    state: &AppState,
    site_id: Uuid,
    rule_id: Uuid,
) -> Result<ip_access_rules::Model, ApiError> {
    ip_access_rules::Entity::find_by_id(rule_id)
        .filter(ip_access_rules::Column::SiteId.eq(site_id))
        .one(&state.db)
        .await?
        .ok_or_else(|| {
            ApiError::NotFound(format!("IP access rule {rule_id} not found"))
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn group_and_ranges_are_mutually_exclusive() {
        let ranges = vec!["10.0.0.1".to_string()];
        assert!(mode_conflict(&Some("group".to_string()), &ranges));

        // A blank group id means "no group" and never conflicts.
        assert!(!mode_conflict(&Some("   ".to_string()), &ranges));
        assert!(!mode_conflict(&None, &ranges));

        // Blank ranges mean "no explicit ranges" and never conflict.
        assert!(!mode_conflict(
            &Some("group".to_string()),
            &["   ".to_string()]
        ));
        assert!(!mode_conflict(&Some("group".to_string()), &[]));
    }

    #[test]
    fn ranges_are_validated_trimmed_and_deduped() {
        assert!(validate_ip_ranges(&[]).is_err());
        assert!(validate_ip_ranges(&["not-an-ip".to_string()]).is_err());

        let out = validate_ip_ranges(&[
            "10.0.0.1".to_string(),
            " 10.0.0.1 ".to_string(),
            "10.0.0.0/24".to_string(),
        ])
        .unwrap();
        assert_eq!(
            out,
            vec!["10.0.0.1".to_string(), "10.0.0.0/24".to_string()]
        );
    }
}
