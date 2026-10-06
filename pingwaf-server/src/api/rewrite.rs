//! Rewrite rules management: request/response header and path rewrites.

use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use axum::Json;
use axum::Router;
use sea_orm::{
    ActiveModelTrait, ColumnTrait, EntityTrait, PaginatorTrait, QueryFilter,
    QueryOrder, Set,
};
use serde::Deserialize;
use uuid::Uuid;

use crate::api::common::{
    load_site_read, load_site_write, non_empty, parse_uuid, Page, Pagination,
};
use crate::api::error::ApiError;
use crate::api::sites::touch_site;
use crate::api::state::AppState;
use crate::auth::AuthUser;
use crate::grpc::notify_config_changed;
use crate::models::rewrite_rules;

/// Valid rewrite directions.
fn is_valid_direction(dir: &str) -> bool {
    matches!(dir, "request" | "response")
}

fn default_direction() -> String {
    "request".to_string()
}

fn default_true() -> bool {
    true
}

#[derive(Debug, Deserialize)]
pub struct ListQuery {
    #[serde(flatten)]
    pub pagination: Pagination,
}

#[derive(Debug, Deserialize)]
pub struct CreateRequest {
    pub name: String,
    #[serde(default = "default_direction")]
    pub direction: String,
    #[serde(default)]
    pub condition_expr: Option<String>,
    #[serde(default = "default_operations")]
    pub operations: serde_json::Value,
    #[serde(default)]
    pub priority: i32,
    #[serde(default = "default_true")]
    pub enabled: bool,
}

fn default_operations() -> serde_json::Value {
    serde_json::json!([])
}

#[derive(Debug, Deserialize, Default)]
pub struct UpdateRequest {
    #[serde(default)]
    pub name: Option<String>,
    #[serde(default)]
    pub direction: Option<String>,
    #[serde(default)]
    pub condition_expr: Option<String>,
    #[serde(default)]
    pub operations: Option<serde_json::Value>,
    #[serde(default)]
    pub priority: Option<i32>,
    #[serde(default)]
    pub enabled: Option<bool>,
}

/// Routes contributed to `/api/v1`.
pub fn routes() -> Router<AppState> {
    Router::new()
        .route("/sites/{site_id}/rewrite-rules", get(list).post(create))
        .route(
            "/sites/{site_id}/rewrite-rules/{rule_id}",
            axum::routing::put(update).delete(remove),
        )
}

/// `GET /api/v1/sites/{site_id}/rewrite-rules`
async fn list(
    State(state): State<AppState>,
    current: AuthUser,
    Path(site_id): Path<String>,
    Query(query): Query<ListQuery>,
) -> Result<Json<Page<rewrite_rules::Model>>, ApiError> {
    let id = parse_uuid(&site_id, "site id")?;
    load_site_read(&state.db, id, &current).await?;
    let pagination = query.pagination.normalise();

    let paginator = rewrite_rules::Entity::find()
        .filter(rewrite_rules::Column::SiteId.eq(id))
        .order_by_asc(rewrite_rules::Column::Priority)
        .order_by_asc(rewrite_rules::Column::Name)
        .paginate(&state.db, pagination.limit());

    let total = paginator.num_items().await?;
    let rows = paginator.fetch_page(pagination.index()).await?;
    Ok(Json(Page::new(rows, total, pagination)))
}

/// `POST /api/v1/sites/{site_id}/rewrite-rules`
async fn create(
    State(state): State<AppState>,
    current: AuthUser,
    Path(site_id): Path<String>,
    Json(payload): Json<CreateRequest>,
) -> Result<Response, ApiError> {
    let id = parse_uuid(&site_id, "site id")?;
    load_site_write(&state.db, id, &current).await?;

    if payload.name.trim().is_empty() || payload.name.len() > 200 {
        return Err(ApiError::BadRequest(
            "name must be 1-200 characters".to_string(),
        ));
    }
    if !is_valid_direction(&payload.direction) {
        return Err(ApiError::BadRequest(format!(
            "invalid direction '{}'; expected request or response",
            payload.direction
        )));
    }
    if !payload.operations.is_array() {
        return Err(ApiError::BadRequest(
            "operations must be a JSON array".to_string(),
        ));
    }

    let timestamp = chrono::Utc::now();
    let model = rewrite_rules::ActiveModel {
        id: Set(Uuid::new_v4()),
        site_id: Set(id),
        name: Set(payload.name.trim().to_string()),
        direction: Set(payload.direction),
        condition_expr: Set(non_empty(&payload.condition_expr)),
        operations: Set(payload.operations),
        priority: Set(payload.priority),
        enabled: Set(payload.enabled),
        created_at: Set(timestamp),
        updated_at: Set(timestamp),
    }
    .insert(&state.db)
    .await?;

    tracing::info!(site_id = %id, rule_id = %model.id, "rewrite rule created");
    touch_site(&state, id).await?;
    notify_config_changed(&state, id).await;

    Ok((StatusCode::CREATED, Json(model)).into_response())
}

/// `PUT /api/v1/sites/{site_id}/rewrite-rules/{rule_id}`
async fn update(
    State(state): State<AppState>,
    current: AuthUser,
    Path((site_id, rule_id)): Path<(String, String)>,
    Json(payload): Json<UpdateRequest>,
) -> Result<Json<rewrite_rules::Model>, ApiError> {
    let id = parse_uuid(&site_id, "site id")?;
    let target = parse_uuid(&rule_id, "rewrite rule id")?;
    load_site_write(&state.db, id, &current).await?;

    let row = find(&state, id, target).await?;
    let mut active: rewrite_rules::ActiveModel = row.into();

    if let Some(name) = non_empty(&payload.name) {
        if name.len() > 200 {
            return Err(ApiError::BadRequest(
                "name must be at most 200 characters".to_string(),
            ));
        }
        active.name = Set(name);
    }
    if let Some(direction) = non_empty(&payload.direction) {
        if !is_valid_direction(&direction) {
            return Err(ApiError::BadRequest(format!(
                "invalid direction '{direction}'"
            )));
        }
        active.direction = Set(direction);
    }
    if let Some(expr) = payload.condition_expr {
        active.condition_expr = Set(non_empty(&Some(expr)));
    }
    if let Some(ops) = payload.operations {
        if !ops.is_array() {
            return Err(ApiError::BadRequest(
                "operations must be a JSON array".to_string(),
            ));
        }
        active.operations = Set(ops);
    }
    if let Some(priority) = payload.priority {
        active.priority = Set(priority);
    }
    if let Some(enabled) = payload.enabled {
        active.enabled = Set(enabled);
    }
    active.updated_at = Set(chrono::Utc::now());

    let updated = active.update(&state.db).await?;
    tracing::info!(site_id = %id, rule_id = %target, "rewrite rule updated");
    touch_site(&state, id).await?;
    notify_config_changed(&state, id).await;

    Ok(Json(updated))
}

/// `DELETE /api/v1/sites/{site_id}/rewrite-rules/{rule_id}`
async fn remove(
    State(state): State<AppState>,
    current: AuthUser,
    Path((site_id, rule_id)): Path<(String, String)>,
) -> Result<Response, ApiError> {
    let id = parse_uuid(&site_id, "site id")?;
    let target = parse_uuid(&rule_id, "rewrite rule id")?;
    load_site_write(&state.db, id, &current).await?;
    find(&state, id, target).await?;

    rewrite_rules::Entity::delete_by_id(target)
        .exec(&state.db)
        .await?;

    tracing::info!(site_id = %id, rule_id = %target, "rewrite rule deleted");
    touch_site(&state, id).await?;
    notify_config_changed(&state, id).await;

    Ok(StatusCode::NO_CONTENT.into_response())
}

async fn find(
    state: &AppState,
    site_id: Uuid,
    rule_id: Uuid,
) -> Result<rewrite_rules::Model, ApiError> {
    rewrite_rules::Entity::find_by_id(rule_id)
        .filter(rewrite_rules::Column::SiteId.eq(site_id))
        .one(&state.db)
        .await?
        .ok_or_else(|| {
            ApiError::NotFound(format!("rewrite rule {rule_id} not found"))
        })
}
