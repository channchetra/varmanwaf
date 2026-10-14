//! IP list catalog and one-step imports - `/api/v1/ip-lists/*`.
//!
//! The catalog lists ready-to-import sources (ipverse country/crawler/ASN
//! lists, a VPN list) and an import creates an ordinary IP group
//! subscription, so the daily sync scheduler keeps it fresh and the existing
//! site-binding machinery applies it.

use axum::extract::{Query, State};
use axum::http::StatusCode;
use axum::routing::{get, post};
use axum::{Json, Router};
use sea_orm::{ActiveModelTrait, ColumnTrait, EntityTrait, QueryFilter, Set};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::api::ip_groups::{ip_group_action, subscription_kind};
use crate::api::state::AppState;
use crate::api::error::ApiError;
use crate::auth::AuthUser;
use crate::ip_lists;
use crate::models::ip_groups;

/// Routes contributed to `/api/v1`.
pub fn routes() -> Router<AppState> {
    Router::new()
        .route("/ip-lists/catalog", get(catalog))
        .route("/ip-lists/import", post(import))
}

#[derive(Debug, Deserialize)]
pub struct CatalogQuery {
    #[serde(default)]
    pub q: Option<String>,
    /// `country` / `bot` / `vpn` / `asn`; empty returns everything.
    #[serde(default)]
    pub category: Option<String>,
}

/// `GET /api/v1/ip-lists/catalog` - the curated sources.
async fn catalog(
    _current: AuthUser,
    Query(query): Query<CatalogQuery>,
) -> Json<ip_lists::Catalog> {
    Json(
        ip_lists::catalog(
            query.q.as_deref().unwrap_or(""),
            query.category.as_deref().unwrap_or(""),
        )
        .await,
    )
}

#[derive(Debug, Deserialize)]
pub struct ImportRequest {
    /// A catalog id (`country:kh`, `bot:Googlebot`, `vpn:strict`,
    /// `asn:15169`, `bot:crawlers`, `bot:monitoring`).
    #[serde(default)]
    pub catalog_id: Option<String>,
    /// Country granularity: `compact` (default) or `detailed`.
    #[serde(default)]
    pub variant: Option<String>,
    /// Custom source URL (alternative to `catalog_id`).
    #[serde(default)]
    pub url: Option<String>,
    /// JSON selector for a custom URL.
    #[serde(default)]
    pub selector: Option<String>,
    /// Display name override.
    #[serde(default)]
    pub name: Option<String>,
    /// Group action: `block` (default) or `allow`.
    #[serde(default)]
    pub action: Option<String>,
    /// Refresh interval in minutes; defaults to daily (1440).
    #[serde(default)]
    pub sync_interval_minutes: Option<i32>,
}

#[derive(Debug, Serialize)]
pub struct ImportView {
    pub group: ip_groups::Model,
    /// Whether the initial fetch succeeded (the group exists either way; a
    /// failed fetch is stored on the group's `last_sync_error`).
    pub synced: bool,
    pub error: Option<String>,
}

/// `POST /api/v1/ip-lists/import` - creates the group subscription and
/// fetches it once, so the console can show real prefixes immediately.
async fn import(
    State(state): State<AppState>,
    current: AuthUser,
    Json(payload): Json<ImportRequest>,
) -> Result<(StatusCode, Json<ImportView>), ApiError> {
    current.require_admin().map_err(ApiError::from)?;

    let catalog_id = payload
        .catalog_id
        .as_deref()
        .map(str::trim)
        .filter(|id| !id.is_empty());
    let custom_url = payload
        .url
        .as_deref()
        .map(str::trim)
        .filter(|url| !url.is_empty());
    if catalog_id.is_some() == custom_url.is_some() {
        return Err(ApiError::BadRequest(
            "provide exactly one of catalog_id or url".to_string(),
        ));
    }

    let plan = match catalog_id {
        Some(id) => {
            let variant = payload.variant.as_deref().unwrap_or("").trim();
            if !variant.is_empty() && variant != "compact" && variant != "detailed"
            {
                return Err(ApiError::BadRequest(
                    "variant must be 'compact' or 'detailed'".to_string(),
                ));
            }
            ip_lists::resolve_import(id, variant).map_err(ApiError::BadRequest)?
        },
        None => {
            let url = custom_url.expect("checked above");
            crate::subscription::validate_source_url(url)
                .map_err(ApiError::BadRequest)?;
            let name = payload
                .name
                .as_deref()
                .map(str::trim)
                .filter(|name| !name.is_empty())
                .ok_or_else(|| {
                    ApiError::BadRequest(
                        "a custom URL import needs a name".to_string(),
                    )
                })?;
            ip_lists::ImportPlan {
                name: name.to_string(),
                description: "Custom IP list subscription".to_string(),
                source_url: url.to_string(),
                selector: payload
                    .selector
                    .as_deref()
                    .map(str::trim)
                    .unwrap_or("")
                    .to_string(),
                suggested_action: "block",
            }
        },
    };

    let action = payload
        .action
        .as_deref()
        .map(str::trim)
        .filter(|action| !action.is_empty())
        .unwrap_or(plan.suggested_action)
        .to_string();
    if !ip_group_action::is_valid(&action) {
        return Err(ApiError::BadRequest(format!(
            "unknown action '{action}' (use block or allow)"
        )));
    }

    // Deduplicate: the same source + selector is one group.
    let mut duplicate = ip_groups::Entity::find().filter(
        ip_groups::Column::SourceUrl.eq(plan.source_url.clone()),
    );
    duplicate = if plan.selector.is_empty() {
        duplicate.filter(
            sea_orm::Condition::any()
                .add(ip_groups::Column::SourceSelector.is_null())
                .add(ip_groups::Column::SourceSelector.eq("")),
        )
    } else {
        duplicate.filter(
            ip_groups::Column::SourceSelector.eq(plan.selector.clone()),
        )
    };
    if let Some(existing) = duplicate.one(&state.db).await? {
        return Err(ApiError::Conflict(format!(
            "this source is already imported as '{}' ({})",
            existing.name, existing.id
        )));
    }

    let interval = payload.sync_interval_minutes.unwrap_or(1440).clamp(0, 10080);
    let now = chrono::Utc::now();
    let group = ip_groups::ActiveModel {
        id: Set(Uuid::new_v4()),
        name: Set(payload
            .name
            .as_deref()
            .map(str::trim)
            .filter(|name| !name.is_empty())
            .unwrap_or(&plan.name)
            .chars()
            .take(200)
            .collect()),
        description: Set(Some(plan.description.clone())),
        ip_ranges: Set(Vec::new()),
        action: Set(action),
        is_global: Set(true),
        subscription_kind: Set(Some(subscription_kind::URL.to_string())),
        subscription_enabled: Set(true),
        source_url: Set(Some(plan.source_url.clone())),
        source_selector: Set(if plan.selector.is_empty() {
            None
        } else {
            Some(plan.selector.clone())
        }),
        sync_interval_minutes: Set(Some(interval)),
        last_synced_at: Set(None),
        last_sync_error: Set(None),
        enabled: Set(true),
        created_at: Set(now),
        updated_at: Set(now),
    }
    .insert(&state.db)
    .await?;

    tracing::info!(
        group_id = %group.id,
        name = %group.name,
        source = %plan.source_url,
        actor = %current.email,
        "IP list imported from the catalog"
    );

    // Fetch once so the console shows real prefixes (and a real error if the
    // source is unreachable - the group keeps existing either way).
    let fallback = group.clone();
    let (group, synced, error) = match crate::api::ip_groups::sync_subscription(
        &state,
        group,
        Some(&current.email),
    )
    .await
    {
        Ok(updated) => (updated, true, None),
        Err(message) => {
            let refreshed = ip_groups::Entity::find_by_id(fallback.id)
                .one(&state.db)
                .await?
                .unwrap_or(fallback);
            (refreshed, false, Some(message))
        },
    };

    Ok((
        StatusCode::CREATED,
        Json(ImportView {
            group,
            synced,
            error,
        }),
    ))
}
