//! CRS ruleset import and catalogue.
//!
//! Imports fetch an archive (GitHub release tag, direct URL or an uploaded
//! base64 archive), parse it with the engine's SecLang parser and store the
//! rule catalogue with file/line provenance. Unsupported rules keep their
//! parser error; directives are recorded, not dropped. Policies bind a
//! ruleset through the `crs_import` layer.

use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use axum::routing::{get, post};
use axum::Json;
use axum::Router;
use chrono::{DateTime, Utc};
use sea_orm::{
    ColumnTrait, EntityTrait, PaginatorTrait, QueryFilter, QueryOrder,
};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::api::common::{parse_uuid, Page, Pagination};
use crate::api::error::ApiError;
use crate::api::state::AppState;
use crate::auth::AuthUser;
use crate::crs::{self, ImportSource};
use crate::models::{crs_rule, crs_ruleset};

/// Routes contributed to `/api/v1`.
pub fn routes() -> Router<AppState> {
    Router::new()
        .route("/crs/releases", get(list_releases))
        .route("/crs/import", post(import_ruleset))
        .route("/crs/rulesets", get(list_rulesets))
        .route(
            "/crs/rulesets/{id}",
            get(get_ruleset).delete(delete_ruleset),
        )
}

#[derive(Debug, Serialize)]
pub struct ReleaseView {
    pub tag: String,
    pub name: String,
    pub published_at: Option<String>,
    pub prerelease: bool,
}

/// `GET /api/v1/crs/releases` - recent `coreruleset/coreruleset` releases,
/// so the console can offer the tag picker the studied product has.
async fn list_releases(
    _current: AuthUser,
) -> Result<Json<Vec<ReleaseView>>, ApiError> {
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(20))
        .build()
        .map_err(ApiError::internal)?;
    let response = client
        .get("https://api.github.com/repos/coreruleset/coreruleset/releases")
        .query(&[("per_page", "30")])
        .header("User-Agent", "VarmanWAF")
        .header("Accept", "application/vnd.github+json")
        .send()
        .await
        .map_err(|err| {
            ApiError::BadGateway(format!("GitHub is unreachable: {err}"))
        })?;
    if !response.status().is_success() {
        return Err(ApiError::BadGateway(format!(
            "GitHub answered HTTP {}",
            response.status()
        )));
    }
    let releases: Vec<serde_json::Value> = response
        .json()
        .await
        .map_err(|err| ApiError::BadGateway(format!("GitHub answered with unexpected JSON: {err}")))?;
    Ok(Json(
        releases
            .into_iter()
            .filter_map(|release| {
                let tag = release.get("tag_name")?.as_str()?.to_string();
                Some(ReleaseView {
                    tag,
                    name: release
                        .get("name")
                        .and_then(|value| value.as_str())
                        .unwrap_or_default()
                        .to_string(),
                    published_at: release
                        .get("published_at")
                        .and_then(|value| value.as_str())
                        .map(str::to_string),
                    prerelease: release
                        .get("prerelease")
                        .and_then(|value| value.as_bool())
                        .unwrap_or(false),
                })
            })
            .collect(),
    ))
}

#[derive(Debug, Deserialize)]
pub struct ImportRequest {
    /// Display name; defaults to "OWASP CRS".
    #[serde(default)]
    pub name: Option<String>,
    #[serde(default)]
    pub github_tag: Option<String>,
    #[serde(default)]
    pub url: Option<String>,
    #[serde(default)]
    pub archive_base64: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct RulesetView {
    pub id: Uuid,
    pub name: String,
    pub version: String,
    pub source: String,
    pub fingerprint: String,
    pub rule_count: i32,
    pub supported_count: i32,
    pub unsupported_count: i32,
    pub directive_count: i32,
    pub imported_at: DateTime<Utc>,
    /// How many policies bind this ruleset.
    pub used_by_policies: i64,
    /// True when this import matched an existing fingerprint.
    pub deduplicated: bool,
}

#[derive(Debug, Serialize)]
pub struct RuleView {
    pub id: Uuid,
    pub rule_id: String,
    pub kind: String,
    pub file: String,
    pub line: i32,
    pub phase: Option<i32>,
    pub severity: String,
    pub paranoia_level: Option<i32>,
    pub category: String,
    pub message: String,
    pub supported: bool,
    pub error: String,
    pub source: String,
}

fn ruleset_view(
    row: crs_ruleset::Model,
    used_by_policies: i64,
    deduplicated: bool,
) -> RulesetView {
    RulesetView {
        id: row.id,
        name: row.name,
        version: row.version,
        source: row.source,
        fingerprint: row.fingerprint,
        rule_count: row.rule_count,
        supported_count: row.supported_count,
        unsupported_count: row.unsupported_count,
        directive_count: row.directive_count,
        imported_at: row.imported_at,
        used_by_policies,
        deduplicated,
    }
}

/// `POST /api/v1/crs/import` - imports an archive (admin only).
async fn import_ruleset(
    State(state): State<AppState>,
    current: AuthUser,
    Json(payload): Json<ImportRequest>,
) -> Result<Json<RulesetView>, ApiError> {
    current.require_admin().map_err(ApiError::from)?;
    let sources = [
        payload.github_tag.as_deref(),
        payload.url.as_deref(),
        payload.archive_base64.as_deref(),
    ]
    .into_iter()
    .flatten()
    .filter(|value| !value.trim().is_empty())
    .count();
    if sources != 1 {
        return Err(ApiError::bad_request(
            "provide exactly one of github_tag, url or archive_base64",
        ));
    }
    let source = if let Some(tag) = payload.github_tag {
        ImportSource::GitHubTag(tag)
    } else if let Some(url) = payload.url {
        ImportSource::Url(url)
    } else {
        ImportSource::ArchiveBase64(payload.archive_base64.unwrap_or_default())
    };
    let name = payload
        .name
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
        .unwrap_or_else(|| "OWASP CRS".to_string());

    let outcome = crs::import(&state.db, &name, &source)
        .await
        .map_err(ApiError::bad_request)?;
    let used = crs::usage_count(&state.db, outcome.ruleset.id)
        .await
        .map_err(ApiError::from)?;
    Ok(Json(ruleset_view(outcome.ruleset, used, outcome.deduplicated)))
}

/// `GET /api/v1/crs/rulesets` - imported rulesets, newest first.
async fn list_rulesets(
    State(state): State<AppState>,
    _current: AuthUser,
) -> Result<Json<Vec<RulesetView>>, ApiError> {
    let rows = crs_ruleset::Entity::find()
        .order_by_desc(crs_ruleset::Column::ImportedAt)
        .all(&state.db)
        .await?;
    let mut items = Vec::with_capacity(rows.len());
    for row in rows {
        let used = crs::usage_count(&state.db, row.id)
            .await
            .map_err(ApiError::from)?;
        items.push(ruleset_view(row, used, false));
    }
    Ok(Json(items))
}

#[derive(Debug, Deserialize)]
pub struct RuleQuery {
    #[serde(default)]
    pub category: Option<String>,
    #[serde(default)]
    pub paranoia: Option<i32>,
    #[serde(default)]
    pub phase: Option<i32>,
    #[serde(default)]
    pub severity: Option<String>,
    #[serde(default)]
    pub q: Option<String>,
    /// `true` / `false` to filter by compile status.
    #[serde(default)]
    pub supported: Option<bool>,
    /// `rule` or `directive`.
    #[serde(default)]
    pub kind: Option<String>,
    #[serde(flatten)]
    pub pagination: Pagination,
}

#[derive(Debug, Serialize)]
pub struct RulesetDetail {
    #[serde(flatten)]
    pub ruleset: RulesetView,
    pub rules: Page<RuleView>,
}

/// `GET /api/v1/crs/rulesets/{id}` - the ruleset plus its filtered rule
/// catalogue (category / paranoia / phase / severity / keyword / status).
async fn get_ruleset(
    State(state): State<AppState>,
    _current: AuthUser,
    Path(id): Path<String>,
    Query(query): Query<RuleQuery>,
) -> Result<Json<RulesetDetail>, ApiError> {
    let id = parse_uuid(&id, "ruleset id")?;
    let row = crs_ruleset::Entity::find_by_id(id)
        .one(&state.db)
        .await?
        .ok_or_else(|| ApiError::not_found("ruleset not found"))?;
    let used = crs::usage_count(&state.db, id).await.map_err(ApiError::from)?;

    let mut find = crs_rule::Entity::find()
        .filter(crs_rule::Column::RulesetId.eq(id))
        .order_by_asc(crs_rule::Column::File)
        .order_by_asc(crs_rule::Column::Line);
    if let Some(category) = query.category.filter(|value| !value.is_empty()) {
        find = find.filter(crs_rule::Column::Category.eq(category));
    }
    if let Some(paranoia) = query.paranoia {
        find = find.filter(crs_rule::Column::ParanoiaLevel.eq(paranoia));
    }
    if let Some(phase) = query.phase {
        find = find.filter(crs_rule::Column::Phase.eq(phase));
    }
    if let Some(severity) = query.severity.filter(|value| !value.is_empty()) {
        find = find.filter(crs_rule::Column::Severity.eq(severity));
    }
    if let Some(keyword) = query.q.filter(|value| !value.is_empty()) {
        let pattern = format!("%{keyword}%");
        find = find.filter(
            sea_orm::Condition::any()
                .add(crs_rule::Column::RuleId.like(pattern.clone()))
                .add(crs_rule::Column::Message.like(pattern.clone()))
                .add(crs_rule::Column::File.like(pattern)),
        );
    }
    if let Some(supported) = query.supported {
        find = find.filter(crs_rule::Column::Supported.eq(supported));
    }
    if let Some(kind) = query.kind.filter(|value| !value.is_empty()) {
        find = find.filter(crs_rule::Column::Kind.eq(kind));
    }

    let pagination = query.pagination.normalise();
    let paginator = find.paginate(&state.db, pagination.limit());
    let total = paginator.num_items().await?;
    let rows = paginator.fetch_page(pagination.index()).await?;
    let rules = Page::new(
        rows.into_iter()
            .map(|row| RuleView {
                id: row.id,
                rule_id: row.rule_id,
                kind: row.kind,
                file: row.file,
                line: row.line,
                phase: row.phase,
                severity: row.severity,
                paranoia_level: row.paranoia_level,
                category: row.category,
                message: row.message,
                supported: row.supported,
                error: row.error,
                source: row.source,
            })
            .collect(),
        total,
        pagination,
    );
    Ok(Json(RulesetDetail {
        ruleset: ruleset_view(row, used, false),
        rules,
    }))
}

/// `DELETE /api/v1/crs/rulesets/{id}` - refuses while a policy binds it.
async fn delete_ruleset(
    State(state): State<AppState>,
    current: AuthUser,
    Path(id): Path<String>,
) -> Result<StatusCode, ApiError> {
    current.require_admin().map_err(ApiError::from)?;
    let id = parse_uuid(&id, "ruleset id")?;
    let row = crs_ruleset::Entity::find_by_id(id)
        .one(&state.db)
        .await?
        .ok_or_else(|| ApiError::not_found("ruleset not found"))?;
    let used = crs::usage_count(&state.db, id).await.map_err(ApiError::from)?;
    if used > 0 {
        return Err(ApiError::Conflict(format!(
            "the ruleset is bound by {used} policy layer(s); unbind it first"
        )));
    }
    crs_ruleset::Entity::delete_by_id(row.id).exec(&state.db).await?;
    tracing::info!(ruleset_id = %id, "CRS ruleset deleted");
    Ok(StatusCode::NO_CONTENT)
}
