//! API assets: the observed endpoint inventory against the declared spec.
//!
//! The inventory is built from stored access logs - method and path
//! aggregates over a bounded window, never bodies or parameters - and each
//! observed endpoint is marked against the site's OpenAPI document
//! (`waf_settings.openapi_spec`). Declared operations with no traffic are
//! listed too, so coverage reads in both directions. An endpoint that was
//! never called cannot appear as observed; the surfaces say so.

use axum::extract::{Path, Query, State};
use axum::routing::{get, post};
use axum::{Json, Router};
use chrono::{DateTime, Duration, Utc};
use sea_orm::{ActiveModelTrait, ColumnTrait, EntityTrait, QueryFilter, Set};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::api::common::{
    load_site_read, load_site_write, parse_uuid, query_all,
};
use crate::api::error::ApiError;
use crate::api::state::AppState;
use crate::api_learn::{self, QueryParam, SchemaNode};
use crate::auth::AuthUser;
use crate::models::{api_learned_schemas, waf_settings};

/// Longest window the inventory may cover.
const MAX_WINDOW_DAYS: i64 = 30;
/// Default window.
const DEFAULT_WINDOW_DAYS: i64 = 7;
/// Hard cap on observed rows, regardless of the requested limit.
const MAX_OBSERVED_ROWS: i64 = 500;
/// Default observed rows.
const DEFAULT_LIMIT: i64 = 200;
/// Most access-log rows one learn run scans.
const MAX_LEARN_ROWS: i64 = 5000;

/// Routes contributed to `/api/v1`.
pub fn routes() -> Router<AppState> {
    Router::new()
        .route("/sites/{site_id}/api-assets", get(list))
        .route("/sites/{site_id}/api-assets/learn", post(learn))
        .route("/sites/{site_id}/api-assets/learned", get(learned))
        .route(
            "/sites/{site_id}/api-assets/openapi-draft",
            get(openapi_draft),
        )
}

#[derive(Debug, Deserialize)]
pub struct AssetsQuery {
    /// Window in days (1-30, default 7).
    pub days: Option<i64>,
    /// Observed rows (1-500, default 200).
    pub limit: Option<i64>,
}

#[derive(Debug, Serialize)]
pub struct ApiAssets {
    site_id: Uuid,
    from: DateTime<Utc>,
    to: DateTime<Utc>,
    window_days: i64,
    spec: SpecStatus,
    /// Observed method+path aggregates, ranked by request count.
    observed: Vec<ObservedEndpoint>,
    /// True when the cap cut the observed list; `spec_only` is then not
    /// computed (an endpoint with traffic beyond the cap would be listed
    /// wrongly).
    observed_truncated: bool,
    /// Declared operations with no observed traffic in the window.
    spec_only: Vec<SpecOperation>,
    limitations: Vec<String>,
}

#[derive(Debug, Serialize)]
pub struct SpecStatus {
    /// Whether an OpenAPI document is configured for the site.
    configured: bool,
    /// `info.title` / `info.version` when present.
    title: Option<String>,
    version: Option<String>,
    /// Declared paths / operations.
    paths: usize,
    operations: usize,
    /// Set when the stored document could not be parsed; coverage is then
    /// unmarked rather than guessed.
    parse_error: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct ObservedEndpoint {
    method: String,
    path: String,
    count: i64,
    /// Responses with status >= 500 in the window.
    errors: i64,
    first_seen: DateTime<Utc>,
    last_seen: DateTime<Utc>,
    /// Whether the site's spec declares this operation.
    in_spec: bool,
    /// The matched spec template, e.g. `/users/{id}`.
    spec_path: Option<String>,
}

#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct SpecOperation {
    /// Lower-case method as declared in the document.
    method: String,
    path: String,
}

/// `GET /api/v1/sites/{site_id}/api-assets?days=&limit=`
async fn list(
    State(state): State<AppState>,
    current: AuthUser,
    Path(site_id): Path<String>,
    Query(query): Query<AssetsQuery>,
) -> Result<Json<ApiAssets>, ApiError> {
    let id = parse_uuid(&site_id, "site id")?;
    load_site_read(&state.db, id, &current).await?;

    let window_days = query
        .days
        .unwrap_or(DEFAULT_WINDOW_DAYS)
        .clamp(1, MAX_WINDOW_DAYS);
    let limit = query
        .limit
        .unwrap_or(DEFAULT_LIMIT)
        .clamp(1, MAX_OBSERVED_ROWS);
    let to = Utc::now();
    let from = to - Duration::days(window_days);

    // ── The declared side: the site's OpenAPI document ──
    let settings = waf_settings::Entity::find()
        .filter(waf_settings::Column::SiteId.eq(id))
        .one(&state.db)
        .await?;
    let raw_spec = settings
        .as_ref()
        .map(|row| row.openapi_spec.trim())
        .filter(|spec| !spec.is_empty());
    let (spec, spec_ops) = match raw_spec {
        Some(raw) => match parse_spec(raw) {
            Ok(parsed) => parsed,
            Err(error) => (
                SpecStatus {
                    configured: true,
                    title: None,
                    version: None,
                    paths: 0,
                    operations: 0,
                    parse_error: Some(error),
                },
                Vec::new(),
            ),
        },
        None => (
            SpecStatus {
                configured: false,
                title: None,
                version: None,
                paths: 0,
                operations: 0,
                parse_error: None,
            },
            Vec::new(),
        ),
    };

    // ── The observed side: method+path aggregates over access logs ──
    let rows = query_all(
        &state.db,
        "SELECT method, path, COUNT(*) AS count, \
                COUNT(*) FILTER (WHERE status_code >= 500) AS errors, \
                MIN(timestamp) AS first_seen, MAX(timestamp) AS last_seen \
         FROM access_logs \
         WHERE site_id = $1 AND timestamp >= $2 AND timestamp < $3 \
           AND path IS NOT NULL AND path <> '' \
         GROUP BY method, path \
         ORDER BY count DESC, path ASC \
         LIMIT $4",
        vec![id.into(), from.into(), to.into(), limit.into()],
    )
    .await?;

    let mut observed = Vec::with_capacity(rows.len());
    for row in &rows {
        let method = row.try_get::<String>("", "method").unwrap_or_default();
        let path = row.try_get::<String>("", "path").unwrap_or_default();
        let spec_path = match_spec(&spec_ops, &method, &path);
        observed.push(ObservedEndpoint {
            method,
            path,
            count: row.try_get::<i64>("", "count").unwrap_or(0),
            errors: row.try_get::<i64>("", "errors").unwrap_or(0),
            first_seen: row.try_get("", "first_seen").unwrap_or(to),
            last_seen: row.try_get("", "last_seen").unwrap_or(to),
            in_spec: spec_path.is_some(),
            spec_path,
        });
    }
    let observed_truncated = observed.len() as i64 >= limit;

    // Declared-but-unused is only trustworthy on a complete observed list.
    let spec_only: Vec<SpecOperation> = if observed_truncated {
        Vec::new()
    } else {
        spec_ops
            .iter()
            .filter(|op| {
                !observed.iter().any(|row| {
                    row.method.eq_ignore_ascii_case(&op.method)
                        && row.spec_path.as_deref() == Some(op.path.as_str())
                })
            })
            .cloned()
            .collect()
    };

    let mut limitations = vec![
        "Observed endpoints come from stored access logs (method and path \
         only); log retention bounds how far back the window can reach."
            .to_string(),
        "A path matches a spec template exactly, or segment by segment with \
         `{param}` placeholders matching one segment; path parameters are \
         not learned."
            .to_string(),
    ];
    if !spec.configured {
        limitations.push(
            "No OpenAPI document is configured for this site, so coverage \
             is not marked; set one on the site's Protection tab."
                .to_string(),
        );
    } else if spec.parse_error.is_some() {
        limitations.push(
            "The stored OpenAPI document could not be parsed; coverage is \
             not marked."
                .to_string(),
        );
    }
    if observed_truncated {
        limitations.push(format!(
            "The observed list hit its cap ({limit} rows); declared-but-\
             unused operations are not computed while it is truncated."
        ));
    }

    Ok(Json(ApiAssets {
        site_id: id,
        from,
        to,
        window_days,
        spec,
        observed,
        observed_truncated,
        spec_only,
        limitations,
    }))
}

#[derive(Debug, Deserialize)]
pub struct LearnRequest {
    /// Window in days (1-30, default 7).
    #[serde(default)]
    pub days: Option<i64>,
}

#[derive(Debug, Serialize)]
pub struct LearnSummary {
    window_days: i64,
    /// Endpoints (method+path) the run touched.
    endpoints: usize,
    /// JSON bodies merged into the stored structures.
    samples: u64,
    /// Bodies skipped because the stored prefix is truncated.
    skipped_truncated: u64,
    /// Bodies skipped because they are not JSON.
    skipped_non_json: u64,
    rows_scanned: u64,
    /// True when the scan hit its row cap; older traffic was not read.
    truncated_scan: bool,
}

/// `POST /api/v1/sites/{site_id}/api-assets/learn` - writers only: merges
/// the window's JSON bodies and query strings into the stored structures
/// (keys, types and counts; values are never read).
async fn learn(
    State(state): State<AppState>,
    current: AuthUser,
    Path(site_id): Path<String>,
    Json(payload): Json<LearnRequest>,
) -> Result<Json<LearnSummary>, ApiError> {
    let id = parse_uuid(&site_id, "site id")?;
    load_site_write(&state.db, id, &current).await?;

    let window_days = payload
        .days
        .unwrap_or(DEFAULT_WINDOW_DAYS)
        .clamp(1, MAX_WINDOW_DAYS);
    let to = Utc::now();
    let from = to - Duration::days(window_days);

    let rows = query_all(
        &state.db,
        "SELECT method, path, query_string, request_body, \
                request_body_truncated, timestamp \
         FROM access_logs \
         WHERE site_id = $1 AND timestamp >= $2 AND timestamp < $3 \
           AND path IS NOT NULL AND path <> '' \
         ORDER BY timestamp DESC LIMIT $4",
        vec![id.into(), from.into(), to.into(), MAX_LEARN_ROWS.into()],
    )
    .await?;
    let truncated_scan = rows.len() as i64 >= MAX_LEARN_ROWS;

    struct Acc {
        schema: SchemaNode,
        params: std::collections::BTreeMap<String, QueryParam>,
        samples: u64,
        first: Option<DateTime<Utc>>,
        last: Option<DateTime<Utc>>,
    }
    let mut acc: std::collections::BTreeMap<(String, String), Acc> =
        std::collections::BTreeMap::new();
    let mut skipped_truncated = 0u64;
    let mut skipped_non_json = 0u64;
    let mut samples = 0u64;

    for row in &rows {
        let method = row.try_get::<String>("", "method").unwrap_or_default();
        let path = row.try_get::<String>("", "path").unwrap_or_default();
        if method.is_empty() || path.is_empty() {
            continue;
        }
        let timestamp = row.try_get::<DateTime<Utc>>("", "timestamp").ok();
        let entry = acc.entry((method, path)).or_insert_with(|| Acc {
            schema: SchemaNode::default(),
            params: std::collections::BTreeMap::new(),
            samples: 0,
            first: None,
            last: None,
        });
        if let Some(ts) = timestamp {
            entry.first = Some(entry.first.map_or(ts, |first| first.min(ts)));
            entry.last = Some(entry.last.map_or(ts, |last| last.max(ts)));
        }
        if let Ok(query) = row.try_get::<String>("", "query_string") {
            if !query.is_empty() {
                api_learn::learn_query(&query, &mut entry.params);
            }
        }
        let truncated = row
            .try_get::<bool>("", "request_body_truncated")
            .unwrap_or(false);
        match row.try_get::<String>("", "request_body") {
            Ok(body) if !body.is_empty() && truncated => skipped_truncated += 1,
            Ok(body) if !body.is_empty() => {
                if api_learn::merge_body(&mut entry.schema, &body) {
                    entry.samples += 1;
                    samples += 1;
                } else {
                    skipped_non_json += 1;
                }
            },
            _ => {},
        }
    }

    for ((method, path), entry) in &acc {
        // Each run replaces the endpoint's row with the window's aggregate,
        // so the stored structure always reflects a stated window.
        let request_schema = (entry.samples > 0).then(|| {
            serde_json::to_value(&entry.schema).unwrap_or(serde_json::json!({}))
        });
        let query_schema = serde_json::to_value(&entry.params)
            .unwrap_or(serde_json::json!({}));
        let existing = api_learned_schemas::Entity::find()
            .filter(api_learned_schemas::Column::SiteId.eq(id))
            .filter(api_learned_schemas::Column::Method.eq(method))
            .filter(api_learned_schemas::Column::Path.eq(path))
            .one(&state.db)
            .await?;
        match existing {
            Some(row) => {
                let mut active: api_learned_schemas::ActiveModel = row.into();
                active.request_schema = Set(request_schema);
                active.query_schema = Set(query_schema);
                active.sample_count = Set(entry.samples as i64);
                active.first_seen = Set(entry.first);
                active.last_seen = Set(entry.last);
                active.updated_at = Set(Utc::now());
                active.update(&state.db).await?;
            },
            None => {
                api_learned_schemas::ActiveModel {
                    id: Set(Uuid::new_v4()),
                    site_id: Set(id),
                    method: Set(method.clone()),
                    path: Set(path.clone()),
                    request_schema: Set(request_schema),
                    query_schema: Set(query_schema),
                    sample_count: Set(entry.samples as i64),
                    first_seen: Set(entry.first),
                    last_seen: Set(entry.last),
                    updated_at: Set(Utc::now()),
                }
                .insert(&state.db)
                .await?;
            },
        }
    }

    Ok(Json(LearnSummary {
        window_days,
        endpoints: acc.len(),
        samples,
        skipped_truncated,
        skipped_non_json,
        rows_scanned: rows.len() as u64,
        truncated_scan,
    }))
}

/// `GET /api/v1/sites/{site_id}/api-assets/learned`
async fn learned(
    State(state): State<AppState>,
    current: AuthUser,
    Path(site_id): Path<String>,
) -> Result<Json<Vec<api_learned_schemas::Model>>, ApiError> {
    let id = parse_uuid(&site_id, "site id")?;
    load_site_read(&state.db, id, &current).await?;
    let rows = api_learned_schemas::Entity::find()
        .filter(api_learned_schemas::Column::SiteId.eq(id))
        .all(&state.db)
        .await?;
    Ok(Json(rows))
}

/// `GET /api/v1/sites/{site_id}/api-assets/openapi-draft`
async fn openapi_draft(
    State(state): State<AppState>,
    current: AuthUser,
    Path(site_id): Path<String>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let id = parse_uuid(&site_id, "site id")?;
    let site = load_site_read(&state.db, id, &current).await?;
    let rows = api_learned_schemas::Entity::find()
        .filter(api_learned_schemas::Column::SiteId.eq(id))
        .all(&state.db)
        .await?;

    // The window is derived from the learned rows' span, so the document
    // states the real coverage instead of a guess.
    let window_days = rows
        .iter()
        .filter_map(|row| row.first_seen)
        .min()
        .map(|first| (Utc::now() - first).num_days().max(1))
        .unwrap_or(0);

    let endpoints: Vec<api_learn::LearnedEndpoint> = rows
        .iter()
        .map(|row| api_learn::LearnedEndpoint {
            method: row.method.clone(),
            path: row.path.clone(),
            request_schema: row.request_schema.clone().and_then(|value| {
                serde_json::from_value::<SchemaNode>(value).ok()
            }),
            query_schema: serde_json::from_value::<
                std::collections::BTreeMap<String, QueryParam>,
            >(row.query_schema.clone())
            .unwrap_or_default(),
            sample_count: row.sample_count,
        })
        .collect();

    Ok(Json(api_learn::openapi_draft(
        &site.domain,
        window_days,
        &endpoints,
    )))
}

/// Parses the OpenAPI document into declared operations.
fn parse_spec(raw: &str) -> Result<(SpecStatus, Vec<SpecOperation>), String> {
    let doc: serde_json::Value =
        serde_json::from_str(raw).map_err(|err| err.to_string())?;
    let paths = doc
        .get("paths")
        .and_then(serde_json::Value::as_object)
        .ok_or_else(|| "the document has no `paths` object".to_string())?;

    let mut operations = Vec::new();
    let mut path_count = 0usize;
    for (template, item) in paths {
        if template.starts_with("x-") {
            continue;
        }
        let Some(methods) = item.as_object() else {
            continue;
        };
        path_count += 1;
        for key in methods.keys() {
            let method = key.to_ascii_lowercase();
            if matches!(
                method.as_str(),
                "get"
                    | "put"
                    | "post"
                    | "delete"
                    | "options"
                    | "head"
                    | "patch"
                    | "trace"
            ) {
                operations.push(SpecOperation {
                    method,
                    path: template.clone(),
                });
            }
        }
    }

    let info = doc.get("info");
    let status = SpecStatus {
        configured: true,
        title: info
            .and_then(|value| value.get("title"))
            .and_then(serde_json::Value::as_str)
            .map(str::to_string),
        version: info
            .and_then(|value| value.get("version"))
            .and_then(serde_json::Value::as_str)
            .map(str::to_string),
        paths: path_count,
        operations: operations.len(),
        parse_error: None,
    };
    Ok((status, operations))
}

/// The spec template an observed method+path matches, if any: exact first,
/// then segment by segment with `{param}` placeholders.
fn match_spec(
    operations: &[SpecOperation],
    method: &str,
    path: &str,
) -> Option<String> {
    let method = method.to_ascii_lowercase();
    for op in operations {
        if op.method == method && op.path == path {
            return Some(op.path.clone());
        }
    }
    let segments: Vec<&str> = path.trim_end_matches('/').split('/').collect();
    for op in operations {
        if op.method != method {
            continue;
        }
        let template: Vec<&str> =
            op.path.trim_end_matches('/').split('/').collect();
        if template.len() != segments.len() {
            continue;
        }
        let matches = template
            .iter()
            .zip(&segments)
            .all(|(t, s)| (t.starts_with('{') && t.ends_with('}')) || t == s);
        if matches {
            return Some(op.path.clone());
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    const SPEC: &str = r#"{
        "openapi": "3.0.0",
        "info": { "title": "Shop API", "version": "1.4.0" },
        "paths": {
            "/users": {
                "get": {},
                "post": {}
            },
            "/users/{id}": {
                "get": {},
                "delete": {}
            },
            "x-internal": {
                "get": {}
            }
        }
    }"#;

    #[test]
    fn the_spec_parses_into_declared_operations() {
        let (status, ops) = parse_spec(SPEC).unwrap();
        assert!(status.configured);
        assert_eq!(status.title.as_deref(), Some("Shop API"));
        assert_eq!(status.version.as_deref(), Some("1.4.0"));
        assert_eq!(status.paths, 2, "x- keys are not paths");
        assert_eq!(status.operations, 4);
        assert!(ops.contains(&SpecOperation {
            method: "get".to_string(),
            path: "/users/{id}".to_string(),
        }));
    }

    #[test]
    fn an_invalid_document_is_reported_not_guessed() {
        assert!(parse_spec("{not json").is_err());
        assert!(parse_spec("{}").is_err(), "no paths object");
    }

    #[test]
    fn matching_prefers_exact_then_template_segments() {
        let (_, ops) = parse_spec(SPEC).unwrap();
        assert_eq!(
            match_spec(&ops, "GET", "/users"),
            Some("/users".to_string())
        );
        assert_eq!(
            match_spec(&ops, "get", "/users/42"),
            Some("/users/{id}".to_string())
        );
        assert_eq!(match_spec(&ops, "PUT", "/users/42"), None);
        assert_eq!(match_spec(&ops, "GET", "/users/42/orders"), None);
        assert_eq!(
            match_spec(&ops, "POST", "/users/"),
            Some("/users".to_string())
        );
    }
}
