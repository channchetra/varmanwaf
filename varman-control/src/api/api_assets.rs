//! API assets: the observed endpoint inventory against the declared spec.
//!
//! The inventory is built from stored access logs - method and path
//! aggregates over a bounded window, never bodies or parameters - and each
//! observed endpoint is marked against the site's OpenAPI document
//! (`waf_settings.openapi_spec`). Declared operations with no traffic are
//! listed too, so coverage reads in both directions. An endpoint that was
//! never called cannot appear as observed; the surfaces say so.

use axum::extract::{Path, Query, State};
use axum::routing::get;
use axum::{Json, Router};
use chrono::{DateTime, Duration, Utc};
use sea_orm::{ColumnTrait, EntityTrait, QueryFilter};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::api::common::{load_site_read, parse_uuid, query_all};
use crate::api::error::ApiError;
use crate::api::state::AppState;
use crate::auth::AuthUser;
use crate::models::waf_settings;

/// Longest window the inventory may cover.
const MAX_WINDOW_DAYS: i64 = 30;
/// Default window.
const DEFAULT_WINDOW_DAYS: i64 = 7;
/// Hard cap on observed rows, regardless of the requested limit.
const MAX_OBSERVED_ROWS: i64 = 500;
/// Default observed rows.
const DEFAULT_LIMIT: i64 = 200;

/// Routes contributed to `/api/v1`.
pub fn routes() -> Router<AppState> {
    Router::new().route("/sites/{site_id}/api-assets", get(list))
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
