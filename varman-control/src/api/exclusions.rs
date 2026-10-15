//! Exclusion packages API: the catalogue, and the site bindings that
//! attach packages at a path prefix.
//!
//! Reads are open to anyone who can see the site (the console renders the
//! catalogue and the bindings); writes are administrators-only. Every
//! mutation re-pushes the site's bundle, so an attached package reaches the
//! edge in the same call that stored it.

use axum::extract::{Path, State};
use axum::routing::{get, post};
use axum::{Json, Router};
use chrono::{DateTime, Utc};
use sea_orm::{ActiveModelTrait, ColumnTrait, EntityTrait, QueryFilter, Set};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::api::common::{load_site_read, load_site_write, parse_uuid};
use crate::api::error::ApiError;
use crate::api::state::AppState;
use crate::auth::AuthUser;
use crate::exclusions;
use crate::grpc::notify_config_changed;
use crate::models::exclusion_packages;

/// Routes contributed to `/api/v1`.
pub fn routes() -> Router<AppState> {
    Router::new()
        .route("/exclusion-packages", get(list).post(create))
        .route("/exclusion-packages/import", post(import_package))
        .route(
            "/exclusion-packages/{key}",
            axum::routing::delete(delete_package),
        )
        .route(
            "/sites/{site_id}/exclusion-bindings",
            get(list_bindings).post(create_binding),
        )
        .route(
            "/sites/{site_id}/exclusion-bindings/{binding_id}",
            axum::routing::put(update_binding).delete(delete_binding),
        )
}

/// Largest upstream file the import accepts (2 MiB).
const MAX_IMPORT_BYTES: usize = 2 * 1024 * 1024;

#[derive(Debug, Serialize)]
pub struct PackageView {
    id: Uuid,
    key: String,
    name: String,
    description: String,
    source_url: String,
    version: String,
    builtin: bool,
    /// `entries` or `seclang`.
    kind: String,
    /// Entries as stored (rule ids/selectors, targets, notes).
    entries: serde_json::Value,
    /// The import report for `seclang` packages.
    import_report: serde_json::Value,
    updated_at: DateTime<Utc>,
}

#[derive(Debug, Serialize)]
pub struct BindingView {
    id: Uuid,
    package_id: Uuid,
    package_key: String,
    package_name: String,
    package_version: String,
    /// True when the package changed since the binding was installed.
    stale: bool,
    path_prefix: String,
    enabled: bool,
    created_at: DateTime<Utc>,
}

#[derive(Debug, Deserialize)]
pub struct CreatePackageRequest {
    key: String,
    name: String,
    #[serde(default)]
    description: String,
    #[serde(default)]
    source_url: String,
    #[serde(default = "default_version")]
    version: String,
    entries: serde_json::Value,
}

fn default_version() -> String {
    "1".to_string()
}

#[derive(Debug, Deserialize)]
pub struct CreateBindingRequest {
    /// Package key (the catalogue key or a custom package's key).
    package_key: String,
    path_prefix: String,
}

#[derive(Debug, Deserialize)]
pub struct UpdateBindingRequest {
    #[serde(default)]
    path_prefix: Option<String>,
    #[serde(default)]
    enabled: Option<bool>,
    /// Re-install the current package version on the binding.
    #[serde(default)]
    reinstall: Option<bool>,
}

/// `GET /api/v1/exclusion-packages` - any signed-in user.
async fn list(
    State(state): State<AppState>,
    _current: AuthUser,
) -> Result<Json<Vec<PackageView>>, ApiError> {
    let rows = exclusion_packages::Entity::find().all(&state.db).await?;
    let mut items: Vec<PackageView> = rows
        .into_iter()
        .map(|row| PackageView {
            id: row.id,
            key: row.key,
            name: row.name,
            description: row.description,
            source_url: row.source_url,
            version: row.version,
            builtin: row.builtin,
            kind: row.kind,
            entries: row.entries,
            import_report: row.import_report.unwrap_or(serde_json::json!(null)),
            updated_at: row.updated_at,
        })
        .collect();
    items.sort_by(|a, b| a.name.cmp(&b.name));
    Ok(Json(items))
}

/// `POST /api/v1/exclusion-packages` - administrators only: define a custom
/// package.
async fn create(
    State(state): State<AppState>,
    current: AuthUser,
    Json(payload): Json<CreatePackageRequest>,
) -> Result<Json<PackageView>, ApiError> {
    current.require_admin().map_err(ApiError::from)?;
    let key = payload.key.trim().to_lowercase();
    if key.is_empty()
        || key.len() > 64
        || !key
            .chars()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-')
    {
        return Err(ApiError::BadRequest(
            "the key must be a lowercase slug (a-z, 0-9, '-')".to_string(),
        ));
    }
    let name = payload.name.trim().to_string();
    if name.is_empty() {
        return Err(ApiError::BadRequest("a name is required".to_string()));
    }
    // Validate before storing; an invalid entry must never reach the
    // compiler.
    exclusions::parse_entries(&payload.entries)
        .map_err(ApiError::BadRequest)?;

    let exists = exclusion_packages::Entity::find()
        .filter(exclusion_packages::Column::Key.eq(&key))
        .one(&state.db)
        .await?
        .is_some();
    if exists {
        return Err(ApiError::Conflict(format!(
            "a package with key '{key}' already exists"
        )));
    }

    let row = exclusion_packages::ActiveModel {
        id: Set(Uuid::new_v4()),
        key: Set(key),
        name: Set(name),
        description: Set(payload.description.trim().to_string()),
        source_url: Set(payload.source_url.trim().to_string()),
        version: Set(payload.version.trim().to_string()),
        entries: Set(payload.entries),
        builtin: Set(false),
        kind: Set(crate::exclusions::KIND_ENTRIES.to_string()),
        source: Set(None),
        import_report: Set(None),
        created_at: Set(Utc::now()),
        updated_at: Set(Utc::now()),
    }
    .insert(&state.db)
    .await?;

    Ok(Json(PackageView {
        id: row.id,
        key: row.key,
        name: row.name,
        description: row.description,
        source_url: row.source_url,
        version: row.version,
        builtin: row.builtin,
        kind: row.kind,
        entries: row.entries,
        import_report: row.import_report.unwrap_or(serde_json::json!(null)),
        updated_at: row.updated_at,
    }))
}

#[derive(Debug, Deserialize)]
pub struct ImportRequest {
    /// The upstream file (https only).
    url: String,
    /// Package key; derived from the URL's file name when omitted.
    #[serde(default)]
    key: Option<String>,
    /// Display name; derived from the key when omitted.
    #[serde(default)]
    name: Option<String>,
}

/// `POST /api/v1/exclusion-packages/import` - administrators only.
///
/// Fetches an upstream SecLang exclusion file, refuses anything that does
/// not parse as SecLang, and stores it as a `seclang` package whose source
/// is appended to the site's virtual patches on attach (where
/// `SecRuleUpdateTargetById` and `SecRuleRemoveById` are applied natively).
/// The import report states what the file contains and what this build
/// applies.
async fn import_package(
    State(state): State<AppState>,
    current: AuthUser,
    Json(payload): Json<ImportRequest>,
) -> Result<Json<PackageView>, ApiError> {
    current.require_admin().map_err(ApiError::from)?;

    let url = payload.url.trim().to_string();
    crate::subscription::validate_source_url(&url)
        .map_err(ApiError::BadRequest)?;
    let client = crate::subscription::subscription_client();
    let response = client.get(&url).send().await.map_err(|err| {
        ApiError::BadGateway(format!("could not fetch the source: {err}"))
    })?;
    if !response.status().is_success() {
        return Err(ApiError::BadGateway(format!(
            "the source answered with HTTP {}",
            response.status()
        )));
    }
    let source = response.text().await.map_err(|err| {
        ApiError::BadGateway(format!("could not read the source: {err}"))
    })?;
    if source.len() > MAX_IMPORT_BYTES {
        return Err(ApiError::BadRequest(format!(
            "the file is larger than {} MiB",
            MAX_IMPORT_BYTES / (1024 * 1024)
        )));
    }

    // The file must parse before it can be stored: a package that cannot
    // compile would silently disable the whole layer on the edge.
    let mut report = exclusions::scan_seclang_report(&source);
    match varman_waf::seclang::SecRuleSet::from_source(&source) {
        Ok(_) => report.valid = true,
        Err(error) => {
            return Err(ApiError::BadRequest(format!(
                "the file does not parse as SecLang: {}",
                error.reason
            )));
        },
    }

    let key = payload
        .key
        .as_deref()
        .map(str::trim)
        .filter(|key| !key.is_empty())
        .map(str::to_lowercase)
        .unwrap_or_else(|| exclusions::key_from_url(&url));
    if key.is_empty()
        || key.len() > 64
        || !key
            .chars()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-')
    {
        return Err(ApiError::BadRequest(
            "the key must be a lowercase slug (a-z, 0-9, '-')".to_string(),
        ));
    }
    let exists = exclusion_packages::Entity::find()
        .filter(exclusion_packages::Column::Key.eq(&key))
        .one(&state.db)
        .await?
        .is_some();
    if exists {
        return Err(ApiError::Conflict(format!(
            "a package with key '{key}' already exists; choose another key \
             or remove the existing package"
        )));
    }
    let name = payload
        .name
        .as_deref()
        .map(str::trim)
        .filter(|name| !name.is_empty())
        .map(str::to_string)
        .unwrap_or_else(|| format!("Imported {key}"));
    let version = report
        .version
        .clone()
        .unwrap_or_else(|| "imported".to_string());
    let report_json =
        serde_json::to_value(&report).unwrap_or(serde_json::json!({}));

    let row = exclusion_packages::ActiveModel {
        id: Set(Uuid::new_v4()),
        key: Set(key.clone()),
        name: Set(name),
        description: Set(format!(
            "Imported from {url} - {} directive(s): {} rule(s), {} \
             exclusion control(s), {} standalone retarget(s), {} removal(s), \
             addressing {} rule id(s). SecLang packages run in the site's \
             virtual patches and apply site-wide.",
            report.directives,
            report.rules,
            report.exclusion_controls,
            report.update_target_by_id,
            report.remove_by_id,
            report.rule_ids.len(),
        )),
        source_url: Set(url),
        version: Set(version),
        entries: Set(serde_json::json!([])),
        builtin: Set(false),
        kind: Set(exclusions::KIND_SECLANG.to_string()),
        source: Set(Some(source)),
        import_report: Set(Some(report_json)),
        created_at: Set(Utc::now()),
        updated_at: Set(Utc::now()),
    }
    .insert(&state.db)
    .await?;

    Ok(Json(PackageView {
        id: row.id,
        key: row.key,
        name: row.name,
        description: row.description,
        source_url: row.source_url,
        version: row.version,
        builtin: row.builtin,
        kind: row.kind,
        entries: row.entries,
        import_report: row.import_report.unwrap_or(serde_json::json!(null)),
        updated_at: row.updated_at,
    }))
}

/// `DELETE /api/v1/exclusion-packages/{key}` - administrators only.
/// Built-in catalogue packages cannot be removed.
async fn delete_package(
    State(state): State<AppState>,
    current: AuthUser,
    Path(key): Path<String>,
) -> Result<Json<serde_json::Value>, ApiError> {
    current.require_admin().map_err(ApiError::from)?;
    let package = exclusion_packages::Entity::find()
        .filter(exclusion_packages::Column::Key.eq(key.trim().to_lowercase()))
        .one(&state.db)
        .await?
        .ok_or_else(|| ApiError::NotFound("package not found".to_string()))?;
    if package.builtin {
        return Err(ApiError::BadRequest(
            "the curated catalogue cannot be removed".to_string(),
        ));
    }
    exclusion_packages::Entity::delete_by_id(package.id)
        .exec(&state.db)
        .await?;
    Ok(Json(serde_json::json!({ "deleted": package.key })))
}

/// `GET /api/v1/sites/{site_id}/exclusion-bindings`
async fn list_bindings(
    State(state): State<AppState>,
    current: AuthUser,
    Path(site_id): Path<String>,
) -> Result<Json<Vec<BindingView>>, ApiError> {
    let id = parse_uuid(&site_id, "site id")?;
    load_site_read(&state.db, id, &current).await?;
    Ok(Json(bindings_for(&state, id).await?))
}

/// `POST /api/v1/sites/{site_id}/exclusion-bindings` - administrators only.
async fn create_binding(
    State(state): State<AppState>,
    current: AuthUser,
    Path(site_id): Path<String>,
    Json(payload): Json<CreateBindingRequest>,
) -> Result<Json<BindingView>, ApiError> {
    let id = parse_uuid(&site_id, "site id")?;
    load_site_write(&state.db, id, &current).await?;

    let prefix = exclusions::validate_path_prefix(&payload.path_prefix)
        .map_err(ApiError::BadRequest)?;
    let package = exclusion_packages::Entity::find()
        .filter(
            exclusion_packages::Column::Key
                .eq(payload.package_key.trim().to_lowercase()),
        )
        .one(&state.db)
        .await?
        .ok_or_else(|| {
            ApiError::NotFound(format!(
                "no package with key '{}'",
                payload.package_key.trim()
            ))
        })?;
    // The stored entries must parse before a binding can exist; SecLang
    // packages instead require their source and the root prefix (the
    // directives are global to the ruleset).
    if package.kind == exclusions::KIND_SECLANG {
        if prefix != "/" {
            return Err(ApiError::BadRequest(
                "SecLang exclusion files apply site-wide; attach at /"
                    .to_string(),
            ));
        }
        if package.source.as_deref().unwrap_or("").trim().is_empty() {
            return Err(ApiError::BadRequest(
                "the package carries no SecLang source".to_string(),
            ));
        }
    } else {
        exclusions::parse_entries(&package.entries)
            .map_err(ApiError::BadRequest)?;
    }

    let duplicate = exclusion_packages::bindings::Entity::find()
        .filter(exclusion_packages::bindings::Column::SiteId.eq(id))
        .filter(exclusion_packages::bindings::Column::PackageId.eq(package.id))
        .filter(exclusion_packages::bindings::Column::PathPrefix.eq(&prefix))
        .one(&state.db)
        .await?
        .is_some();
    if duplicate {
        return Err(ApiError::Conflict(format!(
            "'{}' is already attached at {prefix}",
            package.name
        )));
    }

    let row = exclusion_packages::bindings::ActiveModel {
        id: Set(Uuid::new_v4()),
        site_id: Set(id),
        package_id: Set(package.id),
        path_prefix: Set(prefix),
        enabled: Set(true),
        installed_version: Set(package.version.clone()),
        created_at: Set(Utc::now()),
        updated_at: Set(Utc::now()),
    }
    .insert(&state.db)
    .await?;

    notify_config_changed(&state, id, Some(&current.email)).await;
    let view = bindings_for(&state, id)
        .await?
        .into_iter()
        .find(|binding| binding.id == row.id)
        .ok_or_else(|| ApiError::Internal("binding vanished".to_string()))?;
    Ok(Json(view))
}

/// `PUT /api/v1/sites/{site_id}/exclusion-bindings/{binding_id}`
async fn update_binding(
    State(state): State<AppState>,
    current: AuthUser,
    Path((site_id, binding_id)): Path<(String, String)>,
    Json(payload): Json<UpdateBindingRequest>,
) -> Result<Json<BindingView>, ApiError> {
    let id = parse_uuid(&site_id, "site id")?;
    let binding_id = parse_uuid(&binding_id, "binding id")?;
    load_site_write(&state.db, id, &current).await?;

    let row = exclusion_packages::bindings::Entity::find_by_id(binding_id)
        .filter(exclusion_packages::bindings::Column::SiteId.eq(id))
        .one(&state.db)
        .await?
        .ok_or_else(|| ApiError::NotFound("binding not found".to_string()))?;

    let mut active: exclusion_packages::bindings::ActiveModel = row.into();
    if let Some(prefix) = payload.path_prefix.as_deref() {
        let prefix = exclusions::validate_path_prefix(prefix)
            .map_err(ApiError::BadRequest)?;
        active.path_prefix = Set(prefix);
    }
    if let Some(enabled) = payload.enabled {
        active.enabled = Set(enabled);
    }
    if payload.reinstall == Some(true) {
        let package = exclusion_packages::Entity::find_by_id(
            active.package_id.clone().unwrap(),
        )
        .one(&state.db)
        .await?;
        if let Some(package) = package {
            active.installed_version = Set(package.version);
        }
    }
    active.updated_at = Set(Utc::now());
    active.update(&state.db).await?;

    notify_config_changed(&state, id, Some(&current.email)).await;
    let view = bindings_for(&state, id)
        .await?
        .into_iter()
        .find(|binding| binding.id == binding_id)
        .ok_or_else(|| ApiError::Internal("binding vanished".to_string()))?;
    Ok(Json(view))
}

/// `DELETE /api/v1/sites/{site_id}/exclusion-bindings/{binding_id}`
async fn delete_binding(
    State(state): State<AppState>,
    current: AuthUser,
    Path((site_id, binding_id)): Path<(String, String)>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let id = parse_uuid(&site_id, "site id")?;
    let binding_id = parse_uuid(&binding_id, "binding id")?;
    load_site_write(&state.db, id, &current).await?;

    let result = exclusion_packages::bindings::Entity::delete_many()
        .filter(exclusion_packages::bindings::Column::Id.eq(binding_id))
        .filter(exclusion_packages::bindings::Column::SiteId.eq(id))
        .exec(&state.db)
        .await?;
    if result.rows_affected == 0 {
        return Err(ApiError::NotFound("binding not found".to_string()));
    }
    notify_config_changed(&state, id, Some(&current.email)).await;
    Ok(Json(serde_json::json!({ "deleted": binding_id })))
}

/// Loads a site's bindings joined with their packages.
async fn bindings_for(
    state: &AppState,
    site_id: Uuid,
) -> Result<Vec<BindingView>, ApiError> {
    let bindings = exclusion_packages::bindings::Entity::find()
        .filter(exclusion_packages::bindings::Column::SiteId.eq(site_id))
        .all(&state.db)
        .await?;
    if bindings.is_empty() {
        return Ok(Vec::new());
    }
    let packages = exclusion_packages::Entity::find().all(&state.db).await?;
    let by_id: std::collections::HashMap<Uuid, &exclusion_packages::Model> =
        packages
            .iter()
            .map(|package| (package.id, package))
            .collect();

    let mut views: Vec<BindingView> = bindings
        .into_iter()
        .map(|binding| {
            let package = by_id.get(&binding.package_id);
            BindingView {
                id: binding.id,
                package_id: binding.package_id,
                package_key: package
                    .map(|package| package.key.clone())
                    .unwrap_or_default(),
                package_name: package
                    .map(|package| package.name.clone())
                    .unwrap_or_else(|| "(removed)".to_string()),
                package_version: package
                    .map(|package| package.version.clone())
                    .unwrap_or_default(),
                stale: package.is_some_and(|package| {
                    package.version != binding.installed_version
                }),
                path_prefix: binding.path_prefix,
                enabled: binding.enabled,
                created_at: binding.created_at,
            }
        })
        .collect();
    views.sort_by(|a, b| {
        a.package_name
            .cmp(&b.package_name)
            .then(a.path_prefix.cmp(&b.path_prefix))
    });
    Ok(views)
}
