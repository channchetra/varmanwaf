//! Login security: anomaly-detection settings, GeoIP database upload and
//! the login audit history.
//!
//! The detection itself lives in [`crate::notify::login_anomaly`]; this
//! module is the operator surface — settings, the mmdb upload and the
//! read-back of `login_history`. Everything is administrator-only.

use axum::extract::{DefaultBodyLimit, Multipart, Query, State};
use axum::routing::{get, post};
use axum::{Json, Router};
use sea_orm::{ColumnTrait, EntityTrait, QueryFilter, QueryOrder, QuerySelect};
use serde::Deserialize;
use serde_json::{json, Value};

use crate::api::error::ApiError;
use crate::api::state::AppState;
use crate::auth::AuthUser;
use crate::models::login_history;
use crate::notify::login_anomaly::LoginSecuritySettings;

/// GeoLite2-Country is ~60-70 MB; anything far beyond that is not a geo
/// database worth accepting.
const MAX_MMDB_BYTES: usize = 128 * 1024 * 1024;

/// Routes contributed to `/api/v1`.
pub fn routes() -> Router<AppState> {
    Router::new()
        .route("/login-security", get(show).put(update))
        .route(
            "/login-security/geoip",
            post(upload_geoip).layer(DefaultBodyLimit::max(MAX_MMDB_BYTES)),
        )
        .route("/login-history", get(list_history))
}

/// `GET /api/v1/login-security` — administrators only.
async fn show(
    State(state): State<AppState>,
    current: AuthUser,
) -> Result<Json<LoginSecuritySettings>, ApiError> {
    current.require_admin().map_err(ApiError::from)?;
    Ok(Json(LoginSecuritySettings::load(&state.db).await))
}

#[derive(Debug, Deserialize)]
pub struct UpdateLoginSecurityRequest {
    pub anomaly_enabled: Option<bool>,
    pub baseline_count: Option<u32>,
    pub trusted_header: Option<String>,
    pub trust_last_hop: Option<bool>,
    pub online_geo_url: Option<String>,
    pub geoip_local_enabled: Option<bool>,
}

/// `PUT /api/v1/login-security` — administrators only. Partial update over
/// the stored settings.
async fn update(
    State(state): State<AppState>,
    current: AuthUser,
    Json(payload): Json<UpdateLoginSecurityRequest>,
) -> Result<Json<LoginSecuritySettings>, ApiError> {
    current.require_admin().map_err(ApiError::from)?;
    let mut settings = LoginSecuritySettings::load(&state.db).await;
    if let Some(value) = payload.anomaly_enabled {
        settings.anomaly_enabled = value;
    }
    if let Some(value) = payload.baseline_count {
        settings.baseline_count = value;
    }
    if let Some(value) = payload.trusted_header {
        settings.trusted_header = Some(value.trim().to_ascii_lowercase())
            .filter(|value| !value.is_empty());
    }
    if let Some(value) = payload.trust_last_hop {
        settings.trust_last_hop = value;
    }
    if let Some(value) = payload.online_geo_url {
        settings.online_geo_url = value.trim().to_string();
    }
    if let Some(value) = payload.geoip_local_enabled {
        settings.geoip_local_enabled = value;
    }
    settings.validate().map_err(ApiError::BadRequest)?;
    settings.store(&state.db).await?;
    tracing::info!(
        actor = %current.email,
        anomaly_enabled = settings.anomaly_enabled,
        "login security settings updated"
    );
    Ok(Json(settings))
}

/// `POST /api/v1/login-security/geoip` — administrators only. Accepts a
/// multipart field named `file` holding a MaxMind-format mmdb; the file is
/// validated by opening it before it replaces the previous database.
async fn upload_geoip(
    State(_state): State<AppState>,
    current: AuthUser,
    mut multipart: Multipart,
) -> Result<Json<Value>, ApiError> {
    current.require_admin().map_err(ApiError::from)?;

    let mut bytes: Option<Vec<u8>> = None;
    while let Some(field) = multipart
        .next_field()
        .await
        .map_err(|err| ApiError::BadRequest(err.to_string()))?
    {
        if field.name() == Some("file") {
            bytes = Some(
                field
                    .bytes()
                    .await
                    .map_err(|err| ApiError::BadRequest(err.to_string()))?
                    .to_vec(),
            );
            break;
        }
    }
    let Some(bytes) = bytes else {
        return Err(ApiError::BadRequest(
            "multipart field 'file' is required".to_string(),
        ));
    };
    if bytes.is_empty() {
        return Err(ApiError::BadRequest("uploaded file is empty".to_string()));
    }

    let path = crate::notify::login_anomaly::geoip_mmdb_path();
    let tmp = path.with_extension("mmdb.tmp");
    std::fs::write(&tmp, &bytes)
        .map_err(|err| ApiError::Internal(err.to_string()))?;
    // Validate before replacing: a corrupt upload must keep the old file.
    if let Err(err) = maxminddb::Reader::open_readfile(&tmp) {
        let _ = std::fs::remove_file(&tmp);
        return Err(ApiError::BadRequest(format!(
            "not a valid mmdb database: {err}"
        )));
    }
    if let Err(err) = std::fs::rename(&tmp, &path) {
        let _ = std::fs::remove_file(&tmp);
        return Err(ApiError::Internal(err.to_string()));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(
            &path,
            std::fs::Permissions::from_mode(0o600),
        );
    }

    tracing::info!(
        actor = %current.email,
        bytes = bytes.len(),
        "GeoIP database uploaded"
    );
    Ok(Json(json!({
        "uploaded": true,
        "bytes": bytes.len(),
        "path": path.to_string_lossy(),
    })))
}

#[derive(Debug, Deserialize)]
pub struct ListHistoryQuery {
    pub limit: Option<u64>,
    pub offset: Option<u64>,
    pub email: Option<String>,
}

/// `GET /api/v1/login-history` — administrators only. The login audit
/// trail, newest first.
async fn list_history(
    State(state): State<AppState>,
    current: AuthUser,
    Query(query): Query<ListHistoryQuery>,
) -> Result<Json<Vec<login_history::Model>>, ApiError> {
    current.require_admin().map_err(ApiError::from)?;
    let limit = query.limit.unwrap_or(100).clamp(1, 500);
    let offset = query.offset.unwrap_or(0);
    let mut db_query = login_history::Entity::find()
        .order_by_desc(login_history::Column::CreatedAt)
        .limit(limit)
        .offset(offset);
    if let Some(email) = query
        .email
        .as_deref()
        .map(str::trim)
        .filter(|email| !email.is_empty())
    {
        db_query = db_query.filter(login_history::Column::Email.eq(email));
    }
    Ok(Json(db_query.all(&state.db).await?))
}
