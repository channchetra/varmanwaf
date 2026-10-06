//! Settings API for the Elasticsearch log shipper.
//!
//! These endpoints let an administrator inspect, validate and connectivity-test
//! the ES configuration from the dashboard. The control plane's
//! [`ServerConfig`](crate::config::ServerConfig) is immutable at runtime, so a
//! `PUT` does not hot-swap the running shipper; instead it validates the
//! submitted configuration, probes the cluster with an ephemeral client and
//! reports whether a restart is needed to apply it. This keeps the config file
//! the single source of truth while still giving operators a safe way to check
//! their settings before committing them.

use axum::extract::State;
use axum::routing::{get, post};
use axum::Json;
use axum::Router;
use serde::Serialize;

use crate::api::error::ApiError;
use crate::api::state::AppState;
use crate::auth::AuthUser;
use crate::es::{
    ensure_index_template, ElasticsearchClient, EsConfig, EsHealth,
};

/// Routes contributed to `/api/v1`.
pub fn routes() -> Router<AppState> {
    Router::new()
        .route("/settings/elasticsearch", get(show).put(update))
        .route("/settings/elasticsearch/test", post(test))
}

/// The redacted settings view returned to the dashboard.
#[derive(Debug, Serialize)]
pub struct EsSettingsView {
    /// Effective configuration with secrets masked.
    pub config: EsConfig,
    /// Whether a live shipper is attached to this process.
    pub running: bool,
    /// Live cluster health, when a shipper is running and reachable.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub health: Option<EsHealth>,
    /// True when `config` differs from what the running process was started
    /// with, i.e. a restart is required to apply it.
    pub requires_restart: bool,
}

/// Response of the connectivity probe.
#[derive(Debug, Serialize)]
pub struct EsTestResult {
    pub ok: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub health: Option<EsHealth>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
    /// Whether the index template was installed successfully during the test.
    pub template_installed: bool,
}

/// `GET /api/v1/settings/elasticsearch` — administrators only.
async fn show(
    State(state): State<AppState>,
    current: AuthUser,
) -> Result<Json<EsSettingsView>, ApiError> {
    current.require_admin().map_err(ApiError::from)?;

    let running = state.es.is_some();
    let config = state
        .config
        .elasticsearch
        .clone()
        .unwrap_or_default()
        .redacted();

    // Best-effort live health from the running shipper.
    let health = match &state.es {
        Some(client) => client.health_check().await.ok(),
        None => None,
    };

    Ok(Json(EsSettingsView {
        config,
        running,
        health,
        requires_restart: false,
    }))
}

/// `PUT /api/v1/settings/elasticsearch` — validates and probes a new config.
async fn update(
    State(state): State<AppState>,
    current: AuthUser,
    Json(mut submitted): Json<EsConfig>,
) -> Result<Json<EsSettingsView>, ApiError> {
    current.require_admin().map_err(ApiError::from)?;
    let actor = current.id;

    submitted.normalise();

    // A config that is not enabled may be stored incomplete (an operator saving
    // a draft), so only validate the full shape when it is meant to run.
    if submitted.enabled {
        submitted
            .validate()
            .map_err(|err| ApiError::Unprocessable(err.to_string()))?;
    }

    // Probe the cluster with an ephemeral client when shipping is being turned
    // on, so the operator gets immediate feedback about bad URLs/credentials.
    let mut health = None;
    if submitted.is_active() {
        health = Some(probe(submitted.clone()).await?);
    }

    let stored = state.config.elasticsearch.clone().unwrap_or_default();
    let requires_restart = submitted != stored;

    tracing::info!(
        requested_by = %actor,
        enabled = submitted.enabled,
        urls = ?submitted.urls,
        "elasticsearch settings updated (restart required to apply)"
    );

    Ok(Json(EsSettingsView {
        config: submitted.redacted(),
        running: state.es.is_some(),
        health,
        requires_restart,
    }))
}

/// `POST /api/v1/settings/elasticsearch/test` — connectivity probe.
///
/// With a body, tests the supplied configuration; without one, tests the live
/// shipper (or the stored configuration when nothing is running).
async fn test(
    State(state): State<AppState>,
    current: AuthUser,
    body: Option<Json<EsConfig>>,
) -> Result<Json<EsTestResult>, ApiError> {
    current.require_admin().map_err(ApiError::from)?;

    // Prefer an explicit submission, else the running client, else the stored
    // config. Redacted stored configs cannot be re-probed (secrets masked), so
    // fall back to the live client in that case.
    if let Some(Json(mut submitted)) = body {
        submitted.normalise();
        if submitted.enabled {
            submitted
                .validate()
                .map_err(|err| ApiError::Unprocessable(err.to_string()))?;
        }
        return Ok(Json(run_probe(submitted).await));
    }

    if let Some(client) = &state.es {
        return Ok(Json(match client.health_check().await {
            Ok(health) => EsTestResult {
                ok: true,
                health: Some(health),
                error: None,
                template_installed: true,
            },
            Err(err) => EsTestResult {
                ok: false,
                health: None,
                error: Some(err.to_string()),
                template_installed: false,
            },
        }));
    }

    let stored = state.config.elasticsearch.clone().unwrap_or_default();
    if !stored.is_active() {
        return Err(ApiError::BadRequest(
            "no elasticsearch configuration to test; submit one in the request body".to_string(),
        ));
    }
    Ok(Json(run_probe(stored).await))
}

/// Builds an ephemeral client, checks health and installs the template.
async fn run_probe(mut config: EsConfig) -> EsTestResult {
    config.normalise();
    let client = match ElasticsearchClient::new(config).await {
        Ok(client) => client,
        Err(err) => {
            return EsTestResult {
                ok: false,
                health: None,
                error: Some(err.to_string()),
                template_installed: false,
            }
        },
    };

    let health = match client.health_check().await {
        Ok(health) => health,
        Err(err) => {
            let _ = client.shutdown().await;
            return EsTestResult {
                ok: false,
                health: None,
                error: Some(err.to_string()),
                template_installed: false,
            };
        },
    };

    let template_installed = ensure_index_template(&client).await.is_ok();
    let _ = client.shutdown().await;

    EsTestResult {
        ok: true,
        health: Some(health),
        error: None,
        template_installed,
    }
}

/// Probe variant that surfaces failures as API errors (used by `update`).
async fn probe(config: EsConfig) -> Result<EsHealth, ApiError> {
    let result = run_probe(config).await;
    match result.health {
        Some(health) if result.ok => Ok(health),
        _ => {
            Err(ApiError::Unprocessable(result.error.unwrap_or_else(|| {
                "elasticsearch is unreachable".to_string()
            })))
        },
    }
}
