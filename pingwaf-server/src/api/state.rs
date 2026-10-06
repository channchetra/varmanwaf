//! Shared application state handed to every Axum handler.

use std::sync::Arc;

use chrono::{DateTime, Utc};
use sea_orm::DatabaseConnection;

use crate::api::self_protection::SelfProtection;
use crate::config::ServerConfig;
use crate::es::ElasticsearchClient;
use crate::grpc::cache_status::CacheStatusRegistry;
use crate::grpc::AgentRegistry;
use crate::tls::ControlPlaneTls;

/// Everything an HTTP handler needs.
///
/// Cloning is cheap: the SeaORM connection pool and the agent registry are both
/// internally reference counted.
#[derive(Clone)]
pub struct AppState {
    /// SeaORM connection pool (PostgreSQL).
    pub db: DatabaseConnection,
    /// Immutable server configuration.
    pub config: Arc<ServerConfig>,
    /// Live agent heartbeat streams, used to push commands from the API.
    pub agents: AgentRegistry,
    /// Elasticsearch log shipper, present only when ES is configured and
    /// enabled. `None` keeps the control plane PostgreSQL-only.
    pub es: Option<Arc<ElasticsearchClient>>,
    /// Latest per-site edge cache usage reported by agent heartbeats, backing
    /// `/api/v1/cache/status`.
    pub cache_status: CacheStatusRegistry,
    /// Certificate the dashboard's own HTTPS listener presents. Shared with
    /// the listener so an upload takes effect without a restart.
    pub control_tls: Arc<ControlPlaneTls>,
    /// Self-protection of the 9080 listener: access log, IP allowlist, WAF.
    pub protection: Arc<SelfProtection>,
}

impl AppState {
    pub fn new(
        db: DatabaseConnection,
        config: ServerConfig,
        agents: AgentRegistry,
    ) -> Self {
        Self {
            db,
            config: Arc::new(config),
            agents,
            es: None,
            cache_status: CacheStatusRegistry::new(),
            control_tls: Arc::new(ControlPlaneTls::new(false)),
            protection: Arc::new(SelfProtection::new()),
        }
    }

    /// Same as [`AppState::new`] but sharing an existing cache status registry,
    /// which is what the gRPC service feeds.
    pub fn with_cache_status(
        db: DatabaseConnection,
        config: ServerConfig,
        agents: AgentRegistry,
        cache_status: CacheStatusRegistry,
    ) -> Self {
        Self {
            db,
            config: Arc::new(config),
            agents,
            es: None,
            cache_status,
            control_tls: Arc::new(ControlPlaneTls::new(false)),
            protection: Arc::new(SelfProtection::new()),
        }
    }

    /// JWT signing secret.
    pub fn jwt_secret(&self) -> &str {
        &self.config.jwt_secret
    }

    /// Access token lifetime in hours.
    pub fn jwt_expiration_hours(&self) -> i64 {
        self.config.jwt_expiration_hours
    }

    /// Refresh token lifetime in hours.
    pub fn refresh_expiration_hours(&self) -> i64 {
        self.config.refresh_token_expiration_hours
    }
}

/// Single source of truth for "now", so timestamps written by the API and by the
/// gRPC log shipper are directly comparable.
pub fn now() -> DateTime<Utc> {
    Utc::now()
}

/// Formats an optional timestamp as RFC 3339 for JSON responses.
pub fn format_timestamp(value: &Option<DateTime<Utc>>) -> Option<String> {
    value.map(|ts| ts.to_rfc3339())
}
