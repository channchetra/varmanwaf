//! REST API composition.
//!
//! Every route module contributes a `Router<AppState>` with paths relative to
//! `/api/v1`; this module merges them, attaches the shared middleware stack and
//! finally bakes the [`AppState`] in.

pub mod agents;
pub mod ai;
pub mod analytics;
pub mod api_protection;
pub mod auth;
pub mod blocked_ips;
pub mod bot;
pub mod cache;
pub mod challenge;
pub mod common;
pub mod debug;
pub mod defense;
pub mod error;
pub mod error_pages;
pub mod geo;
pub mod ip_groups;
pub mod ip_rules;
pub mod keys;
pub mod log_retention;
pub mod logs;
pub mod mcp;
pub mod mtls;
pub mod passkeys;
pub mod rate_limiting;
pub mod rewrite;
pub mod rules;
pub mod self_protection;
pub mod settings;
pub mod site_basic_auth;
pub mod sites;
pub mod ssl;
pub mod state;
pub mod system_tls;
pub mod waf_settings;

use crate::frontend::serve_frontend;
use crate::tls::ConnInfo;
use axum::extract::connect_info::ConnectInfo;
use axum::extract::{Request, State};
use axum::http::{HeaderValue, Method, StatusCode};
use axum::middleware::{self, Next};
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use axum::Json;
use axum::Router;
use serde_json::json;
use tower_http::compression::CompressionLayer;
use tower_http::cors::{AllowOrigin, CorsLayer};
use tower_http::trace::TraceLayer;

pub use error::{error_response, ApiError};
pub use state::AppState;

/// Prefix every REST route lives under.
pub const API_PREFIX: &str = "/api/v1";

/// Builds the complete HTTP router, including CORS, compression and tracing.
pub fn build_router(state: AppState) -> Router {
    let config = state.config.clone();

    let api = Router::new()
        .merge(auth::routes())
        .merge(sites::routes())
        .merge(site_basic_auth::routes())
        .merge(keys::routes())
        .merge(agents::routes())
        .merge(rules::routes())
        .merge(rate_limiting::routes())
        .merge(cache::routes())
        .merge(logs::routes())
        .merge(analytics::routes())
        .merge(settings::routes())
        .merge(log_retention::routes())
        .merge(ssl::routes())
        .merge(mtls::routes())
        .merge(passkeys::routes())
        .merge(ip_rules::routes())
        .merge(ip_groups::routes())
        .merge(blocked_ips::routes())
        .merge(geo::routes())
        .merge(bot::routes())
        .merge(challenge::routes())
        .merge(waf_settings::routes())
        .merge(rewrite::routes())
        .merge(error_pages::routes())
        .merge(debug::routes())
        .merge(system_tls::routes())
        .merge(defense::routes())
        .merge(api_protection::routes())
        .merge(ai::routes())
        .merge(mcp::routes())
        .route("/health", get(health))
        .route("/version", get(version))
        .fallback(api_not_found);

    let mut root = Router::new()
        .nest(API_PREFIX, api)
        // The hosted MCP endpoint lives outside `/api/v1` (clients append
        // `/mcp` to the base URL), and hanging off the root router is what
        // makes the self-protection stack below (access log, IP allowlist,
        // WAF) cover it automatically.
        .merge(crate::mcp::routes())
        // Load balancers and container probes usually hit the root path.
        .route("/healthz", get(health));
    // Serve the embedded React frontend for all non-API routes (SPA)
    if config.serve_frontend {
        root = root.fallback(serve_frontend);
    }

    let redirect = RedirectState {
        tls_enabled: state.control_tls.is_enabled(),
    };
    root.layer(middleware::from_fn_with_state(
        redirect,
        redirect_cleartext_to_https,
    ))
    .layer(build_cors(&config.cors_origins))
    .layer(CompressionLayer::new())
    .layer(TraceLayer::new_for_http().make_span_with(
        |request: &axum::http::Request<_>| {
            tracing::info_span!(
                "http_request",
                method = %request.method(),
                path = %request.uri().path(),
            )
        },
    ))
    // Self-protection wraps everything above: the access log sees the final
    // status code, and a request the allowlist or the WAF refuses never
    // reaches the tracing/compression stack. Later `.layer` calls are the
    // outer ones, so `access_log` ends up first.
    .layer(middleware::from_fn_with_state(
        state.clone(),
        self_protection::waf_guard,
    ))
    .layer(middleware::from_fn_with_state(
        state.clone(),
        self_protection::ip_allowlist,
    ))
    .layer(middleware::from_fn_with_state(
        state.clone(),
        self_protection::access_log,
    ))
    .with_state(state)
}

/// Permissive by default (the dashboard is served from the same origin in
/// production); an explicit `cors_origins` list restricts it.
fn build_cors(origins: &[String]) -> CorsLayer {
    let layer = CorsLayer::new()
        .allow_methods([
            Method::GET,
            Method::POST,
            Method::PUT,
            Method::PATCH,
            Method::DELETE,
            Method::OPTIONS,
        ])
        .allow_headers([
            axum::http::header::AUTHORIZATION,
            axum::http::header::CONTENT_TYPE,
            axum::http::header::ACCEPT,
        ])
        .max_age(std::time::Duration::from_secs(3600));

    let parsed: Vec<HeaderValue> = origins
        .iter()
        .filter_map(|origin| match origin.parse::<HeaderValue>() {
            Ok(value) => Some(value),
            Err(err) => {
                tracing::warn!(%origin, error = %err, "ignoring invalid CORS origin");
                None
            }
        })
        .collect();

    if parsed.is_empty() {
        tracing::warn!("no CORS origins configured, allowing any origin");
        layer.allow_origin(AllowOrigin::any())
    } else {
        tracing::info!(origins = ?parsed, "CORS restricted to the configured origins");
        layer.allow_origin(AllowOrigin::list(parsed))
    }
}

/// State of the redirect middleware: whether this process terminates TLS.
///
/// Deliberately smaller than [`AppState`] — the middleware needs no database,
/// which is what lets its connection handling be tested over real sockets.
#[derive(Clone, Copy, Debug)]
pub struct RedirectState {
    pub tls_enabled: bool,
}

/// Sends cleartext requests to the HTTPS listener.
///
/// Only meaningful when this process terminates TLS: the mixed listener keeps
/// accepting plaintext so probes and an operator typing `http://` get a real
/// HTTP answer instead of a reset, and this middleware is what turns that
/// answer into a redirect. Health endpoints are exempt so container and load
/// balancer probes keep working without trusting a certificate. The decision
/// is made from the connection, not from `X-Forwarded-Proto`: a caller talking
/// plaintext to this port must not be able to talk its way past the redirect.
async fn redirect_cleartext_to_https(
    State(state): State<RedirectState>,
    request: Request,
    next: Next,
) -> Response {
    // The extension is `ConnectInfo<ConnInfo>`, not `ConnInfo`: axum inserts
    // the newtype its connect-info service builds. Reading the inner type
    // directly always misses, which silently redirects every TLS request to
    // itself — a loop the browser reports as too many redirects.
    let secured = request
        .extensions()
        .get::<ConnectInfo<ConnInfo>>()
        .is_some_and(|info| info.0.tls);
    if !state.tls_enabled || secured || is_health_probe(request.uri().path()) {
        return next.run(request).await;
    }

    match https_location(&request) {
        // `308` keeps the method and body, which a `301` would not.
        Some(location) => (
            StatusCode::PERMANENT_REDIRECT,
            [(axum::http::header::LOCATION, location)],
        )
            .into_response(),
        // Without a Host header there is no absolute URL to build; let the
        // request through so the failure is the usual 400 rather than a
        // redirect loop.
        None => next.run(request).await,
    }
}

/// The `https://` URL of the request, when the Host header allows building one.
fn https_location(request: &Request) -> Option<HeaderValue> {
    let host = request
        .headers()
        .get(axum::http::header::HOST)?
        .to_str()
        .ok()?;
    let target = request
        .uri()
        .path_and_query()
        .map(|value| value.as_str())
        .unwrap_or("/");
    HeaderValue::from_str(&format!("https://{host}{target}")).ok()
}

/// Paths that answer on both schemes, so probes need no certificate.
pub(crate) fn is_health_probe(path: &str) -> bool {
    matches!(path, "/healthz" | "/api/v1/health")
}

/// `GET /healthz` and `GET /api/v1/health` — verifies the database is reachable.
async fn health(State(state): State<AppState>) -> Response {
    match state.db.ping().await {
        Ok(()) => (
            StatusCode::OK,
            Json(json!({ "status": "ok", "database": "up" })),
        )
            .into_response(),
        Err(err) => {
            tracing::error!(error = %err, "database health check failed");
            (
                StatusCode::SERVICE_UNAVAILABLE,
                Json(json!({ "status": "degraded", "database": "down" })),
            )
                .into_response()
        },
    }
}

/// `GET /api/v1/version` — build metadata the frontend shows in the footer.
async fn version(State(state): State<AppState>) -> Json<serde_json::Value> {
    Json(json!({
        "name": env!("CARGO_PKG_NAME"),
        "version": env!("CARGO_PKG_VERSION"),
        "api": API_PREFIX,
        "registration_open": state.config.allow_registration,
    }))
}

/// JSON 404 for unmatched API routes, so the frontend never has to
/// parse an HTML error page for API calls.
async fn api_not_found(uri: axum::http::Uri) -> Response {
    (
        StatusCode::NOT_FOUND,
        Json(json!({
            "error": {
                "code": "not_found",
                "message": format!("no route matches {}", uri.path()),
            }
        })),
    )
        .into_response()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn request(uri: &str, host: Option<&str>) -> Request {
        let mut builder = Request::builder().uri(uri);
        if let Some(host) = host {
            builder = builder.header(axum::http::header::HOST, host);
        }
        builder.body(axum::body::Body::empty()).unwrap()
    }

    #[test]
    fn cors_accepts_explicit_origins() {
        let _ = build_cors(&["http://localhost:5173".to_string()]);
        let _ = build_cors(&[]);
        // An unparsable origin is dropped rather than panicking.
        let _ = build_cors(&["not a header value".to_string()]);
    }

    #[test]
    fn the_redirect_target_keeps_the_path_query_and_port() {
        let location = https_location(&request(
            "/api/v1/sites?page=2",
            Some("waf.example.com:9080"),
        ))
        .unwrap();
        assert_eq!(
            location,
            "https://waf.example.com:9080/api/v1/sites?page=2"
        );

        // An empty path still points at the root.
        assert_eq!(
            https_location(&request("/", Some("localhost:9080"))).unwrap(),
            "https://localhost:9080/"
        );
        // Without a Host header there is nothing to redirect to.
        assert!(https_location(&request("/", None)).is_none());
    }

    #[test]
    fn only_health_endpoints_answer_on_both_schemes() {
        assert!(is_health_probe("/healthz"));
        assert!(is_health_probe("/api/v1/health"));
        assert!(!is_health_probe("/api/v1/sites"));
        assert!(!is_health_probe("/healthz/extra"));
    }

    /// Drives the middleware over real sockets, with the same listener wiring
    /// `serve_http` uses: what matters here is that a TLS connection is seen as
    /// secured, since reading the wrong connect-info type redirects it to
    /// itself and makes the dashboard unreachable over HTTPS.
    #[tokio::test]
    async fn the_redirect_only_fires_on_cleartext_connections() {
        use crate::pki::tls::{
            crypto_provider, generate_self_signed, parse_chain,
        };
        use crate::tls::{ControlPlaneTls, MixedListener};
        use rustls::pki_types::ServerName;
        use rustls::RootCertStore;
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        use tokio::net::{TcpListener, TcpStream};
        use tokio_rustls::TlsConnector;

        let material =
            generate_self_signed("PingWAF", &["localhost".to_string()], 30)
                .unwrap();
        let tls = ControlPlaneTls::new(true);
        tls.activate(&material.cert_pem, material.key_pem.as_deref().unwrap())
            .unwrap();

        let router = Router::new()
            .route("/dashboard", get(|| async { "ok" }))
            .route("/healthz", get(|| async { "ok" }))
            .layer(middleware::from_fn_with_state(
                RedirectState { tls_enabled: true },
                redirect_cleartext_to_https,
            ));

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let listener = MixedListener::new(listener, tls.acceptor());
        tokio::spawn(async move {
            let _ = axum::serve(
                listener,
                router.into_make_service_with_connect_info::<ConnInfo>(),
            )
            .await;
        });

        const REQUEST: &str =
            "GET /dashboard HTTP/1.1\r\nHost: waf.example.com\r\nConnection: close\r\n\r\n";

        // Cleartext: a real HTTP answer, pointing at the TLS address.
        let mut plain = TcpStream::connect(addr).await.unwrap();
        plain.write_all(REQUEST.as_bytes()).await.unwrap();
        let mut reply = String::new();
        plain.read_to_string(&mut reply).await.unwrap();
        assert!(reply.starts_with("HTTP/1.1 308"), "{reply}");
        assert!(
            reply.contains("location: https://waf.example.com/dashboard"),
            "{reply}"
        );

        // Cleartext probe: answered without a certificate.
        let mut probe = TcpStream::connect(addr).await.unwrap();
        probe
            .write_all(
                b"GET /healthz HTTP/1.1\r\nHost: waf.example.com\r\nConnection: close\r\n\r\n",
            )
            .await
            .unwrap();
        let mut reply = String::new();
        probe.read_to_string(&mut reply).await.unwrap();
        assert!(reply.starts_with("HTTP/1.1 200"), "{reply}");

        // TLS: served as-is.
        let mut roots = RootCertStore::empty();
        roots
            .add(parse_chain(&material.cert_pem).unwrap().remove(0))
            .unwrap();
        let client_config = rustls::ClientConfig::builder_with_provider(
            crypto_provider().clone(),
        )
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_root_certificates(roots)
        .with_no_client_auth();
        let connector = TlsConnector::from(std::sync::Arc::new(client_config));
        let name = ServerName::try_from("localhost").unwrap();
        let mut secure = connector
            .connect(name, TcpStream::connect(addr).await.unwrap())
            .await
            .unwrap();
        secure.write_all(REQUEST.as_bytes()).await.unwrap();
        let mut reply = String::new();
        secure.read_to_string(&mut reply).await.unwrap();
        assert!(reply.starts_with("HTTP/1.1 200"), "{reply}");
    }
}
