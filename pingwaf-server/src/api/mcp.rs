//! Read-only status of the hosted MCP endpoint, rendered by the settings page.
//!
//! The endpoint has no switches of its own: it mounts with the control plane,
//! authenticates with console credentials and sits behind the same API
//! protection (access log, IP allowlist, WAF) as `/api/v1`. This view reports
//! what clients will find, so an operator can paste a client configuration
//! without digging through the docs.

use axum::routing::get;
use axum::{Json, Router};
use serde::Serialize;

use crate::api::error::ApiError;
use crate::api::state::AppState;
use crate::auth::AuthUser;
use crate::mcp::{prompts, resources, tools};

/// Routes contributed to `/api/v1`.
pub fn routes() -> Router<AppState> {
    Router::new().route("/settings/mcp", get(show))
}

/// What the MCP endpoint currently exposes.
#[derive(Debug, Serialize)]
pub struct McpStatusView {
    /// Path clients append to the console origin, e.g. `/mcp`.
    pub path: &'static str,
    /// Wire transport; this server speaks stateless Streamable HTTP (POST).
    pub transport: &'static str,
    /// Tool names in catalogue order, with their write requirement.
    pub tools: Vec<McpToolInfo>,
    /// Prompt count (canned investigation instructions).
    pub prompts: usize,
    /// Resource count (addressable read-only documents).
    pub resources: usize,
}

#[derive(Debug, Serialize)]
pub struct McpToolInfo {
    pub name: &'static str,
    /// Write tools need an API key carrying `write` whose owner is an
    /// administrator; read-only callers never see them in `tools/list`.
    pub write: bool,
}

/// Collects the status from the live catalogue.
fn status() -> McpStatusView {
    McpStatusView {
        path: "/mcp",
        transport: "streamable_http",
        tools: tools::specs()
            .into_iter()
            .map(|spec| McpToolInfo {
                name: spec.name,
                write: spec.write,
            })
            .collect(),
        // Counted from the same payloads the endpoint serves, so the numbers
        // cannot drift from the real catalogue.
        prompts: prompts::list()["prompts"].as_array().map_or(0, Vec::len),
        resources: resources::RESOURCES.len(),
    }
}

/// `GET /api/v1/settings/mcp` — any authenticated console user.
async fn show(_current: AuthUser) -> Result<Json<McpStatusView>, ApiError> {
    Ok(Json(status()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_status_reflects_the_live_catalogue() {
        let view = status();
        assert_eq!(view.path, "/mcp");
        assert_eq!(view.transport, "streamable_http");
        assert!(view
            .tools
            .iter()
            .any(|tool| tool.name == "list_sites" && !tool.write));
        assert!(view
            .tools
            .iter()
            .any(|tool| tool.name == "set_site_status" && tool.write));
        assert!(view.prompts >= 3);
        assert_eq!(view.resources, 5);
    }
}
