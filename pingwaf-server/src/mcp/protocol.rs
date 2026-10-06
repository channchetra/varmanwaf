//! MCP JSON-RPC 2.0 plumbing: framing, protocol-version negotiation and the
//! error codes the spec assigns.

use serde_json::{json, Value};

/// Newest protocol revision this server implements.
pub const LATEST_PROTOCOL_VERSION: &str = "2025-06-18";

/// Revisions the server accepts on `initialize`; anything newer is answered
/// with [`LATEST_PROTOCOL_VERSION`].
pub const SUPPORTED_PROTOCOL_VERSIONS: [&str; 3] =
    ["2024-11-05", "2025-03-26", "2025-06-18"];

pub const SERVER_NAME: &str = "pingwaf";
pub const SERVER_TITLE: &str = "PingWAF control plane";
pub const SERVER_VERSION: &str = env!("CARGO_PKG_VERSION");

// JSON-RPC 2.0 error codes.
pub const PARSE_ERROR: i64 = -32700;
pub const INVALID_REQUEST: i64 = -32600;
pub const METHOD_NOT_FOUND: i64 = -32601;
pub const INVALID_PARAMS: i64 = -32602;
pub const INTERNAL_ERROR: i64 = -32603;

/// Text sent in the `initialize` result; it is the server's one chance to
/// explain itself to a fresh agent, so keep it operational rather than
/// marketing.
pub const INSTRUCTIONS: &str = "PingWAF is a distributed WAF and reverse proxy. This endpoint exposes its control plane: sites, agents, TLS certificates, traffic and security logs, IP groups, and the platform's own defense settings.\n\nSuggested workflow: resolve names with list_sites first, then use get_traffic_summary and query_access_logs (or query_waf_events) to investigate an incident, and get_defense_status before proposing protection changes. Write tools change live configuration, are pushed to the data plane immediately, and are only exposed to callers with write permission. All timestamps are UTC.";

/// A `result` response.
pub fn result(id: &Value, result: Value) -> Value {
    json!({ "jsonrpc": "2.0", "id": id, "result": result })
}

/// An `error` response.
pub fn error(id: &Value, code: i64, message: impl Into<String>) -> Value {
    json!({
        "jsonrpc": "2.0",
        "id": id,
        "error": { "code": code, "message": message.into() },
    })
}

/// The revision used for this session: the client's when supported, the
/// latest otherwise.
pub fn negotiate_version(requested: Option<&str>) -> &'static str {
    requested
        .and_then(|version| {
            SUPPORTED_PROTOCOL_VERSIONS
                .iter()
                .find(|supported| **supported == version)
                .copied()
        })
        .unwrap_or(LATEST_PROTOCOL_VERSION)
}

/// The `initialize` result for the given params.
pub fn initialize_result(params: &Value) -> Value {
    let requested = params.get("protocolVersion").and_then(Value::as_str);
    json!({
        "protocolVersion": negotiate_version(requested),
        "capabilities": {
            "tools": { "listChanged": false },
            "resources": { "subscribe": false, "listChanged": false },
            "prompts": { "listChanged": false },
        },
        "serverInfo": {
            "name": SERVER_NAME,
            "title": SERVER_TITLE,
            "version": SERVER_VERSION,
        },
        "instructions": INSTRUCTIONS,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn versions_are_negotiated_down_to_something_supported() {
        assert_eq!(negotiate_version(None), LATEST_PROTOCOL_VERSION);
        assert_eq!(negotiate_version(Some("2024-11-05")), "2024-11-05");
        assert_eq!(negotiate_version(Some("2025-03-26")), "2025-03-26");
        assert_eq!(
            negotiate_version(Some("2025-06-18")),
            LATEST_PROTOCOL_VERSION
        );
        // Unknown/future revisions fall back to the latest supported one.
        assert_eq!(
            negotiate_version(Some("2099-01-01")),
            LATEST_PROTOCOL_VERSION
        );
        assert!(SUPPORTED_PROTOCOL_VERSIONS.contains(&LATEST_PROTOCOL_VERSION));
    }

    #[test]
    fn initialize_advertises_the_three_capability_families() {
        let result = initialize_result(&json!({
            "protocolVersion": "2025-03-26",
            "clientInfo": { "name": "test", "version": "1" },
        }));
        assert_eq!(result["protocolVersion"], "2025-03-26");
        assert!(result["capabilities"]["tools"].is_object());
        assert!(result["capabilities"]["resources"].is_object());
        assert!(result["capabilities"]["prompts"].is_object());
        assert_eq!(result["serverInfo"]["name"], SERVER_NAME);
        assert!(result["instructions"].as_str().unwrap().len() > 100);
    }

    #[test]
    fn responses_carry_the_jsonrpc_envelope() {
        let ok = result(&json!(7), json!({ "tools": [] }));
        assert_eq!(ok["jsonrpc"], "2.0");
        assert_eq!(ok["id"], 7);
        assert!(ok.get("error").is_none());

        let failed = error(&json!("abc"), METHOD_NOT_FOUND, "nope");
        assert_eq!(failed["error"]["code"], METHOD_NOT_FOUND);
        assert_eq!(failed["error"]["message"], "nope");
    }
}
