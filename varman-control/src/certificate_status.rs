//! Certificate status values shared by the REST API, the gRPC plane and MCP.

/// Certificate is issued and served.
pub const ACTIVE: &str = "active";
/// An issuance or renewal order is in flight.
pub const PENDING: &str = "pending";
/// The certificate lapsed.
pub const EXPIRED: &str = "expired";
/// The last issuance attempt gave up.
pub const FAILED: &str = "failed";

/// True when `status` is one of the four known values.
pub fn is_valid(status: &str) -> bool {
    matches!(status, ACTIVE | PENDING | EXPIRED | FAILED)
}
