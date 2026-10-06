//! Certificate status of the sites the data plane serves.
//!
//! Agents cache rules and ship heartbeats, but the certificates themselves live
//! in the hosting process's certificate provider — an ACME-issued PEM never
//! passes through the agent. This module is the seam between the two: the host
//! registers a snapshot function once at startup, and every heartbeat reports
//! each site's certificate state so the control plane can stop showing a
//! successfully issued certificate as "pending".

use std::collections::HashMap;
use std::sync::{Arc, LazyLock, RwLock};

/// Certificate status of one site, in the vocabulary of the protocol.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CertStatus {
    /// `valid`, `expiring_soon` or `expired`.
    pub status: &'static str,
    /// Unix timestamp (seconds) when the certificate stops being valid.
    pub expires_at: i64,
}

/// Builds the site id → certificate status map.
pub type CertStatusSnapshot =
    Arc<dyn Fn() -> HashMap<String, CertStatus> + Send + Sync>;

/// Registered once at startup and read on every heartbeat; a plain lock is
/// plenty, and unlike `ArcSwapOption` it accepts an unsized trait object.
static CERT_STATUS_SNAPSHOT: LazyLock<RwLock<Option<CertStatusSnapshot>>> =
    LazyLock::new(|| RwLock::new(None));

/// Registers the snapshot the heartbeats report. Called by the host that owns
/// the certificate provider; without it heartbeats carry no SSL state.
pub fn set_snapshot(snapshot: Option<CertStatusSnapshot>) {
    if let Ok(mut guard) = CERT_STATUS_SNAPSHOT.write() {
        *guard = snapshot;
    }
}

/// Certificate status of every site the data plane currently holds.
///
/// Empty when no snapshot is registered, which the control plane reads as
/// "the edge knows nothing about certificates" rather than "issued".
pub fn snapshot() -> HashMap<String, CertStatus> {
    CERT_STATUS_SNAPSHOT
        .read()
        .ok()
        .and_then(|guard| guard.as_ref().map(|snapshot| snapshot()))
        .unwrap_or_default()
}
