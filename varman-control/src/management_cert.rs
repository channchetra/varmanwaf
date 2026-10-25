//! Management-endpoint (dashboard) certificate: the desired request, the
//! certificate the edge issued, and the task that installs it on the 9080
//! listener.
//!
//! The dashboard is served by the control plane, but the only component that
//! can complete an ACME HTTP-01 challenge is the edge: it owns port 80 and
//! the challenge token store, and it answers `/.well-known/acme-challenge/*`
//! before host routing (so a dashboard *domain* that is not a proxied site
//! works too). In the all-in-one deployment both halves live in one process,
//! so:
//!
//! 1. the API stores the request here ([`set_desired`]),
//! 2. the data plane's config assembly turns it into a `__management`
//!    certificate entry, which the ACME task issues/renews (IP identities are
//!    ordered as RFC 8738 IP identifiers under the `shortlived` profile),
//! 3. the data plane publishes the issued material back ([`set_issued`]),
//! 4. [`spawn`] installs it on the listener and persists it with every other
//!    active control-plane certificate (`source = "acme"`).
//!
//! This is deliberately an in-process seam. A split deployment (control
//! plane without an edge on the same host) cannot complete the challenge, so
//! auto-issue stays disabled there ([`set_available`]); a self-signed or
//! uploaded certificate keeps working as before.

use std::net::IpAddr;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, LazyLock};
use std::time::Duration;

use arc_swap::ArcSwapOption;
use chrono::Utc;
use sea_orm::{ActiveModelTrait, DatabaseConnection, EntityTrait, Set};
use tokio::task::JoinHandle;
use tracing::{info, warn};
use uuid::Uuid;

use crate::api::state::AppState;
use crate::api::system_tls::store_and_activate;
use crate::models::certificate_events;
use crate::models::management_certificate::management_certificate as model;

/// Name of the certificate entry the data plane adds for the dashboard.
pub const CERT_NAME: &str = "__management";

/// How long an armed request may stay `pending` before it is marked failed.
const STALE_AFTER: Duration = Duration::from_secs(30 * 60);

/// How often [`spawn`] looks for a newly issued certificate.
const TICK: Duration = Duration::from_secs(15);

/// The certificate the dashboard should present.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Request {
    /// DNS name or IP literal the dashboard is reached by.
    pub identity: String,
    /// ACME contact address.
    pub email: String,
    /// Challenge type; only `http-01` is usable for the dashboard.
    pub challenge: String,
}

/// The certificate the edge actually issued, published by the data plane.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Issued {
    /// Identity the certificate was issued for.
    pub identity: String,
    pub cert_pem: String,
    pub key_pem: String,
}

static DESIRED: LazyLock<ArcSwapOption<Request>> =
    LazyLock::new(ArcSwapOption::empty);
static ISSUED: LazyLock<ArcSwapOption<Issued>> =
    LazyLock::new(ArcSwapOption::empty);
/// Bumped on every change so the data plane's config watcher reloads.
static REVISION: AtomicU64 = AtomicU64::new(0);
/// Whether an edge shares this process (all-in-one).
static AVAILABLE: AtomicBool = AtomicBool::new(false);

/// Records that an edge runs in this process, so auto-issue can work.
pub fn set_available(available: bool) {
    AVAILABLE.store(available, Ordering::Relaxed);
}

/// Whether auto-issue is usable in this deployment.
pub fn available() -> bool {
    AVAILABLE.load(Ordering::Relaxed)
}

/// Publishes the request. Bumps the revision even when the value is
/// unchanged, so an explicit retry reaches the data plane.
pub fn set_desired(request: Option<Request>) {
    DESIRED.store(request.map(Arc::new));
    REVISION.fetch_add(1, Ordering::Relaxed);
}

/// The request the data plane should issue, when armed.
pub fn desired() -> Option<Arc<Request>> {
    DESIRED.load_full()
}

/// Revision of the desired state; the config watcher compares it.
pub fn revision() -> u64 {
    REVISION.load(Ordering::Relaxed)
}

/// Publishes issued material from the data plane.
pub fn set_issued(issued: Option<Issued>) {
    ISSUED.store(issued.map(Arc::new));
}

/// The certificate the edge last reported, when any.
pub fn issued() -> Option<Arc<Issued>> {
    ISSUED.load_full()
}

/// Validates and normalises a dashboard identity: a DNS name or an IP
/// literal. Rejects schemes, paths and anything the CA would refuse anyway,
/// so the operator gets a clear error before an order is created.
pub fn normalize_identity(input: &str) -> Result<String, String> {
    let value = input.trim().to_ascii_lowercase();
    if value.is_empty() {
        return Err(
            "an identity (domain name or IP address) is required".to_string()
        );
    }
    if value.parse::<IpAddr>().is_ok() {
        return Ok(value);
    }
    if value.len() > 253 {
        return Err("the identity is longer than 253 characters".to_string());
    }
    if value.contains('/') || value.contains(' ') || value.contains('@') {
        return Err(
            "the identity must be a DNS name or an IP address, without a \
             scheme, port or path"
                .to_string(),
        );
    }
    let valid = value.contains('.')
        && !value.starts_with('.')
        && !value.ends_with('.')
        && !value.contains("..")
        && value.split('.').all(|label| {
            !label.is_empty()
                && label.len() <= 63
                && label.chars().all(|c| c.is_ascii_alphanumeric() || c == '-')
                && !label.starts_with('-')
                && !label.ends_with('-')
        });
    if !valid {
        return Err(
            "the identity must be a valid DNS name (e.g. waf.example.com) or \
             an IP address"
                .to_string(),
        );
    }
    Ok(value)
}

/// Validates an ACME contact address.
pub fn normalize_email(input: &str) -> Result<String, String> {
    let value = input.trim().to_string();
    let Some((local, domain)) = value.split_once('@') else {
        return Err("a valid contact email is required".to_string());
    };
    let valid = !local.is_empty()
        && local.len() <= 64
        && !domain.is_empty()
        && domain.len() <= 253
        && domain.contains('.')
        && !domain.starts_with('.')
        && !domain.ends_with('.')
        && !value.contains(' ')
        && value.len() <= 254;
    if !valid {
        return Err("a valid contact email is required".to_string());
    }
    Ok(value)
}

/// Loads the settings row, creating the disabled default on first use.
pub async fn load(db: &DatabaseConnection) -> anyhow::Result<model::Model> {
    if let Some(row) = model::Entity::find_by_id(1).one(db).await? {
        return Ok(row);
    }
    let now = Utc::now();
    let row = model::ActiveModel {
        id: Set(1),
        identity: Set(String::new()),
        email: Set(String::new()),
        challenge: Set("http-01".to_string()),
        enabled: Set(false),
        status: Set(model::STATUS_DISABLED.to_string()),
        failure_reason: Set(None),
        requested_at: Set(None),
        installed_fingerprint: Set(None),
        updated_at: Set(now),
    };
    if let Err(err) = row.insert(db).await {
        // A concurrent first read may have won the insert; re-read instead of
        // failing a request over it.
        if let Some(existing) = model::Entity::find_by_id(1).one(db).await? {
            return Ok(existing);
        }
        return Err(err.into());
    }
    Ok(model::Entity::find_by_id(1)
        .one(db)
        .await?
        .expect("management certificate row inserted"))
}

/// Applies an update: persists the row, publishes the desired state and
/// re-arms or disarms issuance.
pub async fn apply(
    db: &DatabaseConnection,
    row: model::Model,
    identity: String,
    email: String,
    enabled: bool,
) -> anyhow::Result<model::Model> {
    let mut active: model::ActiveModel = row.into();
    active.identity = Set(identity.clone());
    active.email = Set(email.clone());
    active.challenge = Set("http-01".to_string());
    active.enabled = Set(enabled);
    active.updated_at = Set(Utc::now());
    if enabled {
        active.status = Set(model::STATUS_PENDING.to_string());
        active.failure_reason = Set(None);
        active.requested_at = Set(Some(Utc::now()));
    } else {
        active.status = Set(model::STATUS_DISABLED.to_string());
        active.failure_reason = Set(None);
        active.requested_at = Set(None);
    }
    let row = active.update(db).await?;
    if enabled {
        set_desired(Some(Request {
            identity,
            email,
            challenge: "http-01".to_string(),
        }));
    } else {
        set_desired(None);
    }
    Ok(row)
}

/// Re-arms a failed or stuck request without changing its identity.
pub async fn retry(
    db: &DatabaseConnection,
    row: model::Model,
) -> anyhow::Result<model::Model> {
    let mut active: model::ActiveModel = row.into();
    active.enabled = Set(true);
    active.status = Set(model::STATUS_PENDING.to_string());
    active.failure_reason = Set(None);
    active.requested_at = Set(Some(Utc::now()));
    active.updated_at = Set(Utc::now());
    let row = active.update(db).await?;
    if row.identity.is_empty() {
        anyhow::bail!("set an identity before retrying");
    }
    set_desired(Some(Request {
        identity: row.identity.clone(),
        email: row.email.clone(),
        challenge: "http-01".to_string(),
    }));
    Ok(row)
}

/// Starts the installer task. It runs for the lifetime of the process.
pub fn spawn(state: AppState) -> JoinHandle<()> {
    tokio::spawn(async move {
        loop {
            tokio::time::sleep(TICK).await;
            if desired().is_none() {
                continue;
            }
            if let Err(err) = tick(&state).await {
                warn!(error = %err, "management certificate install failed");
            }
        }
    })
}

/// Whether issued material should replace what the listener serves.
///
/// The identity guard matters: after an edit from one domain/IP to another,
/// the edge may still report the *previous* identity's certificate until the
/// new order completes. Installing that one would make the handshake fail for
/// the new name.
fn install_needed(
    issued_identity: &str,
    desired_identity: &str,
    installed_fingerprint: Option<&str>,
    issued_fingerprint: &str,
) -> bool {
    issued_identity == desired_identity
        && installed_fingerprint != Some(issued_fingerprint)
}

/// One installer pass: install the reported certificate exactly once, and
/// fail a request that produced nothing for too long.
pub async fn tick(state: &AppState) -> anyhow::Result<()> {
    let Some(request) = desired() else {
        return Ok(());
    };
    let row = load(&state.db).await?;
    let Some(issued) = issued() else {
        return fail_if_stale(&state.db, &row).await;
    };
    let (meta, sans) =
        crate::pki::tls::describe(&issued.cert_pem).map_err(|err| {
            anyhow::anyhow!("unreadable issued certificate: {err}")
        })?;
    if !install_needed(
        &issued.identity,
        &request.identity,
        row.installed_fingerprint.as_deref(),
        &meta.fingerprint_sha256,
    ) {
        return fail_if_stale(&state.db, &row).await;
    }
    store_and_activate(
        state,
        None,
        crate::models::tls_source::ACME,
        &issued.cert_pem,
        &issued.key_pem,
        &meta,
        sans,
    )
    .await
    .map_err(|err| anyhow::anyhow!("cannot install the certificate: {err}"))?;

    let identity = request.identity.clone();
    let fingerprint = meta.fingerprint_sha256.clone();
    let mut active: model::ActiveModel = row.into();
    active.status = Set(model::STATUS_ACTIVE.to_string());
    active.failure_reason = Set(None);
    active.installed_fingerprint = Set(Some(fingerprint.clone()));
    active.updated_at = Set(Utc::now());
    active.update(&state.db).await?;

    write_event(
        &state.db,
        "management_certificate",
        format!(
            "Management certificate for {identity} installed \
             (source: Let's Encrypt, fingerprint {fingerprint})"
        ),
    )
    .await;
    info!(
        identity = %identity,
        fingerprint = %fingerprint,
        "management certificate installed on the control plane listener"
    );
    Ok(())
}

/// Marks a request failed when no certificate arrived within the window.
async fn fail_if_stale(
    db: &DatabaseConnection,
    row: &model::Model,
) -> anyhow::Result<()> {
    if row.status != model::STATUS_PENDING {
        return Ok(());
    }
    let Some(requested_at) = row.requested_at else {
        return Ok(());
    };
    let elapsed = Utc::now().signed_duration_since(requested_at);
    if elapsed < chrono::Duration::from_std(STALE_AFTER).unwrap_or_default() {
        return Ok(());
    }
    let identity = row.identity.clone();
    let reason = format!(
        "No certificate for {identity} was reported within 30 minutes. \
         Check that the edge runs on this host (all-in-one mode) and that DNS \
         points here; the raw ACME transcript is in the SSL Application log."
    );
    let mut active: model::ActiveModel = row.clone().into();
    active.status = Set(model::STATUS_FAILED.to_string());
    active.failure_reason = Set(Some(reason.clone()));
    active.updated_at = Set(Utc::now());
    active.update(db).await?;
    write_event(db, "issuance_failed", reason).await;
    warn!(identity = %identity, "management certificate request timed out");
    Ok(())
}

/// Appends an audit row to the certificate event log.
async fn write_event(
    db: &DatabaseConnection,
    event_type: &str,
    message: String,
) {
    let event = certificate_events::ActiveModel {
        id: Set(Uuid::new_v4()),
        certificate_id: Set(None),
        site_id: Set(None),
        event_type: Set(event_type.to_string()),
        message: Set(message),
        details: Set(None),
        created_at: Set(Utc::now()),
    };
    if let Err(err) = event.insert(db).await {
        warn!(%err, "failed to write management certificate event");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn identities_accept_domains_and_ip_literals() {
        assert_eq!(
            normalize_identity(" WAF.Example.com ").expect("domain"),
            "waf.example.com"
        );
        assert_eq!(
            normalize_identity("203.0.113.7").expect("ipv4"),
            "203.0.113.7"
        );
        assert_eq!(
            normalize_identity("2001:db8::1").expect("ipv6"),
            "2001:db8::1"
        );
        assert_eq!(
            normalize_identity("waf-admin.internal.example").expect("sub"),
            "waf-admin.internal.example"
        );
    }

    #[test]
    fn identities_reject_schemes_paths_and_garbage() {
        for value in [
            "",
            "https://waf.example.com",
            "waf.example.com:9080",
            "waf.example.com/admin",
            "waf",
            "waf..example.com",
            "-waf.example.com",
            "waf-.example.com",
            "waf example.com",
        ] {
            assert!(
                normalize_identity(value).is_err(),
                "{value:?} must be rejected"
            );
        }
    }

    #[test]
    fn emails_require_a_plausible_address() {
        assert_eq!(
            normalize_email(" ops@example.com ").expect("ok"),
            "ops@example.com"
        );
        for value in [
            "",
            "ops",
            "ops@",
            "@example.com",
            "ops@localhost",
            "a b@example.com",
        ] {
            assert!(
                normalize_email(value).is_err(),
                "{value:?} must be rejected"
            );
        }
    }

    #[test]
    fn desired_state_bumps_the_revision_even_when_unchanged() {
        set_desired(Some(Request {
            identity: "waf.example.com".to_string(),
            email: "ops@example.com".to_string(),
            challenge: "http-01".to_string(),
        }));
        let first = revision();
        set_desired(desired().as_deref().cloned());
        assert!(revision() > first, "an explicit retry must reach the edge");
        assert_eq!(
            desired().map(|request| request.identity.clone()),
            Some("waf.example.com".to_string())
        );
        set_desired(None);
        assert!(desired().is_none());
    }

    #[test]
    fn the_certificate_entry_name_is_reserved_and_stable() {
        // The data plane, the ACME task and the installer all address the
        // same entry; a typo would silently issue into a certificate nobody
        // installs.
        assert_eq!(CERT_NAME, "__management");
        assert!(!CERT_NAME.contains('/'));
    }

    #[test]
    fn installation_requires_the_same_identity_and_a_new_fingerprint() {
        // Fresh issuance: install.
        assert!(install_needed(
            "waf.example.com",
            "waf.example.com",
            None,
            "aa"
        ));
        // Renewal: the fingerprint changed, install once.
        assert!(install_needed(
            "waf.example.com",
            "waf.example.com",
            Some("aa"),
            "bb"
        ));
        // The same certificate reported again: do nothing.
        assert!(!install_needed(
            "waf.example.com",
            "waf.example.com",
            Some("aa"),
            "aa"
        ));
        // The identity was edited and the edge still reports the old
        // certificate: never install it for the new name.
        assert!(!install_needed(
            "old.example.com",
            "new.example.com",
            None,
            "aa"
        ));
        // An IP identity follows the same rule.
        assert!(install_needed("203.0.113.7", "203.0.113.7", None, "cc"));
    }
}
