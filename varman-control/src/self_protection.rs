//! Control-plane self-protection state.
//!
//! The middleware that enforces the policy lives in
//! [`crate::api::self_protection`]. This module owns the shared value types it
//! needs, so [`crate::api::state::AppState`] can hold the handle without the
//! state module depending on the HTTP middleware module.

use std::collections::HashSet;
use std::net::IpAddr;
use std::str::FromStr;
use std::sync::{Arc, Mutex};

use arc_swap::ArcSwap;
use chrono::{DateTime, Utc};
use ipnet::IpNet;
use sea_orm::{DatabaseConnection, EntityTrait, Set};
use tokio::sync::mpsc;
use varman_waf::WafEngine;

use crate::models::control_plane_access_log;

/// Rows buffered for one insert.
pub(crate) const LOG_INSERT_BATCH: usize = 200;

/// Pending access-log records before writes are dropped.
pub(crate) const LOG_QUEUE_CAPACITY: usize = 4096;

/// Parsed allow/deny ranges.
#[derive(Debug, Default)]
pub struct Allowlist {
    networks: Vec<IpNet>,
    addresses: HashSet<IpAddr>,
}

impl Allowlist {
    /// Parses every entry; entries that are neither an address nor a CIDR
    /// network are returned as errors (callers decide to refuse or skip).
    pub fn parse<I, S>(values: I) -> (Self, Vec<String>)
    where
        I: IntoIterator<Item = S>,
        S: AsRef<str>,
    {
        let mut networks = Vec::new();
        let mut addresses = HashSet::new();
        let mut invalid = Vec::new();
        for value in values {
            let value = value.as_ref().trim();
            if value.is_empty() {
                continue;
            }
            if let Ok(net) = IpNet::from_str(value) {
                networks.push(net);
            } else if let Ok(addr) = IpAddr::from_str(value) {
                addresses.insert(normalize_ip(&addr));
            } else {
                invalid.push(value.to_string());
            }
        }
        (
            Self {
                networks,
                addresses,
            },
            invalid,
        )
    }

    pub fn is_empty(&self) -> bool {
        self.networks.is_empty() && self.addresses.is_empty()
    }

    pub fn len(&self) -> usize {
        self.networks.len() + self.addresses.len()
    }

    /// Whether `ip` is covered. IPv4-mapped IPv6 peers are folded to IPv4
    /// first so `127.0.0.1` matches a `::ffff:127.0.0.1` connection, and an
    /// IPv6-mapped network (`::ffff:0:0/96`) matches an IPv4 peer.
    pub fn contains(&self, ip: &IpAddr) -> bool {
        let ip = normalize_ip(ip);
        self.addresses.contains(&ip)
            || self.networks.iter().any(|net| match (net, &ip) {
                (IpNet::V6(_), IpAddr::V4(v4)) => {
                    net.contains(&IpAddr::V6(v4.to_ipv6_mapped()))
                },
                _ => net.contains(&ip),
            })
    }
}

/// Folds IPv4-mapped IPv6 addresses (`::ffff:a.b.c.d`) onto their IPv4 form.
pub fn normalize_ip(ip: &IpAddr) -> IpAddr {
    match ip {
        IpAddr::V6(v6) => v6
            .to_ipv4_mapped()
            .map(IpAddr::V4)
            .unwrap_or(IpAddr::V6(*v6)),
        other => *other,
    }
}

/// Everything the middlewares enforce, rebuilt whenever the settings change.
pub struct ProtectionPolicy {
    pub access_log_enabled: bool,
    pub allowlist_enabled: bool,
    pub allowlist: Allowlist,
    /// Refuse specific addresses even when the allowlist accepts them.
    pub denylist_enabled: bool,
    pub denylist: Allowlist,
    /// Built only when the WAF is enabled; `None` short-circuits the guard.
    pub waf: Option<Arc<WafEngine>>,
    /// True when the WAF answers blocks (vs. monitor mode).
    pub waf_blocking: bool,
    /// `updated_at` of the settings row this policy was built from.
    pub settings_updated_at: DateTime<Utc>,
    /// `updated_at` of the referenced `ip_groups` row, if any. Editing or
    /// enabling the group must rebuild the policy even when the settings row
    /// itself did not change.
    pub group_updated_at: Option<DateTime<Utc>>,
}

impl Default for ProtectionPolicy {
    fn default() -> Self {
        Self {
            access_log_enabled: false,
            allowlist_enabled: false,
            allowlist: Allowlist::default(),
            denylist_enabled: false,
            denylist: Allowlist::default(),
            waf: None,
            waf_blocking: false,
            settings_updated_at: DateTime::<Utc>::MIN_UTC,
            group_updated_at: None,
        }
    }
}

/// Read-mostly handle shared through [`crate::api::state::AppState`].
pub struct SelfProtection {
    policy: ArcSwap<ProtectionPolicy>,
    log_tx: mpsc::Sender<LogRecord>,
    /// Parked here until [`SelfProtection::spawn_writer`] runs; the struct
    /// itself only ever uses the sender.
    log_rx: Mutex<Option<mpsc::Receiver<LogRecord>>>,
}

impl SelfProtection {
    /// Creates the handle and the log channel. Call
    /// [`SelfProtection::spawn_writer`] from an async context to start
    /// persisting records; without it records queue up and are dropped.
    pub fn new() -> Self {
        let (log_tx, log_rx) = mpsc::channel(LOG_QUEUE_CAPACITY);
        Self {
            policy: ArcSwap::from_pointee(ProtectionPolicy::default()),
            log_tx,
            log_rx: Mutex::new(Some(log_rx)),
        }
    }

    pub fn policy(&self) -> Arc<ProtectionPolicy> {
        self.policy.load_full()
    }

    pub fn store(&self, policy: ProtectionPolicy) {
        self.policy.store(Arc::new(policy));
    }

    /// Queues one access-log record; never blocks. A full queue drops the
    /// record and says so — losing a log line beats stalling the request.
    pub fn record(&self, record: LogRecord) {
        if let Err(err) = self.log_tx.try_send(record) {
            tracing::warn!(
                error = %err,
                "control plane access log queue is full, dropping record"
            );
        }
    }

    /// Starts the background writer over the given database connection.
    /// A second call is a no-op.
    pub fn spawn_writer(&self, db: DatabaseConnection) {
        let rx = self.log_rx.lock().unwrap_or_else(|e| e.into_inner()).take();
        if let Some(rx) = rx {
            tokio::spawn(write_logs(db, rx));
        }
    }
}

impl Default for SelfProtection {
    fn default() -> Self {
        Self::new()
    }
}

/// One pending access-log row.
#[derive(Debug, Clone)]
pub struct LogRecord {
    pub request_id: Option<String>,
    pub timestamp: DateTime<Utc>,
    pub client_ip: String,
    pub method: String,
    pub host: Option<String>,
    pub path: String,
    pub query_string: Option<String>,
    pub scheme: Option<String>,
    pub protocol: Option<String>,
    pub status_code: Option<i32>,
    pub latency_ms: Option<i64>,
    pub user_agent: Option<String>,
    pub referer: Option<String>,
    pub user_id: Option<uuid::Uuid>,
    pub user_email: Option<String>,
    pub action: String,
    pub reason: Option<String>,
}

impl LogRecord {
    fn into_active(self) -> control_plane_access_log::ActiveModel {
        control_plane_access_log::ActiveModel {
            id: sea_orm::NotSet,
            request_id: Set(self.request_id),
            timestamp: Set(self.timestamp),
            client_ip: Set(self.client_ip),
            method: Set(self.method),
            host: Set(self.host),
            path: Set(self.path),
            query_string: Set(self.query_string),
            scheme: Set(self.scheme),
            protocol: Set(self.protocol),
            status_code: Set(self.status_code),
            latency_ms: Set(self.latency_ms),
            user_agent: Set(self.user_agent),
            referer: Set(self.referer),
            user_id: Set(self.user_id),
            user_email: Set(self.user_email),
            action: Set(self.action),
            reason: Set(self.reason),
        }
    }
}

/// Drains the channel into `control_plane_access_logs`, one insert per batch.
async fn write_logs(db: DatabaseConnection, mut rx: mpsc::Receiver<LogRecord>) {
    let mut batch: Vec<LogRecord> = Vec::with_capacity(LOG_INSERT_BATCH);
    loop {
        // Block for the first record, then take whatever else is queued.
        let Some(first) = rx.recv().await else {
            break;
        };
        batch.push(first);
        while batch.len() < LOG_INSERT_BATCH {
            match rx.try_recv() {
                Ok(record) => batch.push(record),
                Err(_) => break,
            }
        }
        let models: Vec<_> =
            batch.drain(..).map(LogRecord::into_active).collect();
        if let Err(err) = control_plane_access_log::Entity::insert_many(models)
            .exec(&db)
            .await
        {
            tracing::warn!(
                error = %err,
                "failed to write control plane access log batch"
            );
        }
    }
}
