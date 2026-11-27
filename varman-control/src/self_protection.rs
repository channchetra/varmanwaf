//! Control-plane self-protection state.
//!
//! The middlewares that enforce the policy live in
//! [`crate::api::self_protection`]. This module owns the shared value types
//! they need, the settings loader and the background refresher, so
//! [`crate::api::state::AppState`] can hold the handle without the state
//! module depending on the HTTP middleware module.

use std::collections::HashSet;
use std::net::IpAddr;
use std::str::FromStr;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use arc_swap::ArcSwap;
use chrono::{DateTime, Utc};
use ipnet::IpNet;
use sea_orm::sea_query::OnConflict;
use sea_orm::{DatabaseConnection, DbErr, EntityTrait, Set};
use tokio::sync::mpsc;
use varman_waf::{WafEngine, WafEngineConfig, WafMode};

use crate::app_state::AppState;
use crate::models::api_protection::waf_mode;
use crate::models::{
    api_protection_setting, control_plane_access_log, ip_groups,
};

/// Primary key of the single settings row.
const SETTINGS_ID: i32 = 1;

/// How often the background task re-reads the settings row.
pub const REFRESH_INTERVAL: Duration = Duration::from_secs(15);

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

/// Reads the settings row, creating it with the defaults if it is missing.
pub async fn load_settings(
    db: &DatabaseConnection,
) -> Result<api_protection_setting::Model, DbErr> {
    if let Some(row) = api_protection_setting::Entity::find_by_id(SETTINGS_ID)
        .one(db)
        .await?
    {
        return Ok(row);
    }

    let now = Utc::now();
    let insert = api_protection_setting::ActiveModel {
        id: Set(SETTINGS_ID),
        access_log_enabled: Set(true),
        access_log_retention_days: Set(
            crate::models::api_protection::DEFAULT_RETENTION_DAYS,
        ),
        ip_allowlist_enabled: Set(false),
        ip_allowlist_ranges: Set(Vec::new()),
        ip_allowlist_group_id: Set(None),
        ip_denylist_enabled: Set(false),
        ip_denylist_ranges: Set(Vec::new()),
        waf_enabled: Set(false),
        waf_mode: Set(waf_mode::BLOCK.to_string()),
        updated_at: Set(now),
    };
    let ignore_conflict =
        OnConflict::column(api_protection_setting::Column::Id)
            .do_nothing()
            .to_owned();
    match api_protection_setting::Entity::insert(insert)
        .on_conflict(ignore_conflict)
        .exec(db)
        .await
    {
        Ok(_) | Err(DbErr::RecordNotInserted) => {},
        Err(err) => return Err(err),
    }

    api_protection_setting::Entity::find_by_id(SETTINGS_ID)
        .one(db)
        .await?
        .ok_or_else(|| {
            DbErr::RecordNotFound(
                "api protection settings row vanished".to_string(),
            )
        })
}

/// The effective allowlist of a settings row: inline ranges plus the ranges
/// of the referenced group (when it exists and is enabled — a disabled group
/// is not deployed anywhere, so it contributes nothing here either).
pub async fn effective_allowlist(
    db: &DatabaseConnection,
    settings: &api_protection_setting::Model,
) -> Result<(Allowlist, Option<DateTime<Utc>>), DbErr> {
    let mut ranges = settings.ip_allowlist_ranges.clone();
    let mut group_updated_at = None;
    if let Some(group_id) = settings.ip_allowlist_group_id {
        let group = ip_groups::Entity::find_by_id(group_id).one(db).await?;
        match group {
            Some(group) => {
                // Track the row even while it is disabled: enabling or
                // editing the group later must rebuild the policy. Before
                // this timestamp was compared, the policy only rebuilt when
                // the *settings* row changed, so a group enabled after the
                // save kept being ignored until the next save or restart.
                group_updated_at = Some(group.updated_at);
                if group.enabled {
                    ranges.extend(group.ip_ranges);
                } else {
                    tracing::warn!(
                        group_id = %group_id,
                        "API allowlist references a disabled ip group; only the inline ranges apply"
                    );
                }
            },
            None => tracing::warn!(
                group_id = %group_id,
                "API allowlist references a missing ip group; only the inline ranges apply"
            ),
        }
    }
    let (allowlist, invalid) = Allowlist::parse(ranges);
    if !invalid.is_empty() {
        tracing::warn!(
            invalid = ?invalid,
            "ignoring invalid API allowlist entries"
        );
    }
    Ok((allowlist, group_updated_at))
}

/// Builds the enforcement policy from the current settings row.
pub async fn refresh(
    db: &DatabaseConnection,
) -> Result<ProtectionPolicy, DbErr> {
    let settings = load_settings(db).await?;
    let (allowlist, group_updated_at) =
        effective_allowlist(db, &settings).await?;
    let (denylist, invalid_deny) =
        Allowlist::parse(&settings.ip_denylist_ranges);
    if !invalid_deny.is_empty() {
        tracing::warn!(
            invalid = ?invalid_deny,
            "ignoring invalid API denylist entries"
        );
    }
    let waf_blocking = settings.waf_mode == waf_mode::BLOCK;
    let waf = settings.waf_enabled.then(|| {
        // Only the mode differs from the engine baseline; every detection
        // knob is deliberately left at `WafEngineConfig::default`.
        Arc::new(WafEngine::new(&WafEngineConfig {
            mode: if waf_blocking {
                WafMode::Block
            } else {
                WafMode::Monitor
            },
            ..Default::default()
        }))
    });

    Ok(ProtectionPolicy {
        access_log_enabled: settings.access_log_enabled,
        allowlist_enabled: settings.ip_allowlist_enabled,
        allowlist,
        denylist_enabled: settings.ip_denylist_enabled,
        denylist,
        waf,
        waf_blocking,
        settings_updated_at: settings.updated_at,
        group_updated_at,
    })
}

/// Whether a freshly built policy differs from the one in force.
///
/// Both inputs matter: the settings row *and* the referenced IP group. The
/// group is edited on its own page (and enabled by its own switch), so
/// comparing only the settings timestamp left a group enabled after the save
/// out of the enforced policy until something else touched the settings.
fn inputs_changed(
    current: &ProtectionPolicy,
    fresh: &ProtectionPolicy,
) -> bool {
    fresh.settings_updated_at != current.settings_updated_at
        || fresh.group_updated_at != current.group_updated_at
}

/// Background task: re-read the settings every [`REFRESH_INTERVAL`] and swap
/// the policy in when the row changed. Failures keep the previous policy.
pub fn start_refresh_task(state: AppState) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        loop {
            tokio::time::sleep(REFRESH_INTERVAL).await;
            match refresh(&state.db).await {
                Ok(policy) => {
                    let current = state.protection.policy();
                    if inputs_changed(&current, &policy) {
                        tracing::info!(
                            allowlist_enabled = policy.allowlist_enabled,
                            allowlist_entries = policy.allowlist.len(),
                            group_updated_at = ?policy.group_updated_at,
                            waf_enabled = policy.waf.is_some(),
                            "control plane protection settings reloaded"
                        );
                        state.protection.store(policy);
                    }
                },
                Err(err) => tracing::warn!(
                    error = %err,
                    "could not reload control plane protection settings"
                ),
            }
        }
    })
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_referenced_group_edit_rebuilds_the_policy() {
        let base = Utc::now();
        let current = ProtectionPolicy {
            settings_updated_at: base,
            group_updated_at: Some(base),
            ..Default::default()
        };

        // Unchanged inputs: no rebuild.
        let same = ProtectionPolicy {
            settings_updated_at: base,
            group_updated_at: Some(base),
            ..Default::default()
        };
        assert!(!inputs_changed(&current, &same));

        // The group was enabled/edited after the settings save: rebuild.
        let group_edited = ProtectionPolicy {
            settings_updated_at: base,
            group_updated_at: Some(base + chrono::Duration::seconds(1)),
            ..Default::default()
        };
        assert!(inputs_changed(&current, &group_edited));

        // A group appearing or disappearing also rebuilds.
        let group_cleared = ProtectionPolicy {
            settings_updated_at: base,
            group_updated_at: None,
            ..Default::default()
        };
        assert!(inputs_changed(&current, &group_cleared));

        // A settings save still rebuilds.
        let settings_saved = ProtectionPolicy {
            settings_updated_at: base + chrono::Duration::seconds(1),
            group_updated_at: Some(base),
            ..Default::default()
        };
        assert!(inputs_changed(&current, &settings_saved));
    }
}
