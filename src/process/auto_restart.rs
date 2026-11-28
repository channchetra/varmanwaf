// Copyright 2024-2025 Tree xie.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

use super::restart;
use crate::config_apply::{self, ApplyOptions, ApplyOutcome};
use crate::data_plane::ProviderSet;
use crate::plugin::AdminPluginEntry;
use crate::webhook::send_notification;
use arc_swap::{ArcSwap, ArcSwapOption};
use async_trait::async_trait;
use pingap_certificate::validate_servers_tls_for_backend;
use pingap_config::{ConfigManager, PingapConfig, PingapTomlConfig};
use pingap_core::{
    BackgroundTask, BackgroundTaskService, Error as ServiceError,
    NotificationData,
};
use pingap_logger::LoggerReloadHandle;
use pingap_logger::new_env_filter;
use pingora::server::ShutdownWatch;
use pingora::services::background::BackgroundService;
use std::hash::{DefaultHasher, Hash, Hasher};
use std::sync::Arc;
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::Duration;
use tokio::time::interval;
use tracing::{debug, error, info};

static LOG_TARGET: &str = "main::auto_restart";

/// What the previous pass saw: the hash of the raw configuration document
/// and whether that pass was allowed to restart.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct LastSeen {
    hash: u64,
    restart_eligible: bool,
}

/// Per-watcher memo of the raw document the last pass handled.
///
/// Deliberately a field of each service, not a global: two watchers in one
/// process (a second service, a test) must not inherit each other's state.
#[derive(Default)]
struct LastSeenCell(ArcSwapOption<LastSeen>);

impl LastSeenCell {
    /// Whether a pass over a document hashing to `hash` has nothing to do.
    fn skipped(&self, hash: u64, hot_reload_only: bool) -> bool {
        should_skip(self.0.load().as_deref(), hash, hot_reload_only)
    }

    /// Records a document as handled by a pass that finished.
    fn record(&self, hash: u64, restart_eligible: bool) {
        self.0.store(Some(Arc::new(LastSeen {
            hash,
            restart_eligible,
        })));
    }
}

fn raw_hash(raw: &str) -> u64 {
    let mut hasher = DefaultHasher::new();
    raw.hash(&mut hasher);
    hasher.finish()
}

/// Whether a pass over a document hashing to `hash` has nothing to do: the
/// document is the one the last pass already handled, and either that pass
/// could restart or this one cannot. A hot-reload-only pass may leave a
/// change behind that only a restart applies, so the next restart-eligible
/// pass still has to look at the same document.
fn should_skip(
    last: Option<&LastSeen>,
    hash: u64,
    hot_reload_only: bool,
) -> bool {
    last.is_some_and(|last| {
        last.hash == hash && (last.restart_eligible || hot_reload_only)
    })
}

/// Loads the configuration and, when it changed since the last pass,
/// applies it through `apply_config`. Returns `None` when there was nothing
/// new: the poll then costs one storage read and a hash instead of a parse,
/// a validation (which resolves every static upstream address) and a diff.
async fn diff_and_update_config(
    config_manager: Arc<ConfigManager>,
    last_seen: &LastSeenCell,
    hot_reload_only: bool,
    admin_plugin: Option<AdminPluginEntry>,
    providers: &ProviderSet,
) -> Result<Option<PingapConfig>, Box<dyn std::error::Error>> {
    let raw = config_manager.load_all_raw().await?;
    let hash = raw_hash(&raw);
    if last_seen.skipped(hash, hot_reload_only) {
        debug!(target: LOG_TARGET, "config is unchanged");
        return Ok(None);
    }
    let new_config =
        PingapTomlConfig::from_toml(&raw)?.to_pingap_config(true)?;
    let restart_requested = apply_daemon_config(
        config_manager,
        &new_config,
        hot_reload_only,
        admin_plugin,
        providers,
    )
    .await?;
    // Recorded only after a pass that finished. An error - the document
    // does not parse, an address does not resolve - is retried on the next
    // tick, and a pass that asked for a restart is repeated by the next
    // restart-eligible tick in case the restart was abandoned.
    last_seen.record(hash, !hot_reload_only && !restart_requested);
    Ok(Some(new_config))
}

/// Compares configurations and handles updates through hot reload or full restart
///
/// This function:
/// 1. Validates the new configuration
/// 2. Compares it with current config to find differences
/// 3. Attempts hot reload for supported changes:
///    - Server locations
///    - Upstream configurations
///    - Location definitions
///    - Plugin configurations
///    - Certificates (except ACME/Let's Encrypt)
///    - Webhook settings (`webhook`, `webhook_type`, `webhook_notifications`,
///      `webhook_batch_window`, `webhook_batch_max_events`)
/// 4. Sends notifications for successful updates
/// 5. If hot_reload_only=false and there are non-hot-reloadable changes,
///    triggers a full server restart
///
/// Returns whether a restart was requested.
async fn apply_daemon_config(
    config_manager: Arc<ConfigManager>,
    new_config: &PingapConfig,
    hot_reload_only: bool,
    admin_plugin: Option<AdminPluginEntry>,
    providers: &ProviderSet,
) -> Result<bool, Box<dyn std::error::Error>> {
    new_config.validate()?;
    validate_servers_tls_for_backend(&new_config.servers)?;
    let current_config = config_manager.get_current_config();

    let outcome = config_apply::apply_config(
        &current_config,
        new_config,
        &ApplyOptions::daemon(hot_reload_only),
        admin_plugin.as_ref(),
        &config_manager,
        providers,
    )
    .await;

    let (report, restart_reason) = match outcome {
        ApplyOutcome::Unchanged => return Ok(false),
        ApplyOutcome::Failed(message) => {
            // A partial apply must not become the current config: the next
            // diff would be empty, so the failed components would never be
            // retried and the reported config would drift from the running
            // providers. Keep the previous config; the watcher re-detects
            // this diff and tries again.
            error!(
                target: LOG_TARGET,
                failures = %message,
                "config apply failed; keeping the previous config and retrying"
            );
            send_notification(NotificationData {
                category: "reload_config_fail".to_string(),
                message: message.clone(),
                ..Default::default()
            })
            .await;
            // Return an error, not `Ok(false)`: `diff_and_update_config`
            // records the document hash as handled only on success, so an
            // error is what makes the watcher retry this document on the next
            // tick.
            return Err(std::io::Error::other(format!(
                "config apply failed: {message}"
            ))
            .into());
        },
        ApplyOutcome::Applied(report) => (report, None),
        ApplyOutcome::RestartRequired { report, reason } => {
            (report, Some(reason))
        },
    };

    if hot_reload_only {
        let (updated_category_list, original_diff_result) =
            current_config.diff(&report.config);
        debug!(
            target: LOG_TARGET,
            updated_category_list = updated_category_list.join(","),
            original_diff_result = original_diff_result.join("\n"),
            "current config diff from hot reload config"
        );
        // no update config
        if original_diff_result.is_empty() {
            return Ok(false);
        }
        // update current config to be hot reload config
        config_manager.set_current_config(report.config);
        send_notification(NotificationData {
            category: "diff_config".to_string(),
            message: original_diff_result.join("\n").trim().to_string(),
            ..Default::default()
        })
        .await;
        return Ok(false);
    }
    // restart mode
    // update current config to be hot reload config
    config_manager.set_current_config(report.config);

    let should_restart = restart_reason.is_some();
    send_notification(NotificationData {
        category: "diff_config".to_string(),
        message: report.diff.join("\n").trim().to_string(),
        ..Default::default()
    })
    .await;
    if should_restart {
        let _ = restart().await;
    }
    Ok(should_restart)
}

/// AutoRestart service manages configuration updates on a schedule
///
/// The service alternates between hot reloads and full restarts based on:
/// - restart_unit: Determines frequency of full restarts vs hot reloads
/// - hot_reload_only: Forces hot reload only mode
/// - count: Tracks intervals to coordinate restart timing
struct AutoRestart {
    /// How many intervals to wait before allowing a full restart (vs hot reload)
    restart_unit: u32,
    /// If true, only perform hot reloads and never restart
    hot_reload_only: bool,
    config_manager: Arc<ConfigManager>,
    log_reload_handle: LoggerReloadHandle,
    current_log_level: ArcSwap<String>,
    /// Re-registered with every plugin rebuild, or the admin listener would
    /// lose its plugin after the first reload. The rebuild gets this
    /// watcher's `config_manager` for it.
    admin_plugin: Option<AdminPluginEntry>,
    /// The registries this watcher reloads. Owned, so a second plane or a
    /// test never shares them.
    providers: ProviderSet,
    /// The document this watcher last handled. Per instance, never shared.
    last_seen: LastSeenCell,
}

/// Creates a new auto-restart service that checks for config changes
/// periodically.
///
/// The service ticks at most every 10 seconds (and at `interval` when that is
/// shorter); `restart_unit` keeps a full-restart opportunity on the original
/// cadence even then.
pub fn new_auto_restart_service(
    config_manager: Arc<ConfigManager>,
    log_reload_handle: LoggerReloadHandle,
    interval: Duration,
    hot_reload_only: bool,
    admin_plugin: Option<AdminPluginEntry>,
    providers: ProviderSet,
) -> BackgroundTaskService {
    let mut restart_unit = 1_u32;
    let unit = Duration::from_secs(10);
    if interval > unit {
        restart_unit = (interval.as_secs() / unit.as_secs()) as u32;
    }

    let current_log_level = config_manager
        .get_current_config()
        .basic
        .log_level
        .clone()
        .unwrap_or_default();

    let task = Box::new(AutoRestart {
        log_reload_handle,
        config_manager,
        hot_reload_only,
        restart_unit,
        current_log_level: ArcSwap::from_pointee(current_log_level),
        admin_plugin,
        providers,
        last_seen: LastSeenCell::default(),
    });
    let name = "auto_restart";
    BackgroundTaskService::new_single(name, interval.min(unit), name, task)
}

/// ConfigObserverService provides real-time config file monitoring
///
/// This service:
/// 1. Watches the config file/storage for changes
/// 2. Triggers immediate hot reload when changes detected
/// 3. Can optionally perform full restarts if needed
/// 4. Runs continuously until server shutdown
///
/// The service uses tokio::select! to handle:
/// - Periodic checks (interval-based)
/// - File system events (real-time)
/// - Graceful shutdown signals
pub struct ConfigObserverService {
    config_manager: Arc<ConfigManager>,
    log_reload_handle: LoggerReloadHandle,
    current_log_level: ArcSwap<String>,
    /// How often to check for changes
    interval: Duration,
    /// If true, only perform hot reloads when changes detected
    hot_reload_only: bool,
    /// Re-registered with every plugin rebuild, like the polling service.
    admin_plugin: Option<AdminPluginEntry>,
    /// The registries this watcher reloads. Owned, never shared.
    providers: ProviderSet,
    delay: AtomicU32,
    /// The document this watcher last handled. Per instance, never shared.
    last_seen: LastSeenCell,
}

const MIN_DELAY: u32 = 500;
const MAX_DELAY: u32 = 60 * 1000;

/// Creates the push-driven watcher used by storage backends that support
/// observation (etcd). It reacts to the backend's watch stream and has no
/// polling cadence of its own; `interval` is only the fallback tick.
pub fn new_observer_service(
    config_manager: Arc<ConfigManager>,
    log_reload_handle: LoggerReloadHandle,
    interval: Duration,
    hot_reload_only: bool,
    admin_plugin: Option<AdminPluginEntry>,
    providers: ProviderSet,
) -> ConfigObserverService {
    let current_log_level = config_manager
        .get_current_config()
        .basic
        .log_level
        .clone()
        .unwrap_or_default();

    ConfigObserverService {
        config_manager,
        log_reload_handle,
        interval,
        hot_reload_only,
        current_log_level: ArcSwap::from_pointee(current_log_level),
        admin_plugin,
        providers,
        delay: AtomicU32::new(MIN_DELAY),
        last_seen: LastSeenCell::default(),
    }
}

static OBSERVER_NAME: &str = "configObserver";

#[async_trait]
impl BackgroundService for ConfigObserverService {
    async fn start(&self, mut shutdown: ShutdownWatch) {
        if !self.config_manager.support_observer() {
            return;
        }
        let period_human: humantime::Duration = self.interval.into();

        info!(
            target: LOG_TARGET,
            name = OBSERVER_NAME,
            interval = period_human.to_string(),
            "background service is running",
        );
        let mut period = interval(self.interval);

        let mut observer = match self.config_manager.observe().await {
            Ok(observer) => observer,
            Err(e) => {
                error!(
                    target: LOG_TARGET,
                    error = %e,
                    "create storage observe fail"
                );
                return;
            },
        };

        loop {
            tokio::select! {
                _ = shutdown.changed() => {
                    break;
                }
                _ = period.tick() => {
                    // fetch and diff update
                    // some change may be restart
                    if let Some(new_config) = run_diff_and_update_config(
                        self.config_manager.clone(),
                        &self.last_seen,
                        self.hot_reload_only,
                        self.admin_plugin.clone(),
                        &self.providers,
                    ).await {
                        reload_log_level(
                            &self.log_reload_handle,
                            &self.current_log_level,
                            &new_config,
                        );
                    }
                }
                result = observer.watch() => {
                    let delay = self.delay.load(Ordering::Relaxed);
                    match result {
                        Ok(updated)  => {
                            if delay > MIN_DELAY {
                                self.delay.store(MIN_DELAY, Ordering::Relaxed);
                            }
                            if !updated {
                                continue;
                            }
                            // only hot reload for observe updated
                            run_diff_and_update_config(
                                self.config_manager.clone(),
                                &self.last_seen,
                                true,
                                self.admin_plugin.clone(),
                                &self.providers,
                            ).await;
                        },
                        Err(e) => {
                            error!(
                               target: LOG_TARGET,
                               error = %e,
                               "observe updated fail"
                            );
                            tokio::time::sleep(Duration::from_millis(delay as u64)).await;
                            if delay < MAX_DELAY {
                               self.delay.store(delay * 2, Ordering::Relaxed);
                            }
                        }
                    }
                }
            }
        }
    }
}

/// Helper function to run the config diff and update process
/// Logs any errors that occur during the update
async fn run_diff_and_update_config(
    config_manager: Arc<ConfigManager>,
    last_seen: &LastSeenCell,
    hot_reload_only: bool,
    admin_plugin: Option<AdminPluginEntry>,
    providers: &ProviderSet,
) -> Option<PingapConfig> {
    match diff_and_update_config(
        config_manager,
        last_seen,
        hot_reload_only,
        admin_plugin,
        providers,
    )
    .await
    {
        Ok(new_config) => new_config,
        Err(e) => {
            error!(
                target: LOG_TARGET,
                error = %e,
                "update config fail",
            );
            None
        },
    }
}

#[async_trait]
impl BackgroundTask for AutoRestart {
    async fn execute(&self, count: u32) -> Result<bool, ServiceError> {
        // Calculate if this iteration should be hot reload only.
        //
        // `restart_unit` is how many check ticks make one full config interval
        // (the service itself runs every min(interval, 10s)). Full restart is
        // offered when `count` is a multiple of `restart_unit`.
        //
        // When interval ≤ 10s, `restart_unit == 1`, so every tick after the
        // first is a full-restart opportunity — otherwise non-hot-reloadable
        // changes (server addr, threads, …) would never take effect.
        //
        // count=0 is always hot-reload-only so the first pass is gentle.
        let hot_reload_only = self.hot_reload_only
            || count == 0
            || !count.is_multiple_of(self.restart_unit);
        if let Some(new_config) = run_diff_and_update_config(
            self.config_manager.clone(),
            &self.last_seen,
            hot_reload_only,
            self.admin_plugin.clone(),
            &self.providers,
        )
        .await
        {
            reload_log_level(
                &self.log_reload_handle,
                &self.current_log_level,
                &new_config,
            );
        }
        Ok(true)
    }
}

/// Applies the log level of `new_config` when it differs from the one in
/// place, and remembers it so an unchanged level is not re-applied on the
/// next pass.
fn reload_log_level(
    handle: &LoggerReloadHandle,
    current: &ArcSwap<String>,
    new_config: &PingapConfig,
) {
    let new_level = new_config.basic.log_level.clone().unwrap_or_default();
    let current_level = current.load();
    if new_level == **current_level {
        return;
    }
    info!(
        target: LOG_TARGET,
        current_level = current_level.as_str(),
        new_level,
        "reload log level"
    );
    match handle.modify(|filter| *filter = new_env_filter(&new_level)) {
        Ok(()) => current.store(Arc::new(new_level)),
        Err(e) => error!(
            target: LOG_TARGET,
            error = %e,
            "reload log level fail"
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::{AutoRestart, LastSeen, LastSeenCell, should_skip};
    use crate::data_plane::ProviderSet;
    use arc_swap::ArcSwap;
    use pingap_config::ConfigManager;
    use pingap_logger::{LoggerReloadHandle, new_env_filter};
    use pretty_assertions::assert_eq;
    use std::sync::Arc;

    /// A watcher with its own memo. The reload handle is never used: the test
    /// exercises the handled-document memo, not a log-level reload.
    fn test_watcher(config_manager: Arc<ConfigManager>) -> AutoRestart {
        let (_layer, log_reload_handle): (_, LoggerReloadHandle) =
            tracing_subscriber::reload::Layer::new(new_env_filter("INFO"));
        AutoRestart {
            restart_unit: 1,
            hot_reload_only: false,
            config_manager,
            log_reload_handle,
            current_log_level: ArcSwap::from_pointee(String::new()),
            admin_plugin: None,
            providers: ProviderSet::new(),
            last_seen: LastSeenCell::default(),
        }
    }

    /// The handled document used to live in a process global, so a second
    /// watcher inherited it and skipped a document it had never applied.
    #[test]
    fn two_watchers_do_not_share_the_handled_document_memo() {
        let config_manager = Arc::new(
            pingap_config::new_memory_config_manager("[basic]\n", None),
        );
        let first = test_watcher(config_manager.clone());
        let second = test_watcher(config_manager);

        first.last_seen.record(7, true);

        assert!(first.last_seen.skipped(7, false));
        assert!(
            !second.last_seen.skipped(7, false),
            "a second watcher must still apply the document its first pass sees"
        );
    }

    #[test]
    fn test_should_skip() {
        // Nothing seen yet: every pass runs.
        assert_eq!(false, should_skip(None, 1, true));
        assert_eq!(false, should_skip(None, 1, false));

        // A changed document runs whatever the last pass was.
        let hot_only = LastSeen {
            hash: 1,
            restart_eligible: false,
        };
        assert_eq!(false, should_skip(Some(&hot_only), 2, true));
        assert_eq!(false, should_skip(Some(&hot_only), 2, false));

        // Unchanged after a hot-reload-only pass: another hot-reload-only
        // pass has nothing to add, a restart-eligible one still has to look.
        assert_eq!(true, should_skip(Some(&hot_only), 1, true));
        assert_eq!(false, should_skip(Some(&hot_only), 1, false));

        // Unchanged after a restart-eligible pass that needed no restart:
        // nothing is left for either kind of pass.
        let settled = LastSeen {
            hash: 1,
            restart_eligible: true,
        };
        assert_eq!(true, should_skip(Some(&settled), 1, true));
        assert_eq!(true, should_skip(Some(&settled), 1, false));
    }
}
