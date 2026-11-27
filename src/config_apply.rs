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

//! Applies a new [`PingapConfig`] to the process-wide providers in place.
//!
//! Two roots reload configuration at runtime: the file-configured daemon's
//! watcher (`src/process/auto_restart.rs`) and the agent-hosted data plane
//! (`src/varman/data_plane.rs`). They differ in *policy* - what may be
//! committed, restarted or notified - never in how a changed category is
//! pushed into its provider. That policy is [`ApplyOptions`], so the
//! difference stays visible at each call site instead of drifting inside two
//! copies of the same scaffold.
//!
//! Each root still owns its trigger and its commit:
//!
//! * the daemon validates the document, decides between a hot reload and a
//!   restart, commits the projection and records the document hash;
//! * the agent-hosted plane merges the ACME state, owns the watcher
//!   bookkeeping, never restarts, and commits the merged document.
//!
//! [`apply_config`] only rebuilds providers and reports whether the caller
//! may commit.

use crate::certificates::try_update_certificates;
use crate::locations::try_init_locations;
use crate::plugin::{AdminPlugin, try_init_plugins};
use crate::server_locations::try_init_server_locations;
use crate::upstreams::{try_init_upstreams, try_update_upstreams};
use crate::webhook::{
    get_webhook_sender, reload_webhook_notification_sender, send_notification,
};
use pingap_config::{
    CATEGORY_CERTIFICATE, CATEGORY_LOCATION, CATEGORY_PLUGIN,
    CATEGORY_UPSTREAM, ConfigManager, PingapConfig,
};
use pingap_core::{NotificationData, NotificationLevel};
use std::sync::Arc;
use tracing::{debug, error, info};

static LOG_TARGET: &str = "main::config_apply";

/// What one provider rebuild did.
///
/// Every provider's `try_init_*`/`try_update_*` returns this, so an apply pass
/// consumes them all the same way: a non-empty `errors` means the provider
/// kept its previous state and the update did not apply, while `Err` is a
/// failure of the call itself.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ProviderUpdate {
    /// Names of the entries created or reloaded.
    pub updated: Vec<String>,
    /// Per-entry failures, joined with `;`. Empty when the update applied.
    pub errors: String,
}

impl ProviderUpdate {
    /// The update applied: no entry failed.
    pub fn is_ok(&self) -> bool {
        self.errors.is_empty()
    }

    /// Nothing changed and nothing failed.
    pub fn is_empty(&self) -> bool {
        self.updated.is_empty() && self.errors.is_empty()
    }
}

/// The policy an apply pass follows.
///
/// Every field exists because the two roots really do behave differently;
/// [`ApplyOptions::daemon`] and [`ApplyOptions::agent_data_plane`] are the two
/// policies in production.
#[derive(Clone, Copy, Debug)]
pub struct ApplyOptions {
    /// Whether a change no provider can apply in place (`basic`, server
    /// `addr`/`threads`, ...) is applied hot and *not* reported as
    /// [`ApplyOutcome::RestartRequired`].
    ///
    /// The agent-hosted plane sets this: it never restarts, so a
    /// control-plane rule push must not ask for one. The daemon clears it so
    /// its watcher restarts on such a change.
    pub hot_reload_only: bool,
    /// Build upstreams with the process webhook sender and run the health
    /// check of every new or changed upstream before it takes traffic.
    ///
    /// The daemon sets this. The agent-hosted plane does neither: its
    /// periodic `HealthCheckTask` owns checking and it passes no notification
    /// sender (its `try_init_upstreams` call has always used `None`).
    pub update_health_checks: bool,
    /// Rebuild every provider from `next` even when its category is unchanged.
    ///
    /// The agent-hosted plane has always reloaded all five from the whole
    /// document - entries are content-keyed, so unchanged ones are reused,
    /// but the calls still publish a fresh provider map and bump the plugin
    /// provider version. The daemon only touches the categories its diff
    /// reports, because the same diff decides between hot reload and restart.
    pub rebuild_unchanged: bool,
    /// Send the `reload_config` notifications for rebuilt categories, the
    /// webhook change and the certificate parse failure.
    ///
    /// The daemon sets this. The agent-hosted plane never emitted reload
    /// notifications; its webhook is configured by the control plane.
    pub notify: bool,
    /// Reload the webhook settings from `next.basic` before the other
    /// categories and carry them in the projection.
    ///
    /// The daemon sets this. The agent-hosted plane's rule document carries
    /// no webhook settings, so taking them from it would clear the process
    /// webhook.
    pub reload_webhook: bool,
    /// Leave certificates out of the in-place apply when any certificate in
    /// `next` still has to be issued by the lets-encrypt task: neither the
    /// projection nor the certificate provider is touched.
    ///
    /// The daemon sets this: an `acme` entry is created at runtime, so it must
    /// not be committed as a loaded certificate nor rebuilt by either side.
    /// The agent-hosted plane builds its provider from the whole certificate
    /// map (an unissued entry keeps serving the previous certificate), so it
    /// does not.
    pub skip_acme_certificates: bool,
}

impl ApplyOptions {
    /// The file-configured daemon's policy.
    pub fn daemon(hot_reload_only: bool) -> Self {
        Self {
            hot_reload_only,
            update_health_checks: true,
            rebuild_unchanged: false,
            notify: true,
            reload_webhook: true,
            skip_acme_certificates: true,
        }
    }

    /// The agent-hosted data plane's policy.
    pub fn agent_data_plane() -> Self {
        Self {
            hot_reload_only: true,
            update_health_checks: false,
            rebuild_unchanged: true,
            notify: false,
            reload_webhook: false,
            skip_acme_certificates: false,
        }
    }
}

/// The diff an apply pass was given, plus the config it may commit.
pub struct ApplyReport {
    /// Lines of `PingapConfig::diff(previous, next)`, for the caller's
    /// `diff_config` notification.
    pub diff: Vec<String>,
    /// The previous config with every hot-reloadable component taken from
    /// `next`. Committing it is the caller's decision.
    pub config: PingapConfig,
}

/// What an apply pass did.
pub enum ApplyOutcome {
    /// Nothing in `next` differs from `previous`; no provider was touched and
    /// the previous config stays current.
    Unchanged,
    /// Every applied component succeeded.
    Applied(ApplyReport),
    /// The hot-reloadable components succeeded, but `next` also changes
    /// something only a restart applies. `reason` lists that difference.
    RestartRequired { report: ApplyReport, reason: String },
    /// At least one provider failed to rebuild; `message` is the joined
    /// failure list. The previous config must stay current so the next pass
    /// retries the same change.
    Failed(String),
}

/// Makes `config` the current configuration when every provider rebuilt.
///
/// A partially applied config must never become current: the next diff would
/// be empty, so the components that failed would never be retried and the
/// reported config would drift from the running providers. Keeping the
/// previous config makes the watcher re-detect the same change.
///
/// Returns whether the config was committed.
pub fn commit_if_applied(
    config_manager: &ConfigManager,
    config: PingapConfig,
    outcome: &ApplyOutcome,
) -> bool {
    if let ApplyOutcome::Failed(_) = outcome {
        return false;
    }
    config_manager.set_current_config(config);
    true
}

/// Which provider families a pass has to rebuild.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
struct Categories {
    upstreams: bool,
    locations: bool,
    plugins: bool,
    certificates: bool,
    server_locations: bool,
}

impl Categories {
    fn all() -> Self {
        Self {
            upstreams: true,
            locations: true,
            plugins: true,
            certificates: true,
            server_locations: true,
        }
    }
}

/// Applies `next` over `previous`.
///
/// `admin_plugin` is the root's admin listener plugin, if it serves one. It is
/// not part of the document and has to be re-registered on every plugin
/// rebuild, or the admin listener would lose its plugin after a reload.
/// `config_manager` is the manager every admin plugin reads and writes the
/// configuration through; it is forwarded to the plugin rebuild instead of
/// being looked up from a process global.
pub async fn apply_config(
    previous: &PingapConfig,
    next: &PingapConfig,
    options: &ApplyOptions,
    admin_plugin: Option<&AdminPlugin>,
    config_manager: &Arc<ConfigManager>,
) -> ApplyOutcome {
    let (changed, diff) = previous.diff(next);
    debug!(
        target: LOG_TARGET,
        updated_category_list = changed.join(","),
        original_diff_result = diff.join("\n"),
        "current config diff from new config"
    );
    // A hot-reload-only pass may leave a change behind that only a restart
    // applies, but there is nothing to do when the document itself is equal.
    if diff.is_empty() && !options.rebuild_unchanged {
        return ApplyOutcome::Unchanged;
    }

    let projection = hot_projection(previous, next, options).await;
    let categories = dispatch(previous, next, &changed, options);
    let failures = apply_categories(
        next,
        categories,
        options,
        admin_plugin,
        config_manager,
    )
    .await;
    if !failures.is_empty() {
        return ApplyOutcome::Failed(failures.join(";"));
    }

    let report = ApplyReport {
        diff,
        config: projection,
    };
    if !options.hot_reload_only {
        let (_, reason) = report.config.diff(next);
        debug!(
            target: LOG_TARGET,
            new_config_result = reason.join("\n"),
            "hot reload config diff from new config"
        );
        if !reason.is_empty() {
            return ApplyOutcome::RestartRequired {
                report,
                reason: reason.join("\n"),
            };
        }
    }
    ApplyOutcome::Applied(report)
}

/// Which providers the pass rebuilds. Categories the diff does not name stay
/// untouched unless the caller asked for a full rebuild.
fn dispatch(
    previous: &PingapConfig,
    next: &PingapConfig,
    changed: &[String],
    options: &ApplyOptions,
) -> Categories {
    if options.rebuild_unchanged {
        return Categories::all();
    }
    let changed = |category: &str| changed.iter().any(|item| item == category);
    let locations = changed(CATEGORY_LOCATION);
    Categories {
        upstreams: changed(CATEGORY_UPSTREAM),
        locations,
        plugins: changed(CATEGORY_PLUGIN),
        certificates: changed(CATEGORY_CERTIFICATE)
            && !(options.skip_acme_certificates && has_acme_certificate(next)),
        // The server->location index owns host/path/weight ordering. A
        // location edit must rebuild it even when no server's name list
        // changed, or the new routing never applies.
        server_locations: locations
            || server_location_lists_changed(previous, next),
    }
}

async fn apply_categories(
    next: &PingapConfig,
    categories: Categories,
    options: &ApplyOptions,
    admin_plugin: Option<&AdminPlugin>,
    config_manager: &Arc<ConfigManager>,
) -> Vec<String> {
    let mut failures = vec![];

    if categories.upstreams {
        let result = if options.update_health_checks {
            as_step(
                try_update_upstreams(
                    &next.upstreams,
                    Some(get_webhook_sender()),
                )
                .await,
            )
        } else {
            // The agent-hosted plane's rebuild reports no names; it must not
            // gain the daemon's success log line.
            as_silent_step(try_init_upstreams(&next.upstreams, None))
        };
        if let Some(failure) = run_step(&UPSTREAM_STEP, options, result).await {
            failures.push(failure);
        }
    }
    if categories.locations {
        let result = as_step(try_init_locations(&next.locations));
        if let Some(failure) = run_step(&LOCATION_STEP, options, result).await {
            failures.push(failure);
        }
    }
    if categories.plugins {
        let (updated, errors) = try_init_plugins(
            &next.plugins,
            admin_plugin.cloned(),
            config_manager.clone(),
        );
        // `try_init_plugins` still reports the old tuple; a non-empty error
        // means it kept the previous map.
        let result = as_step(Ok(ProviderUpdate { updated, errors }));
        if let Some(failure) = run_step(&PLUGIN_STEP, options, result).await {
            failures.push(failure);
        }
    }
    if categories.certificates {
        let result = as_step(try_update_certificates(&next.certificates));
        if let Some(failure) =
            run_step(&CERTIFICATE_STEP, options, result).await
        {
            failures.push(failure);
        }
    }
    if categories.server_locations {
        let result =
            as_step(try_init_server_locations(&next.servers, &next.locations));
        if let Some(failure) =
            run_step(&SERVER_LOCATION_STEP, options, result).await
        {
            failures.push(failure);
        }
    }

    failures
}

/// The config a hot reload can commit: the previous document with every
/// component that can change in place taken from `next`.
async fn hot_projection(
    previous: &PingapConfig,
    next: &PingapConfig,
    options: &ApplyOptions,
) -> PingapConfig {
    let mut projection = previous.clone();

    // The webhook goes first, so the notifications for everything else this
    // change reloads already go out with the new settings.
    if options.reload_webhook
        && reload_webhook_notification_sender(
            &mut projection.basic,
            &next.basic,
        )
    {
        info!(target: LOG_TARGET, "reload webhook success");
        if options.notify {
            send_notification(NotificationData {
                category: "reload_config".to_string(),
                level: NotificationLevel::Info,
                message: "Webhook is modified".to_string(),
                ..Default::default()
            })
            .await;
        }
    }

    // A server's location list can change without its `locations` table
    // changing; the index still has to see it.
    for (name, server) in next.servers.iter() {
        if let Some(current) = projection.servers.get_mut(name)
            && server.locations != current.locations
        {
            current.locations.clone_from(&server.locations);
        }
    }

    projection.upstreams = next.upstreams.clone();
    projection.locations = next.locations.clone();
    projection.plugins = next.plugins.clone();

    // An `acme` certificate is created by the lets-encrypt service, so it
    // cannot be reloaded as a loaded certificate; the service owns it.
    if !(options.skip_acme_certificates && has_acme_certificate(next)) {
        projection.certificates = next.certificates.clone();
    }

    projection
}

/// One provider family's log and notification wording. Everything else about
/// a step - the call itself and its failure recording - is shared.
struct Step {
    /// Name used in the recorded failure message.
    name: &'static str,
    /// Log line after a successful rebuild.
    success: &'static str,
    /// Log line after a failed rebuild.
    failure: &'static str,
    /// Label used by the `reload_config` notification.
    label: &'static str,
    /// Whether a successful rebuild is reported even when no entry is named.
    /// Plugins stayed silent when nothing was rebuilt.
    always_report: bool,
    /// Category of the error-level notification a failure sends, if any.
    error_notification: Option<&'static str>,
}

const UPSTREAM_STEP: Step = Step {
    name: "upstream",
    success: "reload upstream success",
    failure: "reload upstream fail",
    label: "Upstream",
    always_report: true,
    error_notification: None,
};

const LOCATION_STEP: Step = Step {
    name: "location",
    success: "reload location success",
    failure: "reload location fail",
    label: "Location",
    always_report: true,
    error_notification: None,
};

const PLUGIN_STEP: Step = Step {
    name: "plugin",
    success: "reload plugin success",
    failure: "reload plugin fail",
    label: "Plugin",
    always_report: false,
    error_notification: None,
};

const CERTIFICATE_STEP: Step = Step {
    name: "certificate",
    success: "reload certificate success",
    failure: "parse certificate fail",
    label: "Certificate",
    always_report: true,
    error_notification: Some("parse_certificate_fail"),
};

const SERVER_LOCATION_STEP: Step = Step {
    name: "server",
    success: "reload server location success",
    failure: "reload server fail",
    label: "Server Location",
    always_report: true,
    error_notification: None,
};

/// What a provider reports after a successful rebuild.
enum StepReport {
    /// The rebuild's names, for the log and notification.
    Named(ProviderUpdate),
    /// The rebuild succeeded but reports no names (the agent-hosted plane's
    /// upstream call). Nothing is logged: it never was on that path.
    Silent,
}

/// Converts a provider result into a step report.
///
/// Per-entry `errors` mean the provider kept its previous map, so the step
/// failed even though the call returned `Ok`; a fatal failure is the `Err`.
fn as_step(
    result: Result<ProviderUpdate, String>,
) -> Result<StepReport, String> {
    match result {
        Ok(update) if update.is_ok() => Ok(StepReport::Named(update)),
        Ok(update) => Err(update.errors),
        Err(error) => Err(error),
    }
}

/// [`as_step`] for a rebuild whose success reports no names and logs nothing.
fn as_silent_step(
    result: Result<ProviderUpdate, String>,
) -> Result<StepReport, String> {
    as_step(result).map(|_| StepReport::Silent)
}

/// Logs one step's result, sends its notification, and returns the failure
/// message to record (if it failed).
async fn run_step(
    step: &Step,
    options: &ApplyOptions,
    result: Result<StepReport, String>,
) -> Option<String> {
    match result {
        Ok(StepReport::Named(update)) => {
            if step.always_report || !update.is_empty() {
                info!(target: LOG_TARGET, "{}", step.success);
                if options.notify {
                    send_notification(NotificationData {
                        category: "reload_config".to_string(),
                        level: NotificationLevel::Info,
                        message: format_message(step.label, update.updated),
                        ..Default::default()
                    })
                    .await;
                }
            }
            None
        },
        Ok(StepReport::Silent) => None,
        Err(error) => {
            error!(target: LOG_TARGET, error, "{}", step.failure);
            if options.notify
                && let Some(category) = step.error_notification
            {
                send_notification(NotificationData {
                    category: category.to_string(),
                    level: NotificationLevel::Error,
                    message: error.clone(),
                    ..Default::default()
                })
                .await;
            }
            Some(format!("{} reload fail: {error}", step.name))
        },
    }
}

fn format_message(name: &str, list: Vec<String>) -> String {
    if list.is_empty() {
        return format!("{name} is removed",);
    }
    if list.len() > 1 {
        return format!("{name}s({}) are modified", list.join(","));
    }
    format!("{name}({}) is modified", list.join(","))
}

fn has_acme_certificate(config: &PingapConfig) -> bool {
    config.certificates.values().any(|cert| cert.acme.is_some())
}

/// Whether an existing server's location list differs. A server `next` adds
/// does not count: it needs a restart anyway, and the hot projection cannot
/// add it to the previous document.
fn server_location_lists_changed(
    previous: &PingapConfig,
    next: &PingapConfig,
) -> bool {
    next.servers.iter().any(|(name, server)| {
        previous
            .servers
            .get(name)
            .is_some_and(|current| current.locations != server.locations)
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config_manager::try_init_memory_config_manager;
    use pingap_config::{
        CertificateConf, LocationConf, PluginConf, ServerConf, UpstreamConf,
    };
    use pretty_assertions::assert_eq;

    /// A local manager for the plugin rebuild. The admin plugin reads and
    /// writes through it, so `apply_config` takes it instead of a global.
    fn new_config_manager() -> Arc<ConfigManager> {
        Arc::new(pingap_config::new_memory_config_manager("[basic]\n", None))
    }

    fn config_with_upstream(name: &str) -> PingapConfig {
        let mut config = PingapConfig::default();
        config.upstreams.insert(
            name.to_string(),
            UpstreamConf {
                addrs: vec!["127.0.0.1:80".to_string()],
                ..Default::default()
            },
        );
        config
    }

    fn config_with_location(name: &str) -> PingapConfig {
        let mut config = PingapConfig::default();
        config.locations.insert(
            name.to_string(),
            LocationConf {
                weight: Some(1),
                ..Default::default()
            },
        );
        config
    }

    fn config_with_plugin(name: &str) -> PingapConfig {
        let mut config = PingapConfig::default();
        let plugin: PluginConf =
            toml::from_str(r#"category = "mock""#).expect("plugin config");
        config.plugins.insert(name.to_string(), plugin);
        config
    }

    fn config_with_server(locations: &[&str]) -> PingapConfig {
        let mut config = PingapConfig::default();
        config.servers.insert(
            "apply-engine-server".to_string(),
            ServerConf {
                addr: "127.0.0.1:8080".to_string(),
                locations: Some(
                    locations.iter().map(|item| item.to_string()).collect(),
                ),
                ..Default::default()
            },
        );
        config
    }

    fn dispatch_of(
        previous: &PingapConfig,
        next: &PingapConfig,
        options: &ApplyOptions,
    ) -> Categories {
        let (changed, _) = previous.diff(next);
        dispatch(previous, next, &changed, options)
    }

    #[test]
    fn a_clean_provider_update_becomes_the_reported_names() {
        // Arrange
        let update = ProviderUpdate {
            updated: vec!["applied".to_string()],
            errors: String::new(),
        };

        // Act
        let report = as_step(Ok(update)).expect("a clean update must apply");

        // Assert
        match report {
            StepReport::Named(update) => {
                assert_eq!(vec!["applied".to_string()], update.updated);
            },
            StepReport::Silent => panic!("the named path must report names"),
        }
    }

    #[test]
    fn a_provider_update_with_entry_errors_fails_the_step() {
        // Arrange: the provider kept its previous map.
        let update = ProviderUpdate {
            updated: vec!["kept".to_string()],
            errors: "parse fail(bad)".to_string(),
        };

        // Act
        let result = as_step(Ok(update));

        // Assert: the partial list must not be reported as applied.
        match result {
            Err(error) => assert_eq!("parse fail(bad)", error),
            Ok(_) => panic!("entry errors must fail the step"),
        }
    }

    #[test]
    fn a_fatal_provider_error_is_the_step_failure() {
        // Act
        let result = as_step(Err("init fail".to_string()));

        // Assert
        match result {
            Err(error) => assert_eq!("init fail", error),
            Ok(_) => panic!("a fatal provider error must fail the step"),
        }
    }

    #[test]
    fn an_upstream_change_dispatches_only_the_upstream_step() {
        // Arrange
        let previous = PingapConfig::default();
        let next = config_with_upstream("apply-engine-upstream");

        // Act
        let categories =
            dispatch_of(&previous, &next, &ApplyOptions::daemon(false));

        // Assert
        assert_eq!(
            Categories {
                upstreams: true,
                ..Default::default()
            },
            categories
        );
    }

    #[test]
    fn a_location_change_dispatches_locations_and_the_server_index() {
        // Arrange
        let previous = PingapConfig::default();
        let next = config_with_location("apply-engine-location");

        // Act
        let categories =
            dispatch_of(&previous, &next, &ApplyOptions::daemon(false));

        // Assert: a new route also has to be ordered into the server index.
        assert!(categories.locations);
        assert!(categories.server_locations);
        assert!(!categories.upstreams);
        assert!(!categories.plugins);
        assert!(!categories.certificates);
    }

    #[test]
    fn a_server_location_list_change_dispatches_only_the_server_index() {
        // Arrange
        let previous = config_with_server(&["low"]);
        let mut next = previous.clone();
        next.servers
            .get_mut("apply-engine-server")
            .expect("the test server")
            .locations = Some(vec!["high".to_string()]);

        // Act
        let categories =
            dispatch_of(&previous, &next, &ApplyOptions::daemon(false));

        // Assert: the locations table did not change, only its ordering.
        assert!(categories.server_locations);
        assert!(!categories.locations);
        assert!(!categories.upstreams);
        assert!(!categories.plugins);
        assert!(!categories.certificates);
    }

    #[test]
    fn a_plugin_change_dispatches_only_the_plugin_step() {
        // Arrange
        let previous = PingapConfig::default();
        let next = config_with_plugin("apply-engine-plugin");

        // Act
        let categories =
            dispatch_of(&previous, &next, &ApplyOptions::daemon(false));

        // Assert
        assert!(categories.plugins);
        assert!(!categories.upstreams);
        assert!(!categories.locations);
        assert!(!categories.certificates);
        assert!(!categories.server_locations);
    }

    #[test]
    fn an_acme_certificate_is_left_to_the_lets_encrypt_service() {
        // Arrange
        let previous = PingapConfig::default();
        let mut next = PingapConfig::default();
        next.certificates.insert(
            "apply-engine-acme".to_string(),
            CertificateConf {
                domains: Some("acme.example.com".to_string()),
                acme: Some("http://acme@example.com".to_string()),
                ..Default::default()
            },
        );

        // Act
        let categories =
            dispatch_of(&previous, &next, &ApplyOptions::daemon(false));

        // Assert
        assert!(!categories.certificates);
    }

    #[test]
    fn a_loaded_certificate_change_dispatches_the_certificate_step() {
        // Arrange
        let previous = PingapConfig::default();
        let mut next = PingapConfig::default();
        next.certificates.insert(
            "apply-engine-cert".to_string(),
            CertificateConf {
                domains: Some("app.example.com".to_string()),
                ..Default::default()
            },
        );

        // Act
        let categories =
            dispatch_of(&previous, &next, &ApplyOptions::daemon(false));

        // Assert
        assert!(categories.certificates);
    }

    #[test]
    fn the_agent_policy_rebuilds_every_provider_from_the_whole_document() {
        // Arrange: an unchanged document.
        let previous = config_with_upstream("apply-engine-rebuild");

        // Act
        let categories = dispatch_of(
            &previous,
            &previous,
            &ApplyOptions::agent_data_plane(),
        );

        // Assert
        assert_eq!(Categories::all(), categories);
    }

    #[tokio::test]
    async fn an_equal_document_is_unchanged() {
        // Arrange
        let config = config_with_upstream("apply-engine-equal");

        // Act
        let outcome = apply_config(
            &config,
            &config,
            &ApplyOptions::daemon(false),
            None,
            &new_config_manager(),
        )
        .await;

        // Assert
        assert!(matches!(outcome, ApplyOutcome::Unchanged));
    }

    #[tokio::test]
    async fn a_non_hot_reloadable_change_asks_for_a_restart_when_allowed() {
        // Arrange
        let previous = PingapConfig::default();
        let mut next = PingapConfig::default();
        next.basic.log_level = Some("debug".to_string());

        // Act
        let restarting = apply_config(
            &previous,
            &next,
            &ApplyOptions::daemon(false),
            None,
            &new_config_manager(),
        )
        .await;
        let hot_only = apply_config(
            &previous,
            &next,
            &ApplyOptions::daemon(true),
            None,
            &new_config_manager(),
        )
        .await;

        // Assert: the log level is not a hot-reloadable component.
        match restarting {
            ApplyOutcome::RestartRequired { reason, .. } => {
                assert!(reason.contains("log_level"), "{reason}");
            },
            _ => panic!("a non-hot change must ask for a restart"),
        }
        assert!(matches!(hot_only, ApplyOutcome::Applied(_)));
    }

    #[tokio::test]
    async fn a_failing_provider_leaves_the_previous_state_intact() {
        // Arrange: only the certificate category changes, and its PEM cannot
        // be parsed, so the certificate provider keeps the previous map.
        let previous = PingapConfig::default();
        let mut next = PingapConfig::default();
        next.certificates.insert(
            "apply-engine-bad-cert".to_string(),
            CertificateConf {
                domains: Some("bad.example.com".to_string()),
                tls_cert: Some("not a certificate".to_string()),
                tls_key: Some("not a key".to_string()),
                ..Default::default()
            },
        );
        let config_manager = try_init_memory_config_manager("[basic]\n", None)
            .expect("in-memory config manager");
        config_manager.set_current_config(previous.clone());

        // Act
        let outcome = apply_config(
            &previous,
            &next,
            &ApplyOptions::daemon(false),
            None,
            &new_config_manager(),
        )
        .await;
        let committed =
            commit_if_applied(&config_manager, next.clone(), &outcome);

        // Assert: the failed apply is reported, and the previous config is
        // still the one the providers and the watcher see.
        match &outcome {
            ApplyOutcome::Failed(message) => {
                assert!(
                    message.contains("certificate reload fail"),
                    "{message}"
                );
            },
            _ => panic!("a broken certificate must fail the apply"),
        }
        assert!(!committed);
        let (_, current_diff) =
            previous.diff(config_manager.get_current_config().as_ref());
        assert!(
            current_diff.is_empty(),
            "the previous config must stay current: {current_diff:?}"
        );
    }
}
