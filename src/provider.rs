//! Types shared by the provider registries and the apply engine.
//!
//! They live here rather than in `config_apply` so the registries do not have
//! to import the orchestrator that drives them.

use pingap_config::PluginConf;

/// A named admin plugin configuration: the listener name and its plugin
/// table. Distinct from the built `AdminServe` plugin and from the URL query
/// of `--admin`.
pub type AdminPluginEntry = (String, PluginConf);

/// The result of a provider rebuild.
///
/// A non-empty `errors` means the provider kept its previous state and the
/// update did not apply.
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

/// The one wording for a provider construction failure, naming the rebuild
/// that failed.
pub(crate) fn provider_error(
    operation: &str,
    error: impl std::fmt::Display,
) -> String {
    format!("{operation}: {error}")
}
