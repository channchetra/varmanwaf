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

use crate::config_apply::ProviderUpdate;
use ahash::AHashMap;
use arc_swap::ArcSwap;
use pingap_config::UpstreamConf;
use pingap_core::{Error, NotificationSender};
use pingap_upstream::{
    Upstream, UpstreamProvider, Upstreams, new_ahash_upstreams,
};
use std::collections::HashMap;
use std::sync::Arc;
use std::sync::LazyLock;
use tracing::error;

static LOG_TARGET: &str = "main::upstreams";

type Result<T> = std::result::Result<T, String>;

/// The construction failure in the wording the callers have always logged
/// (`Error::Invalid`'s display).
fn invalid_error(error: impl std::fmt::Display) -> String {
    Error::Invalid {
        message: error.to_string(),
    }
    .to_string()
}

/// One owner's upstream registry. Constructed per data plane, never shared.
pub struct Provider {
    upstreams: ArcSwap<Upstreams>,
}

impl Provider {
    /// A registry with no upstreams.
    pub fn new() -> Self {
        Self {
            upstreams: ArcSwap::from_pointee(AHashMap::new()),
        }
    }

    fn store(&self, data: Upstreams) {
        self.upstreams.store(Arc::new(data));
    }

    /// Initialize the upstreams
    ///
    /// # Arguments
    /// * `upstream_configs` - The upstream configurations
    /// * `sender` - The notification sender
    ///
    /// # Returns
    /// The names of the upstreams that were built, or the construction failure.
    pub fn init_upstreams(
        self: &Arc<Self>,
        upstream_configs: &HashMap<String, UpstreamConf>,
        sender: Option<Arc<NotificationSender>>,
    ) -> Result<ProviderUpdate> {
        let (upstreams, updated) =
            new_ahash_upstreams(upstream_configs, self.clone(), sender)
                .map_err(invalid_error)?;

        self.store(upstreams);
        Ok(ProviderUpdate {
            updated,
            errors: String::new(),
        })
    }

    /// Rebuild and health-check the changed upstreams before publishing them.
    pub async fn update_upstreams(
        self: &Arc<Self>,
        upstream_configs: &HashMap<String, UpstreamConf>,
        sender: Option<Arc<NotificationSender>>,
    ) -> Result<ProviderUpdate> {
        let (upstreams, updated_upstreams) =
            new_ahash_upstreams(upstream_configs, self.clone(), sender)
                .map_err(invalid_error)?;
        for (name, up) in upstreams.iter() {
            // no need to run health check if not new upstream
            if !updated_upstreams.contains(name) {
                continue;
            }
            // run health check before switch to new upstream
            if let Err(e) = up.run_health_check().await {
                error!(
                    target: LOG_TARGET,
                    error = %e,
                    upstream = name,
                    "update upstream health check fail"
                );
            }
        }
        self.store(upstreams);
        Ok(ProviderUpdate {
            updated: updated_upstreams,
            errors: String::new(),
        })
    }
}

impl Default for Provider {
    fn default() -> Self {
        Self::new()
    }
}

impl UpstreamProvider for Provider {
    fn get(&self, name: &str) -> Option<Arc<Upstream>> {
        self.upstreams.load().get(name).cloned()
    }

    fn list(&self) -> Vec<(String, Arc<Upstream>)> {
        self.upstreams
            .load()
            .iter()
            .map(|(k, v)| (k.to_string(), v.clone()))
            .collect()
    }
}

// Compatibility layer for the pre-provider-set callers and the test suite.
// Production assembly and reload use the owned `Provider`, so these are dead
// in a non-test build by design.
#[allow(dead_code)]
static UPSTREAM_PROVIDER: LazyLock<Arc<Provider>> = LazyLock::new(|| {
    Arc::new(Provider {
        upstreams: ArcSwap::from_pointee(AHashMap::new()),
    })
});

#[allow(dead_code)]
pub fn new_upstream_provider() -> Arc<dyn UpstreamProvider> {
    UPSTREAM_PROVIDER.clone()
}

/// Compatibility wrapper over the process-wide registry.
///
/// Production assembly and reload go through [`new_upstream_provider`]'s
/// [`Provider`] instead; this is kept for the legacy paths and tests that
/// have not been converted to an owned provider set.
#[allow(dead_code)]
pub fn try_init_upstreams(
    upstream_configs: &HashMap<String, UpstreamConf>,
    sender: Option<Arc<NotificationSender>>,
) -> Result<ProviderUpdate> {
    UPSTREAM_PROVIDER.init_upstreams(upstream_configs, sender)
}

/// Compatibility wrapper over the process-wide registry; see
/// [`try_init_upstreams`].
#[allow(dead_code)]
pub async fn try_update_upstreams(
    upstream_configs: &HashMap<String, UpstreamConf>,
    sender: Option<Arc<NotificationSender>>,
) -> Result<ProviderUpdate> {
    UPSTREAM_PROVIDER
        .update_upstreams(upstream_configs, sender)
        .await
}
