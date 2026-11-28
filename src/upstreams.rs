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

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    #[tokio::test]
    async fn update_upstreams_health_checks_changed_backends() {
        let listener =
            tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let origin = tokio::spawn(async move {
            loop {
                let Ok((mut stream, _)) = listener.accept().await else {
                    break;
                };
                let mut buf = [0u8; 1024];
                let _ = stream.read(&mut buf).await;
                let _ = stream
                    .write_all(
                        b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
                    )
                    .await;
            }
        });

        let provider = Arc::new(Provider::new());
        let configs = HashMap::from([(
            "origin".to_string(),
            UpstreamConf {
                addrs: vec![addr.to_string()],
                health_check: Some(format!("http://{addr}/health")),
                ..Default::default()
            },
        )]);

        let update = provider
            .update_upstreams(&configs, None)
            .await
            .expect("the upstream must build");
        assert!(update.is_ok(), "{}", update.errors);
        assert_eq!(vec!["origin".to_string()], update.updated);
        assert!(provider.get("origin").is_some());
        origin.abort();
    }
}
