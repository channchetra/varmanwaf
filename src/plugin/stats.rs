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

use super::{Plugin, get_hash_key, get_step_conf_in, get_str_conf};
use crate::process::get_start_time;
use async_trait::async_trait;
use bytes::Bytes;
use pingap_config::{PluginCategory, PluginConf};
use pingap_core::{
    Ctx, HttpResponse, PluginStep, RequestPluginResult, get_hostname,
};
use pingap_performance::{get_process_system_info, get_processing_accepted};
use pingap_plugin::redacted_params;
use pingap_plugin::{Error, get_plugin_factory};
use pingora::proxy::Session;
use serde::Serialize;
use std::borrow::Cow;
use std::sync::Arc;
use std::time::Duration;
use tracing::debug;

static LOG_TARGET: &str = "main::stats";

type Result<T> = std::result::Result<T, Error>;

/// ServerStats collects and represents comprehensive server metrics including:
/// - Request processing statistics
/// - System resource utilization
/// - Server identification information
/// - Network connection details
#[derive(Serialize)]
struct ServerStats {
    // Request processing
    processing: i32,
    accepted: u64,
    location_processing: i32,
    location_accepted: u64,

    // Server identification
    hostname: String,
    version: String,
    rustc_version: String,

    // Uptime
    start_time: u64,
    /// Human-readable duration since `start_time` (e.g. "2 days 3 hours").
    uptime: String,

    // Memory
    memory_mb: usize,
    /// Human-readable process memory (e.g. "1.2 GB").
    memory: String,
    /// Human-readable total system memory.
    total_memory: String,
    /// Human-readable used system memory.
    used_memory: String,

    // System
    arch: String,
    cpus: usize,
    physical_cpus: usize,

    // Resource usage
    threads: i64,
    fd_count: usize,

    // Network connections
    tcp_count: usize,
    tcp6_count: usize,
}

/// Stats plugin that exposes server metrics and statistics via an HTTP endpoint
pub struct Stats {
    path: String,
    plugin_step: PluginStep,
    hash_value: String,
}

/// Implementation for creating a Stats instance from plugin configuration
impl TryFrom<&PluginConf> for Stats {
    type Error = Error;

    /// Attempts to create a Stats instance from the provided configuration
    ///
    /// # Arguments
    ///
    /// * `value` - Plugin configuration containing path and step settings
    ///
    /// # Returns
    ///
    /// Returns a Result containing the Stats instance if configuration is valid,
    /// or an Error if the configuration is invalid
    fn try_from(value: &PluginConf) -> Result<Self> {
        let hash_value = get_hash_key(value);
        // Stats responses are produced on the request path only.
        let step = get_step_conf_in(
            value,
            &PluginCategory::Stats.to_string(),
            PluginStep::Request,
            &[PluginStep::Request, PluginStep::ProxyUpstream],
        )?;

        Ok(Self {
            hash_value,
            plugin_step: step,
            path: get_str_conf(value, "path"),
        })
    }
}

impl Stats {
    /// Creates a new Stats plugin instance from the given plugin configuration
    ///
    /// # Arguments
    ///
    /// * `params` - The plugin configuration parameters
    ///
    /// # Returns
    ///
    /// Returns a Result containing the Stats plugin instance or an error
    pub fn new(params: &PluginConf) -> Result<Self> {
        debug!(target: LOG_TARGET, params = redacted_params(params), "new stats plugin");
        Self::try_from(params)
    }
}

#[async_trait]
impl Plugin for Stats {
    #[inline]
    fn config_key(&self) -> Cow<'_, str> {
        Cow::Borrowed(&self.hash_value)
    }
    /// Handles incoming HTTP requests for the Stats plugin
    ///
    /// # Arguments
    ///
    /// * `step` - The current plugin execution step
    /// * `session` - The HTTP session containing request details
    /// * `ctx` - The current state context
    ///
    /// # Returns
    ///
    /// `Skipped` when the step or path does not match, `Respond` with the
    /// JSON stats payload when it does. A serialisation failure is returned
    /// as a 500 response, not as `Err`.
    #[inline]
    async fn handle_request(
        &self,
        step: PluginStep,
        session: &mut Session,
        ctx: &mut Ctx,
    ) -> pingora::Result<RequestPluginResult> {
        if step != self.plugin_step {
            return Ok(RequestPluginResult::Skipped);
        }
        if session.req_header().uri.path() != self.path {
            return Ok(RequestPluginResult::Skipped);
        }
        let uptime: humantime::Duration =
            Duration::from_secs(pingap_core::now_sec() - get_start_time())
                .into();
        let (processing, accepted) = get_processing_accepted();
        let info = get_process_system_info();
        let resp = HttpResponse::try_from_json(&ServerStats {
            accepted,
            processing,
            location_processing: ctx.state.location_processing_count,
            location_accepted: ctx.state.location_accepted_count,
            hostname: get_hostname().to_string(),
            version: pingap_util::get_pkg_version().to_string(),
            rustc_version: pingap_util::get_rustc_version().to_string(),
            start_time: get_start_time(),
            uptime: uptime.to_string(),
            memory_mb: info.memory_mb,
            memory: info.memory,
            arch: info.arch,
            cpus: info.cpus,
            physical_cpus: info.physical_cpus,
            total_memory: info.total_memory,
            used_memory: info.used_memory,
            threads: info.threads,
            fd_count: info.fd_count,
            tcp_count: info.tcp_count,
            tcp6_count: info.tcp6_count,
            // upstream_healthy_status: get_upstream_healthy_status(),
        })
        .unwrap_or_else(|e| {
            HttpResponse::unknown_error(Bytes::from(e.to_string()))
        });
        Ok(RequestPluginResult::Respond(resp))
    }
}

/// Registers the stats plugin; called by the binary's start-up registration.
pub(crate) fn register() {
    get_plugin_factory()
        .register("stats", |params| Ok(Arc::new(Stats::new(params)?)));
}

#[cfg(test)]
mod tests {
    use super::Stats;
    use pingap_config::PluginConf;
    use pingap_core::{Ctx, Plugin, PluginStep, RequestPluginResult};
    use pingora::proxy::Session;
    use pretty_assertions::assert_eq;
    use tokio_test::io::Builder;

    #[test]
    fn test_stats_params() {
        let params = Stats::try_from(
            &toml::from_str::<PluginConf>(
                r###"
        path = "/stats"
    "###,
            )
            .unwrap(),
        )
        .unwrap();

        assert_eq!("/stats", params.path);
        assert_eq!("request", params.plugin_step.to_string());

        let result = Stats::try_from(
            &toml::from_str::<PluginConf>(
                r###"
        step = "response"
        path = "/stats"
    "###,
            )
            .unwrap(),
        );

        assert_eq!(
            "Plugin stats invalid, message: Invalid step(response), expect one of: request, proxy_upstream",
            result.err().unwrap().to_string()
        );
    }

    #[tokio::test]
    async fn test_stats() {
        let stats = Stats::new(
            &toml::from_str::<PluginConf>(
                r###"
            path = "/stats"
        "###,
            )
            .unwrap(),
        )
        .unwrap();

        let headers = ["Accept-Encoding: gzip"].join("\r\n");
        let input_header =
            format!("GET /vicanso/pingap?size=1 HTTP/1.1\r\n{headers}\r\n\r\n");
        let mock_io = Builder::new().read(input_header.as_bytes()).build();
        let mut session = Session::new_h1(Box::new(mock_io));
        session.read_request().await.unwrap();

        let result = stats
            .handle_request(
                PluginStep::Request,
                &mut session,
                &mut Ctx::default(),
            )
            .await
            .unwrap();
        assert_eq!(true, result == RequestPluginResult::Skipped);

        let headers = ["Accept-Encoding: gzip"].join("\r\n");
        let input_header = format!("GET /stats HTTP/1.1\r\n{headers}\r\n\r\n");
        let mock_io = Builder::new().read(input_header.as_bytes()).build();
        let mut session = Session::new_h1(Box::new(mock_io));
        session.read_request().await.unwrap();

        // pass
        let result = stats
            .handle_request(
                PluginStep::Request,
                &mut session,
                &mut Ctx::default(),
            )
            .await
            .unwrap();
        let RequestPluginResult::Respond(resp) = result else {
            panic!("result is not Respond");
        };
        assert_eq!(200, resp.status.as_u16());
    }
}
