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

use ahash::AHashMap;
use arc_swap::ArcSwap;
use pingap_config::PluginConf;
use pingap_core::{Plugin, PluginProvider, Plugins};
use pingap_plugin::get_plugin_factory;
// Reuse the canonical plugin-config helpers instead of keeping a second copy.
// `get_hash_key` in particular MUST stay byte-identical to the one plugins use
// to compute their config key, otherwise hot-reload change detection breaks.
pub(crate) use pingap_plugin::{
    get_hash_key, get_int_conf, get_step_conf_in, get_str_conf,
    get_str_slice_conf,
};
use pingap_proxy::ServerConf;
use pingap_util::base64_encode;
use serde::{Deserialize, Serialize};
use snafu::Snafu;
use std::collections::HashMap;
use std::str::FromStr;
use std::sync::Arc;
use std::sync::LazyLock;
use std::sync::atomic::{AtomicU64, Ordering};
use tracing::{error, info};

mod admin;
mod stats;

/// UUID for the admin server plugin, generated at runtime
pub static ADMIN_SERVER_PLUGIN: &str = "pingap:admin";

/// Name and configuration of a plugin the root constructs itself and hands to
/// [`try_init_plugins`], instead of the registry deriving it from a
/// process-global set during boot.
pub type AdminPlugin = (String, PluginConf);

static LOG_TARGET: &str = "main::plugin";

#[derive(Debug, PartialEq, Deserialize, Serialize, Default)]
struct AdminPluginParams {
    max_age: Option<String>,
}

/// Parses admin plugin configuration from an address string.
///
/// # Arguments
/// * `addr` - The address string to parse in URL format
///
/// # Returns
/// A tuple containing:
/// - ServerConf: The server configuration
/// - String: The plugin name
/// - PluginConf: The plugin configuration
///
/// # Errors
/// Returns Error::Invalid if URL parsing fails
pub fn parse_admin_plugin(
    addr: &str,
) -> Result<(ServerConf, String, PluginConf)> {
    let info = url::Url::from_str(&format!("http://{addr}")).map_err(|e| {
        Error::Invalid {
            category: "url".to_string(),
            message: e.to_string(),
        }
    })?;
    let mut addr = info.host_str().unwrap_or_default().to_string();
    addr = format!("{addr}:{}", info.port().unwrap_or(80));

    let mut authorization = "".to_string();
    if !info.username().is_empty() {
        authorization = urlencoding::decode(info.username())
            .unwrap_or_default()
            .to_string();
        // if not base64 string
        if let Some(pass) = info.password() {
            authorization = base64_encode(format!("{authorization}:{pass}"));
        }
    }
    let mut path = info.path().to_string();
    if path.is_empty() {
        path = "/".to_string();
    }
    let params: AdminPluginParams =
        serde_qs::from_str(info.query().unwrap_or_default())
            .unwrap_or_default();
    let max_age = params.max_age.unwrap_or("2d".to_string());

    let data = format!(
        r#"
    category = "admin"
    path = "{path}"
    authorizations = [
        "{authorization}"
    ]
    max_age = "{max_age}"
    remark = "Admin serve"
    "#,
    );
    Ok((
        ServerConf {
            name: "pingap:admin".to_string(),
            admin: true,
            addr,
            ..Default::default()
        },
        ADMIN_SERVER_PLUGIN.to_string(),
        toml::from_str::<PluginConf>(&data).unwrap_or_default(),
    ))
}

/// Error types for plugin operations
#[derive(Debug, Snafu)]
pub enum Error {
    #[snafu(display("Plugin {category} invalid, message: {message}"))]
    Invalid { category: String, message: String },
}
type Result<T, E = Error> = std::result::Result<T, E>;

/// Returns a list of built-in plugins with their default configurations.
///
/// Includes plugins for:
/// - Compression (gzip, br, zstd)
/// - Ping health check
/// - Stats reporting
/// - Request ID generation
/// - Accept-Encoding adjustment
pub fn get_builtin_proxy_plugins() -> Vec<(String, PluginConf)> {
    vec![
        // default level, gzip:6 br:6 zstd:3
        (
            "pingap:compression".to_string(),
            toml::from_str::<PluginConf>(
                r###"
category = "compression"
gzip_level = 6
br_level = 6
zstd_level = 6
remark = "Compression for http, support zstd:6, br:6, gzip:6"
"###,
            )
            .unwrap_or_default(),
        ),
        (
            "pingap:compressionUpstream".to_string(),
            toml::from_str::<PluginConf>(
                r###"
category = "compression"
gzip_level = 6
br_level = 6
zstd_level = 6 
mode = "upstream"
remark = "Compression for upstream response, support zstd:6, br:6, gzip:6"
"###,
            )
            .unwrap_or_default(),
        ),
        (
            "pingap:ping".to_string(),
            toml::from_str::<PluginConf>(
                r###"
category = "ping"
path = "/ping"
remark = "Ping pong"
"###,
            )
            .unwrap_or_default(),
        ),
        (
            "pingap:stats".to_string(),
            toml::from_str::<PluginConf>(
                r###"
category = "stats"
path = "/stats"
remark = "Get stats of server"
"###,
            )
            .unwrap_or_default(),
        ),
        (
            "pingap:requestId".to_string(),
            toml::from_str::<PluginConf>(
                r###"
category = "request_id"
remark = "Generate a request id for service"
"###,
            )
            .unwrap_or_default(),
        ),
        (
            "pingap:acceptEncodingAdjustment".to_string(),
            toml::from_str::<PluginConf>(
                r###"
category = "accept_encoding"
encodings = "zstd, br, gzip"
only_one_encoding = true
remark = "Adjust the accept encoding order and choose one encoding"
"###,
            )
            .unwrap_or_default(),
        ),
    ]
}

struct Provider {
    plugins: ArcSwap<Plugins>,
    /// Bumped on every `store`, so locations drop the plugin lists they
    /// resolved against the previous set.
    version: AtomicU64,
}

impl Provider {
    fn store(&self, data: Plugins) {
        self.plugins.store(Arc::new(data));
        self.version.fetch_add(1, Ordering::Release);
    }
}

static PLUGIN_PROVIDER: LazyLock<Arc<Provider>> = LazyLock::new(|| {
    Arc::new(Provider {
        plugins: ArcSwap::from_pointee(AHashMap::new()),
        version: AtomicU64::new(0),
    })
});

impl PluginProvider for Provider {
    fn get(&self, name: &str) -> Option<Arc<dyn Plugin>> {
        self.plugins.load().get(name).cloned()
    }

    fn version(&self) -> u64 {
        self.version.load(Ordering::Acquire)
    }
}

pub fn new_plugin_provider() -> Arc<dyn PluginProvider> {
    PLUGIN_PROVIDER.clone()
}

/// Parses plugin configurations and instantiates plugin instances.
///
/// # Arguments
/// * `configs` - Vector of (name, config) tuples for plugins to initialize
///
/// # Returns
/// A tuple of the plugins that were created, keyed by name, and the errors for
/// the configurations that failed. One failure does not stop the remaining
/// plugins from being created; the caller decides what to do with the errors.
pub fn parse_plugins(
    configs: Vec<(String, PluginConf)>,
) -> (Plugins, Vec<Error>) {
    let mut plugins: Plugins = AHashMap::new();
    let mut errors: Vec<Error> = vec![];
    for (name, conf) in configs.iter() {
        let name = name.to_string();
        let category = if let Some(value) = conf.get("category") {
            value.as_str().unwrap_or_default().to_string()
        } else {
            "".to_string()
        };
        if category.is_empty() {
            errors.push(Error::Invalid {
                category: "".to_string(),
                message: format!("category of {name} can not be empty"),
            });
            continue;
        }

        match get_plugin_factory().create(conf) {
            Ok(plugin) => {
                plugins.insert(name.clone(), plugin.clone());
            },
            Err(e) => {
                errors.push(Error::Invalid {
                    category,
                    message: format!("create plugin {name} failed, {e}"),
                });
            },
        }
    }

    // let plugin =
    //     get_plugin_factory()
    //         .create(conf)
    //         .map_err(|e| Error::Invalid {
    //             category,
    //             message: format!("create plugin {name} failed, {}", e),
    //         })?;
    // plugins.insert(name.clone(), plugin.clone());
    // }

    (plugins, errors)
}

/// Registers the plugins that live outside `pingap-plugin`'s own link set.
///
/// `pingap-imageoptim` registers through a `#[ctor]`, which only runs when the
/// crate is linked. Naming it here is that link edge, and the call makes the
/// registration explicit instead of relying on an unused import in `main`.
pub fn register_builtin_plugins() {
    #[cfg(feature = "imageoptim")]
    pingap_imageoptim::register();
}

/// Initializes or updates plugins based on configuration.
///
/// # Arguments
/// * `plugins` - HashMap of plugin names to configurations
/// * `admin` - The admin listener plugin parsed by the root, if it serves one.
///   It is passed explicitly because it is not part of the loaded document and
///   must not depend on start-up order.
///
/// # Returns
/// Vector of plugin names that were created or updated
///
/// # Errors
/// Returns Error if plugin initialization fails
pub fn try_init_plugins(
    plugins: &HashMap<String, PluginConf>,
    admin: Option<AdminPlugin>,
) -> (Vec<String>, String) {
    let mut plugin_configs: Vec<(String, PluginConf)> = plugins
        .iter()
        .map(|(name, value)| (name.to_string(), value.clone()))
        .collect();

    let mut errors = vec![];
    // A configuration entry named like the admin plugin wins, exactly as it
    // did when the plugin was injected from the process-global address.
    if let Some((name, conf)) = admin
        && !plugins.contains_key(&name)
    {
        plugin_configs.push((name, conf));
    }

    plugin_configs.extend(get_builtin_proxy_plugins());

    let mut updated_plugins = vec![];
    let mut plugins = AHashMap::new();
    let mut pending_configs = Vec::with_capacity(plugin_configs.len());
    for (name, conf) in plugin_configs {
        let conf_hash_key = get_hash_key(&conf);
        let current = PLUGIN_PROVIDER.get(&name);
        // already current -> reuse the running instance unchanged
        if let Some(plugin) = current.as_ref()
            && plugin.config_key() == conf_hash_key
        {
            plugins.insert(name, plugin.clone());
            continue;
        }
        // changed (or new) -> rebuild from the configuration
        // This only labels the build log: the category's own constructor
        // validates `step` and rejects one it does not implement.
        let step = conf
            .get("step")
            .and_then(|value| value.as_str())
            .unwrap_or("request");
        let category = conf
            .get("category")
            .and_then(|value| value.as_str())
            .unwrap_or_default()
            .to_string();
        if current.is_some() {
            info!(target: LOG_TARGET, name, step, category, "plugin will be reloaded");
        } else {
            info!(target: LOG_TARGET, name, step, category, "plugin will be created");
        }
        updated_plugins.push(name.clone());
        pending_configs.push((name, conf));
    }
    let (new_plugins, new_errors) = parse_plugins(pending_configs);
    plugins.extend(new_plugins);
    errors.extend(new_errors);
    // Swap the registry only when every plugin built. Storing the partial map
    // would drop the plugins that failed to rebuild, so the running config
    // would reference plugins that no longer exist.
    let error = if errors.is_empty() {
        PLUGIN_PROVIDER.store(plugins);
        String::new()
    } else {
        let error = errors
            .iter()
            .map(|e| e.to_string())
            .collect::<Vec<_>>()
            .join(";");
        error!(target: LOG_TARGET, error, "parse plugins failed");
        error
    };

    (updated_plugins, error)
}

#[cfg(test)]
#[test]
pub fn initialize_test_plugins() {
    let plugins = HashMap::from([
        (
            "test:mock".to_string(),
            toml::from_str::<PluginConf>(
                r###"
category = "mock"
path = "/mock"
status = 999
data = "abc"
"###,
            )
            .unwrap(),
        ),
        (
            "test:add_headers".to_string(),
            toml::from_str::<PluginConf>(
                r###"
category = "response_headers"
step = "response"
add_headers = [
"X-Service:1",
"X-Service:2",
]
set_headers = [
"X-Response-Id:123"
]
remove_headers = [
"Content-Type"
]
"###,
            )
            .unwrap(),
        ),
    ]);
    let (_, error) = try_init_plugins(&plugins, None);
    assert!(error.is_empty());
}
