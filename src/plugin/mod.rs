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
use pingap_config::{ConfigManager, PluginConf};
use pingap_core::{Plugin, PluginProvider, Plugins};
use pingap_plugin::{Error, get_plugin_factory};
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
use std::collections::HashMap;
use std::str::FromStr;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use tracing::{error, info};

use crate::data_plane::ProviderSet;
use crate::provider::{AdminPluginEntry, ProviderUpdate};

mod admin;
mod stats;

pub(crate) use self::admin::AdminServe;

/// UUID for the admin server plugin, generated at runtime
pub static ADMIN_SERVER_PLUGIN: &str = "pingap:admin";

/// Name and configuration of a plugin the root constructs itself and hands to
/// [`Provider::replace_plugins`], instead of the registry deriving it from a
/// process-global set during boot.
static LOG_TARGET: &str = "main::plugin";

#[derive(Debug, PartialEq, Deserialize, Serialize, Default)]
struct AdminPluginQuery {
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
/// Returns Error::Invalid if URL parsing, the username's percent-encoding or
/// the query string fails to parse
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
        let user = urlencoding::decode(info.username()).map_err(|e| {
            Error::Invalid {
                category: "admin".to_string(),
                message: format!(
                    "invalid percent-encoding in admin username: {e}"
                ),
            }
        })?;
        authorization = user.to_string();
        // if not base64 string
        if let Some(pass) = info.password() {
            // `info.password()` is the raw url component: `--admin=u:p%40ss@h`
            // must store `u:p@ss`, not the escaped form. Decode it like the
            // username so a colon or space can be written percent-encoded.
            let pass =
                urlencoding::decode(pass).map_err(|e| Error::Invalid {
                    category: "admin".to_string(),
                    message: format!(
                        "invalid percent-encoding in admin password: {e}"
                    ),
                })?;
            authorization = base64_encode(format!("{authorization}:{pass}"));
        }
    }
    let mut path = info.path().to_string();
    if path.is_empty() {
        path = "/".to_string();
    }
    let params: AdminPluginQuery =
        serde_qs::from_str(info.query().unwrap_or_default()).map_err(|e| {
            Error::Invalid {
                category: "admin".to_string(),
                message: format!("invalid admin query: {e}"),
            }
        })?;
    let max_age = params.max_age.unwrap_or("2d".to_string());

    // Build the map directly: a path or credential containing a quote must
    // not be able to break (or inject into) a TOML document, and a parse
    // failure must not quietly become an empty plugin config.
    let mut plugin_conf = PluginConf::new();
    plugin_conf.insert(
        "category".to_string(),
        toml::Value::String("admin".to_string()),
    );
    plugin_conf.insert("path".to_string(), toml::Value::String(path));
    plugin_conf.insert(
        "authorizations".to_string(),
        toml::Value::Array(vec![toml::Value::String(authorization)]),
    );
    plugin_conf.insert("max_age".to_string(), toml::Value::String(max_age));
    plugin_conf.insert(
        "remark".to_string(),
        toml::Value::String("Admin serve".to_string()),
    );
    Ok((
        ServerConf {
            name: "pingap:admin".to_string(),
            admin: true,
            addr,
            ..Default::default()
        },
        ADMIN_SERVER_PLUGIN.to_string(),
        plugin_conf,
    ))
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
            .expect("built-in plugin config must parse"),
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
            .expect("built-in plugin config must parse"),
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
            .expect("built-in plugin config must parse"),
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
            .expect("built-in plugin config must parse"),
        ),
        (
            "pingap:requestId".to_string(),
            toml::from_str::<PluginConf>(
                r###"
category = "request_id"
remark = "Generate a request id for service"
"###,
            )
            .expect("built-in plugin config must parse"),
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
            .expect("built-in plugin config must parse"),
        ),
    ]
}

/// One owner's plugin registry. Constructed per data plane, never shared.
pub struct Provider {
    plugins: ArcSwap<Plugins>,
    /// Bumped on every `store`, so locations drop the plugin lists they
    /// resolved against the previous set.
    version: AtomicU64,
}

impl Provider {
    /// A registry with no plugins.
    pub fn new() -> Self {
        Self {
            plugins: ArcSwap::from_pointee(AHashMap::new()),
            version: AtomicU64::new(0),
        }
    }

    fn store(&self, data: Plugins) {
        self.plugins.store(Arc::new(data));
        self.version.fetch_add(1, Ordering::Release);
    }
}

impl Default for Provider {
    fn default() -> Self {
        Self::new()
    }
}

impl PluginProvider for Provider {
    fn get(&self, name: &str) -> Option<Arc<dyn Plugin>> {
        self.plugins.load().get(name).cloned()
    }

    fn version(&self) -> u64 {
        self.version.load(Ordering::Acquire)
    }
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

    (plugins, errors)
}

/// Registers the plugins that live outside `pingap-plugin`'s own link set.
///
/// `pingap-imageoptim` registers through a `#[ctor]`, which only runs when the
/// crate is linked. Naming it here is that link edge, and the call makes the
/// registration explicit instead of relying on an unused import in `main`.
pub fn register_builtin_plugins() {
    pingap_plugin::register_builtins();
    #[cfg(feature = "imageoptim")]
    pingap_imageoptim::register();
    varman_plugin::register();
}

impl Provider {
    /// Initializes or updates the plugins of this registry.
    ///
    /// # Arguments
    /// * `plugins` - HashMap of plugin names to configurations
    /// * `admin` - The admin listener plugin parsed by the root, if it serves
    ///   one. It is passed explicitly because it is not part of the loaded
    ///   document and must not depend on start-up order.
    /// * `config_manager` - The manager every admin plugin reads and writes
    ///   the configuration through.
    /// * `providers` - The plane's provider set, handed to the admin plugin so
    ///   its introspection endpoints read the same registries as the plane.
    ///
    /// # Returns
    /// Vector of plugin names that were created or updated
    pub fn replace_plugins(
        &self,
        plugins: &HashMap<String, PluginConf>,
        admin: Option<AdminPluginEntry>,
        config_manager: Arc<ConfigManager>,
        providers: &ProviderSet,
    ) -> ProviderUpdate {
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
        let mut pending_admins: Vec<(String, PluginConf)> = vec![];
        for (name, conf) in plugin_configs {
            let conf_hash_key = get_hash_key(&conf);
            let current = self.get(&name);
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
            // Built below with the manager this call was handed: the factory has
            // none to give it. Covers the `--admin` listener and any
            // `category = "admin"` entry in the document alike.
            if category == "admin" {
                pending_admins.push((name, conf));
                continue;
            }
            pending_configs.push((name, conf));
        }
        let (mut new_plugins, new_errors) = parse_plugins(pending_configs);
        errors.extend(new_errors);
        for (name, conf) in pending_admins {
            match AdminServe::new(&conf, config_manager.clone(), providers) {
                Ok(plugin) => {
                    new_plugins.insert(name, Arc::new(plugin));
                },
                Err(e) => errors.push(Error::Invalid {
                    category: "admin".to_string(),
                    message: format!("create plugin {name} failed, {e}"),
                }),
            }
        }
        plugins.extend(new_plugins);
        // Swap the registry only when every plugin built. Storing the partial map
        // would drop the plugins that failed to rebuild, so the running config
        // would reference plugins that no longer exist.
        let error = if errors.is_empty() {
            self.store(plugins);
            String::new()
        } else {
            // The registry was not swapped, so none of the rebuilt plugins was
            // installed: reporting their names would claim a change that did
            // not happen.
            updated_plugins.clear();
            let error = errors
                .iter()
                .map(|e| e.to_string())
                .collect::<Vec<_>>()
                .join(";");
            error!(target: LOG_TARGET, error, "parse plugins failed");
            error
        };

        ProviderUpdate {
            updated: updated_plugins,
            errors: error,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The message of a rejected admin address, asserting the `admin`
    /// category so a decode failure cannot pass as a URL-parse failure.
    fn admin_error(addr: &str) -> String {
        let error = parse_admin_plugin(addr)
            .expect_err("the admin address must be rejected");
        let Error::Invalid { category, message } = error else {
            panic!("expected an Invalid error, got {error}");
        };
        assert_eq!("admin", category);
        message
    }

    #[test]
    fn a_valid_admin_address_is_parsed() {
        let (server, name, conf) =
            parse_admin_plugin("admin:secret@127.0.0.1:3018/?max_age=1d")
                .expect("a valid admin address must parse");

        assert_eq!("127.0.0.1:3018", server.addr);
        assert!(server.admin);
        assert_eq!(ADMIN_SERVER_PLUGIN, name);
        assert_eq!(
            Some("1d"),
            conf.get("max_age").and_then(|value| value.as_str())
        );
        assert_eq!(
            Some("/"),
            conf.get("path").and_then(|value| value.as_str())
        );
    }

    /// Regression: the password was read from the raw url component, so
    /// `--admin=u:p%40ss@host` stored `u:p%40ss`. Both halves of the
    /// credential are percent-decoded before being base64-encoded.
    #[test]
    fn a_percent_encoded_admin_credential_is_decoded() {
        let authorization = |addr: &str| {
            let (_, _, conf) = parse_admin_plugin(addr)
                .expect("a percent-encoded credential must parse");
            conf.get("authorizations")
                .and_then(|value| value.as_array())
                .and_then(|items| items.first())
                .and_then(|value| value.as_str())
                .unwrap_or_default()
                .to_string()
        };

        assert_eq!(
            base64_encode("u:p@ss"),
            authorization("u:p%40ss@127.0.0.1:3018")
        );

        // A space in the user name and a colon plus a space in the password
        // stay unambiguous: the plugin splits the decoded value on the first
        // colon, so the password keeps its own colons.
        assert_eq!(
            base64_encode("u ser:pa: ss"),
            authorization("u%20ser:pa%3A%20ss@127.0.0.1:3018")
        );
    }

    #[test]
    fn a_malformed_query_is_rejected_instead_of_defaulted() {
        // `max_age` is a string, not a nested map: the parse must fail
        // instead of silently falling back to the defaults.
        let message = admin_error("127.0.0.1:3018/?max_age[a]=1");
        assert!(message.contains("invalid admin query"), "{message}");
    }

    #[test]
    fn a_malformed_username_encoding_is_rejected() {
        // `%FF` is a valid escape that does not decode to UTF-8.
        let message = admin_error("ad%FFmin:secret@127.0.0.1:3018/");
        assert!(
            message.contains("invalid percent-encoding in admin username"),
            "{message}"
        );
    }

    #[test]
    fn a_malformed_password_encoding_is_rejected() {
        // Same failure mode as the user name, named for the password so the
        // message points at the half that is actually broken.
        let message = admin_error("admin:sec%FFret@127.0.0.1:3018/");
        assert!(
            message.contains("invalid percent-encoding in admin password"),
            "{message}"
        );
    }

    #[test]
    fn an_out_of_range_port_is_rejected() {
        let error = parse_admin_plugin("127.0.0.1:99999")
            .expect_err("an out-of-range port must be rejected");
        let Error::Invalid { category, .. } = error else {
            panic!("expected an Invalid error, got {error}");
        };
        assert_eq!("url", category);
    }

    /// A `category = "admin"` entry in the document (the shape `conf/plugins.toml`
    /// documents) is not in the factory any more: it is built with the manager
    /// the caller passed, exactly like the `--admin` listener.
    #[test]
    fn a_document_admin_plugin_is_built_with_the_given_manager() {
        pingap_plugin::register_builtins();
        let manager = Arc::new(pingap_config::new_memory_config_manager(
            "[basic]\n",
            None,
        ));
        let plugins = HashMap::from([(
            "test:documentAdmin".to_string(),
            toml::from_str::<PluginConf>(
                r#"
category = "admin"
path = "/test-admin"
allow_unauthenticated = true
"#,
            )
            .unwrap(),
        )]);

        let update = Provider::new().replace_plugins(
            &plugins,
            None,
            manager.clone(),
            &ProviderSet::new(),
        );

        assert!(update.errors.is_empty(), "{}", update.errors);
        assert!(
            update
                .updated
                .iter()
                .any(|name| name == "test:documentAdmin"),
            "the document admin plugin must be created: {:?}",
            update.updated
        );

        // A bad admin config is reported against its name instead of being
        // skipped, and keeps the previous plugin map.
        let plugins = HashMap::from([(
            "test:badAdmin".to_string(),
            toml::from_str::<PluginConf>(r#"category = "admin""#).unwrap(),
        )]);
        let update = Provider::new().replace_plugins(
            &plugins,
            None,
            manager,
            &ProviderSet::new(),
        );

        assert!(update.errors.contains("test:badAdmin"), "{}", update.errors);
        assert!(
            update.errors.contains("authorizations is empty"),
            "{}",
            update.errors
        );
        assert!(
            update.updated.is_empty(),
            "a skipped swap must not report updated plugins: {:?}",
            update.updated
        );
    }
}
