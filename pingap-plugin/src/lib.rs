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

use pingap_config::PluginConf;
use pingap_core::PluginStep;
use snafu::Snafu;
use std::fmt::Write;
use std::str::FromStr;

#[derive(Debug, Snafu)]
pub enum Error {
    #[snafu(display("Plugin {category} invalid, message: {message}"))]
    Invalid { category: String, message: String },
    #[snafu(display("Plugin {category} not found"))]
    NotFound { category: String },
    #[snafu(display("Plugin {category}, base64 decode error {source}"))]
    Base64Decode {
        category: String,
        source: base64::DecodeError,
    },
    #[snafu(display("Plugin {category}, exceed limit {value}/{max}"))]
    Exceed {
        category: String,
        max: f64,
        value: f64,
    },
    #[snafu(display("Plugin {category}, regex error {source}"))]
    Regex {
        category: String,
        source: Box<fancy_regex::Error>,
    },
    #[snafu(display("Plugin {category}, base64 decode error {source}"))]
    ParseDuration {
        category: String,
        source: humantime::DurationError,
    },
}

/// Helper functions for accessing plugin configuration values
pub fn get_str_conf(value: &PluginConf, key: &str) -> String {
    value
        .get(key)
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string()
}

pub fn get_str_slice_conf(value: &PluginConf, key: &str) -> Vec<String> {
    value
        .get(key)
        .and_then(|v| v.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|item| item.as_str())
                .map(String::from) // same as .map(|s| s.to_string())
                .collect()
        })
        .unwrap_or_default()
}

/// Configuration keys whose values are credentials and must not reach a log.
const SECRET_CONFIG_KEYS: [&str; 8] = [
    "api_key",
    "authorizations",
    "client_secret",
    "cookie_secret",
    "keys",
    "password",
    "secret",
    "token",
];

/// Placeholder printed instead of a credential value.
const REDACTED: &str = "<redacted>";

/// Renders a plugin configuration for a debug log with every credential value
/// replaced by [`REDACTED`].
///
/// Auth plugins log their configuration at construction. Printing the raw
/// table wrote base64 credentials, API keys, JWT and challenge secrets into
/// the log. The shape of a list is preserved so the log still shows how many
/// credentials are configured, and every other key is rendered unchanged.
pub fn redacted_params(conf: &PluginConf) -> String {
    let mut table = conf.clone();
    for key in SECRET_CONFIG_KEYS {
        if let Some(value) = table.get_mut(key) {
            *value = redacted_value(value);
        }
    }
    table.to_string()
}

fn redacted_value(value: &toml::Value) -> toml::Value {
    match value {
        toml::Value::Array(items) => toml::Value::Array(
            items
                .iter()
                .map(|_| toml::Value::String(REDACTED.to_string()))
                .collect(),
        ),
        _ => toml::Value::String(REDACTED.to_string()),
    }
}

pub fn get_int_conf(value: &PluginConf, key: &str) -> i64 {
    get_int_conf_or_default(value, key, 0)
}

pub fn get_int_conf_or_default(
    value: &PluginConf,
    key: &str,
    default_value: i64,
) -> i64 {
    value
        .get(key)
        .and_then(|v| v.as_integer()) // assume PluginConf value can be converted to i64
        .unwrap_or(default_value)
}

/// Resolves `step`, rejecting a value the plugin does not implement.
///
/// A missing `step` keeps `default_value`; an unknown or unsupported value is
/// an error, so a misconfigured `step` surfaces at `pingap -t` instead of
/// turning into a plugin that quietly never runs.
pub fn get_step_conf_in(
    value: &PluginConf,
    category: &str,
    default_value: PluginStep,
    allowed: &[PluginStep],
) -> Result<PluginStep, Error> {
    let Some(step) = value.get("step").and_then(|v| v.as_str()) else {
        return Ok(default_value);
    };
    let invalid = || Error::Invalid {
        category: category.to_string(),
        message: format!(
            "Invalid step({step}), expect one of: {}",
            allowed
                .iter()
                .map(|item| item.to_string())
                .collect::<Vec<_>>()
                .join(", ")
        ),
    };
    let step = PluginStep::from_str(step).map_err(|_| invalid())?;
    if !allowed.contains(&step) {
        return Err(invalid());
    }
    Ok(step)
}

/// Whether a restriction list is a whitelist or a blacklist.
///
/// Parsed rather than compared literally: `type` used to be tested against the
/// string `deny`, so every other spelling — including `Deny` — silently selected
/// allow mode and inverted the policy.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub(crate) enum RestrictionCategory {
    #[default]
    Allow,
    Deny,
}

impl RestrictionCategory {
    /// Given whether the request matched the configured list, returns whether
    /// it is allowed through.
    #[inline]
    pub(crate) fn allows(&self, found: bool) -> bool {
        match self {
            Self::Allow => found,
            Self::Deny => !found,
        }
    }
}

/// Parses the `type` of a restriction plugin from the already-extracted string.
/// Absent means `allow`, which is the documented default; anything that is not
/// `allow` or `deny` is rejected.
pub(crate) fn restriction_category_from(
    value: &str,
    category: &str,
) -> Result<RestrictionCategory, Error> {
    match value.to_lowercase().as_str() {
        "" | "allow" => Ok(RestrictionCategory::Allow),
        "deny" => Ok(RestrictionCategory::Deny),
        other => Err(Error::Invalid {
            category: category.to_string(),
            message: format!("Invalid type({other}), expect allow or deny"),
        }),
    }
}

/// Deserializes a plugin's configuration into typed parameters.
///
/// `category`, `step` and the descriptive `remark` are not parameters of the
/// plugin itself, so they are removed first. With
/// `#[serde(default, deny_unknown_fields)]` on `T`, a misspelled key or a
/// value of the wrong TOML type becomes a construction error instead of a
/// silent default, and `pingap -t` reports it through `validate_plugins`.
pub fn parse_params<T>(conf: &PluginConf, category: &str) -> Result<T, Error>
where
    T: serde::de::DeserializeOwned,
{
    let mut table = conf.clone();
    table.remove("category");
    table.remove("step");
    table.remove("remark");
    toml::Value::Table(table)
        .try_into::<T>()
        .map_err(|e| Error::Invalid {
            category: category.to_string(),
            message: e.to_string(),
        })
}

/// Returns true if `accept_encoding` lists `coding` as an acceptable encoding.
///
/// Matches on comma/`;`-delimited token boundaries (so `x-gzip` does not match
/// `gzip`) and treats an explicit `q=0` as "not acceptable". Shared by the
/// `accept_encoding` and `compression` plugins so the two cannot disagree about
/// what the client accepts.
pub(crate) fn accepts_encoding(accept_encoding: &str, coding: &str) -> bool {
    accept_encoding.split(',').any(|part| {
        let mut segments = part.split(';');
        let name = segments.next().unwrap_or_default().trim();
        if !name.eq_ignore_ascii_case(coding) {
            return false;
        }
        // Acceptable unless the token is explicitly weighted q=0.
        !segments.any(|seg| {
            let seg = seg.trim();
            seg.get(..2).is_some_and(|p| p.eq_ignore_ascii_case("q="))
                && seg[2..].trim().parse::<f32>().is_ok_and(|q| q <= 0.0)
        })
    })
}

/// Generates a unique hash key for a plugin configuration to detect changes.
///
/// # Arguments
/// * `conf` - The plugin configuration to hash
///
/// # Returns
/// A string containing the CRC32 hash of the sorted configuration key-value pairs
pub fn get_hash_key(conf: &PluginConf) -> String {
    let mut items: Vec<_> = conf.iter().collect();
    // sort by key
    items.sort_unstable_by_key(|(k, _)| *k);

    // pre-allocate capacity to reduce subsequent memory reallocation.
    let mut buf = String::with_capacity(256);
    for (i, (key, value)) in items.iter().enumerate() {
        if i > 0 {
            buf.push('\n');
        }
        // use write! macro to write the formatted string directly into the buffer, avoid format! to produce temporary String.
        // because writing to String will not fail, so it can be safely.
        let _ = write!(&mut buf, "{key}:{value}");
    }

    let hash = crc32fast::hash(buf.as_bytes());
    format!("{hash:X}")
}

/// Generates the module's explicit registration function. The root calls
/// [`register_builtins`] at start-up; nothing depends on a pre-main
/// constructor any more.
macro_rules! register_plugin {
    ($category:literal, $ty:ty) => {
        pub(crate) fn register() {
            $crate::get_plugin_factory().register($category, |params| {
                Ok(::std::sync::Arc::new(<$ty>::new(params)?))
            });
        }
    };
}

mod accept_encoding;
mod basic_auth;
pub mod bot_dns;
mod combined_auth;
mod compression;
mod cors;
mod csrf;
mod directory;
mod forward_auth;
pub mod geo;
#[cfg(feature = "geo-restriction")]
mod geo_restriction;
mod ip_restriction;
mod jwt;
mod key_auth;
mod limit;
mod mock;
mod ping;
mod plugin;
mod redirect;
mod referer_restriction;
mod request_id;
mod response_headers;
mod sub_filter;
pub mod text;
mod traffic_splitting;
mod ua_restriction;

pub use plugin::get_plugin_factory;

/// Registers every generic plugin in this crate.
///
/// The binary calls this once, before any config is parsed, so availability
/// is a visible start-up step instead of a pre-main constructor side effect.
pub fn register_builtins() {
    accept_encoding::register();
    basic_auth::register();
    combined_auth::register();
    compression::register();
    cors::register();
    csrf::register();
    directory::register();
    forward_auth::register();
    #[cfg(feature = "geo-restriction")]
    geo_restriction::register();
    ip_restriction::register();
    jwt::register();
    key_auth::register();
    limit::register();
    mock::register();
    ping::register();
    redirect::register();
    referer_restriction::register();
    request_id::register();
    response_headers::register();
    sub_filter::register();
    traffic_splitting::register();
    ua_restriction::register();
}
