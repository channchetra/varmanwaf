//! Configuration for the Elasticsearch log shipper.
//!
//! [`EsConfig`] is deliberately flat and fully `serde`-driven so it can be
//! embedded in [`crate::config::ServerConfig`] (TOML / env), returned verbatim
//! by the settings API and round-tripped through JSON without a second type.
//!
//! Every field carries a `#[serde(default = …)]` so a partial configuration —
//! the common case when an operator only sets `urls` and `enabled` — still
//! produces a working shipper.

use serde::{Deserialize, Serialize};

/// Default index prefix; daily indices become `{prefix}-access-YYYY.MM.DD` and
/// `{prefix}-security-YYYY.MM.DD`.
pub const DEFAULT_INDEX_PREFIX: &str = "pingwaf";
/// Maximum number of documents accumulated before a bulk request is sent.
pub const DEFAULT_BULK_MAX_SIZE: usize = 1000;
/// Maximum time (ms) a document may sit in the buffer before it is flushed.
pub const DEFAULT_BULK_FLUSH_INTERVAL_MS: u64 = 5000;
/// Maximum request/response body bytes recorded per document (8 KiB).
pub const DEFAULT_MAX_BODY_SIZE: usize = 8 * 1024;
/// Maximum size of the on-disk write-ahead buffer (512 MiB).
pub const DEFAULT_BUFFER_MAX_SIZE_MB: usize = 512;
/// Number of documents the in-memory channel may hold before producers start
/// dropping. Sized to absorb a burst without ever applying back-pressure to the
/// proxy hot path.
pub const DEFAULT_CHANNEL_CAPACITY: usize = 65_536;
/// Timeout (seconds) applied to every outbound ES request.
pub const DEFAULT_REQUEST_TIMEOUT_SECS: u64 = 30;

fn default_index_prefix() -> String {
    DEFAULT_INDEX_PREFIX.to_string()
}

fn default_bulk_max_size() -> usize {
    DEFAULT_BULK_MAX_SIZE
}

fn default_bulk_flush_interval_ms() -> u64 {
    DEFAULT_BULK_FLUSH_INTERVAL_MS
}

fn default_max_body_size() -> usize {
    DEFAULT_MAX_BODY_SIZE
}

fn default_buffer_max_size_mb() -> usize {
    DEFAULT_BUFFER_MAX_SIZE_MB
}

fn default_channel_capacity() -> usize {
    DEFAULT_CHANNEL_CAPACITY
}

fn default_request_timeout_secs() -> u64 {
    DEFAULT_REQUEST_TIMEOUT_SECS
}

/// Runtime configuration of the Elasticsearch log shipper.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct EsConfig {
    /// Elasticsearch node URL(s). Multiple nodes are tried round-robin, which
    /// gives client-side failover without a load balancer.
    #[serde(default)]
    pub urls: Vec<String>,
    /// Index prefix; indices are named `{prefix}-access-YYYY.MM.DD` and
    /// `{prefix}-security-YYYY.MM.DD`.
    #[serde(default = "default_index_prefix")]
    pub index_prefix: String,

    // ── Authentication ────────────────────────────────────────────────────
    /// Basic-auth username. Ignored when `api_key` is set.
    #[serde(default)]
    pub username: Option<String>,
    /// Basic-auth password.
    #[serde(default)]
    pub password: Option<String>,
    /// Elasticsearch API key, sent as `Authorization: ApiKey <key>`. Takes
    /// precedence over username/password.
    #[serde(default)]
    pub api_key: Option<String>,

    // ── Bulk settings ─────────────────────────────────────────────────────
    /// Maximum documents per bulk request.
    #[serde(default = "default_bulk_max_size")]
    pub bulk_max_size: usize,
    /// Maximum time before the buffer is flushed, in milliseconds.
    #[serde(default = "default_bulk_flush_interval_ms")]
    pub bulk_flush_interval_ms: u64,

    // ── Body truncation ───────────────────────────────────────────────────
    /// Maximum request/response body bytes kept per document.
    #[serde(default = "default_max_body_size")]
    pub max_body_size: usize,

    // ── Enable/disable ────────────────────────────────────────────────────
    /// Master switch; a disabled shipper never touches the network or disk.
    #[serde(default)]
    pub enabled: bool,

    // ── Local write-ahead buffer ──────────────────────────────────────────
    /// Directory for the on-disk WAL used while ES is unreachable. `None`
    /// disables buffering (failed batches are dropped after a warning).
    #[serde(default)]
    pub buffer_dir: Option<String>,
    /// Maximum total size of the on-disk buffer, in megabytes. Oldest segments
    /// are discarded once the ceiling is reached.
    #[serde(default = "default_buffer_max_size_mb")]
    pub buffer_max_size_mb: usize,

    // ── Advanced ──────────────────────────────────────────────────────────
    /// Capacity of the in-memory document channel.
    #[serde(default = "default_channel_capacity")]
    pub channel_capacity: usize,
    /// Per-request timeout, in seconds.
    #[serde(default = "default_request_timeout_secs")]
    pub request_timeout_secs: u64,
}

impl Default for EsConfig {
    fn default() -> Self {
        Self {
            urls: Vec::new(),
            index_prefix: default_index_prefix(),
            username: None,
            password: None,
            api_key: None,
            bulk_max_size: DEFAULT_BULK_MAX_SIZE,
            bulk_flush_interval_ms: DEFAULT_BULK_FLUSH_INTERVAL_MS,
            max_body_size: DEFAULT_MAX_BODY_SIZE,
            enabled: false,
            buffer_dir: None,
            buffer_max_size_mb: DEFAULT_BUFFER_MAX_SIZE_MB,
            channel_capacity: DEFAULT_CHANNEL_CAPACITY,
            request_timeout_secs: DEFAULT_REQUEST_TIMEOUT_SECS,
        }
    }
}

impl EsConfig {
    /// Validates the configuration, rejecting values that cannot produce a
    /// working shipper. Only meaningful when [`Self::enabled`] is true; a
    /// disabled config is always accepted so it can be stored incomplete.
    pub fn validate(&self) -> anyhow::Result<()> {
        anyhow::ensure!(
            !self.urls.iter().all(|url| url.trim().is_empty()),
            "at least one elasticsearch url is required"
        );
        for url in &self.urls {
            let trimmed = url.trim();
            anyhow::ensure!(
                trimmed.starts_with("http://") || trimmed.starts_with("https://"),
                "elasticsearch url '{trimmed}' must start with http:// or https://"
            );
        }
        anyhow::ensure!(
            self.bulk_max_size > 0,
            "bulk_max_size must be positive"
        );
        anyhow::ensure!(
            self.bulk_flush_interval_ms > 0,
            "bulk_flush_interval_ms must be positive"
        );
        anyhow::ensure!(
            self.max_body_size > 0,
            "max_body_size must be positive"
        );
        anyhow::ensure!(
            self.channel_capacity > 0,
            "channel_capacity must be positive"
        );
        anyhow::ensure!(
            self.request_timeout_secs > 0,
            "request_timeout_secs must be positive"
        );
        if self.api_key.is_none() {
            // Basic auth is all-or-nothing: a username without a password (or
            // vice versa) is almost always a typo.
            anyhow::ensure!(
                self.username.is_none() || self.password.is_some(),
                "elasticsearch username requires a password"
            );
        }
        Ok(())
    }

    /// Normalises user input in place: trims URLs, drops empties and strips a
    /// trailing slash so `{base}/_bulk` never collapses into `//_bulk`.
    pub fn normalise(&mut self) {
        self.urls = self
            .urls
            .iter()
            .map(|url| url.trim().trim_end_matches('/').to_string())
            .filter(|url| !url.is_empty())
            .collect();
        self.index_prefix =
            self.index_prefix.trim().trim_end_matches('-').to_string();
        if self.index_prefix.is_empty() {
            self.index_prefix = default_index_prefix();
        }
    }

    /// A copy safe to return over the API: secrets are replaced with `***`.
    pub fn redacted(&self) -> Self {
        let mut copy = self.clone();
        if copy.password.is_some() {
            copy.password = Some("***".to_string());
        }
        if copy.api_key.is_some() {
            copy.api_key = Some("***".to_string());
        }
        copy
    }

    /// True when the shipper should start: enabled and pointing somewhere.
    pub fn is_active(&self) -> bool {
        self.enabled && self.urls.iter().any(|url| !url.trim().is_empty())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> EsConfig {
        EsConfig {
            urls: vec!["https://es.example.com:9200/".to_string()],
            enabled: true,
            api_key: Some("secret".to_string()),
            ..Default::default()
        }
    }

    #[test]
    fn defaults_are_inactive_but_valid_shape() {
        let config = EsConfig::default();
        assert!(!config.enabled);
        assert!(!config.is_active());
        assert_eq!(config.index_prefix, DEFAULT_INDEX_PREFIX);
    }

    #[test]
    fn normalise_trims_and_strips_slash() {
        let mut config = sample();
        config.urls.push("   ".to_string());
        config.normalise();
        assert_eq!(
            config.urls,
            vec!["https://es.example.com:9200".to_string()]
        );
    }

    #[test]
    fn validate_rejects_missing_urls_and_bad_auth() {
        let mut config = sample();
        config.normalise();
        config.validate().expect("valid");

        config.urls.clear();
        assert!(config.validate().is_err());

        let mut auth = sample();
        auth.api_key = None;
        auth.username = Some("user".to_string());
        auth.password = None;
        assert!(auth.validate().is_err());
    }

    #[test]
    fn redacted_hides_secrets() {
        let mut config = sample();
        config.password = Some("hunter2".to_string());
        let redacted = config.redacted();
        assert_eq!(redacted.password.as_deref(), Some("***"));
        assert_eq!(redacted.api_key.as_deref(), Some("***"));
    }

    #[test]
    fn serde_defaults_fill_missing_fields() {
        let config: EsConfig = serde_json::from_str(
            r#"{"urls":["http://localhost:9200"],"enabled":true}"#,
        )
        .expect("partial config parses");
        assert_eq!(config.bulk_max_size, DEFAULT_BULK_MAX_SIZE);
        assert_eq!(config.max_body_size, DEFAULT_MAX_BODY_SIZE);
        assert_eq!(config.index_prefix, DEFAULT_INDEX_PREFIX);
        assert!(config.is_active());
    }
}
