use serde::{Deserialize, Serialize};

/// Configuration for the PingWAF agent.
///
/// Controls how the agent connects to the control plane server, caches rules
/// locally, and ships logs/metrics.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentConfig {
    /// gRPC server URL (e.g., "http://localhost:9090")
    pub server_url: String,
    /// API key for authentication with control plane
    pub api_key: String,
    /// Unique identifier for this agent (auto-generated if empty)
    pub agent_id: String,
    /// Heartbeat interval in seconds
    #[serde(default = "default_heartbeat_interval")]
    pub heartbeat_interval_secs: u64,
    /// Local cache directory for rules (persist across restarts)
    #[serde(default = "default_cache_dir")]
    pub cache_dir: String,
    /// Maximum log batch size before flush
    #[serde(default = "default_log_batch_size")]
    pub log_batch_size: usize,
    /// Maximum time to buffer logs before flush (seconds)
    #[serde(default = "default_log_flush_interval")]
    pub log_flush_interval_secs: u64,
    /// Maximum request body size to log (bytes), 0 = no body logging
    #[serde(default = "default_max_body_log_size")]
    pub max_body_log_size: usize,
    /// Initial reconnection delay in milliseconds
    #[serde(default = "default_reconnect_initial_delay")]
    pub reconnect_initial_delay_ms: u64,
    /// Maximum reconnection delay in milliseconds
    #[serde(default = "default_reconnect_max_delay")]
    pub reconnect_max_delay_ms: u64,
    /// Whether to fail-open when disconnected (true = allow traffic, false = use cached rules)
    #[serde(default = "default_fail_open")]
    pub fail_open: bool,
    /// Host probe sampling interval in seconds
    #[serde(default = "default_probe_interval")]
    pub probe_interval_secs: u64,
    /// Filesystem to report disk usage for ("/" by default)
    #[serde(default = "default_probe_disk_path")]
    pub probe_disk_path: String,
    /// Interval for shipping edge metrics to the control plane (seconds);
    /// 0 disables metric shipping
    #[serde(default = "default_metrics_ship_interval")]
    pub metrics_ship_interval_secs: u64,
}

fn default_heartbeat_interval() -> u64 {
    30
}
fn default_cache_dir() -> String {
    "/var/lib/pingwaf/cache".to_string()
}
fn default_log_batch_size() -> usize {
    100
}
fn default_log_flush_interval() -> u64 {
    5
}
fn default_max_body_log_size() -> usize {
    8192
}
fn default_reconnect_initial_delay() -> u64 {
    1000
}
fn default_reconnect_max_delay() -> u64 {
    60000
}
fn default_fail_open() -> bool {
    true
}
fn default_probe_interval() -> u64 {
    crate::probe::DEFAULT_INTERVAL_SECS
}
fn default_probe_disk_path() -> String {
    "/".to_string()
}
fn default_metrics_ship_interval() -> u64 {
    30
}

impl Default for AgentConfig {
    fn default() -> Self {
        Self {
            server_url: "http://localhost:9090".to_string(),
            api_key: String::new(),
            agent_id: String::new(),
            heartbeat_interval_secs: default_heartbeat_interval(),
            cache_dir: default_cache_dir(),
            log_batch_size: default_log_batch_size(),
            log_flush_interval_secs: default_log_flush_interval(),
            max_body_log_size: default_max_body_log_size(),
            reconnect_initial_delay_ms: default_reconnect_initial_delay(),
            reconnect_max_delay_ms: default_reconnect_max_delay(),
            fail_open: default_fail_open(),
            probe_interval_secs: default_probe_interval(),
            probe_disk_path: default_probe_disk_path(),
            metrics_ship_interval_secs: default_metrics_ship_interval(),
        }
    }
}

impl AgentConfig {
    /// Returns the agent_id, generating a UUID if one is not configured.
    pub fn resolved_agent_id(&self) -> String {
        if self.agent_id.is_empty() {
            uuid::Uuid::new_v4().to_string()
        } else {
            self.agent_id.clone()
        }
    }
}
