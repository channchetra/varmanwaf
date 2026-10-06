use std::sync::atomic::{AtomicI64, AtomicU64, Ordering};
use std::time::Instant;

/// Collected system metrics for heartbeat reporting.
#[derive(Debug, Clone)]
pub struct SystemMetrics {
    pub cpu_usage_percent: f64,
    pub memory_usage_bytes: u64,
    pub active_connections: u64,
    pub requests_per_second: u64,
    pub blocked_requests_total: u64,
    pub requests_total: u64,
}

/// Collects system and application metrics for the agent heartbeat.
///
/// Uses lock-free atomic counters for the hot path (request recording)
/// and periodic system reads for CPU/memory.
pub struct MetricsCollector {
    /// Total requests seen
    requests_total: AtomicU64,
    /// Total requests blocked by WAF
    blocked_requests_total: AtomicU64,
    /// Current active connections (can go negative briefly during cleanup)
    active_connections: AtomicI64,
    /// Timestamp of last RPS calculation
    last_rps_time: std::sync::Mutex<Instant>,
    /// Requests count at last RPS calculation
    last_rps_count: AtomicU64,
    /// Last calculated RPS value
    cached_rps: AtomicU64,
}

impl MetricsCollector {
    /// Create a new metrics collector.
    pub fn new() -> Self {
        Self {
            requests_total: AtomicU64::new(0),
            blocked_requests_total: AtomicU64::new(0),
            active_connections: AtomicI64::new(0),
            last_rps_time: std::sync::Mutex::new(Instant::now()),
            last_rps_count: AtomicU64::new(0),
            cached_rps: AtomicU64::new(0),
        }
    }

    /// Record a request (called on every proxied request).
    ///
    /// This is on the hot path and must be extremely fast — only atomic ops.
    #[inline]
    pub fn record_request(&self, blocked: bool) {
        self.requests_total.fetch_add(1, Ordering::Relaxed);
        if blocked {
            self.blocked_requests_total.fetch_add(1, Ordering::Relaxed);
        }
    }

    /// Track active connection count changes.
    #[inline]
    pub fn record_connection(&self, delta: i64) {
        self.active_connections.fetch_add(delta, Ordering::Relaxed);
    }

    /// Get current active connections.
    #[inline]
    pub fn active_connections(&self) -> u64 {
        let val = self.active_connections.load(Ordering::Relaxed);
        if val < 0 {
            0
        } else {
            val as u64
        }
    }

    /// Get total requests.
    #[inline]
    pub fn requests_total(&self) -> u64 {
        self.requests_total.load(Ordering::Relaxed)
    }

    /// Get total blocked requests.
    #[inline]
    pub fn blocked_requests_total(&self) -> u64 {
        self.blocked_requests_total.load(Ordering::Relaxed)
    }

    /// Collect a full metrics snapshot (called periodically for heartbeat).
    ///
    /// This recalculates RPS and reads system metrics. Not on the hot path,
    /// so it's okay to be slightly more expensive.
    pub fn collect(&self) -> SystemMetrics {
        // Calculate RPS
        let rps = self.calculate_rps();

        // Read system metrics
        let (cpu_usage, memory_usage) = read_system_metrics();

        SystemMetrics {
            cpu_usage_percent: cpu_usage,
            memory_usage_bytes: memory_usage,
            active_connections: self.active_connections(),
            requests_per_second: rps,
            blocked_requests_total: self.blocked_requests_total(),
            requests_total: self.requests_total(),
        }
    }

    /// Calculate requests per second since last collection.
    fn calculate_rps(&self) -> u64 {
        let current_count = self.requests_total.load(Ordering::Relaxed);
        let previous_count =
            self.last_rps_count.swap(current_count, Ordering::Relaxed);

        if let Ok(mut last_time) = self.last_rps_time.lock() {
            let now = Instant::now();
            let elapsed = now.duration_since(*last_time).as_secs_f64();
            *last_time = now;

            if elapsed > 0.0 {
                let rps =
                    ((current_count - previous_count) as f64 / elapsed) as u64;
                self.cached_rps.store(rps, Ordering::Relaxed);
                return rps;
            }
        }

        self.cached_rps.load(Ordering::Relaxed)
    }
}

impl Default for MetricsCollector {
    fn default() -> Self {
        Self::new()
    }
}

/// Read CPU and memory metrics from the system.
///
/// Platform-specific implementation:
/// - Linux: reads /proc/stat and /proc/meminfo
/// - macOS: uses sysctl via Command
/// - Other: returns zeros
fn read_system_metrics() -> (f64, u64) {
    #[cfg(target_os = "linux")]
    {
        read_linux_metrics()
    }
    #[cfg(target_os = "macos")]
    {
        read_macos_metrics()
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    {
        (0.0, 0)
    }
}

#[cfg(target_os = "linux")]
fn read_linux_metrics() -> (f64, u64) {
    let cpu = read_linux_cpu().unwrap_or(0.0);
    let mem = read_linux_memory().unwrap_or(0);
    (cpu, mem)
}

#[cfg(target_os = "linux")]
fn read_linux_cpu() -> Option<f64> {
    // Read /proc/stat for CPU usage
    let stat = std::fs::read_to_string("/proc/stat").ok()?;
    let first_line = stat.lines().next()?;
    let parts: Vec<&str> = first_line.split_whitespace().collect();
    if parts.len() < 5 {
        return None;
    }

    // user, nice, system, idle
    let user: u64 = parts[1].parse().ok()?;
    let nice: u64 = parts[2].parse().ok()?;
    let system: u64 = parts[3].parse().ok()?;
    let idle: u64 = parts[4].parse().ok()?;

    let total = user + nice + system + idle;
    if total == 0 {
        return Some(0.0);
    }

    let busy = user + nice + system;
    Some((busy as f64 / total as f64) * 100.0)
}

#[cfg(target_os = "linux")]
fn read_linux_memory() -> Option<u64> {
    // Read /proc/meminfo for memory usage
    let meminfo = std::fs::read_to_string("/proc/meminfo").ok()?;
    let mut mem_total: u64 = 0;
    let mut mem_available: u64 = 0;

    for line in meminfo.lines() {
        if line.starts_with("MemTotal:") {
            mem_total = parse_meminfo_value(line)?;
        } else if line.starts_with("MemAvailable:") {
            mem_available = parse_meminfo_value(line)?;
        }
    }

    if mem_total > 0 {
        Some((mem_total - mem_available) * 1024) // Convert kB to bytes
    } else {
        None
    }
}

#[cfg(target_os = "linux")]
fn parse_meminfo_value(line: &str) -> Option<u64> {
    line.split_whitespace().nth(1)?.parse().ok()
}

#[cfg(target_os = "macos")]
fn read_macos_metrics() -> (f64, u64) {
    let cpu = read_macos_cpu().unwrap_or(0.0);
    let mem = read_macos_memory().unwrap_or(0);
    (cpu, mem)
}

#[cfg(target_os = "macos")]
fn read_macos_cpu() -> Option<f64> {
    // Use `top` command for a quick CPU sample
    let output = std::process::Command::new("top")
        .args(["-l", "1", "-n", "0"])
        .output()
        .ok()?;

    let stdout = String::from_utf8_lossy(&output.stdout);
    for line in stdout.lines() {
        if line.contains("CPU usage:") {
            // Parse "CPU usage: 5.26% user, 10.52% sys, 84.21% idle"
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() >= 4 {
                let user: f64 = parts[2].trim_end_matches('%').parse().ok()?;
                let sys: f64 = parts[4].trim_end_matches('%').parse().ok()?;
                return Some(user + sys);
            }
        }
    }
    None
}

#[cfg(target_os = "macos")]
fn read_macos_memory() -> Option<u64> {
    // Use vm_stat for memory usage
    let output = std::process::Command::new("vm_stat").output().ok()?;
    let stdout = String::from_utf8_lossy(&output.stdout);

    let mut page_size: u64 = 4096; // Default macOS page size
    let mut active_pages: u64 = 0;
    let mut wired_pages: u64 = 0;
    let mut compressed_pages: u64 = 0;

    for line in stdout.lines() {
        if line.starts_with("Mach Virtual Memory Statistics:") {
            // Try to extract page size from "(page size of X bytes)"
            if let Some(start) = line.find("page size of ") {
                let rest = &line[start + 13..];
                if let Some(end) = rest.find(" bytes") {
                    page_size = rest[..end].parse().unwrap_or(4096);
                }
            }
        } else if line.starts_with("Pages active:") {
            active_pages = parse_vm_stat_value(line).unwrap_or(0);
        } else if line.starts_with("Pages wired down:") {
            wired_pages = parse_vm_stat_value(line).unwrap_or(0);
        } else if line.starts_with("Pages occupied by compressor:") {
            compressed_pages = parse_vm_stat_value(line).unwrap_or(0);
        }
    }

    let used_bytes =
        (active_pages + wired_pages + compressed_pages) * page_size;
    if used_bytes > 0 {
        Some(used_bytes)
    } else {
        None
    }
}

#[cfg(target_os = "macos")]
fn parse_vm_stat_value(line: &str) -> Option<u64> {
    // Format: "Pages active:                          123456."
    let value_str = line.split(':').nth(1)?.trim().trim_end_matches('.');
    value_str.parse().ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use tracing::debug;

    #[test]
    fn test_metrics_collector_basic() {
        let collector = MetricsCollector::new();

        assert_eq!(collector.requests_total(), 0);
        assert_eq!(collector.blocked_requests_total(), 0);
        assert_eq!(collector.active_connections(), 0);

        collector.record_request(false);
        collector.record_request(true);
        collector.record_request(false);

        assert_eq!(collector.requests_total(), 3);
        assert_eq!(collector.blocked_requests_total(), 1);
    }

    #[test]
    fn test_connection_tracking() {
        let collector = MetricsCollector::new();

        collector.record_connection(1);
        collector.record_connection(1);
        assert_eq!(collector.active_connections(), 2);

        collector.record_connection(-1);
        assert_eq!(collector.active_connections(), 1);
    }

    #[test]
    fn test_collect_returns_metrics() {
        let collector = MetricsCollector::new();
        collector.record_request(false);

        let metrics = collector.collect();
        assert_eq!(metrics.requests_total, 1);
        assert_eq!(metrics.blocked_requests_total, 0);
        // CPU and memory may be 0 in test environments
        debug!("Collected metrics: {:?}", metrics);
    }
}
