//! Dynamically blocked-IP ledger: the in-memory map, its TTL rules and the
//! `blocked_ips.json` persistence used by [`RuleCache`].

use std::path::Path;
use std::time::Duration;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use tracing::{debug, info, warn};

use super::RuleCache;

// ─────────────────────────────────────────────────────────────
// Blocked IP tracking (with TTL)
// ─────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BlockedIpEntry {
    pub ip: String,
    pub site_id: String,
    pub reason: String,
    /// When the block was recorded; drives the control plane's list order.
    /// Files written before this field existed load with the epoch default.
    #[serde(default = "default_blocked_at")]
    pub blocked_at: DateTime<Utc>,
    /// None = permanent block
    pub expires_at: Option<DateTime<Utc>>,
}

fn default_blocked_at() -> DateTime<Utc> {
    DateTime::from_timestamp(0, 0).expect("epoch is a valid timestamp")
}

impl BlockedIpEntry {
    pub fn is_expired(&self) -> bool {
        match self.expires_at {
            Some(exp) => Utc::now() >= exp,
            None => false,
        }
    }
}

impl RuleCache {
    // ─── IP Blocking ────────────────────────────────────────

    /// Check if an IP is dynamically blocked for a given site.
    pub fn is_ip_blocked(&self, site_id: &str, ip: &str) -> bool {
        let key = format!("{}:{}", site_id, ip);
        match self.blocked_ips.get(&key) {
            Some(entry) => {
                if entry.is_expired() {
                    drop(entry);
                    self.blocked_ips.remove(&key);
                    false
                } else {
                    true
                }
            },
            None => false,
        }
    }

    /// The reason an IP is dynamically blocked for a site, or `None`. The
    /// reason prefix (`"waf: "` / `"rate limit: "`) identifies which policy
    /// produced the block so callers can downgrade WAF-originated blocks
    /// without touching rate-limit or control-plane-issued ones.
    pub fn blocked_reason(&self, site_id: &str, ip: &str) -> Option<String> {
        let key = format!("{}:{}", site_id, ip);
        match self.blocked_ips.get(&key) {
            Some(entry) => {
                if entry.is_expired() {
                    drop(entry);
                    self.blocked_ips.remove(&key);
                    None
                } else {
                    Some(entry.reason.clone())
                }
            },
            None => None,
        }
    }

    /// Block an IP for a site, optionally with a duration.
    pub fn block_ip(
        &self,
        site_id: &str,
        ip: &str,
        duration: Option<Duration>,
        reason: &str,
    ) {
        let key = format!("{}:{}", site_id, ip);
        let expires_at = duration.map(|d| {
            Utc::now()
                + chrono::Duration::from_std(d)
                    .unwrap_or(chrono::Duration::hours(1))
        });

        let entry = BlockedIpEntry {
            ip: ip.to_string(),
            site_id: site_id.to_string(),
            reason: reason.to_string(),
            blocked_at: Utc::now(),
            expires_at,
        };

        self.blocked_ips.insert(key.clone(), entry);
        info!(site_id = %site_id, ip = %ip, reason = %reason, "Blocked IP");

        // Persist blocked IPs
        if let Err(e) = self.persist_blocked_ips() {
            warn!(error = %e, "Failed to persist blocked IPs");
        }
    }

    /// Unblock an IP for a site.
    pub fn unblock_ip(&self, site_id: &str, ip: &str) {
        let key = format!("{}:{}", site_id, ip);
        if self.blocked_ips.remove(&key).is_some() {
            info!(site_id = %site_id, ip = %ip, "Unblocked IP");
            if let Err(e) = self.persist_blocked_ips() {
                warn!(error = %e, "Failed to persist blocked IPs");
            }
        }
    }

    /// Drop every WAF auto-block (`"waf: "` reason) for a site, keeping
    /// rate-limit and control-plane-issued blocks. Returns the number of
    /// entries removed. Used when a site leaves enforcing mode (block →
    /// monitor/off, or observation mode switched on): the stale auto-blocks
    /// would otherwise keep refusing clients for up to the full window even
    /// though the engine no longer produces block verdicts.
    pub fn clear_waf_auto_blocks(&self, site_id: &str) -> usize {
        let prefix = format!("{site_id}:");
        let stale: Vec<String> = self
            .blocked_ips
            .iter()
            .filter(|e| {
                e.key().starts_with(&prefix)
                    && !e.value().is_expired()
                    && e.value().reason.starts_with("waf: ")
            })
            .map(|e| e.key().clone())
            .collect();
        let removed = stale.len();
        for key in &stale {
            self.blocked_ips.remove(key);
        }
        if removed > 0 {
            info!(
                site_id = %site_id,
                removed,
                "cleared WAF auto-blocks after leaving enforcing mode"
            );
            if let Err(e) = self.persist_blocked_ips() {
                warn!(error = %e, "Failed to persist blocked IPs");
            }
        }
        removed
    }

    /// Drop every dynamic block for a site, regardless of origin. Used when
    /// the site itself is deleted: its entries would otherwise linger until
    /// their expiry (and be re-loaded from disk on restart).
    pub fn clear_site_blocks(&self, site_id: &str) -> usize {
        let prefix = format!("{site_id}:");
        let stale: Vec<String> = self
            .blocked_ips
            .iter()
            .filter(|e| e.key().starts_with(&prefix))
            .map(|e| e.key().clone())
            .collect();
        let removed = stale.len();
        for key in &stale {
            self.blocked_ips.remove(key);
        }
        if removed > 0 {
            debug!(
                site_id = %site_id,
                removed,
                "cleared blocks for removed site"
            );
            if let Err(e) = self.persist_blocked_ips() {
                warn!(error = %e, "Failed to persist blocked IPs");
            }
        }
        removed
    }

    /// Clean up expired IP blocks.
    pub fn cleanup_expired_blocks(&self) {
        let mut expired_keys = Vec::new();
        for entry in self.blocked_ips.iter() {
            if entry.value().is_expired() {
                expired_keys.push(entry.key().clone());
            }
        }
        for key in &expired_keys {
            self.blocked_ips.remove(key);
        }
        if !expired_keys.is_empty() {
            debug!(count = expired_keys.len(), "Cleaned up expired IP blocks");
            if let Err(e) = self.persist_blocked_ips() {
                warn!(
                    error = %e,
                    "expired IP blocks removed in memory but not persisted"
                );
            }
        }
    }

    /// Snapshot of every block currently in force, for the heartbeat report.
    /// Expired entries are dropped on read so a lapsed block is never
    /// re-propagated to the control plane.
    pub fn blocked_ips_snapshot(&self) -> Vec<BlockedIpEntry> {
        self.blocked_ips
            .iter()
            .filter(|e| !e.value().is_expired())
            .map(|e| e.value().clone())
            .collect()
    }

    /// Persist blocked IPs to disk.
    pub(super) fn persist_blocked_ips(&self) -> anyhow::Result<()> {
        if !self.cache_dir.exists() {
            return Ok(());
        }

        let blocked_path = self.cache_dir.join("blocked_ips.json");
        let entries: Vec<BlockedIpEntry> = self
            .blocked_ips
            .iter()
            .filter(|e| !e.value().is_expired())
            .map(|e| e.value().clone())
            .collect();

        let json = serde_json::to_string_pretty(&entries)?;
        std::fs::write(&blocked_path, json)?;
        Ok(())
    }

    /// Load the ledger persisted next to the rule bundle.
    pub(super) fn load_blocked_ips(
        &self,
        blocked_path: &Path,
    ) -> anyhow::Result<()> {
        if !blocked_path.exists() {
            return Ok(());
        }
        let blocked_json = std::fs::read_to_string(blocked_path)?;
        let blocked: Vec<BlockedIpEntry> = serde_json::from_str(&blocked_json)?;
        let mut loaded = 0;
        for entry in blocked {
            if !entry.is_expired() {
                let key = format!("{}:{}", entry.site_id, entry.ip);
                self.blocked_ips.insert(key, entry);
                loaded += 1;
            }
        }
        debug!(count = loaded, "Loaded blocked IPs from disk");
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn clear_waf_auto_blocks_removes_only_waf_reasons() {
        let dir = tempfile::tempdir().unwrap();
        let cache =
            RuleCache::new(dir.path().to_path_buf(), "test".to_string())
                .unwrap();

        cache.block_ip("site-1", "203.0.113.1", None, "waf: sqli probe");
        cache.block_ip("site-1", "203.0.113.2", None, "rate limit: login");
        cache.block_ip("site-1", "203.0.113.3", None, "manual abuse");
        cache.block_ip("site-2", "203.0.113.1", None, "waf: other site");

        let removed = cache.clear_waf_auto_blocks("site-1");
        assert_eq!(removed, 1);
        assert_eq!(cache.blocked_reason("site-1", "203.0.113.1"), None);
        assert_eq!(
            cache.blocked_reason("site-1", "203.0.113.2").as_deref(),
            Some("rate limit: login")
        );
        assert_eq!(
            cache.blocked_reason("site-1", "203.0.113.3").as_deref(),
            Some("manual abuse")
        );
        // Another site's WAF auto-blocks are untouched.
        assert_eq!(
            cache.blocked_reason("site-2", "203.0.113.1").as_deref(),
            Some("waf: other site")
        );

        // Clearing again is a no-op.
        assert_eq!(cache.clear_waf_auto_blocks("site-1"), 0);
    }
}
