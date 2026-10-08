//! Failed-authentication streak tracker (Phase 8, account-takeover defense).
//!
//! Credential stuffing and password spraying show up as a burst of upstream
//! authentication failures (401/403) for *state-changing* requests from one
//! client. The tracker keeps a per-`(site, client)` failure window and
//! temporarily refuses further requests once the configured threshold is
//! crossed.
//!
//! Only `POST`/`PUT`/`PATCH`/`DELETE` responses count: credential submissions
//! are state-changing, while expired-token polling (a common legitimate
//! source of 401s) is not — so ordinary SPAs cannot trip the tracker.
//!
//! The window and the block both expire on their own; the entry map is
//! bounded and purged lazily so a spray from many addresses cannot grow it
//! without limit.

use std::time::{Duration, Instant};

use dashmap::DashMap;

/// One client's failure window.
#[derive(Debug, Clone, Copy)]
struct Entry {
    window_start: Instant,
    failures: u32,
    blocked_until: Option<Instant>,
}

/// Per-`(site, client)` failed-authentication streaks.
pub struct FailedAuthTracker {
    threshold: u32,
    window: Duration,
    block_for: Duration,
    entries: DashMap<String, Entry>,
}

/// Outcome of recording one authentication failure.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RecordOutcome {
    /// Still below the threshold.
    Counted,
    /// This failure crossed the threshold; the client is now blocked.
    Blocked,
    /// The tracker is disabled.
    Disabled,
}

impl FailedAuthTracker {
    /// A tracker with `threshold` failures per `window_secs` blocking the
    /// client for `block_secs`; `threshold == 0` disables it.
    pub fn new(threshold: u32, window_secs: u64, block_secs: u64) -> Self {
        Self {
            threshold,
            window: Duration::from_secs(window_secs.max(1)),
            block_for: Duration::from_secs(block_secs.max(1)),
            entries: DashMap::new(),
        }
    }

    pub fn enabled(&self) -> bool {
        self.threshold > 0
    }

    pub fn threshold(&self) -> u32 {
        self.threshold
    }

    /// Record one authentication failure for `key` (site + client).
    pub fn record_failure(&self, key: &str) -> RecordOutcome {
        if !self.enabled() {
            return RecordOutcome::Disabled;
        }
        let now = Instant::now();
        self.purge(now);
        let mut entry = self.entries.entry(key.to_string()).or_insert(Entry {
            window_start: now,
            failures: 0,
            blocked_until: None,
        });
        if now.duration_since(entry.window_start) > self.window {
            entry.window_start = now;
            entry.failures = 0;
        }
        entry.failures = entry.failures.saturating_add(1);
        if entry.failures >= self.threshold {
            entry.blocked_until = Some(now + self.block_for);
            entry.failures = 0;
            entry.window_start = now;
            tracing::warn!(
                key,
                threshold = self.threshold,
                block_secs = self.block_for.as_secs(),
                "failed-authentication streak crossed; client temporarily blocked"
            );
            RecordOutcome::Blocked
        } else {
            RecordOutcome::Counted
        }
    }

    /// `true` while `key` is inside its block window.
    pub fn is_blocked(&self, key: &str) -> bool {
        if !self.enabled() {
            return false;
        }
        let now = Instant::now();
        let Some(mut entry) = self.entries.get_mut(key) else {
            return false;
        };
        match entry.blocked_until {
            Some(until) if now < until => true,
            Some(_) => {
                // Block expired: start a fresh window so the next failure
                // does not instantly re-block.
                entry.blocked_until = None;
                entry.window_start = now;
                entry.failures = 0;
                false
            },
            None => false,
        }
    }

    /// Seconds until `key`'s block expires, when blocked.
    pub fn retry_after_secs(&self, key: &str) -> Option<u64> {
        let now = Instant::now();
        let entry = self.entries.get(key)?;
        let until = entry.blocked_until?;
        (until > now).then(|| (until - now).as_secs().max(1))
    }

    /// Drop expired entries once the map grows large; also called per record.
    fn purge(&self, now: Instant) {
        if self.entries.len() < 10_000 {
            return;
        }
        self.entries.retain(|_, entry| {
            if let Some(until) = entry.blocked_until {
                return now < until;
            }
            now.duration_since(entry.window_start) <= self.window
        });
    }

    #[cfg(test)]
    fn entry_count(&self) -> usize {
        self.entries.len()
    }
}

/// Request methods whose authentication failures feed the tracker.
pub fn is_state_changing(method: &str) -> bool {
    matches!(method, "POST" | "PUT" | "PATCH" | "DELETE")
}

#[cfg(test)]
mod tests {
    use super::{FailedAuthTracker, RecordOutcome, is_state_changing};
    use std::time::Duration;

    #[test]
    fn threshold_crossing_blocks_and_expires() {
        let tracker = FailedAuthTracker::new(3, 60, 1);
        assert!(tracker.enabled());
        assert_eq!(tracker.record_failure("s|ip"), RecordOutcome::Counted);
        assert_eq!(tracker.record_failure("s|ip"), RecordOutcome::Counted);
        assert!(!tracker.is_blocked("s|ip"));
        assert_eq!(tracker.record_failure("s|ip"), RecordOutcome::Blocked);
        assert!(tracker.is_blocked("s|ip"));
        assert!(tracker.retry_after_secs("s|ip").is_some());

        std::thread::sleep(Duration::from_millis(1100));
        assert!(!tracker.is_blocked("s|ip"), "block must expire");
        assert!(tracker.retry_after_secs("s|ip").is_none());
        // A fresh window starts after the block, so one failure is not enough.
        assert_eq!(tracker.record_failure("s|ip"), RecordOutcome::Counted);
    }

    #[test]
    fn clients_and_sites_are_isolated() {
        let tracker = FailedAuthTracker::new(2, 60, 60);
        tracker.record_failure("site-a|1.2.3.4");
        assert_eq!(
            tracker.record_failure("site-a|1.2.3.4"),
            RecordOutcome::Blocked
        );
        assert!(tracker.is_blocked("site-a|1.2.3.4"));
        assert!(!tracker.is_blocked("site-a|5.6.7.8"));
        assert!(!tracker.is_blocked("site-b|1.2.3.4"));
    }

    #[test]
    fn window_expiry_resets_the_streak() {
        let tracker = FailedAuthTracker::new(2, 1, 60);
        assert_eq!(tracker.record_failure("k"), RecordOutcome::Counted);
        std::thread::sleep(Duration::from_millis(1100));
        // The old failure fell out of the window: this one is not a crossing.
        assert_eq!(tracker.record_failure("k"), RecordOutcome::Counted);
    }

    #[test]
    fn zero_threshold_disables_the_tracker() {
        let tracker = FailedAuthTracker::new(0, 60, 60);
        assert!(!tracker.enabled());
        assert_eq!(tracker.record_failure("k"), RecordOutcome::Disabled);
        assert!(!tracker.is_blocked("k"));
        assert_eq!(tracker.entry_count(), 0);
    }

    #[test]
    fn only_state_changing_methods_count() {
        assert!(is_state_changing("POST"));
        assert!(is_state_changing("PUT"));
        assert!(is_state_changing("PATCH"));
        assert!(is_state_changing("DELETE"));
        assert!(!is_state_changing("GET"));
        assert!(!is_state_changing("HEAD"));
        assert!(!is_state_changing("OPTIONS"));
    }
}
