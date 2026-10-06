//! Latest per-site edge cache usage, as reported by agent heartbeats.
//!
//! The control plane does not hold the edge cache: every agent accounts its own
//! disk usage against the per-domain quota ledger (`pingap_cache::DiskQuotaManager`)
//! and ships the counters in `AgentHeartbeat.site_statuses`. This registry keeps
//! the newest report per (site, agent) so `/api/v1/cache/status` answers from
//! memory instead of round-tripping every edge on each dashboard refresh.
//!
//! Reports are never removed: an agent that stops heartbeating leaves its last
//! known numbers behind, and `reported_at` tells the caller how stale they are.
//! That beats a status endpoint that silently reports zero usage for a site
//! whose edge is briefly unreachable.

use std::collections::HashMap;
use std::sync::Arc;

use chrono::{DateTime, Utc};
use pingwaf_proto::control_plane::SiteStatus;
use serde::Serialize;
use tokio::sync::RwLock;
use uuid::Uuid;

/// Aggregated cache usage of one site across every edge that reported it.
#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct SiteCacheStatus {
    pub site_id: Uuid,
    pub domain: String,
    /// Edges that reported this site.
    pub edges: usize,
    /// Sum of on-disk usage across those edges.
    pub disk_bytes: u64,
    /// Per-edge quota ceiling. The quota is per domain *per edge*, so a site on
    /// three edges may use three times this before evictions start.
    pub quota_bytes_per_edge: u64,
    /// `quota_bytes_per_edge * edges`, the budget the site actually has.
    pub quota_bytes_total: u64,
    /// Cache entries tracked across all edges.
    pub items: u64,
    /// Entries evicted to stay under quota, since the edges started.
    pub evictions_total: u64,
    /// `disk_bytes / quota_bytes_total * 100`, or `0` when unlimited.
    pub usage_percent: f64,
    /// Newest report time across the edges.
    pub reported_at: DateTime<Utc>,
}

/// One agent's last report for one site.
///
/// The protocol also carries `cache_hits`/`cache_misses`, but no edge component
/// counts them yet, so they are deliberately not folded in: serving a constant
/// zero as a hit ratio reads as "the cache never works" rather than "unknown".
/// Hit ratios belong to [`crate::api::analytics`], which derives them from the
/// access logs.
#[derive(Debug, Clone)]
struct Report {
    domain: String,
    disk_bytes: u64,
    quota_bytes: u64,
    items: u64,
    evictions: u64,
    reported_at: DateTime<Utc>,
}

#[derive(Default)]
struct Inner {
    /// site_id -> agent_id -> last report.
    sites: HashMap<Uuid, HashMap<Uuid, Report>>,
}

/// Cheap-to-clone handle to the reported cache usage.
#[derive(Clone, Default)]
pub struct CacheStatusRegistry {
    inner: Arc<RwLock<Inner>>,
}

impl CacheStatusRegistry {
    pub fn new() -> Self {
        Self::default()
    }

    /// Folds one heartbeat's site statuses into the registry.
    ///
    /// A malformed `site_id` is skipped rather than failing the heartbeat: the
    /// status feed is a dashboard convenience and must never take down the
    /// control channel.
    pub async fn record_heartbeat(
        &self,
        agent_id: Uuid,
        statuses: &[SiteStatus],
    ) {
        if statuses.is_empty() {
            return;
        }
        let now = Utc::now();
        let mut inner = self.inner.write().await;
        let mut recorded = 0usize;
        for status in statuses {
            let Ok(site_id) = Uuid::parse_str(&status.site_id) else {
                tracing::debug!(
                    site_id = %status.site_id,
                    "ignoring site status with an unparsable site id"
                );
                continue;
            };
            inner.sites.entry(site_id).or_default().insert(
                agent_id,
                Report {
                    domain: status.domain.clone(),
                    disk_bytes: status.cache_disk_bytes,
                    quota_bytes: status.cache_quota_bytes,
                    items: status.cache_items,
                    evictions: status.cache_evictions,
                    reported_at: now,
                },
            );
            recorded += 1;
        }
        if recorded > 0 {
            tracing::debug!(%agent_id, sites = recorded, "recorded cache status");
        }
    }

    /// Aggregated status of every site that has reported, ordered by domain.
    pub async fn all(&self) -> Vec<SiteCacheStatus> {
        let inner = self.inner.read().await;
        let mut out: Vec<SiteCacheStatus> = inner
            .sites
            .iter()
            .map(|(site_id, reports)| aggregate(*site_id, reports))
            .collect();
        out.sort_by(|a, b| {
            a.domain.cmp(&b.domain).then(a.site_id.cmp(&b.site_id))
        });
        out
    }

    /// Aggregated status of one site, `None` when no edge has reported it.
    pub async fn site(&self, site_id: Uuid) -> Option<SiteCacheStatus> {
        let inner = self.inner.read().await;
        inner
            .sites
            .get(&site_id)
            .map(|reports| aggregate(site_id, reports))
    }

    /// Sites that have reported at least once. Used by the status endpoint to
    /// tell "no data yet" from "no usage".
    pub async fn known_sites(&self) -> Vec<Uuid> {
        self.inner.read().await.sites.keys().copied().collect()
    }
}

/// Sums one site's reports. The ceiling is the *largest* reported rather than
/// the sum: every edge of a site runs the same rules, so a difference means one
/// of them has not picked up the latest config yet.
fn aggregate(
    site_id: Uuid,
    reports: &HashMap<Uuid, Report>,
) -> SiteCacheStatus {
    let mut domain = String::new();
    let mut disk_bytes = 0u64;
    let mut quota_bytes_per_edge = 0u64;
    let mut items = 0u64;
    let mut evictions_total = 0u64;
    let mut reported_at = None;

    for report in reports.values() {
        if !report.domain.is_empty() {
            domain.clone_from(&report.domain);
        }
        disk_bytes = disk_bytes.saturating_add(report.disk_bytes);
        quota_bytes_per_edge = quota_bytes_per_edge.max(report.quota_bytes);
        items = items.saturating_add(report.items);
        evictions_total = evictions_total.saturating_add(report.evictions);
        reported_at = Some(
            reported_at.map_or(report.reported_at, |latest: DateTime<Utc>| {
                latest.max(report.reported_at)
            }),
        );
    }

    let edges = reports.len();
    let quota_bytes_total = quota_bytes_per_edge.saturating_mul(edges as u64);

    SiteCacheStatus {
        site_id,
        domain,
        edges,
        disk_bytes,
        quota_bytes_per_edge,
        quota_bytes_total,
        items,
        evictions_total,
        usage_percent: if quota_bytes_total == 0 {
            0.0
        } else {
            (disk_bytes as f64 / quota_bytes_total as f64) * 100.0
        },
        reported_at: reported_at.unwrap_or_else(Utc::now),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn status(
        site_id: Uuid,
        domain: &str,
        disk: u64,
        quota: u64,
    ) -> SiteStatus {
        SiteStatus {
            site_id: site_id.to_string(),
            domain: domain.to_string(),
            requests_total: 0,
            requests_blocked: 0,
            cache_hits: 8,
            cache_misses: 2,
            ssl_status: String::new(),
            ssl_expires_at: None,
            cache_disk_bytes: disk,
            cache_items: 4,
            cache_evictions: 1,
            cache_quota_bytes: quota,
        }
    }

    #[tokio::test]
    async fn reports_from_several_edges_are_summed() {
        let registry = CacheStatusRegistry::new();
        let site = Uuid::new_v4();
        let one = Uuid::new_v4();
        let two = Uuid::new_v4();

        registry
            .record_heartbeat(one, &[status(site, "example.com", 100, 1024)])
            .await;
        registry
            .record_heartbeat(two, &[status(site, "example.com", 250, 1024)])
            .await;

        let view = registry.site(site).await.expect("reported");
        assert_eq!(2, view.edges);
        assert_eq!(350, view.disk_bytes);
        // The ceiling is per edge, so the site's real budget is twice that.
        assert_eq!(1024, view.quota_bytes_per_edge);
        assert_eq!(2048, view.quota_bytes_total);
        assert_eq!(8, view.items);
    }

    #[tokio::test]
    async fn a_new_heartbeat_replaces_the_previous_one() {
        let registry = CacheStatusRegistry::new();
        let site = Uuid::new_v4();
        let agent = Uuid::new_v4();

        registry
            .record_heartbeat(agent, &[status(site, "example.com", 100, 1024)])
            .await;
        registry
            .record_heartbeat(agent, &[status(site, "example.com", 900, 1024)])
            .await;

        let view = registry.site(site).await.expect("reported");
        assert_eq!(1, view.edges);
        assert_eq!(900, view.disk_bytes);
        // 900 of 1024 is just under 88%.
        assert!((87.89..87.90).contains(&view.usage_percent));
    }

    #[tokio::test]
    async fn unparsable_site_ids_are_skipped() {
        let registry = CacheStatusRegistry::new();
        let mut broken = status(Uuid::new_v4(), "example.com", 100, 1024);
        broken.site_id = "not-a-uuid".to_string();
        registry.record_heartbeat(Uuid::new_v4(), &[broken]).await;
        assert!(registry.all().await.is_empty());
    }

    #[tokio::test]
    async fn an_unlimited_domain_reports_zero_percent() {
        let registry = CacheStatusRegistry::new();
        let site = Uuid::new_v4();
        registry
            .record_heartbeat(
                Uuid::new_v4(),
                &[status(site, "example.com", 500, 0)],
            )
            .await;
        let view = registry.site(site).await.expect("reported");
        assert_eq!(0.0, view.usage_percent);
        assert_eq!(0, view.quota_bytes_total);
    }
}
