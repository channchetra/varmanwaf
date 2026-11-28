//! Edge rule cache: bundle storage, disk persistence and the public surface.
//!
//! The pure site/WAF/route model lives in [`model`] and the blocked-IP
//! ledger in [`blocked_ips`]; both are re-exported here so `cache::Foo` keeps
//! resolving for callers.

mod blocked_ips;
mod model;

pub use blocked_ips::*;
pub use model::*;

use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicI64, Ordering};
use std::sync::{Arc, Mutex};

use arc_swap::ArcSwap;
use chrono::{DateTime, TimeZone, Utc};
use dashmap::DashMap;
use pingap_cache::quota;
use pingap_core::normalize_host;
use serde::{Deserialize, Serialize};
use tracing::{debug, info, warn};

use varman_protocol::control_plane as proto;

use model::{
    failover_registry_from, lookup_with_wildcard, site_enforcement,
    waf_enforcing,
};

// ─────────────────────────────────────────────────────────────
// Disk persistence metadata
// ─────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
struct CacheMetadata {
    config_hash: String,
    updated_at: DateTime<Utc>,
    agent_id: String,
    version: u32,
}

// ─────────────────────────────────────────────────────────────
// RuleCache — the main public interface
// ─────────────────────────────────────────────────────────────

/// Thread-safe local rule cache with disk persistence.
///
/// Uses `ArcSwap` for lock-free reads on the hot path and a separate
/// `DashMap` for dynamically-blocked IPs (which change more frequently
/// than rule bundles).
pub struct RuleCache {
    /// In-memory rule storage (fast, lock-free reads via ArcSwap)
    inner: ArcSwap<CachedRules>,
    /// Dynamically blocked IPs: key = "site_id:ip"
    blocked_ips: DashMap<String, BlockedIpEntry>,
    /// Disk persistence directory
    cache_dir: PathBuf,
    /// Agent ID for metadata
    agent_id: String,
    /// Domains this agent currently holds a ceiling for.
    ///
    /// The ledger is shared with the `cache` plugins built from the static
    /// config, which set their own `disk_quota_mb`. Sweeping only what is
    /// recorded here is what keeps a bundle naming no site at all - the first
    /// one, before the control plane has answered - from wiping those.
    quota_domains: Mutex<HashSet<String>>,
    /// Unix seconds of the last successful full-config application; 0 = never.
    last_config_sync_at: AtomicI64,
    /// Unix seconds of the last successful single-site rule bundle
    /// application; 0 = never.
    last_policy_sync_at: AtomicI64,
}

impl RuleCache {
    /// Create a new rule cache, loading from disk if a previous cache exists.
    pub fn new(
        cache_dir: PathBuf,
        agent_id: String,
    ) -> anyhow::Result<Arc<Self>> {
        let cache = Arc::new(Self {
            inner: ArcSwap::new(Arc::new(CachedRules::default())),
            blocked_ips: DashMap::new(),
            cache_dir: cache_dir.clone(),
            agent_id,
            quota_domains: Mutex::new(HashSet::new()),
            last_config_sync_at: AtomicI64::new(0),
            last_policy_sync_at: AtomicI64::new(0),
        });

        // Ensure cache directory exists
        if let Err(e) = std::fs::create_dir_all(&cache_dir) {
            warn!(error = %e, "Failed to create cache directory, running without persistence");
        } else {
            // Try to load existing cache from disk
            if let Err(e) = cache.load_from_disk() {
                debug!(error = %e, "No existing cache found on disk or failed to load");
            } else {
                info!("Loaded rule cache from disk");
            }
        }

        // Quotas persisted with the rules take effect before the first push
        // from the control plane arrives.
        cache.apply_cache_quotas();

        Ok(cache)
    }

    /// Directory where the agent persists its state (rules, blocked IPs,
    /// and the ACME account/certificate store used by the data plane).
    pub fn cache_dir(&self) -> &Path {
        &self.cache_dir
    }

    /// Applies the `disk_quota_mb` of every enabled, cache-eligible rule to the
    /// edge's cache ledger, and drops the domains that are no longer
    /// configured.
    ///
    /// The ledger is the process-wide one the proxy's file cache writes
    /// through (`pingap_cache::global_disk_quota`), *not* a private copy: the
    /// cached objects live wherever the `cache` plugin's `directory` points,
    /// and a second ledger rooted elsewhere would only ever read zero and
    /// purge nothing. Because this runs as soon as the rules are known -
    /// possibly before the proxy has built that backend - the ceilings are
    /// parked and replayed by `pingap_cache::quota` once it exists.
    ///
    /// A site answers on several domains (primary plus alternates) while the
    /// rules are per site, so every domain of a site gets the largest ceiling
    /// configured for it. Several sites sharing a domain get the largest of
    /// theirs: the ledger accounts per domain, and the smaller ceiling would
    /// otherwise be unenforceable anyway.
    pub fn apply_cache_quotas(&self) {
        let rules = self.inner.load();
        // The global disk budget is the ceiling every site quota is clamped
        // against: an unlimited site (`0`) may use up to the budget, a
        // capped site is lowered to `min(site, global)`. No budget (`0`)
        // leaves the site quotas untouched.
        let global_space_mb = rules
            .global_cache
            .as_ref()
            .map(|g| u64::from(g.max_space_mb()))
            .unwrap_or(0);
        let mut tracked: HashMap<String, u64> = HashMap::new();
        for site in rules.sites.values() {
            let mut quota_mb = site
                .cache_rules
                .iter()
                .filter(|rule| rule.enabled && rule.cache_eligible)
                .map(|rule| u64::from(rule.disk_quota_mb))
                .max()
                .unwrap_or(0);
            if global_space_mb > 0 {
                quota_mb = if quota_mb == 0 {
                    global_space_mb
                } else {
                    quota_mb.min(global_space_mb)
                };
            }
            for domain in site.all_domains() {
                if domain.is_empty() {
                    continue;
                }
                let entry = tracked.entry(domain.to_string()).or_insert(0);
                *entry = (*entry).max(quota_mb);
            }
        }
        for (domain, quota_mb) in &tracked {
            quota::set_quota(domain, *quota_mb);
        }
        // Ceilings this agent set for a domain no rule names any more. Only
        // its own are swept: a `cache` plugin configured from the static file
        // keeps the ceiling it asked for, even when the control plane has
        // nothing to say about that namespace.
        let mut owned = self
            .quota_domains
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        for domain in owned.iter() {
            if !tracked.contains_key(domain) {
                quota::forget_quota(domain);
            }
        }
        *owned = tracked.keys().cloned().collect();
        debug!(domains = owned.len(), "applied cache disk quotas");
    }

    /// Per-site cache disk usage for the heartbeat, so the control plane can
    /// answer `/api/v1/cache/status` without polling every edge.
    ///
    /// `cache_hits`/`cache_misses` stay at zero: this agent holds the rules, not
    /// the data path, so it has nothing to count. The control plane derives hit
    /// ratios from the access logs instead of trusting a constant zero here.
    pub fn cache_statuses(&self) -> Vec<proto::SiteStatus> {
        let rules = self.inner.load();
        // Usage comes from the shared ledger; before the proxy has built a
        // file cache backend there is none, and nothing on disk to report.
        // The configured ceiling is still reported, so the control plane can
        // show "0 of 512 MB" rather than "unconfigured" for a site whose quota
        // simply has not started filling yet.
        let ledger = pingap_cache::global_disk_quota();
        // Certificate state comes from the hosting process, which owns the
        // provider the ACME task writes into; without one every site reports
        // an empty status and the control plane leaves its rows alone.
        let ssl = crate::cert_status::snapshot();
        let mut out = Vec::with_capacity(rules.sites.len());
        for (site_id, site) in rules.sites.iter() {
            // A site answers on its primary domain and every alias, and the
            // ledger accounts each one separately. The ceiling is the largest
            // rather than the sum: `apply_cache_quotas` gives every hostname of
            // a site the same budget, so adding them would inflate it.
            let mut disk_bytes = 0u64;
            let mut items = 0u64;
            let mut evictions = 0u64;
            let mut quota_mb = 0u64;
            for domain in site.all_domains() {
                if domain.is_empty() {
                    continue;
                }
                if let Some(usage) = ledger.and_then(|l| l.get_usage(domain)) {
                    disk_bytes = disk_bytes.saturating_add(usage.current_bytes);
                    items = items.saturating_add(usage.item_count);
                    evictions = evictions.saturating_add(usage.evictions_total);
                }
                quota_mb = quota_mb
                    .max(quota::configured_quota_mb(domain).unwrap_or(0));
            }
            let status = ssl.get(site_id);
            out.push(proto::SiteStatus {
                site_id: site_id.clone(),
                domain: site.domain.clone(),
                requests_total: 0,
                requests_blocked: 0,
                cache_hits: 0,
                cache_misses: 0,
                ssl_status: status
                    .map(|status| status.status.to_string())
                    .unwrap_or_default(),
                ssl_expires_at: status.map(|status| prost_types::Timestamp {
                    seconds: status.expires_at,
                    nanos: 0,
                }),
                cache_disk_bytes: disk_bytes,
                cache_items: items,
                cache_evictions: evictions,
                cache_quota_bytes: quota_mb.saturating_mul(quota::BYTES_PER_MB),
            });
        }
        out
    }

    /// Purges this agent's edge cache for a site.
    ///
    /// An empty `urls` list purges the whole site (every domain it answers
    /// on); otherwise each entry is matched against the ledger keys. Returns
    /// the number of cache objects removed.
    pub async fn purge_site(
        &self,
        site_id: &str,
        urls: &[String],
    ) -> anyhow::Result<usize> {
        let domains: Vec<String> = {
            let rules = self.inner.load();
            match rules.sites.get(site_id) {
                Some(site) => site
                    .all_domains()
                    .filter(|domain| !domain.is_empty())
                    .map(str::to_string)
                    .collect(),
                None => Vec::new(),
            }
        };
        if domains.is_empty() {
            anyhow::bail!(
                "no cached rules for site {site_id}, nothing to purge"
            );
        }
        let Some(ledger) = pingap_cache::global_disk_quota() else {
            // Memory-only or not-yet-initialised edge: there is no disk cache
            // to delete from, which answers the purge rather than failing it.
            debug!(site_id, "no file cache backend, nothing to purge");
            return Ok(0);
        };
        let mut purged = 0;
        for domain in &domains {
            purged += if urls.is_empty() {
                ledger.purge_domain(domain).await.purged_count
            } else {
                ledger.purge_urls(domain, urls).await.purged_count
            };
        }
        info!(
            site_id,
            domains = domains.len(),
            purged,
            "purged edge cache for site"
        );
        Ok(purged)
    }

    /// Update the cache from a proto RuleBundle received from the control plane.
    pub fn update_from_bundle(
        &self,
        bundle: &proto::RuleBundle,
    ) -> anyhow::Result<()> {
        let site_rules = Arc::new(Self::convert_bundle(bundle));
        let site_id = bundle.site_id.clone();
        let domain = site_rules.domain.clone();
        let alternate_domains = site_rules.alternate_domains.clone();

        // Capture the pre-sync enforcement state: leaving it (block mode,
        // observation off) invalidates the site's WAF auto-blocks.
        let previous = self
            .inner
            .load()
            .sites
            .get(&site_id)
            .map(|s| site_enforcement(Some(s)));

        // Swap in updated rules
        self.inner.rcu(|current| {
            let mut updated = (**current).clone();
            // Remove old domain index entries for this site. Removal keys
            // are normalized the same way as insertion keys below, so an
            // entry written as `EXAMPLE.com` is still findable for cleanup.
            if let Some(old_site) = updated.sites.get(&site_id) {
                updated
                    .domain_index
                    .remove(&normalize_host(&old_site.domain));
                for alt in &old_site.alternate_domains {
                    updated.domain_index.remove(&normalize_host(alt));
                }
            }
            // Insert new site
            updated
                .domain_index
                .insert(normalize_host(&domain), site_id.clone());
            for alt in &alternate_domains {
                updated
                    .domain_index
                    .insert(normalize_host(alt), site_id.clone());
            }
            updated
                .sites
                .insert(site_id.clone(), Arc::clone(&site_rules));
            // Every bundle carries the complete failover registry, so one
            // push refreshes it wholesale — including wholesale deletions
            // (an empty registry must replace a stale non-empty one).
            updated.failover_registry =
                failover_registry_from(&bundle.site_policies);
            if let Some(default_fail_open) = bundle.default_fail_open {
                updated.global_fail_open = Some(default_fail_open);
            }
            if let Some(global_cache) = &bundle.global_cache {
                updated.global_cache =
                    Some(Self::convert_global_cache(global_cache));
            }
            updated.config_hash = bundle.config_hash.as_str().into();
            // A single-site push changes only this bundle; its hash is the
            // reload signal (the full-config fingerprint does not exist here).
            updated.data_plane_hash = bundle.config_hash.as_str().into();
            updated.policy_revision = bundle.policy_revision;
            updated.updated_at = Utc::now();
            Arc::new(updated)
        });

        info!(site_id = %site_id, domain = %domain, "Updated rule cache from bundle");

        // The bundle may have changed a site's cache rules, so the per-domain
        // ceilings have to follow before the next write is accounted.
        self.apply_cache_quotas();

        // The site left enforcing mode: drop its stale WAF auto-blocks so
        // monitor/observation mode is not silently overridden by blocks the
        // engine issued under the previous configuration.
        let current = self
            .inner
            .load()
            .sites
            .get(&site_id)
            .map(|s| site_enforcement(Some(s)));
        if previous.is_some_and(waf_enforcing)
            && !current.is_some_and(waf_enforcing)
        {
            self.clear_waf_auto_blocks(&site_id);
        }

        // Persist asynchronously (best effort)
        if let Err(e) = self.persist_to_disk() {
            warn!(error = %e, "Failed to persist rule cache to disk");
        }

        self.last_policy_sync_at
            .store(Utc::now().timestamp(), Ordering::Relaxed);

        Ok(())
    }

    /// Update cache from a full SiteConfig (used on initial registration).
    pub fn update_from_site_config(
        &self,
        config: &proto::SiteConfig,
    ) -> anyhow::Result<()> {
        // Pre-sync enforcement state per site, so leaving enforcing mode
        // (block → monitor/off, observation on) drops the site's stale
        // WAF auto-blocks after the swap.
        let previous: HashMap<String, (WafMode, bool)> = self
            .inner
            .load()
            .sites
            .iter()
            .map(|(id, s)| (id.clone(), site_enforcement(Some(s))))
            .collect();

        self.inner.rcu(|current| {
            let mut updated = (**current).clone();
            // The agent's reported hash is the per-site bundle fingerprint -
            // the value `SyncRules` compares for delta sync and the control
            // plane publishes for apply-status. The full-config fingerprint
            // is a different value and only a fallback for configs that
            // carry no bundles.
            updated.config_hash = config
                .sites
                .iter()
                .filter_map(|site| site.rules.as_ref())
                .map(|rules| rules.config_hash.as_str())
                .next()
                .unwrap_or(config.config_hash.as_str())
                .into();
            // The reported `config_hash` above is one site's bundle hash, but
            // the reload watcher must see a change to ANY site. Use the outer
            // full-config fingerprint; a cert/origin edit on a non-first site
            // changes it while the first site's bundle hash stays put.
            updated.data_plane_hash = if config.config_hash.is_empty() {
                updated.config_hash.clone()
            } else {
                config.config_hash.as_str().into()
            };
            updated.policy_revision = config
                .sites
                .iter()
                .filter_map(|site| site.rules.as_ref())
                .map(|rules| rules.policy_revision)
                .max()
                .unwrap_or(0);
            updated.updated_at = Utc::now();

            // The bundles embed the same registry in every site; one pass
            // over whichever bundle carries it is enough. Replacement is
            // unconditional so deleting the last policy also clears the
            // agent-side registry.
            for site in &config.sites {
                if let Some(ref bundle) = site.rules {
                    updated.failover_registry =
                        failover_registry_from(&bundle.site_policies);
                    if let Some(default_fail_open) = bundle.default_fail_open {
                        updated.global_fail_open = Some(default_fail_open);
                    }
                    if let Some(global_cache) = &bundle.global_cache {
                        updated.global_cache =
                            Some(Self::convert_global_cache(global_cache));
                    }
                    break;
                }
            }

            for site in &config.sites {
                if let Some(ref bundle) = site.rules {
                    let mut site_rules = Self::convert_bundle(bundle);
                    // Override domain from site-level field
                    if !site.domain.is_empty() {
                        // Remove old domain index
                        updated
                            .domain_index
                            .remove(&normalize_host(&site_rules.domain));
                        site_rules.domain = site.domain.clone();
                    }
                    site_rules.site_id = site.id.clone();
                    site_rules.alternate_domains =
                        site.alternate_domains.clone();
                    site_rules.status = site_status_str(site.status);
                    site_rules.proxy_trust = ProxyTrustConfig {
                        enabled: site.trust_proxy_headers,
                        header: site.trusted_header.clone(),
                        last_hop_only: site.trust_last_hop,
                        trusted_ranges: site.trusted_proxy_ranges.clone(),
                    };

                    // Update domain index
                    updated.domain_index.insert(
                        normalize_host(&site_rules.domain),
                        site.id.clone(),
                    );
                    for alt in &site_rules.alternate_domains {
                        updated
                            .domain_index
                            .insert(normalize_host(alt), site.id.clone());
                    }
                    updated.sites.insert(site.id.clone(), Arc::new(site_rules));
                }
            }

            // A full site config is authoritative: sites the control plane
            // no longer lists are dropped here together with their domain
            // index entries, so a deleted site stops being served from
            // stale cached rules (they would otherwise survive every sync
            // and even a restart via the disk cache).
            let known: std::collections::HashSet<&String> =
                config.sites.iter().map(|s| &s.id).collect();
            let ghost_ids: Vec<String> = updated
                .sites
                .keys()
                .filter(|id| !known.contains(*id))
                .cloned()
                .collect();
            for id in &ghost_ids {
                if let Some(old) = updated.sites.remove(id) {
                    updated.domain_index.remove(&normalize_host(&old.domain));
                    for alt in &old.alternate_domains {
                        updated.domain_index.remove(&normalize_host(alt));
                    }
                }
            }

            Arc::new(updated)
        });

        info!(
            sites = self.inner.load().sites.len(),
            "Updated rule cache from full site config"
        );

        self.apply_cache_quotas();

        // Sites the control plane deleted lose every dynamic block — the
        // entries would otherwise linger until expiry and reload from disk.
        let current = self.inner.load();
        for id in previous.keys() {
            if !current.sites.contains_key(id) {
                self.clear_site_blocks(id);
            }
        }
        drop(current);

        // Sites that left enforcing mode lose their WAF auto-blocks, the
        // same way as on a single-bundle update.
        for site in config.sites.iter().filter(|s| !s.id.is_empty()) {
            let current = self
                .inner
                .load()
                .sites
                .get(&site.id)
                .map(|s| site_enforcement(Some(s)));
            if previous.get(&site.id).copied().is_some_and(waf_enforcing)
                && !current.is_some_and(waf_enforcing)
            {
                self.clear_waf_auto_blocks(&site.id);
            }
        }

        if let Err(e) = self.persist_to_disk() {
            warn!(error = %e, "Failed to persist rule cache to disk");
        }

        self.last_config_sync_at
            .store(Utc::now().timestamp(), Ordering::Relaxed);

        Ok(())
    }

    /// Look up site rules by domain name.
    ///
    /// Hot path: only the `Arc` is cloned, the rules themselves are shared
    /// with the cache.
    ///
    /// An exact-miss falls back to wildcard sites: `www.a.example.com`
    /// tries `*.a.example.com`, then `*.example.com`, and so on — the same
    /// semantics `pingap_location`'s `HostSelector::Suffix` uses for
    /// routing, so a wildcard site routed to a location no longer loses
    /// its WAF rules, cache policy, challenge and error pages.
    pub fn get_site_rules(&self, domain: &str) -> Option<Arc<SiteRules>> {
        let rules = self.inner.load();
        let site_id = lookup_with_wildcard(&rules.domain_index, domain)?;
        rules.sites.get(site_id).cloned()
    }

    /// The site's disconnected policy for `domain`, when the control plane
    /// has one registered (primary or alternate domain match, including a
    /// wildcard match with the same fallback as [`Self::get_site_rules`]).
    pub fn failover_for_domain(&self, domain: &str) -> Option<FailoverMode> {
        let rules = self.inner.load();
        lookup_with_wildcard(&rules.failover_registry, domain).copied()
    }

    /// The control-plane-wide fail-open default, when it has ever been
    /// synced. `None` means the agent must fall back to its local setting.
    pub fn global_fail_open(&self) -> Option<bool> {
        self.inner.load().global_fail_open
    }

    /// Look up site rules by site ID.
    pub fn get_site_rules_by_id(
        &self,
        site_id: &str,
    ) -> Option<Arc<SiteRules>> {
        let rules = self.inner.load();
        rules.sites.get(site_id).cloned()
    }

    /// Get all cached site rules (snapshot).
    pub fn all_sites(&self) -> Arc<CachedRules> {
        self.inner.load_full()
    }

    /// Get current config hash for delta sync. Cheap: clones the `Arc`, not
    /// the string.
    pub fn config_hash(&self) -> Arc<str> {
        self.inner.load().config_hash.clone()
    }

    /// Full-configuration fingerprint for the data-plane reload watcher.
    /// Falls back to the per-site hash for caches written before the field
    /// existed.
    pub fn data_plane_hash(&self) -> Arc<str> {
        let rules = self.inner.load();
        if rules.data_plane_hash.is_empty() {
            rules.config_hash.clone()
        } else {
            rules.data_plane_hash.clone()
        }
    }

    /// Revision of the policy bundle last applied (0 = none / never), for
    /// the heartbeat's applied-state report.
    pub fn policy_revision(&self) -> i32 {
        self.inner.load().policy_revision
    }

    /// When a full site config was last applied successfully, for the
    /// heartbeat's sync report.
    pub fn config_synced_at(&self) -> Option<DateTime<Utc>> {
        self.sync_marker(&self.last_config_sync_at)
    }

    /// When a single-site rule bundle was last applied successfully.
    pub fn policy_synced_at(&self) -> Option<DateTime<Utc>> {
        self.sync_marker(&self.last_policy_sync_at)
    }

    fn sync_marker(&self, cell: &AtomicI64) -> Option<DateTime<Utc>> {
        let secs = cell.load(Ordering::Relaxed);
        if secs <= 0 {
            None
        } else {
            Utc.timestamp_opt(secs, 0).single()
        }
    }

    // ─── Disk Persistence ───────────────────────────────────

    /// Persist current rules to disk.
    pub fn persist_to_disk(&self) -> anyhow::Result<()> {
        if !self.cache_dir.exists() {
            return Ok(());
        }

        let rules = self.inner.load();
        let sites_path = self.cache_dir.join("sites.json");
        let metadata_path = self.cache_dir.join("metadata.json");

        // Write sites
        let sites_json = serde_json::to_string_pretty(&**rules)?;
        std::fs::write(&sites_path, sites_json)?;

        // Write metadata
        let metadata = CacheMetadata {
            config_hash: rules.config_hash.to_string(),
            updated_at: rules.updated_at,
            agent_id: self.agent_id.clone(),
            version: 1,
        };
        let meta_json = serde_json::to_string_pretty(&metadata)?;
        std::fs::write(&metadata_path, meta_json)?;

        // Write blocked IPs
        self.persist_blocked_ips()?;

        debug!("Persisted rule cache to disk");
        Ok(())
    }

    /// Load rules from disk.
    pub fn load_from_disk(&self) -> anyhow::Result<()> {
        let sites_path = self.cache_dir.join("sites.json");
        let blocked_path = self.cache_dir.join("blocked_ips.json");

        if !sites_path.exists() {
            anyhow::bail!("No cache file found at {:?}", sites_path);
        }

        let sites_json = std::fs::read_to_string(&sites_path)?;
        let cached: CachedRules = serde_json::from_str(&sites_json)?;

        info!(
            sites = cached.sites.len(),
            config_hash = %cached.config_hash,
            "Loaded rule cache from disk"
        );

        self.inner.store(Arc::new(cached));

        // Load blocked IPs
        self.load_blocked_ips(&blocked_path)?;

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn update_from_site_config_removes_deleted_sites() {
        let dir = tempfile::tempdir().unwrap();
        let cache =
            RuleCache::new(dir.path().to_path_buf(), "test".to_string())
                .unwrap();

        let site = |id: &str, domain: &str| proto::Site {
            id: id.to_string(),
            name: id.to_string(),
            domain: domain.to_string(),
            alternate_domains: Vec::new(),
            status: 0,
            rules: Some(proto::RuleBundle {
                site_id: id.to_string(),
                config_hash: "hash".to_string(),
                ..Default::default()
            }),
            trust_proxy_headers: false,
            trusted_header: String::new(),
            trust_last_hop: false,
            trusted_proxy_ranges: Vec::new(),
        };
        cache
            .update_from_site_config(&proto::SiteConfig {
                sites: vec![
                    site("site-1", "a.example.com"),
                    site("site-2", "b.example.com"),
                ],
                ..Default::default()
            })
            .unwrap();
        assert!(cache.get_site_rules_by_id("site-2").is_some());
        cache.block_ip("site-2", "203.0.113.1", None, "waf: stale");

        // A sync without site-2 drops the site, its domain index entries
        // and its dynamic blocks — it must not keep serving from stale
        // cached rules.
        cache
            .update_from_site_config(&proto::SiteConfig {
                sites: vec![site("site-1", "a.example.com")],
                ..Default::default()
            })
            .unwrap();
        assert!(cache.get_site_rules_by_id("site-2").is_none());
        assert!(cache.get_site_rules("b.example.com").is_none());
        assert_eq!(cache.blocked_reason("site-2", "203.0.113.1"), None);
        // The surviving site is untouched.
        assert!(cache.get_site_rules_by_id("site-1").is_some());
    }

    #[test]
    fn wildcard_sites_resolve_subdomains_via_fallback() {
        let dir = tempfile::tempdir().unwrap();
        let cache =
            RuleCache::new(dir.path().to_path_buf(), "test".to_string())
                .unwrap();

        let policies = vec![
            proto::SitePolicy {
                domain: "*.example.com".to_string(),
                alternate_domains: Vec::new(),
                mode: proto::FailoverMode::FailoverClosed as i32,
            },
            proto::SitePolicy {
                domain: "app.example.com".to_string(),
                alternate_domains: Vec::new(),
                mode: proto::FailoverMode::FailoverOpen as i32,
            },
        ];
        let site = |id: &str, domain: &str| proto::Site {
            id: id.to_string(),
            name: id.to_string(),
            domain: domain.to_string(),
            alternate_domains: Vec::new(),
            status: 0,
            rules: Some(proto::RuleBundle {
                site_id: id.to_string(),
                config_hash: "hash".to_string(),
                site_policies: policies.clone(),
                ..Default::default()
            }),
            trust_proxy_headers: false,
            trusted_header: String::new(),
            trust_last_hop: false,
            trusted_proxy_ranges: Vec::new(),
        };
        cache
            .update_from_site_config(&proto::SiteConfig {
                sites: vec![
                    site("site-exact", "app.example.com"),
                    site("site-wild", "*.example.com"),
                    site("site-deep", "*.a.example.com"),
                ],
                ..Default::default()
            })
            .unwrap();

        let id_of = |domain: &str| {
            cache.get_site_rules(domain).map(|r| r.site_id.clone())
        };

        // An exact site always wins over any wildcard.
        assert_eq!(id_of("app.example.com").as_deref(), Some("site-exact"));
        // Direct subdomains fall back to the wildcard site — before this
        // fix a wildcard site lost its WAF rules, cache policy, challenge
        // and error pages entirely.
        assert_eq!(id_of("foo.example.com").as_deref(), Some("site-wild"));
        // The most specific wildcard wins for deeper names.
        assert_eq!(id_of("a.example.com").as_deref(), Some("site-wild"));
        assert_eq!(id_of("www.a.example.com").as_deref(), Some("site-deep"));
        // The apex itself is not covered by a wildcard — the same
        // semantics as `HostSelector::Suffix` in the routing layer.
        assert!(cache.get_site_rules("example.com").is_none());

        // The failover registry follows the same fallback, so a wildcard
        // site's disconnected policy actually applies to its subdomains.
        assert_eq!(
            cache.failover_for_domain("app.example.com"),
            Some(FailoverMode::Open)
        );
        assert_eq!(
            cache.failover_for_domain("foo.example.com"),
            Some(FailoverMode::Closed)
        );
        assert_eq!(cache.failover_for_domain("example.com"), None);
    }

    #[test]
    fn site_config_reports_the_bundle_hash() {
        let dir = tempfile::tempdir().unwrap();
        let cache =
            RuleCache::new(dir.path().to_path_buf(), "test".to_string())
                .expect("cache");
        let config = proto::SiteConfig {
            sites: vec![proto::Site {
                id: "site-1".to_string(),
                domain: "example.com".to_string(),
                rules: Some(proto::RuleBundle {
                    site_id: "site-1".to_string(),
                    config_hash: "bundle-hash".to_string(),
                    policy_revision: 7,
                    ..Default::default()
                }),
                ..Default::default()
            }],
            config_hash: "config-hash".to_string(),
            updated_at: None,
        };
        cache.update_from_site_config(&config).unwrap();
        // The per-site bundle fingerprint is what SyncRules and
        // apply-status compare; the full-config fingerprint is a different
        // value and must not overwrite it.
        assert_eq!(&*cache.config_hash(), "bundle-hash");
        assert_eq!(&*cache.data_plane_hash(), "config-hash");
        assert_eq!(cache.policy_revision(), 7);
    }

    #[test]
    fn data_plane_hash_tracks_every_site_not_just_the_first() {
        let dir = tempfile::tempdir().unwrap();
        let cache =
            RuleCache::new(dir.path().to_path_buf(), "test".to_string())
                .expect("cache");
        let config = |second_hash: &str, outer: &str| proto::SiteConfig {
            sites: vec![
                proto::Site {
                    id: "site-a".to_string(),
                    domain: "a.example.com".to_string(),
                    rules: Some(proto::RuleBundle {
                        site_id: "site-a".to_string(),
                        config_hash: "first-hash".to_string(),
                        ..Default::default()
                    }),
                    ..Default::default()
                },
                proto::Site {
                    id: "site-b".to_string(),
                    domain: "b.example.com".to_string(),
                    rules: Some(proto::RuleBundle {
                        site_id: "site-b".to_string(),
                        config_hash: second_hash.to_string(),
                        ..Default::default()
                    }),
                    ..Default::default()
                },
            ],
            config_hash: outer.to_string(),
            updated_at: None,
        };

        cache
            .update_from_site_config(&config("second-hash", "outer-1"))
            .unwrap();
        assert_eq!(&*cache.config_hash(), "first-hash");
        let first = cache.data_plane_hash();

        // Only the second site changes. The per-site hash used for delta sync
        // stays on the first bundle; the reload fingerprint must move.
        cache
            .update_from_site_config(&config("second-hash-2", "outer-2"))
            .unwrap();
        assert_eq!(&*cache.config_hash(), "first-hash");
        assert_ne!(first, cache.data_plane_hash());
    }

    #[test]
    fn global_space_clamps_site_quotas() {
        let dir = tempfile::tempdir().unwrap();
        let cache =
            RuleCache::new(dir.path().to_path_buf(), "test".to_string())
                .unwrap();
        const DOMAIN: &str = "clamp-test.example.com";

        let site = |quota_mb: u32| {
            Arc::new(SiteRules {
                site_id: "site-1".to_string(),
                domain: DOMAIN.to_string(),
                alternate_domains: Vec::new(),
                config_hash: String::new(),
                status: site_status::ACTIVE.to_string(),
                waf_config: None,
                rate_limit_rules: Vec::new(),
                ip_access_rules: Vec::new(),
                geo_config: None,
                cache_rules: vec![CacheRule {
                    id: "r1".to_string(),
                    name: "static".to_string(),
                    match_expression: String::new(),
                    edge_ttl_seconds: 300,
                    browser_ttl_seconds: 60,
                    disk_quota_mb: quota_mb,
                    cache_eligible: true,
                    cache_key_headers: Vec::new(),
                    respect_origin_headers: true,
                    stale_while_revalidate_seconds: 0,
                    enabled: true,
                }],
                challenge_config: None,
                rewrite_rules: Vec::new(),
                error_pages: Vec::new(),
                ssl_config: None,
                upstreams: Vec::new(),
                routes: Vec::new(),
                bot_protection: None,
                basic_auth: None,
                observation_mode: false,
                proxy_trust: ProxyTrustConfig::default(),
                cache_settings: None,
            })
        };
        let store = |global_space_mb: Option<u32>, quota_mb: u32| {
            cache.inner.store(Arc::new(CachedRules {
                sites: [(DOMAIN.to_string(), site(quota_mb))]
                    .into_iter()
                    .collect(),
                domain_index: HashMap::new(),
                failover_registry: HashMap::new(),
                global_fail_open: None,
                global_cache: global_space_mb.map(|max_space_mb| {
                    GlobalCacheSettings {
                        max_space_mb: Some(max_space_mb),
                        ..Default::default()
                    }
                }),
                updated_at: Utc::now(),
                config_hash: Arc::from(""),
                data_plane_hash: Arc::from(""),
                policy_revision: 0,
            }));
        };

        // No budget: the site quota passes through untouched.
        store(None, 2048);
        cache.apply_cache_quotas();
        assert_eq!(quota::configured_quota_mb(DOMAIN), Some(2048));

        // A budget caps an explicit site quota.
        store(Some(1024), 2048);
        cache.apply_cache_quotas();
        assert_eq!(quota::configured_quota_mb(DOMAIN), Some(1024));

        // An unlimited site is capped at the budget.
        store(Some(1024), 0);
        cache.apply_cache_quotas();
        assert_eq!(quota::configured_quota_mb(DOMAIN), Some(1024));

        // No budget at all leaves unlimited as unlimited — parking 0 clears
        // the parked ceiling entirely (`configured_quota_mb` answers None).
        store(None, 0);
        cache.apply_cache_quotas();
        assert_eq!(quota::configured_quota_mb(DOMAIN), None);
    }
}
