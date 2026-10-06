//! Immutable security runtime snapshots (mandate §13).
//!
//! Configuration changes never mutate the active request-path structures.
//! Instead the control plane (or the agent's rule cache) compiles a new
//! [`SecuritySnapshot`] and [`SecurityRuntime::replace`]s it atomically; each
//! request keeps the snapshot it started with until it finishes, so no
//! request ever observes a half-applied configuration.
//!
//! ```text
//! receive desired configuration
//!   → validate → compile (pipelines, matchers) → new SecuritySnapshot
//!   → atomic swap → ACK configuration version
//! ```
//!
//! The snapshot carries a monotonically increasing `revision`; the control
//! plane/agent version handshake (desired/active/last-good) is layered on top
//! in later phases.

use std::collections::BTreeMap;
use std::sync::Arc;

use arc_swap::{ArcSwap, Guard};

use super::SecurityPipeline;

/// Per-site runtime: immutable once built.
#[derive(Debug)]
pub struct SiteRuntime {
    pub site_id: String,
    /// Domains (and alternate domains) this runtime answers for, lowercased.
    pub domains: Vec<String>,
    /// Compiled detection pipeline for the site.
    pub pipeline: Arc<SecurityPipeline>,
}

impl SiteRuntime {
    pub fn new(
        site_id: impl Into<String>,
        domains: Vec<String>,
        pipeline: Arc<SecurityPipeline>,
    ) -> Self {
        Self {
            site_id: site_id.into(),
            domains: domains
                .into_iter()
                .map(|domain| domain.trim().to_ascii_lowercase())
                .collect(),
            pipeline,
        }
    }
}

/// One immutable point-in-time view of every protected site's security
/// runtime.
#[derive(Debug)]
pub struct SecuritySnapshot {
    revision: u64,
    /// Domain → runtime. All of a site's domains point at the same
    /// [`SiteRuntime`].
    sites: BTreeMap<String, Arc<SiteRuntime>>,
}

impl SecuritySnapshot {
    /// An empty snapshot at `revision` (a data plane can start from it before
    /// the first configuration arrives).
    pub fn empty(revision: u64) -> Self {
        Self {
            revision,
            sites: BTreeMap::new(),
        }
    }

    pub fn revision(&self) -> u64 {
        self.revision
    }

    pub fn site_count(&self) -> usize {
        let mut ids: Vec<&str> =
            self.sites.values().map(|s| s.site_id.as_str()).collect();
        ids.sort_unstable();
        ids.dedup();
        ids.len()
    }

    /// Add a site runtime, indexing every one of its domains.
    pub fn with_site(mut self, runtime: SiteRuntime) -> Self {
        let runtime = Arc::new(runtime);
        for domain in &runtime.domains {
            self.sites.insert(domain.clone(), Arc::clone(&runtime));
        }
        self
    }

    /// Runtime for an exact domain (case-insensitive). Wildcard matching is a
    /// later slice; callers should already pass the canonical authority.
    pub fn site_for_domain(&self, domain: &str) -> Option<&Arc<SiteRuntime>> {
        let domain = domain.trim().to_ascii_lowercase();
        self.sites.get(&domain)
    }

    /// Runtime for a site id (linear scan; snapshots are small).
    pub fn site(&self, site_id: &str) -> Option<&Arc<SiteRuntime>> {
        self.sites
            .values()
            .find(|runtime| runtime.site_id == site_id)
    }

    pub fn domains(&self) -> impl Iterator<Item = &str> {
        self.sites.keys().map(String::as_str)
    }
}

/// Atomic holder for the active snapshot.
pub struct SecurityRuntime {
    current: ArcSwap<SecuritySnapshot>,
}

impl SecurityRuntime {
    pub fn new(snapshot: SecuritySnapshot) -> Self {
        Self {
            current: ArcSwap::from_pointee(snapshot),
        }
    }

    /// Load the active snapshot. The returned guard pins it for the duration
    /// of a request, immune to concurrent replacements.
    pub fn load(&self) -> Guard<Arc<SecuritySnapshot>> {
        self.current.load()
    }

    /// Atomically install a new snapshot; returns the previous one.
    pub fn replace(&self, snapshot: SecuritySnapshot) -> Arc<SecuritySnapshot> {
        self.current.swap(Arc::new(snapshot))
    }

    pub fn revision(&self) -> u64 {
        self.current.load().revision()
    }
}

impl std::fmt::Debug for SecurityRuntime {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SecurityRuntime")
            .field("revision", &self.revision())
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::{SecurityRuntime, SecuritySnapshot, SiteRuntime};
    use crate::pipeline::SecurityPipeline;
    use std::sync::Arc;

    fn runtime(site_id: &str, domains: &[&str]) -> SiteRuntime {
        SiteRuntime::new(
            site_id,
            domains.iter().map(|d| d.to_string()).collect(),
            Arc::new(SecurityPipeline::new(Vec::new())),
        )
    }

    #[test]
    fn empty_snapshot_answers_nothing() {
        let snapshot = SecuritySnapshot::empty(1);
        assert_eq!(snapshot.revision(), 1);
        assert_eq!(snapshot.site_count(), 0);
        assert!(snapshot.site_for_domain("example.com").is_none());
        assert!(snapshot.site("missing").is_none());
    }

    #[test]
    fn site_domains_are_indexed_case_insensitively() {
        let snapshot = SecuritySnapshot::empty(7)
            .with_site(runtime("s1", &["Example.COM", "alt.example.com"]));
        assert_eq!(snapshot.site_count(), 1);
        assert_eq!(
            snapshot
                .site_for_domain("example.com")
                .map(|s| s.site_id.as_str()),
            Some("s1")
        );
        assert_eq!(
            snapshot
                .site_for_domain(" ALT.EXAMPLE.COM ")
                .map(|s| s.site_id.as_str()),
            Some("s1")
        );
        assert!(snapshot.site_for_domain("other.example.com").is_none());
        assert_eq!(snapshot.site("s1").map(|s| s.site_id.as_str()), Some("s1"));
        let mut domains: Vec<&str> = snapshot.domains().collect();
        domains.sort_unstable();
        assert_eq!(domains, vec!["alt.example.com", "example.com"]);
    }

    #[test]
    fn replace_is_atomic_and_old_guards_stay_consistent() {
        let handle = SecurityRuntime::new(
            SecuritySnapshot::empty(1).with_site(runtime("s1", &["a.example"])),
        );
        // A request that started on revision 1 holds this guard.
        let in_flight = handle.load();
        assert_eq!(in_flight.revision(), 1);
        assert!(in_flight.site_for_domain("b.example").is_none());

        let previous = handle.replace(
            SecuritySnapshot::empty(2).with_site(runtime("s2", &["b.example"])),
        );
        assert_eq!(previous.revision(), 1);
        assert_eq!(handle.revision(), 2);

        // The pinned guard still sees the old world...
        assert!(in_flight.site_for_domain("b.example").is_none());
        assert_eq!(
            in_flight
                .site_for_domain("a.example")
                .map(|s| s.site_id.as_str()),
            Some("s1")
        );
        // ...while new loads see the swapped one.
        let fresh = handle.load();
        assert_eq!(fresh.revision(), 2);
        assert!(fresh.site_for_domain("a.example").is_none());
        assert_eq!(
            fresh
                .site_for_domain("b.example")
                .map(|s| s.site_id.as_str()),
            Some("s2")
        );
    }

    #[test]
    fn rebuilt_site_replaces_the_previous_runtime() {
        let handle = SecurityRuntime::new(
            SecuritySnapshot::empty(1)
                .with_site(runtime("s1", &["example.com"])),
        );
        let before = Arc::clone(
            handle
                .load()
                .site_for_domain("example.com")
                .expect("site exists"),
        );
        handle.replace(
            SecuritySnapshot::empty(2)
                .with_site(runtime("s1", &["example.com"])),
        );
        let after = Arc::clone(
            handle
                .load()
                .site_for_domain("example.com")
                .expect("site exists"),
        );
        assert!(!Arc::ptr_eq(&before, &after));
        assert_eq!(before.site_id, after.site_id);
    }
}
