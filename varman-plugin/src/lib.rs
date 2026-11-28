//! VarmanWAF-specific plugins.
//!
//! The generic Pingap plugins stay in `pingap-plugin`; the WAF engine, stream
//! inspection, external processor, shadow comparison and per-site custom
//! layers live here because they depend on `varman-waf`, `varman-agent` and
//! `varman-challenge`.

mod cache;
mod challenge;
mod error_page;
mod rewrite;
#[cfg(test)]
mod test_support;
mod waf;

pub use waf::{PENDING_ACCESS_SWEEP_TTL, sweep_stale_access};

use pingap_plugin::get_plugin_factory;
use std::sync::Arc;

/// Registers this crate's plugins with the process-wide factory.
///
/// Registration is explicit so the root's startup order is visible and a
/// feature-gated build cannot lose a plugin to link-time constructor
/// collection.
pub fn register() {
    let factory = get_plugin_factory();
    factory
        .register("waf", |params| Ok(Arc::new(waf::WafPlugin::new(params)?)));
    factory.register("challenge", |params| {
        Ok(Arc::new(challenge::ChallengePlugin::new(params)?))
    });
    factory
        .register("cache", |params| Ok(Arc::new(cache::Cache::new(params)?)));
    factory.register("rewrite", |params| {
        Ok(Arc::new(rewrite::RewritePlugin::new(params)?))
    });
    factory.register("error_page", |params| {
        Ok(Arc::new(error_page::ErrorPagePlugin::new(params)?))
    });
}

#[cfg(test)]
mod tests {
    use super::register;
    use pingap_plugin::get_plugin_factory;

    #[test]
    fn registers_every_varman_plugin_category() {
        register();
        let supported = get_plugin_factory().supported_plugins();
        for category in ["waf", "challenge", "cache", "rewrite", "error_page"] {
            assert!(
                supported.iter().any(|item| item == category),
                "missing plugin category {category}"
            );
        }
    }
}
