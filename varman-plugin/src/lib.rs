//! VarmanWAF-specific plugins.
//!
//! The generic Pingap plugins stay in `pingap-plugin`; the WAF engine, stream
//! inspection, external processor, shadow comparison and per-site custom
//! layers live here because they depend on `varman-waf`, `varman-agent` and
//! `varman-challenge`.

mod waf;

/// Failed-authentication streak tracker (ATO defense).
pub mod waf_ato;
/// Per-site custom layers: SecLang virtual patches + OpenAPI validation.
pub mod waf_custom;
/// External-processor transport.
pub mod waf_processor;
/// Shadow execution of the Varman pipeline beside the legacy engine.
pub mod waf_shadow;
/// Stream inspection: body tails and WebSocket frames.
pub mod waf_stream;

pub use waf::{PENDING_ACCESS_SWEEP_TTL, sweep_stale_access};

use pingap_plugin::get_plugin_factory;
use std::sync::Arc;

/// Registers this crate's plugins with the process-wide factory.
///
/// Registration is explicit so the root's startup order is visible and a
/// feature-gated build cannot lose a plugin to link-time constructor
/// collection.
pub fn register() {
    get_plugin_factory()
        .register("waf", |params| Ok(Arc::new(waf::WafPlugin::new(params)?)));
}
