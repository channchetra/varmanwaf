//! Semantic detectors (Phase 6).
//!
//! Semantic detectors run after the fast lane and reason about the *structure*
//! of a value rather than matching literal signatures: comment-obfuscated
//! keywords, whitespace variants, stacked statements, quote-context breaks
//! and time-based shapes. They are budgeted and must degrade, never error.

pub mod command;
pub mod deser;
pub mod nosql;
pub mod sql;
pub mod ssrf;
pub mod ssti;
pub mod xss;
pub mod xxe;

pub use command::CommandInjectionDetector;
pub use deser::DeserializationDetector;
pub use nosql::NosqlInjectionDetector;
pub use sql::SqlStructuralDetector;
pub use ssrf::SsrfStructuralDetector;
pub use ssti::SstiDetector;
pub use xss::HtmlXssDetector;
pub use xxe::XxeDetector;
