//! Semantic detectors (Phase 6).
//!
//! Semantic detectors run after the fast lane and reason about the *structure*
//! of a value rather than matching literal signatures: comment-obfuscated
//! keywords, whitespace variants, stacked statements, quote-context breaks
//! and time-based shapes. They are budgeted and must degrade, never error.

pub mod body_shape;
pub mod command;
pub mod deser;
pub mod dlp;
pub mod graphql;
pub mod jwt;
pub mod ldap_xpath;
pub mod nosql;
pub mod proto;
pub mod sql;
pub mod sql_ast;
pub mod ssrf;
pub mod ssti;
pub mod ti;
pub mod websocket;
pub mod xss;
pub mod xxe;

pub use body_shape::BodyShapeDetector;
pub use command::CommandInjectionDetector;
pub use deser::DeserializationDetector;
pub use dlp::DlpDetector;
pub use graphql::GraphqlAbuseDetector;
pub use jwt::JwtDetector;
pub use ldap_xpath::LdapXPathDetector;
pub use nosql::NosqlInjectionDetector;
pub use proto::PrototypePollutionDetector;
pub use sql::SqlStructuralDetector;
pub use sql_ast::SqlAstDetector;
pub use ssrf::SsrfStructuralDetector;
pub use ssti::SstiDetector;
pub use ti::{TiDetector, TiIndicators};
pub use websocket::WebSocketDetector;
pub use xss::HtmlXssDetector;
pub use xxe::XxeDetector;
