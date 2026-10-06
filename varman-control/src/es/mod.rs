//! Elasticsearch log shipping.
//!
//! This module is the control plane's long-term, full-text log store. It sits
//! alongside the PostgreSQL tables in [`crate::models`]: Postgres keeps recent
//! logs for the dashboard's paginated queries, while Elasticsearch receives the
//! same events for full-text search and long retention.
//!
//! The public surface is small:
//! - [`ElasticsearchClient`] — the non-blocking bulk shipper
//! - [`EsConfig`] — its configuration
//! - [`AccessLogDocument`] / [`SecurityEventDocument`] — the indexed shapes
//! - [`ensure_index_template`] — one-shot mapping/ILM bootstrap

pub mod client;
pub mod config;
pub mod models;
pub mod template;

pub use client::{
    BulkResult, DocumentType, ElasticsearchClient, EsDocument, EsHealth,
};
pub use config::EsConfig;
pub use models::{AccessLogDocument, SecurityEventDocument};
pub use template::ensure_index_template;
