//! `mtls_cas` and `mtls_client_certificates` — the certificate authorities a
//! site trusts for client authentication, and the certificates issued from
//! them.
//!
//! `key_pem` on either table is private key material: it is written once (for
//! generated material) and handed to the operator exactly once, then optionally
//! cleared.

use sea_orm::entity::prelude::*;
use serde::{Deserialize, Serialize};

/// `mtls_cas` — one certificate authority per row.
pub mod mtls_cas {
    use super::*;

    #[derive(
        Clone, Debug, PartialEq, DeriveEntityModel, Serialize, Deserialize,
    )]
    #[sea_orm(table_name = "mtls_cas")]
    pub struct Model {
        #[sea_orm(primary_key, auto_increment = false)]
        pub id: Uuid,
        pub site_id: Uuid,
        pub name: String,
        /// `generated` (key held here) or `imported` (certificate only).
        pub source: String,
        #[sea_orm(column_type = "Text")]
        pub cert_pem: String,
        #[sea_orm(column_type = "Text")]
        pub key_pem: Option<String>,
        pub subject_dn: String,
        pub serial: String,
        pub fingerprint_sha256: String,
        /// Organization every client certificate must carry; `None` skips the
        /// check.
        pub expected_organization: Option<String>,
        pub not_before: DateTimeUtc,
        pub not_after: DateTimeUtc,
        pub is_active: bool,
        pub created_at: DateTimeUtc,
    }

    #[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
    pub enum Relation {}

    impl ActiveModelBehavior for ActiveModel {}
}

/// `mtls_client_certificates` — a certificate issued to one client.
pub mod mtls_client_certificates {
    use super::*;

    #[derive(
        Clone, Debug, PartialEq, DeriveEntityModel, Serialize, Deserialize,
    )]
    #[sea_orm(table_name = "mtls_client_certificates")]
    pub struct Model {
        #[sea_orm(primary_key, auto_increment = false)]
        pub id: Uuid,
        pub site_id: Uuid,
        pub ca_id: Uuid,
        pub name: String,
        pub common_name: String,
        pub organization: Option<String>,
        pub serial: String,
        pub fingerprint_sha256: String,
        #[sea_orm(column_type = "Text")]
        pub cert_pem: String,
        #[sea_orm(column_type = "Text")]
        pub key_pem: Option<String>,
        pub not_before: DateTimeUtc,
        pub not_after: DateTimeUtc,
        pub status: String,
        pub revoked_at: Option<DateTimeUtc>,
        pub revocation_reason: Option<String>,
        pub created_at: DateTimeUtc,
    }

    #[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
    pub enum Relation {}

    impl ActiveModelBehavior for ActiveModel {}
}

/// Values `mtls_cas.source` accepts.
pub mod ca_source {
    pub const GENERATED: &str = "generated";
    pub const IMPORTED: &str = "imported";

    pub fn is_valid(source: &str) -> bool {
        matches!(source, GENERATED | IMPORTED)
    }
}

/// Values `mtls_client_certificates.status` accepts.
pub mod client_cert_status {
    pub const ACTIVE: &str = "active";
    pub const REVOKED: &str = "revoked";

    pub fn is_valid(status: &str) -> bool {
        matches!(status, ACTIVE | REVOKED)
    }
}
