//! Entity for the management-endpoint (dashboard) certificate.
//!
//! `management_certificate` is the single-row request table for a dashboard
//! certificate issued by ACME instead of uploaded by hand. The certificate
//! material itself lives where every active control-plane certificate lives
//! (`control_plane_certificates`, source `acme`); this row carries the
//! request (identity, contact), its lifecycle status and the fingerprint of
//! the last installed certificate, so a renewal is installed exactly once.

use sea_orm::entity::prelude::*;
use serde::{Deserialize, Serialize};

/// `management_certificate` - the dashboard's ACME request and status.
pub mod management_certificate {
    use super::*;

    pub const STATUS_DISABLED: &str = "disabled";
    pub const STATUS_PENDING: &str = "pending";
    pub const STATUS_ACTIVE: &str = "active";
    pub const STATUS_FAILED: &str = "failed";

    #[derive(
        Clone, Debug, PartialEq, DeriveEntityModel, Serialize, Deserialize,
    )]
    #[sea_orm(table_name = "management_certificate")]
    pub struct Model {
        /// Always `1`.
        #[sea_orm(primary_key, auto_increment = false)]
        pub id: i32,
        /// DNS name or IP literal the dashboard is reached by.
        pub identity: String,
        /// ACME contact address.
        pub email: String,
        /// `http-01` (the edge answers the challenge on port 80).
        pub challenge: String,
        /// Whether issuance/renewal is armed.
        pub enabled: bool,
        /// `disabled`, `pending`, `active` or `failed`.
        pub status: String,
        /// Why the last order failed, when it did.
        pub failure_reason: Option<String>,
        /// When issuance was last (re)armed; the stale sweep uses it.
        pub requested_at: Option<DateTimeUtc>,
        /// SHA-256 of the certificate the control plane last installed.
        pub installed_fingerprint: Option<String>,
        pub updated_at: DateTimeUtc,
    }

    #[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
    pub enum Relation {}

    impl ActiveModelBehavior for ActiveModel {}
}
