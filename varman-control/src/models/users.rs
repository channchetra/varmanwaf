//! Entities for dashboard users and the API keys used by agents.

use sea_orm::entity::prelude::*;
use serde::{Deserialize, Serialize};

/// Role of a dashboard user: `admin` may mutate everything, `viewer` is
/// read-only.
pub mod role {
    pub const ADMIN: &str = "admin";
    /// Read-only auditor: may inspect every resource but never mutate.
    pub const AUDITOR: &str = "auditor";
    pub const VIEWER: &str = "viewer";

    pub fn is_valid(role: &str) -> bool {
        matches!(role, ADMIN | AUDITOR | VIEWER)
    }
}

/// `users` — dashboard credentials.
pub mod users {
    use super::*;

    #[derive(Clone, Debug, PartialEq, DeriveEntityModel)]
    #[sea_orm(table_name = "users")]
    pub struct Model {
        #[sea_orm(primary_key, auto_increment = false)]
        pub id: Uuid,
        #[sea_orm(unique)]
        pub email: String,
        pub password_hash: String,
        pub name: Option<String>,
        pub role: String,
        /// Disabled accounts are refused at login and on every token check.
        pub disabled: bool,
        /// First-login flag: the console forces a password change.
        pub must_change_password: bool,
        /// Bumped on credential-sensitive changes (password change, role
        /// change, disable). Tokens embed the version they were minted
        /// with; a mismatch invalidates them immediately.
        pub token_version: i64,
        pub created_at: DateTimeUtc,
        pub updated_at: DateTimeUtc,
    }

    #[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
    pub enum Relation {}

    impl ActiveModelBehavior for ActiveModel {}
}

/// `api_keys` — hashed agent credentials.
///
/// `key_hash` is a bcrypt digest and must never leave the process, so it is
/// skipped by serde even though the rest of the row is serialisable.
pub mod api_keys {
    use super::*;

    #[derive(
        Clone, Debug, PartialEq, DeriveEntityModel, Serialize, Deserialize,
    )]
    #[sea_orm(table_name = "api_keys")]
    pub struct Model {
        #[sea_orm(primary_key, auto_increment = false)]
        pub id: Uuid,
        pub user_id: Uuid,
        pub name: String,
        #[serde(skip)]
        pub key_hash: String,
        pub key_prefix: String,
        pub permissions: Vec<String>,
        pub expires_at: Option<DateTimeUtc>,
        pub last_used_at: Option<DateTimeUtc>,
        pub created_at: DateTimeUtc,
    }

    #[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
    pub enum Relation {}

    impl ActiveModelBehavior for ActiveModel {}
}

/// Permission strings stored in `api_keys.permissions`.
pub mod permission {
    /// Register agents and ship logs/metrics.
    pub const AGENT: &str = "agent";
    /// Read sites, rules and logs.
    pub const READ: &str = "read";
    /// Create and update sites, rules and settings.
    pub const WRITE: &str = "write";

    pub fn is_valid(permission: &str) -> bool {
        matches!(permission, AGENT | READ | WRITE)
    }
}
