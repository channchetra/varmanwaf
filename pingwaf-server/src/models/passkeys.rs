//! `passkey_credentials` and `passkey_states` — the WebAuthn credentials bound
//! to dashboard accounts, and the short-lived ceremony state (challenge and
//! owner) a registration or login consumes.
//!
//! `public_key` holds the base64url-encoded COSE key the authenticator reported;
//! the matching private key never leaves the authenticator.

use sea_orm::entity::prelude::*;
use serde::{Deserialize, Serialize};

/// `passkey_credentials` — one registered passkey per row.
pub mod passkey_credentials {
    use super::*;

    #[derive(
        Clone, Debug, PartialEq, DeriveEntityModel, Serialize, Deserialize,
    )]
    #[sea_orm(table_name = "passkey_credentials")]
    pub struct Model {
        #[sea_orm(primary_key, auto_increment = false)]
        pub id: Uuid,
        pub user_id: Uuid,
        /// Base64url credential id, unique across every account.
        pub cred_id: String,
        #[sea_orm(column_type = "Text")]
        pub public_key: String,
        /// Operator-facing label; renaming does not invalidate the credential.
        pub name: String,
        /// Signature counter reported by the authenticator, used to spot clones.
        pub counter: i64,
        pub created_at: DateTimeUtc,
        pub last_used_at: DateTimeUtc,
    }

    #[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
    pub enum Relation {}

    impl ActiveModelBehavior for ActiveModel {}
}

/// `passkey_states` — the in-flight challenge of one ceremony. Rows are keyed by
/// the ids the verifier uses (`reg:<user id>` / `login:<challenge>`) and are
/// deleted as soon as the ceremony finishes or expires.
pub mod passkey_states {
    use super::*;

    #[derive(
        Clone, Debug, PartialEq, DeriveEntityModel, Serialize, Deserialize,
    )]
    #[sea_orm(table_name = "passkey_states")]
    pub struct Model {
        #[sea_orm(primary_key, auto_increment = false)]
        pub id: String,
        #[sea_orm(column_type = "Text")]
        pub state_json: String,
        pub expires_at: DateTimeUtc,
    }

    #[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
    pub enum Relation {}

    impl ActiveModelBehavior for ActiveModel {}
}
