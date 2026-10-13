//! Authentication and authorisation primitives: JWT minting/verification,
//! bcrypt password hashing and the Axum extractors that enforce both.

pub mod jwt;
pub mod middleware;
pub mod password;

use crate::models::user;

pub use jwt::{
    create_agent_token, create_refresh_token, create_token, verify_agent_token,
    verify_refresh_token, verify_token, verify_user_token, Claims, JwtError,
    AGENT_ROLE, ISSUER, TOKEN_TYPE_AGENT, TOKEN_TYPE_DASHBOARD,
    TOKEN_TYPE_REFRESH,
};
pub use middleware::{bearer_token, AdminUser, AuthError, AuthUser};
pub use password::{
    hash_password, hash_password_with_cost, validate_password, verify_password,
    PasswordError, MAX_PASSWORD_BYTES, MIN_PASSWORD_LENGTH,
};

/// True when a token's embedded `ver` still matches the account row.
///
/// Tokens minted before the claim existed deserialize as version 0, so a
/// control-plane upgrade keeps every pre-upgrade session alive until the
/// account's next bump.
pub(crate) fn token_version_valid(
    claims_ver: i64,
    account: &user::Model,
) -> bool {
    claims_ver == account.token_version
}

#[cfg(test)]
mod tests {
    use super::*;
    use sea_orm::Set;

    fn account(token_version: i64) -> user::Model {
        user::Model {
            id: uuid::Uuid::new_v4(),
            email: "ops@example.com".to_string(),
            password_hash: String::new(),
            name: None,
            role: crate::models::role::ADMIN.to_string(),
            disabled: false,
            must_change_password: false,
            token_version: Set(token_version).unwrap(),
            created_at: chrono::Utc::now(),
            updated_at: chrono::Utc::now(),
        }
    }

    #[test]
    fn token_version_mismatch_is_invalid() {
        let account = account(2);
        assert!(token_version_valid(2, &account));
        assert!(!token_version_valid(1, &account));
    }

    #[test]
    fn legacy_tokens_stay_valid_at_version_zero() {
        // Accounts never bumped (or migrated with the default) accept the
        // version-0 claims that pre-revocation releases minted.
        let account = account(0);
        assert!(token_version_valid(0, &account));
    }
}
