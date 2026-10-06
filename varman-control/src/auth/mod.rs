//! Authentication and authorisation primitives: JWT minting/verification,
//! bcrypt password hashing and the Axum extractors that enforce both.

pub mod jwt;
pub mod middleware;
pub mod password;

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
