//! Axum extractors that turn a `Authorization: Bearer <jwt>` header into an
//! [`AuthUser`], plus role helpers used by the write endpoints.

use axum::extract::{FromRef, FromRequestParts};
use axum::http::header::AUTHORIZATION;
use axum::http::request::Parts;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use uuid::Uuid;

use crate::api::error::error_response;
use crate::api::state::AppState;
use crate::auth::jwt::{verify_user_token, Claims, JwtError};
use crate::models::role;

/// Scheme prefix accepted in the `Authorization` header.
const BEARER_PREFIX: &str = "Bearer ";

/// Identity of the caller behind a request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthUser {
    pub id: Uuid,
    pub email: String,
    pub role: String,
}

impl AuthUser {
    pub fn new(
        id: Uuid,
        email: impl Into<String>,
        role: impl Into<String>,
    ) -> Self {
        Self {
            id,
            email: email.into(),
            role: role.into(),
        }
    }

    pub fn is_admin(&self) -> bool {
        self.role == role::ADMIN
    }

    /// Fails with `403` unless the caller is an administrator.
    pub fn require_admin(&self) -> Result<(), AuthError> {
        if self.is_admin() {
            Ok(())
        } else {
            Err(AuthError::Forbidden(
                "administrator role required".to_string(),
            ))
        }
    }
}

impl From<&Claims> for AuthUser {
    fn from(claims: &Claims) -> Self {
        AuthUser {
            // Already validated by `from_request_parts` before we get here.
            id: claims.subject_id().unwrap_or_else(|_| Uuid::nil()),
            email: claims.email.clone(),
            role: claims.role.clone(),
        }
    }
}

/// Rejection returned by [`AuthUser`]; always renders as `401`/`403`.
#[derive(Debug)]
pub enum AuthError {
    /// No `Authorization` header at all.
    MissingCredentials,
    /// Header present but not a `Bearer` token.
    MalformedCredentials,
    /// Signature/claims problem.
    InvalidToken(String),
    /// `exp` in the past.
    ExpiredToken,
    /// Valid identity, insufficient role.
    Forbidden(String),
}

impl std::fmt::Display for AuthError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AuthError::MissingCredentials => {
                f.write_str("missing authorization header")
            },
            AuthError::MalformedCredentials => {
                f.write_str("authorization header must use the Bearer scheme")
            },
            AuthError::InvalidToken(msg) => write!(f, "invalid token: {msg}"),
            AuthError::ExpiredToken => f.write_str("token expired"),
            AuthError::Forbidden(msg) => write!(f, "forbidden: {msg}"),
        }
    }
}

impl std::error::Error for AuthError {}

impl AuthError {
    fn code(&self) -> &'static str {
        match self {
            AuthError::Forbidden(_) => "forbidden",
            AuthError::ExpiredToken => "token_expired",
            _ => "unauthorized",
        }
    }

    fn status(&self) -> StatusCode {
        match self {
            AuthError::Forbidden(_) => StatusCode::FORBIDDEN,
            _ => StatusCode::UNAUTHORIZED,
        }
    }
}

impl From<JwtError> for AuthError {
    fn from(err: JwtError) -> Self {
        match err {
            JwtError::Expired => AuthError::ExpiredToken,
            other => AuthError::InvalidToken(other.to_string()),
        }
    }
}

impl From<AuthError> for crate::api::error::ApiError {
    fn from(err: AuthError) -> Self {
        match err {
            AuthError::Forbidden(msg) => {
                crate::api::error::ApiError::Forbidden(msg)
            },
            other => {
                crate::api::error::ApiError::Unauthorized(other.to_string())
            },
        }
    }
}

impl IntoResponse for AuthError {
    fn into_response(self) -> Response {
        let status = self.status();
        let code = self.code();
        let mut response = error_response(status, code, &self.to_string());
        // RFC 6750: tell the client which scheme we expect.
        response.headers_mut().insert(
            axum::http::header::WWW_AUTHENTICATE,
            axum::http::HeaderValue::from_static(
                "Bearer realm=\"pingwaf\", error=\"invalid_token\"",
            ),
        );
        response
    }
}

/// Pulls the raw bearer token out of the request headers.
pub fn bearer_token(parts: &Parts) -> Result<String, AuthError> {
    let header = parts
        .headers
        .get(AUTHORIZATION)
        .ok_or(AuthError::MissingCredentials)?;
    let value = header
        .to_str()
        .map_err(|_| AuthError::MalformedCredentials)?
        .trim();
    let token = value
        .strip_prefix(BEARER_PREFIX)
        .or_else(|| value.strip_prefix("bearer "))
        .ok_or(AuthError::MalformedCredentials)?
        .trim();
    if token.is_empty() {
        return Err(AuthError::MalformedCredentials);
    }
    Ok(token.to_string())
}

impl<S> FromRequestParts<S> for AuthUser
where
    S: Send + Sync,
    AppState: FromRef<S>,
{
    type Rejection = AuthError;

    async fn from_request_parts(
        parts: &mut Parts,
        state: &S,
    ) -> Result<Self, Self::Rejection> {
        let app_state = AppState::from_ref(state);
        let token = bearer_token(parts)?;
        let claims = verify_user_token(&token, app_state.jwt_secret())?;
        let id = claims.subject_id().map_err(|err| {
            AuthError::InvalidToken(format!("subject is not a UUID: {err}"))
        })?;
        if !role::is_valid(&claims.role) {
            return Err(AuthError::InvalidToken(format!(
                "unknown role '{}'",
                claims.role
            )));
        }
        Ok(AuthUser {
            id,
            email: claims.email.clone(),
            role: claims.role.clone(),
        })
    }
}

/// Extractor that additionally enforces the `admin` role.
#[derive(Debug, Clone)]
pub struct AdminUser(pub AuthUser);

impl AdminUser {
    pub fn id(&self) -> Uuid {
        self.0.id
    }
}

impl<S> FromRequestParts<S> for AdminUser
where
    S: Send + Sync,
    AppState: FromRef<S>,
{
    type Rejection = AuthError;

    async fn from_request_parts(
        parts: &mut Parts,
        state: &S,
    ) -> Result<Self, Self::Rejection> {
        let user = AuthUser::from_request_parts(parts, state).await?;
        user.require_admin()?;
        Ok(AdminUser(user))
    }
}

impl std::ops::Deref for AdminUser {
    type Target = AuthUser;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn admin_check_rejects_viewers() {
        let viewer =
            AuthUser::new(Uuid::new_v4(), "v@example.com", role::VIEWER);
        assert!(!viewer.is_admin());
        assert!(viewer.require_admin().is_err());

        let admin = AuthUser::new(Uuid::new_v4(), "a@example.com", role::ADMIN);
        assert!(admin.is_admin());
        assert!(admin.require_admin().is_ok());
    }

    #[test]
    fn error_statuses() {
        assert_eq!(
            AuthError::MissingCredentials.status(),
            StatusCode::UNAUTHORIZED
        );
        assert_eq!(AuthError::ExpiredToken.status(), StatusCode::UNAUTHORIZED);
        assert_eq!(
            AuthError::Forbidden("nope".into()).status(),
            StatusCode::FORBIDDEN
        );
    }
}
