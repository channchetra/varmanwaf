//! API key format and identification shared by every transport.
//!
//! Agents (gRPC), the hosted MCP endpoint and the REST API all authenticate a
//! presented `pwk_…` key the same way: the visible prefix narrows the candidate
//! rows, then each candidate is bcrypt-verified. The naming conventions of the
//! keys the system mints itself (bootstrap, agent enrollment) live here too, so
//! the HTTP layer, the gRPC plane and the MCP surface depend on the crate root
//! instead of on each other.

use chrono::Utc;
use sea_orm::{
    ActiveModelTrait, ColumnTrait, DatabaseConnection, EntityTrait,
    QueryFilter, Set,
};
use uuid::Uuid;

use crate::auth::password::verify_password;
use crate::error::ApiError;
use crate::models::{api_key, permission, role, user};

/// Human visible prefix length, matching the `key_prefix` column width.
pub const KEY_PREFIX_LENGTH: usize = 8;

/// Name of the all-in-one bootstrap key seeded at startup (`lib.rs`).
pub const BOOTSTRAP_KEY_NAME: &str = "_all-in-one-bootstrap";
/// Name prefix of the enrollment keys minted by `POST /agents/enroll`.
pub const AGENT_ENROLLMENT_PREFIX: &str = "agent-enrollment-";

/// True for keys the system mints on its own (bootstrap, agent enrollment).
/// The UI shows these as "system" instead of a creator account, and guards
/// their deletion: revoking them strands agent (re-)registration until a new
/// key is minted.
pub fn is_system_key(name: &str) -> bool {
    name == BOOTSTRAP_KEY_NAME || name.starts_with(AGENT_ENROLLMENT_PREFIX)
}

/// Generates a `pwk_…` key with 128 bits of entropy from two UUIDv4 payloads.
pub fn generate_key() -> String {
    format!("pwk_{}{}", Uuid::new_v4().simple(), Uuid::new_v4().simple())
}

/// First `KEY_PREFIX_LENGTH` bytes of a presented key, when they are a valid
/// ASCII prefix.
///
/// `RegisterAgent` is unauthenticated, so a key with a multi-byte character on
/// the prefix boundary must be rejected rather than panicking while slicing.
/// Release builds abort on panic, which would let one request stop the
/// control plane.
fn key_prefix(raw: &str) -> Option<&str> {
    let raw = raw.trim();
    let prefix = raw.get(..KEY_PREFIX_LENGTH)?;
    prefix.is_ascii().then_some(prefix)
}

/// Resolves a raw API key to the key row and its owning user.
///
/// The key prefix narrows the candidate set (it is indexed) and each candidate is
/// then bcrypt-verified, which keeps the lookup constant-ish time and avoids
/// storing the plaintext or a reversible digest.
pub async fn authenticate_api_key(
    db: &DatabaseConnection,
    raw_key: &str,
) -> Result<(api_key::Model, user::Model), ApiError> {
    let raw_key = raw_key.trim();
    let Some(prefix) = key_prefix(raw_key) else {
        return Err(ApiError::Unauthorized("invalid API key".to_string()));
    };

    let candidates = api_key::Entity::find()
        .filter(api_key::Column::KeyPrefix.eq(prefix))
        .all(db)
        .await?;

    for candidate in candidates {
        let matches = verify_password(raw_key, &candidate.key_hash)
            .map_err(|err| ApiError::Internal(err.to_string()))?;
        if !matches {
            continue;
        }
        if let Some(expires_at) = candidate.expires_at {
            if expires_at <= Utc::now() {
                tracing::warn!(key_id = %candidate.id, "expired API key presented");
                return Err(ApiError::Unauthorized(
                    "API key has expired".to_string(),
                ));
            }
        }

        let owner = user::Entity::find_by_id(candidate.user_id)
            .one(db)
            .await?
            .ok_or_else(|| {
                ApiError::Unauthorized(
                    "API key owner no longer exists".to_string(),
                )
            })?;
        if owner.disabled {
            return Err(ApiError::Unauthorized(
                "API key owner is disabled".to_string(),
            ));
        }
        if !role::is_valid(&owner.role) {
            return Err(ApiError::Unauthorized(
                "API key owner has an unknown role".to_string(),
            ));
        }

        // Record usage without failing the request when the write races.
        let mut touched: api_key::ActiveModel = candidate.clone().into();
        touched.last_used_at = Set(Some(Utc::now()));
        if let Err(err) = touched.update(db).await {
            tracing::warn!(error = %err, key_id = %candidate.id, "could not record key usage");
        }

        return Ok((candidate, owner));
    }

    Err(ApiError::Unauthorized("invalid API key".to_string()))
}

/// True when the key is allowed to register agents and ship telemetry.
///
/// Permissions are an explicit allow-list: the key must carry the `agent`
/// permission. Keys minted before this check with an empty permission list are
/// no longer allowed to enrol agents and must be re-granted the permission.
pub fn key_allows_agent(key: &api_key::Model) -> bool {
    key.permissions.iter().any(|p| p == permission::AGENT)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generated_keys_have_a_stable_prefix() {
        let key = generate_key();
        assert!(key.starts_with("pwk_"));
        assert_eq!(key.len(), 4 + 64);
        assert_eq!(key[..KEY_PREFIX_LENGTH].len(), KEY_PREFIX_LENGTH);
        assert_ne!(generate_key(), key);
    }

    #[test]
    fn system_keys_are_recognised_by_name_convention() {
        assert!(is_system_key("_all-in-one-bootstrap"));
        assert!(is_system_key("agent-enrollment-20261012-091500"));
        // Ordinary operator-chosen names are not system keys, even when they
        // flirt with the conventions.
        assert!(!is_system_key("agent-enrollment"));
        assert!(!is_system_key("bootstrap"));
        assert!(!is_system_key("ci-deploy"));
        assert!(!is_system_key(""));
    }

    #[test]
    fn agent_permission_check() {
        let key = api_key::Model {
            id: Uuid::new_v4(),
            user_id: Uuid::new_v4(),
            name: "agent".into(),
            key_hash: String::new(),
            key_prefix: "pwk_abcd".into(),
            permissions: vec![permission::AGENT.to_string()],
            expires_at: None,
            last_used_at: None,
            created_at: Utc::now(),
        };
        assert!(key_allows_agent(&key));

        let mut read_only = key.clone();
        read_only.permissions = vec![permission::READ.to_string()];
        assert!(!key_allows_agent(&read_only));

        let mut empty = key.clone();
        empty.permissions = Vec::new();
        // Empty permissions must not imply `agent`; legacy keys have to be
        // re-granted explicitly.
        assert!(!key_allows_agent(&empty));
    }

    #[test]
    fn malformed_key_prefixes_are_rejected_without_panicking() {
        let key = generate_key();
        assert_eq!(key_prefix(&key), Some(&key[..KEY_PREFIX_LENGTH]));
        assert_eq!(key_prefix("short"), None);
        // Byte 8 falls inside a multi-byte character: slicing would panic.
        assert_eq!(key_prefix("aéééé"), None);
        // A valid UTF-8 boundary is still rejected unless it is ASCII.
        assert_eq!(key_prefix("ééééé"), None);
    }
}
