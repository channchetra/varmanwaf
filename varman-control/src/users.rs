//! Shared write rules for dashboard accounts.
//!
//! Accounts are created and passwords reset from three places: the REST API
//! ([`crate::api::auth`], [`crate::api::users`]), the administrator seed at
//! boot ([`crate::seed_admin`]) and the `varman user` maintenance commands.
//! Address normalization, bcrypt hashing, the forced-change flag and the
//! token-version bump live here so those callers cannot drift apart.

use std::fmt;

use chrono::{DateTime, Utc};
use sea_orm::{ActiveModelTrait, ConnectionTrait, DbErr, EntityTrait, Set};
use uuid::Uuid;

use crate::auth::password::{hash_password, PasswordError};
use crate::email::{normalize_email, InvalidEmail};
use crate::models::{role, user};

/// Failure of a shared account write.
///
/// The REST handlers map this onto [`crate::api::error::ApiError`] and the
/// maintenance CLI onto `anyhow`; the variants only name what those callers
/// have to distinguish.
#[derive(Debug)]
pub enum UserWriteError {
    /// The address is not structurally valid.
    InvalidEmail(InvalidEmail),
    /// The plaintext cannot be hashed (too short or a bcrypt failure).
    Password(PasswordError),
    /// The role is not `admin`, `auditor` or `viewer`.
    UnknownRole(String),
    /// No account row has this id.
    NotFound(Uuid),
    /// PostgreSQL rejected the write.
    Database(DbErr),
}

impl fmt::Display for UserWriteError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidEmail(err) => write!(f, "{err}"),
            Self::Password(err) => write!(f, "{err}"),
            Self::UnknownRole(role_name) => {
                write!(f, "unknown role '{role_name}'")
            },
            Self::NotFound(id) => write!(f, "user {id} not found"),
            Self::Database(err) => write!(f, "{err}"),
        }
    }
}

impl std::error::Error for UserWriteError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::InvalidEmail(err) => Some(err),
            Self::Password(err) => Some(err),
            Self::Database(err) => Some(err),
            Self::UnknownRole(_) | Self::NotFound(_) => None,
        }
    }
}

/// Creates an enabled account with a hashed password.
///
/// The address is normalized with [`crate::email::normalize_email`], so the
/// caller may pass it as typed. `must_change_password` stays per caller: the
/// administrator-created account, the seeded administrator and the maintenance
/// CLI force a replacement at first sign-in, while self-registration passes
/// `false` because the holder chose the password.
pub async fn create_user(
    db: &impl ConnectionTrait,
    email: &str,
    password: &str,
    role_name: &str,
    name: Option<String>,
    must_change_password: bool,
) -> Result<user::Model, UserWriteError> {
    new_user(email, password, role_name, name, must_change_password)?
        .insert(db)
        .await
        .map_err(UserWriteError::Database)
}

/// Builds the row [`create_user`] inserts, before it is written.
fn new_user(
    email: &str,
    password: &str,
    role_name: &str,
    name: Option<String>,
    must_change_password: bool,
) -> Result<user::ActiveModel, UserWriteError> {
    if !role::is_valid(role_name) {
        return Err(UserWriteError::UnknownRole(role_name.to_string()));
    }
    let email = normalize_email(email).map_err(UserWriteError::InvalidEmail)?;
    let password_hash =
        hash_password(password).map_err(UserWriteError::Password)?;
    let timestamp = Utc::now();
    Ok(user::ActiveModel {
        id: Set(Uuid::new_v4()),
        email: Set(email),
        password_hash: Set(password_hash),
        name: Set(name),
        role: Set(role_name.to_string()),
        disabled: Set(false),
        must_change_password: Set(must_change_password),
        token_version: Set(0),
        created_at: Set(timestamp),
        updated_at: Set(timestamp),
    })
}

/// Replaces an account's password with an administrator-chosen one.
///
/// This is the reset rule shared by the REST reset route and
/// `varman user reset-password`: the account must replace the password at the
/// next sign-in and every token minted before the reset is revoked, the
/// account's own sessions included. Self-service changes deliberately do not
/// use this function — the holder chose the new secret, so that path clears
/// the forced-change flag instead.
pub async fn set_password(
    db: &impl ConnectionTrait,
    user_id: Uuid,
    password: &str,
) -> Result<user::Model, UserWriteError> {
    let row = user::Entity::find_by_id(user_id)
        .one(db)
        .await
        .map_err(UserWriteError::Database)?
        .ok_or(UserWriteError::NotFound(user_id))?;
    let password_hash =
        hash_password(password).map_err(UserWriteError::Password)?;
    password_reset(row, password_hash, Utc::now())
        .update(db)
        .await
        .map_err(UserWriteError::Database)
}

/// Applies the credential invalidation of a password reset to `row`.
fn password_reset(
    row: user::Model,
    password_hash: String,
    now: DateTime<Utc>,
) -> user::ActiveModel {
    let token_version = row.token_version + 1;
    let mut active: user::ActiveModel = row.into();
    active.password_hash = Set(password_hash);
    active.must_change_password = Set(true);
    active.token_version = Set(token_version);
    active.updated_at = Set(now);
    active
}

#[cfg(test)]
mod tests {
    use std::collections::{BTreeMap, VecDeque};
    use std::sync::{Arc, Mutex};

    use sea_orm::{
        Database, DatabaseBackend, DatabaseConnection, DbErr, IdenStatic,
        Iterable, ModelTrait, ProxyDatabaseTrait, ProxyExecResult, ProxyRow,
        Statement, Value,
    };

    use super::*;
    use crate::auth::password::verify_password;

    fn account(created_at: DateTime<Utc>, token_version: i64) -> user::Model {
        user::Model {
            id: Uuid::new_v4(),
            email: "ops@example.com".to_string(),
            password_hash: "old-hash".to_string(),
            name: None,
            role: role::ADMIN.to_string(),
            disabled: false,
            must_change_password: false,
            token_version,
            created_at,
            updated_at: created_at,
        }
    }

    fn encode_row<M>(model: &M) -> ProxyRow
    where
        M: ModelTrait,
    {
        let values = <<M::Entity as EntityTrait>::Column as Iterable>::iter()
            .map(|column| (column.as_str().to_string(), model.get(column)))
            .collect::<BTreeMap<String, Value>>();
        ProxyRow::new(values)
    }

    /// The string parameters of a statement, in column order.
    fn string_values(statement: &Statement) -> Vec<String> {
        statement
            .values
            .as_ref()
            .map(|values| {
                values
                    .iter()
                    .filter_map(|value| match value {
                        Value::String(Some(text)) => Some((**text).clone()),
                        _ => None,
                    })
                    .collect()
            })
            .unwrap_or_default()
    }

    /// Answers queued reads in order and records every statement.
    #[derive(Debug)]
    struct RecordingQueue {
        batches: Mutex<VecDeque<Vec<ProxyRow>>>,
        statements: Arc<Mutex<Vec<Statement>>>,
    }

    #[async_trait::async_trait]
    impl ProxyDatabaseTrait for RecordingQueue {
        async fn query(
            &self,
            statement: Statement,
        ) -> Result<Vec<ProxyRow>, DbErr> {
            self.statements
                .lock()
                .expect("statement log")
                .push(statement);
            self.batches
                .lock()
                .expect("query queue")
                .pop_front()
                .ok_or_else(|| {
                    DbErr::Custom("no queued query result".to_string())
                })
        }

        async fn execute(
            &self,
            statement: Statement,
        ) -> Result<ProxyExecResult, DbErr> {
            self.statements
                .lock()
                .expect("statement log")
                .push(statement);
            Ok(ProxyExecResult::new(0, 0))
        }
    }

    async fn database(
        batches: Vec<Vec<ProxyRow>>,
    ) -> (DatabaseConnection, Arc<Mutex<Vec<Statement>>>) {
        let statements = Arc::new(Mutex::new(Vec::new()));
        let queue = RecordingQueue {
            batches: Mutex::new(batches.into()),
            statements: Arc::clone(&statements),
        };
        let db = Database::connect_proxy(
            DatabaseBackend::Postgres,
            Arc::new(Box::new(queue)),
        )
        .await
        .expect("the proxy connection cannot fail");
        (db, statements)
    }

    #[test]
    fn creation_normalizes_the_address_and_hashes_the_password() {
        let active = new_user(
            "  Ops@Example.COM ",
            "correct horse battery",
            role::AUDITOR,
            Some("Ops".to_string()),
            true,
        )
        .expect("valid input");

        assert_eq!(active.email.unwrap(), "ops@example.com");
        assert!(verify_password(
            "correct horse battery",
            &active.password_hash.unwrap()
        )
        .unwrap());
        assert_eq!(active.role.unwrap(), role::AUDITOR);
        assert_eq!(active.name.unwrap(), Some("Ops".to_string()));
        assert!(active.must_change_password.unwrap());
        assert!(!active.disabled.unwrap());
        assert_eq!(active.token_version.unwrap(), 0);
        assert_eq!(active.created_at.unwrap(), active.updated_at.unwrap());
    }

    #[test]
    fn an_unknown_role_is_rejected() {
        let err = new_user(
            "ops@example.com",
            "correct horse battery",
            "root",
            None,
            false,
        )
        .unwrap_err();
        assert!(
            matches!(err, UserWriteError::UnknownRole(ref role) if role == "root")
        );
    }

    #[test]
    fn a_short_password_is_rejected() {
        let err =
            new_user("ops@example.com", "short", role::VIEWER, None, false)
                .unwrap_err();
        assert!(matches!(err, UserWriteError::Password(_)));
    }

    #[tokio::test]
    async fn reset_hashes_the_password_and_revokes_tokens() {
        let created_at = Utc::now();
        let existing = account(created_at, 7);
        let reset = account(created_at, 8);
        let (db, statements) = database(vec![
            vec![encode_row(&existing)],
            vec![encode_row(&reset)],
        ])
        .await;

        set_password(&db, existing.id, "correct horse battery")
            .await
            .expect("the reset must succeed");

        let statements = statements.lock().expect("statement log");
        let update = statements
            .iter()
            .find(|statement| statement.sql.starts_with("UPDATE \"users\""))
            .expect("the reset must update the users table");
        let values = update.values.as_ref().expect("update values");

        let hash = string_values(update)
            .into_iter()
            .find(|value| value.starts_with("$2"))
            .expect("the new bcrypt hash is written");
        assert!(
            verify_password("correct horse battery", &hash).unwrap(),
            "the stored hash must verify the new password"
        );
        assert!(values.iter().any(|value| *value == Value::Bool(Some(true))));
        assert!(
            values.iter().any(|value| *value == Value::BigInt(Some(8))),
            "the reset must bump token_version"
        );
        let updated_at = values
            .iter()
            .find_map(|value| match value {
                Value::ChronoDateTimeUtc(Some(instant)) => Some(**instant),
                _ => None,
            })
            .expect("the reset must write updated_at");
        assert!(updated_at > created_at);
    }
}
