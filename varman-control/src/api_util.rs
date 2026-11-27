//! Database and query helpers shared by the REST API, the MCP tool registry
//! and the control-plane services.
//!
//! The [`crate::api`] modules re-export these so the handlers and existing
//! callers keep their historical paths; code that is not an HTTP handler
//! imports them from here.

use chrono::Utc;
use sea_orm::{
    ColumnTrait, ConnectionTrait, DatabaseConnection, EntityTrait, QueryFilter,
    Statement,
};
use uuid::Uuid;

use crate::app_state::AppState;
use crate::error::ApiError;
use crate::models::site;

/// Parses a path/query UUID with a 400 instead of a 500.
pub fn parse_uuid(value: &str, what: &str) -> Result<Uuid, ApiError> {
    Uuid::parse_str(value.trim()).map_err(|err| {
        ApiError::BadRequest(format!("invalid {what} '{value}': {err}"))
    })
}

/// Runs a parameterised read-only statement.
pub async fn query_all(
    db: &DatabaseConnection,
    sql: &str,
    values: Vec<sea_orm::Value>,
) -> Result<Vec<sea_orm::QueryResult>, ApiError> {
    db.query_all(Statement::from_sql_and_values(
        sea_orm::DatabaseBackend::Postgres,
        sql,
        values,
    ))
    .await
    .map_err(ApiError::from)
}

/// Escapes LIKE metacharacters so a user-supplied value matches literally.
pub(crate) fn escape_like(value: &str) -> String {
    let mut escaped = String::with_capacity(value.len());
    for ch in value.chars() {
        if matches!(ch, '\\' | '%' | '_') {
            escaped.push('\\');
        }
        escaped.push(ch);
    }
    escaped
}

/// Updates `sites.updated_at` so agents see a fresh configuration fingerprint.
pub async fn touch_site(
    state: &AppState,
    site_id: Uuid,
) -> Result<(), ApiError> {
    site::Entity::update_many()
        .col_expr(
            site::Column::UpdatedAt,
            sea_orm::sea_query::Expr::value(Utc::now()),
        )
        .filter(site::Column::Id.eq(site_id))
        .exec(&state.db)
        .await?;
    Ok(())
}
