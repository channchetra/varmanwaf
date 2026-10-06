//! API protection settings and the control plane's own access log.
//!
//! The dashboard edits the 9080 listener's self-protection from here: the
//! access-log switch and retention, the IP allowlist (inline ranges plus an
//! optional `ip_groups` reference) and the control plane WAF. Every write
//! rebuilds the in-process policy at once, so the change applies to the next
//! request instead of waiting for the background refresh.
//!
//! A write that would enable the allowlist without covering the caller's own
//! connection is refused unless `force` is set — a console that locks out the
//! person holding it is worse than a warning.

use axum::extract::connect_info::ConnectInfo;
use axum::extract::{Query, State};
use axum::routing::get;
use axum::Router;
use axum::{Extension, Json};
use chrono::Utc;
use sea_orm::{
    ActiveModelTrait, ColumnTrait, EntityTrait, PaginatorTrait, QueryFilter,
    QueryOrder, Set, Unchanged,
};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::api::common::{non_empty, Page, Pagination};
use crate::api::error::ApiError;
use crate::api::logs::{free_text_filter, resolve_window, text_filter};
use crate::api::self_protection;
use crate::api::state::AppState;
use crate::auth::AuthUser;
use crate::models::api_protection::{
    waf_mode, MAX_RETENTION_DAYS, MIN_RETENTION_DAYS,
};
use crate::models::{
    api_protection_setting, control_plane_access_log, ip_groups,
};
use crate::tls::ConnInfo;

/// Routes contributed to `/api/v1`.
pub fn routes() -> Router<AppState> {
    Router::new()
        .route("/settings/api-protection", get(show).put(update))
        .route("/logs/control-plane", get(list_logs))
}

/// The settings row plus what the allowlist currently resolves to.
#[derive(Debug, Serialize)]
pub struct ApiProtectionView {
    #[serde(flatten)]
    pub settings: api_protection_setting::Model,
    /// Entries the effective allowlist holds right now (inline ranges plus the
    /// referenced group); `0` while the allowlist is switched off, since
    /// nothing is enforced then.
    pub effective_allowlist_entries: usize,
}

/// [`ApiProtectionView::effective_allowlist_entries`] for a settings row and
/// its resolved allowlist.
fn effective_entries(
    settings: &api_protection_setting::Model,
    allowlist: &self_protection::Allowlist,
) -> usize {
    if settings.ip_allowlist_enabled {
        allowlist.len()
    } else {
        0
    }
}

#[derive(Debug, Deserialize)]
pub struct UpdateApiProtectionRequest {
    #[serde(default)]
    pub access_log_enabled: Option<bool>,
    #[serde(default)]
    pub access_log_retention_days: Option<i32>,
    #[serde(default)]
    pub ip_allowlist_enabled: Option<bool>,
    #[serde(default)]
    pub ip_allowlist_ranges: Option<Vec<String>>,
    /// Absent or `null` leaves the reference alone; an empty string clears it;
    /// a UUID points the allowlist at that `ip_groups` row.
    #[serde(default, deserialize_with = "deserialize_optional_uuid")]
    pub ip_allowlist_group_id: Option<Option<Uuid>>,
    #[serde(default)]
    pub waf_enabled: Option<bool>,
    #[serde(default)]
    pub waf_mode: Option<String>,
    /// Applies a change even though it would exclude this connection from the
    /// allowlist. Without it the API refuses the lockout.
    #[serde(default)]
    pub force: bool,
}

/// Distinguishes "leave unchanged" (absent / `null`) from "clear" (empty
/// string), which a plain `Option<Uuid>` cannot express.
fn deserialize_optional_uuid<'de, D>(
    deserializer: D,
) -> Result<Option<Option<Uuid>>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    use serde::de::Error;

    let value = Option::<String>::deserialize(deserializer)?;
    match value {
        None => Ok(None),
        Some(raw) if raw.trim().is_empty() => Ok(Some(None)),
        Some(raw) => Uuid::parse_str(raw.trim())
            .map(|id| Some(Some(id)))
            .map_err(D::Error::custom),
    }
}

/// Converts a merged row into an [`api_protection_setting::ActiveModel`] that
/// writes every column.
///
/// The plain `ActiveModel::from(model)` conversion marks every field
/// `Unchanged`, and SeaORM only writes the columns explicitly marked `Set`:
/// with just `updated_at` set, a save would discard every edited switch while
/// answering `Ok`. [`the_model_writer_marks_every_column_for_writing`] fails
/// when a future column is added without updating this function.
fn writable(
    row: api_protection_setting::Model,
) -> api_protection_setting::ActiveModel {
    api_protection_setting::ActiveModel {
        id: Unchanged(row.id),
        access_log_enabled: Set(row.access_log_enabled),
        access_log_retention_days: Set(row.access_log_retention_days),
        ip_allowlist_enabled: Set(row.ip_allowlist_enabled),
        ip_allowlist_ranges: Set(row.ip_allowlist_ranges),
        ip_allowlist_group_id: Set(row.ip_allowlist_group_id),
        waf_enabled: Set(row.waf_enabled),
        waf_mode: Set(row.waf_mode),
        updated_at: Set(row.updated_at),
    }
}

/// `GET /api/v1/settings/api-protection` — administrators only.
async fn show(
    State(state): State<AppState>,
    current: AuthUser,
) -> Result<Json<ApiProtectionView>, ApiError> {
    current.require_admin().map_err(ApiError::from)?;
    let settings = self_protection::load_settings(&state.db).await?;
    let allowlist =
        self_protection::effective_allowlist(&state.db, &settings).await?;
    let entries = effective_entries(&settings, &allowlist);
    Ok(Json(ApiProtectionView {
        settings,
        effective_allowlist_entries: entries,
    }))
}

/// `PUT /api/v1/settings/api-protection` — administrators only.
async fn update(
    State(state): State<AppState>,
    current: AuthUser,
    peer: Option<Extension<ConnectInfo<ConnInfo>>>,
    Json(payload): Json<UpdateApiProtectionRequest>,
) -> Result<Json<ApiProtectionView>, ApiError> {
    current.require_admin().map_err(ApiError::from)?;

    let row = self_protection::load_settings(&state.db).await?;
    let mut prospective = row;

    if let Some(enabled) = payload.access_log_enabled {
        prospective.access_log_enabled = enabled;
    }
    if let Some(days) = payload.access_log_retention_days {
        if !(MIN_RETENTION_DAYS..=MAX_RETENTION_DAYS).contains(&days) {
            return Err(ApiError::BadRequest(format!(
                "access log retention must be between {MIN_RETENTION_DAYS} and {MAX_RETENTION_DAYS} days"
            )));
        }
        prospective.access_log_retention_days = days;
    }
    if let Some(enabled) = payload.ip_allowlist_enabled {
        prospective.ip_allowlist_enabled = enabled;
    }
    if let Some(ranges) = payload.ip_allowlist_ranges {
        let ranges: Vec<String> = ranges
            .into_iter()
            .map(|value| value.trim().to_string())
            .filter(|value| !value.is_empty())
            .collect();
        let (_, invalid) = self_protection::Allowlist::parse(&ranges);
        if !invalid.is_empty() {
            return Err(ApiError::BadRequest(format!(
                "invalid allowlist entries (expected an address or CIDR): {}",
                invalid.join(", ")
            )));
        }
        prospective.ip_allowlist_ranges = ranges;
    }
    if let Some(group_id) = payload.ip_allowlist_group_id {
        if let Some(group_id) = group_id {
            let exists = ip_groups::Entity::find_by_id(group_id)
                .one(&state.db)
                .await?;
            if exists.is_none() {
                return Err(ApiError::BadRequest(format!(
                    "ip group {group_id} not found"
                )));
            }
        }
        prospective.ip_allowlist_group_id = group_id;
    }
    if let Some(enabled) = payload.waf_enabled {
        prospective.waf_enabled = enabled;
    }
    if let Some(mode) = non_empty(&payload.waf_mode) {
        if !waf_mode::is_valid(&mode) {
            return Err(ApiError::BadRequest(format!(
                "waf_mode must be '{}' or '{}'",
                waf_mode::BLOCK,
                waf_mode::MONITOR
            )));
        }
        prospective.waf_mode = mode;
    }

    // Lockout guard: enabling the allowlist (or narrowing it) must not cut off
    // the very connection editing it, unless the operator insists.
    if prospective.ip_allowlist_enabled && !payload.force {
        let allowlist =
            self_protection::effective_allowlist(&state.db, &prospective)
                .await?;
        let caller_ip = peer.map(|Extension(info)| info.0.peer_addr.ip());
        match caller_ip {
            Some(ip) if allowlist.contains(&ip) => {},
            Some(ip) => {
                return Err(ApiError::Unprocessable(format!(
                    "the new allowlist does not include your address ({ip}); add it first, or send force=true to apply anyway"
                )));
            },
            None => {
                return Err(ApiError::Unprocessable(
                    "cannot verify that the new allowlist includes this connection; send force=true to apply anyway"
                        .to_string(),
                ));
            },
        }
    }

    let mut active = writable(prospective);
    active.updated_at = Set(Utc::now());
    let updated = active.update(&state.db).await?;

    // Apply at once; the background refresh would pick this up within its
    // interval, but a security switch should not lag.
    let policy = self_protection::refresh(&state.db).await?;
    state.protection.store(policy);

    tracing::info!(
        actor = %current.id,
        access_log_enabled = updated.access_log_enabled,
        allowlist_enabled = updated.ip_allowlist_enabled,
        allowlist_ranges = updated.ip_allowlist_ranges.len(),
        waf_enabled = updated.waf_enabled,
        waf_mode = %updated.waf_mode,
        "api protection settings updated"
    );

    let allowlist =
        self_protection::effective_allowlist(&state.db, &updated).await?;
    let entries = effective_entries(&updated, &allowlist);
    Ok(Json(ApiProtectionView {
        settings: updated,
        effective_allowlist_entries: entries,
    }))
}

/// Filters accepted by the control plane log listing.
#[derive(Debug, Deserialize)]
pub struct ControlPlaneLogQuery {
    #[serde(flatten)]
    pub pagination: Pagination,
    pub from: Option<String>,
    pub to: Option<String>,
    pub client_ip: Option<String>,
    pub method: Option<String>,
    pub action: Option<String>,
    pub status_code: Option<i32>,
    pub path: Option<String>,
    pub host: Option<String>,
    pub request_id: Option<String>,
    /// Free-text search over the path and host (OR).
    pub q: Option<String>,
}

/// `GET /api/v1/logs/control-plane` — administrators only; the log is
/// cross-tenant by nature and has no site column to scope it by.
async fn list_logs(
    State(state): State<AppState>,
    current: AuthUser,
    Query(query): Query<ControlPlaneLogQuery>,
) -> Result<Json<Page<control_plane_access_log::Model>>, ApiError> {
    current.require_admin().map_err(ApiError::from)?;
    let (from, to) = resolve_window(&query.from, &query.to)?;
    let pagination = query.pagination.normalise();

    let mut condition = sea_orm::Condition::all()
        .add(control_plane_access_log::Column::Timestamp.gte(from))
        .add(control_plane_access_log::Column::Timestamp.lt(to));

    if let Some(ip) = non_empty(&query.client_ip) {
        condition = condition
            .add(text_filter(control_plane_access_log::Column::ClientIp, &ip));
    }
    if let Some(method) = non_empty(&query.method) {
        condition = condition.add(text_filter(
            control_plane_access_log::Column::Method,
            &method.to_uppercase(),
        ));
    }
    if let Some(action) = non_empty(&query.action) {
        condition = condition.add(text_filter(
            control_plane_access_log::Column::Action,
            &action,
        ));
    }
    if let Some(status) = query.status_code {
        if !(100..=599).contains(&status) {
            return Err(ApiError::BadRequest(
                "status_code must be between 100 and 599".to_string(),
            ));
        }
        condition = condition
            .add(control_plane_access_log::Column::StatusCode.eq(status));
    }
    if let Some(path) = non_empty(&query.path) {
        condition = condition
            .add(control_plane_access_log::Column::Path.contains(path));
    }
    if let Some(host) = non_empty(&query.host) {
        condition = condition
            .add(text_filter(control_plane_access_log::Column::Host, &host));
    }
    if let Some(request_id) = non_empty(&query.request_id) {
        condition = condition
            .add(control_plane_access_log::Column::RequestId.eq(request_id));
    }
    if let Some(q) = non_empty(&query.q) {
        condition = condition.add(free_text_filter(
            control_plane_access_log::Column::Path,
            control_plane_access_log::Column::Host,
            &q,
        ));
    }

    let paginator = control_plane_access_log::Entity::find()
        .filter(condition)
        .order_by_desc(control_plane_access_log::Column::Timestamp)
        .paginate(&state.db, pagination.limit());

    let total = paginator.num_items().await?;
    let rows = paginator.fetch_page(pagination.index()).await?;
    Ok(Json(Page::new(rows, total, pagination)))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn stored() -> api_protection_setting::Model {
        api_protection_setting::Model {
            id: 1,
            access_log_enabled: true,
            access_log_retention_days: 30,
            ip_allowlist_enabled: false,
            ip_allowlist_ranges: vec!["10.0.0.0/8".to_string()],
            ip_allowlist_group_id: None,
            waf_enabled: true,
            waf_mode: waf_mode::BLOCK.to_string(),
            updated_at: Utc::now(),
        }
    }

    #[test]
    fn the_model_writer_marks_every_column_for_writing() {
        // Regression: merging edits into a `Model` and then `.into()`-ing it
        // leaves every field `Unchanged`, so only `updated_at` (the single
        // explicit `Set`) reached the database — every switch the operator
        // flipped was silently discarded. All non-PK columns must be `Set`;
        // this test fails when a new column lands without updating
        // `writable()`.
        use sea_orm::{ActiveValue, Iterable, PrimaryKeyToColumn};

        let active = writable(stored());
        for column in api_protection_setting::Column::iter() {
            if api_protection_setting::PrimaryKey::from_column(column).is_some()
            {
                continue;
            }
            let value = active.get(column);
            assert!(
                matches!(value, ActiveValue::Set(_)),
                "column {column:?} is {value:?}: writable() must Set it"
            );
        }
    }

    #[test]
    fn group_reference_distinguishes_absent_null_and_clear() {
        #[derive(Debug, Deserialize)]
        struct Wrapper {
            #[serde(default, deserialize_with = "deserialize_optional_uuid")]
            group: Option<Option<Uuid>>,
        }

        // Absent and `null` both leave the reference alone.
        let parsed: Wrapper = serde_json::from_str("{}").unwrap();
        assert_eq!(parsed.group, None);
        let parsed: Wrapper =
            serde_json::from_str(r#"{"group":null}"#).unwrap();
        assert_eq!(parsed.group, None);

        // An empty string clears it.
        let parsed: Wrapper = serde_json::from_str(r#"{"group":""}"#).unwrap();
        assert_eq!(parsed.group, Some(None));

        // A UUID points at a group.
        let id = Uuid::new_v4();
        let parsed: Wrapper =
            serde_json::from_str(&format!(r#"{{"group":"{id}"}}"#)).unwrap();
        assert_eq!(parsed.group, Some(Some(id)));

        // Garbage is a hard error rather than a silent clear.
        assert!(serde_json::from_str::<Wrapper>(r#"{"group":"nope"}"#).is_err());
    }
}
