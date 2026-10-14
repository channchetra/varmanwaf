//! Security alert rules and silences - `/api/v1/alerts/*`.
//!
//! Rules watch stored security events (see [`crate::alerts`]); the preview
//! endpoint evaluates a rule on demand and reports exactly what the last
//! tick would have seen, without dispatching anything.

use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::routing::{get, post};
use axum::{Json, Router};
use chrono::{DateTime, Utc};
use sea_orm::{
    ActiveModelTrait, ColumnTrait, EntityTrait, QueryFilter, QueryOrder, Set,
};
use serde::{Deserialize, Serialize};
use serde_json::json;
use uuid::Uuid;

use crate::alerts;
use crate::api::common::parse_uuid;
use crate::api::error::ApiError;
use crate::api::state::AppState;
use crate::auth::AuthUser;
use crate::models::alerts::{METRIC_BLOCKED_RATIO, METRICS};
use crate::models::{
    alert_rule, alert_silence, notification_channel, severity, site,
};

/// Routes contributed to `/api/v1`.
pub fn routes() -> Router<AppState> {
    Router::new()
        .route("/alerts/rules", get(list_rules).post(create_rule))
        .route(
            "/alerts/rules/{id}",
            get(show_rule).put(update_rule).delete(delete_rule),
        )
        .route("/alerts/rules/{id}/preview", post(preview_rule))
        .route(
            "/alerts/silences",
            get(list_silences).post(create_silence),
        )
        .route("/alerts/silences/{id}", axum::routing::delete(delete_silence))
}

/// Event types a rule may filter on. Mirrors the vocabulary the agents
/// stamp on shipped events (all WAF decisions currently arrive as `waf`).
pub const EVENT_TYPES: [&str; 6] =
    ["waf", "managed", "ip_geo", "bot", "rate_limit", "challenge"];

fn default_true() -> bool {
    true
}

fn default_cooldown() -> i32 {
    900
}

fn default_severity() -> String {
    severity::WARNING.to_string()
}

#[derive(Debug, Deserialize)]
pub struct RuleRequest {
    pub name: String,
    #[serde(default = "default_true")]
    pub enabled: bool,
    pub metric: String,
    pub threshold: f64,
    pub window_seconds: i32,
    #[serde(default)]
    pub min_samples: i32,
    #[serde(default)]
    pub site_id: Option<Uuid>,
    #[serde(default)]
    pub event_type: String,
    #[serde(default)]
    pub rule_id_contains: String,
    #[serde(default = "default_severity")]
    pub severity: String,
    #[serde(default)]
    pub channels: Vec<Uuid>,
    #[serde(default = "default_cooldown")]
    pub cooldown_seconds: i32,
}

/// Validated rule content, ready to store.
struct ValidatedRule {
    name: String,
    enabled: bool,
    metric: String,
    threshold: f64,
    window_seconds: i32,
    min_samples: i32,
    site_id: Option<Uuid>,
    event_type: String,
    rule_id_contains: String,
    severity: String,
    channels: serde_json::Value,
    cooldown_seconds: i32,
}

async fn validate_rule(
    state: &AppState,
    payload: RuleRequest,
) -> Result<ValidatedRule, ApiError> {
    let name = payload.name.trim().to_string();
    if name.is_empty() || name.chars().count() > 200 {
        return Err(ApiError::bad_request(
            "name must be 1-200 characters",
        ));
    }
    if !METRICS.contains(&payload.metric.as_str()) {
        return Err(ApiError::bad_request(format!(
            "metric must be one of: {}",
            METRICS.join(", ")
        )));
    }
    if !payload.threshold.is_finite() || payload.threshold <= 0.0 {
        return Err(ApiError::bad_request(
            "threshold must be a positive number",
        ));
    }
    if payload.metric == METRIC_BLOCKED_RATIO && payload.threshold > 100.0 {
        return Err(ApiError::bad_request(
            "a blocked-ratio threshold cannot exceed 100",
        ));
    }
    if !(alerts::MIN_WINDOW..=alerts::MAX_WINDOW).contains(&payload.window_seconds)
    {
        return Err(ApiError::bad_request(format!(
            "window_seconds must be between {} and {}",
            alerts::MIN_WINDOW,
            alerts::MAX_WINDOW
        )));
    }
    if !(0..=1_000_000).contains(&payload.min_samples) {
        return Err(ApiError::bad_request(
            "min_samples must be between 0 and 1000000",
        ));
    }
    if payload.metric != METRIC_BLOCKED_RATIO && payload.min_samples != 0 {
        return Err(ApiError::bad_request(
            "min_samples only applies to the blocked_ratio metric; leave it 0",
        ));
    }
    if !(alerts::MIN_COOLDOWN..=alerts::MAX_COOLDOWN)
        .contains(&payload.cooldown_seconds)
    {
        return Err(ApiError::bad_request(format!(
            "cooldown_seconds must be between {} and {}",
            alerts::MIN_COOLDOWN,
            alerts::MAX_COOLDOWN
        )));
    }
    if !severity::ALL.contains(&payload.severity.as_str()) {
        return Err(ApiError::bad_request(format!(
            "severity must be one of: {}",
            severity::ALL.join(", ")
        )));
    }
    let event_type = payload.event_type.trim().to_string();
    if !event_type.is_empty() && !EVENT_TYPES.contains(&event_type.as_str()) {
        return Err(ApiError::bad_request(format!(
            "event_type must be empty or one of: {}",
            EVENT_TYPES.join(", ")
        )));
    }
    let rule_id_contains = payload.rule_id_contains.trim().to_string();
    if rule_id_contains.chars().count() > 64 {
        return Err(ApiError::bad_request(
            "rule_id_contains must be at most 64 characters",
        ));
    }
    if let Some(site_id) = payload.site_id {
        let exists = site::Entity::find_by_id(site_id)
            .one(&state.db)
            .await?
            .is_some();
        if !exists {
            return Err(ApiError::bad_request("site not found"));
        }
    }
    if !payload.channels.is_empty() {
        let found = notification_channel::Entity::find()
            .filter(notification_channel::Column::Id.is_in(payload.channels.clone()))
            .all(&state.db)
            .await?;
        if found.len() != payload.channels.len() {
            return Err(ApiError::bad_request(
                "one or more notification channels do not exist",
            ));
        }
    }

    Ok(ValidatedRule {
        name,
        enabled: payload.enabled,
        metric: payload.metric,
        threshold: payload.threshold,
        window_seconds: payload.window_seconds,
        min_samples: payload.min_samples,
        site_id: payload.site_id,
        event_type,
        rule_id_contains,
        severity: payload.severity,
        channels: json!(payload.channels),
        cooldown_seconds: payload.cooldown_seconds,
    })
}

fn require_admin(current: &AuthUser) -> Result<(), ApiError> {
    current.require_admin().map_err(ApiError::from)
}

async fn list_rules(
    State(state): State<AppState>,
    _current: AuthUser,
) -> Result<Json<Vec<alert_rule::Model>>, ApiError> {
    let rows = alert_rule::Entity::find()
        .order_by_asc(alert_rule::Column::Name)
        .all(&state.db)
        .await?;
    Ok(Json(rows))
}

async fn show_rule(
    State(state): State<AppState>,
    _current: AuthUser,
    Path(id): Path<String>,
) -> Result<Json<alert_rule::Model>, ApiError> {
    let id = parse_uuid(&id, "rule id")?;
    let row = alert_rule::Entity::find_by_id(id)
        .one(&state.db)
        .await?
        .ok_or_else(|| ApiError::not_found("alert rule not found"))?;
    Ok(Json(row))
}

async fn create_rule(
    State(state): State<AppState>,
    current: AuthUser,
    Json(payload): Json<RuleRequest>,
) -> Result<(StatusCode, Json<alert_rule::Model>), ApiError> {
    require_admin(&current)?;
    let validated = validate_rule(&state, payload).await?;
    let now = Utc::now();
    let row = alert_rule::ActiveModel {
        id: Set(Uuid::new_v4()),
        name: Set(validated.name),
        enabled: Set(validated.enabled),
        metric: Set(validated.metric),
        threshold: Set(validated.threshold),
        window_seconds: Set(validated.window_seconds),
        min_samples: Set(validated.min_samples),
        site_id: Set(validated.site_id),
        event_type: Set(validated.event_type),
        rule_id_contains: Set(validated.rule_id_contains),
        severity: Set(validated.severity),
        channels: Set(validated.channels),
        cooldown_seconds: Set(validated.cooldown_seconds),
        last_fired_at: Set(None),
        last_value: Set(None),
        last_samples: Set(None),
        last_evaluated_at: Set(None),
        created_at: Set(now),
        updated_at: Set(now),
    }
    .insert(&state.db)
    .await?;
    tracing::info!(rule = %row.name, actor = %current.email, "alert rule created");
    Ok((StatusCode::CREATED, Json(row)))
}

async fn update_rule(
    State(state): State<AppState>,
    current: AuthUser,
    Path(id): Path<String>,
    Json(payload): Json<RuleRequest>,
) -> Result<Json<alert_rule::Model>, ApiError> {
    require_admin(&current)?;
    let id = parse_uuid(&id, "rule id")?;
    let existing = alert_rule::Entity::find_by_id(id)
        .one(&state.db)
        .await?
        .ok_or_else(|| ApiError::not_found("alert rule not found"))?;
    let validated = validate_rule(&state, payload).await?;
    let mut active: alert_rule::ActiveModel = existing.into();
    active.name = Set(validated.name);
    active.enabled = Set(validated.enabled);
    active.metric = Set(validated.metric);
    active.threshold = Set(validated.threshold);
    active.window_seconds = Set(validated.window_seconds);
    active.min_samples = Set(validated.min_samples);
    active.site_id = Set(validated.site_id);
    active.event_type = Set(validated.event_type);
    active.rule_id_contains = Set(validated.rule_id_contains);
    active.severity = Set(validated.severity);
    active.channels = Set(validated.channels);
    active.cooldown_seconds = Set(validated.cooldown_seconds);
    active.updated_at = Set(Utc::now());
    let row = active.update(&state.db).await?;
    tracing::info!(rule = %row.name, actor = %current.email, "alert rule updated");
    Ok(Json(row))
}

async fn delete_rule(
    State(state): State<AppState>,
    current: AuthUser,
    Path(id): Path<String>,
) -> Result<StatusCode, ApiError> {
    require_admin(&current)?;
    let id = parse_uuid(&id, "rule id")?;
    let row = alert_rule::Entity::find_by_id(id)
        .one(&state.db)
        .await?
        .ok_or_else(|| ApiError::not_found("alert rule not found"))?;
    alert_rule::Entity::delete_by_id(row.id).exec(&state.db).await?;
    tracing::info!(rule = %row.name, actor = %current.email, "alert rule deleted");
    Ok(StatusCode::NO_CONTENT)
}

#[derive(Debug, Serialize)]
pub struct PreviewView {
    pub metric: String,
    pub value: f64,
    pub hits: i64,
    pub samples: i64,
    pub threshold: f64,
    pub min_samples: i32,
    pub window_seconds: i32,
    /// Whether the threshold is met right now (before cooldown/silence).
    pub threshold_met: bool,
    pub silenced: bool,
    pub silence_reason: Option<String>,
    /// Requests are the ratio denominator; stated explicitly so the number
    /// is never mistaken for something else.
    pub samples_basis: &'static str,
    pub evaluated_at: DateTime<Utc>,
}

/// `POST /api/v1/alerts/rules/{id}/preview` - evaluate now, dispatch
/// nothing. This is what the console's "What would it see?" button calls.
async fn preview_rule(
    State(state): State<AppState>,
    _current: AuthUser,
    Path(id): Path<String>,
) -> Result<Json<PreviewView>, ApiError> {
    let id = parse_uuid(&id, "rule id")?;
    let rule = alert_rule::Entity::find_by_id(id)
        .one(&state.db)
        .await?
        .ok_or_else(|| ApiError::not_found("alert rule not found"))?;
    let now = Utc::now();
    let evaluation = alerts::evaluate(&state.db, &rule, now)
        .await
        .map_err(ApiError::from)?;
    let silence = alerts::silenced(&state.db, rule.site_id, now)
        .await
        .map_err(ApiError::from)?;
    Ok(Json(PreviewView {
        metric: rule.metric.clone(),
        value: evaluation.value,
        hits: evaluation.hits,
        samples: evaluation.samples,
        threshold: rule.threshold,
        min_samples: rule.min_samples,
        window_seconds: rule.window_seconds,
        threshold_met: evaluation.threshold_met,
        silenced: silence.is_some(),
        silence_reason: silence.map(|row| row.reason),
        samples_basis: if rule.metric == METRIC_BLOCKED_RATIO {
            "requests seen in the window (access logs)"
        } else {
            "matching security events in the window"
        },
        evaluated_at: now,
    }))
}

#[derive(Debug, Deserialize)]
pub struct SilenceRequest {
    #[serde(default)]
    pub site_id: Option<Uuid>,
    #[serde(default)]
    pub reason: String,
    /// Defaults to now.
    #[serde(default)]
    pub starts_at: Option<DateTime<Utc>>,
    /// `null` silences until deleted.
    #[serde(default)]
    pub ends_at: Option<DateTime<Utc>>,
}

async fn list_silences(
    State(state): State<AppState>,
    _current: AuthUser,
) -> Result<Json<Vec<alert_silence::Model>>, ApiError> {
    let rows = alert_silence::Entity::find()
        .order_by_desc(alert_silence::Column::CreatedAt)
        .all(&state.db)
        .await?;
    Ok(Json(rows))
}

async fn create_silence(
    State(state): State<AppState>,
    current: AuthUser,
    Json(payload): Json<SilenceRequest>,
) -> Result<(StatusCode, Json<alert_silence::Model>), ApiError> {
    require_admin(&current)?;
    let reason = payload.reason.trim().to_string();
    if reason.chars().count() > 200 {
        return Err(ApiError::bad_request(
            "reason must be at most 200 characters",
        ));
    }
    let starts_at = payload.starts_at.unwrap_or_else(Utc::now);
    if let Some(ends_at) = payload.ends_at {
        if ends_at <= starts_at {
            return Err(ApiError::bad_request(
                "ends_at must be after starts_at",
            ));
        }
    }
    if let Some(site_id) = payload.site_id {
        let exists = site::Entity::find_by_id(site_id)
            .one(&state.db)
            .await?
            .is_some();
        if !exists {
            return Err(ApiError::bad_request("site not found"));
        }
    }
    let row = alert_silence::ActiveModel {
        id: Set(Uuid::new_v4()),
        site_id: Set(payload.site_id),
        reason: Set(reason),
        starts_at: Set(starts_at),
        ends_at: Set(payload.ends_at),
        created_by: Set(current.email.clone()),
        created_at: Set(Utc::now()),
    }
    .insert(&state.db)
    .await?;
    tracing::info!(
        silence = %row.id,
        site = ?row.site_id,
        actor = %current.email,
        "alert silence created"
    );
    Ok((StatusCode::CREATED, Json(row)))
}

async fn delete_silence(
    State(state): State<AppState>,
    current: AuthUser,
    Path(id): Path<String>,
) -> Result<StatusCode, ApiError> {
    require_admin(&current)?;
    let id = parse_uuid(&id, "silence id")?;
    let row = alert_silence::Entity::find_by_id(id)
        .one(&state.db)
        .await?
        .ok_or_else(|| ApiError::not_found("silence not found"))?;
    alert_silence::Entity::delete_by_id(row.id)
        .exec(&state.db)
        .await?;
    tracing::info!(silence = %row.id, actor = %current.email, "alert silence deleted");
    Ok(StatusCode::NO_CONTENT)
}
