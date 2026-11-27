//! Interception reports: the REST surface.
//!
//! The dashboard only ever loads [`summary`]; the full report is built when
//! an operator asks for it and served as a download, so the console stays
//! light. Report generation (the aggregations and the HTML document) lives
//! in [`crate::report`], and the scheduled delivery in
//! [`crate::report_scheduler`]; this module parses the request, enforces the
//! administrator check and returns the response.

use axum::extract::{Query, State};
use axum::http::{header, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use chrono::{DateTime, Duration, NaiveDate, TimeZone, Utc};
use chrono_tz::Tz;
use sea_orm::EntityTrait;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::api::common::{load_site_read, parse_uuid};
use crate::api::display::timezone;
use crate::api::error::ApiError;
use crate::api::state::AppState;
use crate::auth::AuthUser;
use crate::report::{
    self, ActionFilter, DailyPoint, LabelCount, ReportData, Window,
    MAX_RANGE_DAYS,
};
use crate::report_scheduler::{
    fire, load_settings, store_settings, FiredReport, ReportSettings,
};

/// Routes contributed to `/api/v1`.
pub fn routes() -> Router<AppState> {
    Router::new()
        .route("/reports/summary", get(summary))
        .route("/reports/interception", get(interception_report))
        .route("/reports/settings", get(show_settings).put(save_settings))
        .route("/reports/send-now", post(send_now))
}

#[derive(Debug, Deserialize)]
pub struct ReportQuery {
    /// Inclusive start: `YYYY-MM-DD` or RFC 3339. Defaults to 24h before `to`.
    pub from: Option<String>,
    /// End: `YYYY-MM-DD` (whole day) or RFC 3339. Defaults to now.
    pub to: Option<String>,
    /// One site; omitted aggregates every site the administrator can see.
    pub site_id: Option<String>,
    /// `all` (default), `blocked` or `monitor` - filters by the action the
    /// edge took.
    pub action: Option<String>,
    /// Substring filter over the client IP and the request path.
    pub q: Option<String>,
}

async fn resolve_window(
    state: &AppState,
    current: &AuthUser,
    query: &ReportQuery,
) -> Result<Window, ApiError> {
    let tz = timezone(&state.db).await;
    let (from, to) = window_bounds(
        query.from.as_deref(),
        query.to.as_deref(),
        Utc::now(),
        tz,
    )?;
    let site = match query
        .site_id
        .as_deref()
        .map(str::trim)
        .filter(|raw| !raw.is_empty())
    {
        Some(raw) => {
            let id = parse_uuid(raw, "site id")?;
            load_site_read(&state.db, id, current).await?;
            Some(id)
        },
        None => None,
    };
    let action = ActionFilter::parse(query.action.as_deref())?;
    let q = query
        .q
        .as_deref()
        .map(str::trim)
        .filter(|raw| !raw.is_empty())
        .map(str::to_string);
    Ok(Window {
        from,
        to,
        site,
        action,
        q,
        tz,
    })
}

/// Resolves the requested bounds: date-only inputs, RFC 3339 instants, the
/// 24-hour default and the 92-day cap. Pure so it is unit-testable.
fn window_bounds(
    from: Option<&str>,
    to: Option<&str>,
    now: DateTime<Utc>,
    tz: Tz,
) -> Result<(DateTime<Utc>, DateTime<Utc>), ApiError> {
    let to = match to.map(str::trim).filter(|raw| !raw.is_empty()) {
        Some(raw) => parse_bound(raw, true, tz)?,
        None => now,
    };
    let from = match from.map(str::trim).filter(|raw| !raw.is_empty()) {
        Some(raw) => parse_bound(raw, false, tz)?,
        None => to - Duration::hours(24),
    };
    if from >= to {
        return Err(ApiError::BadRequest(
            "'from' must be earlier than 'to'".to_string(),
        ));
    }
    if (to - from) > Duration::days(MAX_RANGE_DAYS) {
        return Err(ApiError::BadRequest(format!(
            "range is capped at {MAX_RANGE_DAYS} days"
        )));
    }
    Ok((from, to))
}

/// Parses one bound: RFC 3339, or a bare `YYYY-MM-DD` interpreted in the
/// instance timezone (an end date covers that whole local day).
fn parse_bound(
    raw: &str,
    is_end: bool,
    tz: Tz,
) -> Result<DateTime<Utc>, ApiError> {
    if let Ok(instant) = DateTime::parse_from_rfc3339(raw) {
        return Ok(instant.with_timezone(&Utc));
    }
    if let Ok(day) = NaiveDate::parse_from_str(raw, "%Y-%m-%d") {
        let target = if is_end {
            day.succ_opt().unwrap_or(day)
        } else {
            day
        };
        let midnight = target
            .and_hms_opt(0, 0, 0)
            .expect("midnight is a valid time");
        // A DST gap at local midnight resolves to the earliest valid
        // instant; zones without such transitions are unaffected.
        let local = tz
            .from_local_datetime(&midnight)
            .earliest()
            .unwrap_or_else(|| tz.from_utc_datetime(&midnight));
        return Ok(local.with_timezone(&Utc));
    }
    Err(ApiError::BadRequest(format!(
        "invalid date '{raw}' (use YYYY-MM-DD or RFC 3339)"
    )))
}

#[derive(Debug, Serialize)]
pub struct ReportSummary {
    pub from: DateTime<Utc>,
    pub to: DateTime<Utc>,
    pub site_id: Option<Uuid>,
    pub events: i64,
    pub blocked: i64,
    pub monitored: i64,
    pub unique_ips: i64,
    pub unique_paths: i64,
    pub top_type: Option<LabelCount>,
    pub top_country: Option<LabelCount>,
    pub top_ip: Option<LabelCount>,
    pub daily: Vec<DailyPoint>,
}

/* ── Handlers ─────────────────────────────────────────────────────── */

/// `GET /api/v1/reports/summary` — administrators only. Light aggregates
/// for the dashboard card and the reports page.
async fn summary(
    State(state): State<AppState>,
    current: AuthUser,
    Query(query): Query<ReportQuery>,
) -> Result<Json<ReportSummary>, ApiError> {
    current.require_admin().map_err(ApiError::from)?;
    let window = resolve_window(&state, &current, &query).await?;

    let totals = report::totals(&state.db, &window).await?;
    let types = report::type_rows(&state.db, &window).await?;
    let country = report::top_country(&state.db, &window).await?;
    let ips = report::top_ips(&state.db, &window).await?;
    let daily = report::daily(&state.db, &window).await?;

    Ok(Json(ReportSummary {
        from: window.from,
        to: window.to,
        site_id: window.site,
        events: totals.events,
        blocked: totals.blocked,
        monitored: totals.events - totals.blocked,
        unique_ips: totals.ips,
        unique_paths: totals.paths,
        top_type: types.first().map(|row| LabelCount {
            label: row.label.clone(),
            count: row.count,
        }),
        top_country: country,
        top_ip: ips.first().map(|row| LabelCount {
            label: row.ip.clone(),
            count: row.requests,
        }),
        daily,
    }))
}

/// `GET /api/v1/reports/interception` — administrators only. The full report
/// as a self-contained HTML attachment.
async fn interception_report(
    State(state): State<AppState>,
    current: AuthUser,
    Query(query): Query<ReportQuery>,
) -> Result<Response, ApiError> {
    current.require_admin().map_err(ApiError::from)?;
    let window = resolve_window(&state, &current, &query).await?;

    let totals = report::totals(&state.db, &window).await?;
    let types = report::type_rows(&state.db, &window).await?;
    let ips = report::top_ips(&state.db, &window).await?;
    let ips_by_blocked = report::top_ips_by_blocked(&state.db, &window).await?;
    let paths = report::top_paths(&state.db, &window).await?;
    let daily = report::daily(&state.db, &window).await?;
    let settings = load_settings(&state.db).await;

    let scope = match window.site {
        Some(id) => crate::models::site::Entity::find_by_id(id)
            .one(&state.db)
            .await?
            .map(|site| {
                if site.name.is_empty() {
                    site.domain
                } else {
                    format!("{} ({})", site.name, site.domain)
                }
            })
            .unwrap_or_else(|| id.to_string()),
        None => "All sites".to_string(),
    };

    let html = report::render_report(ReportData {
        from: window.from,
        to: window.to,
        scope,
        actor: current.email.clone(),
        title: settings.title.clone(),
        footer_note: settings.footer_note.clone(),
        tz: window.tz,
        totals,
        types,
        ips,
        ips_by_blocked,
        paths,
        daily,
    });

    let from_label = window.from.with_timezone(&window.tz).date_naive();
    let to_label = (window.to - Duration::seconds(1))
        .with_timezone(&window.tz)
        .date_naive();
    let filename =
        format!("varmanwaf-interception-{from_label}-{to_label}.html");

    Ok((
        StatusCode::OK,
        [
            (header::CONTENT_TYPE, "text/html; charset=utf-8".to_string()),
            (
                header::CONTENT_DISPOSITION,
                format!("attachment; filename=\"{filename}\""),
            ),
            (header::CACHE_CONTROL, "no-store".to_string()),
        ],
        html,
    )
        .into_response())
}

/// `GET /api/v1/reports/settings` — administrators only.
async fn show_settings(
    State(state): State<AppState>,
    current: AuthUser,
) -> Result<Json<ReportSettings>, ApiError> {
    current.require_admin().map_err(ApiError::from)?;
    Ok(Json(load_settings(&state.db).await))
}

/// `PUT /api/v1/reports/settings` — administrators only.
///
/// Saving with the schedule enabled **arms** it (`last_fired = now`), so the
/// first report goes out at the next occurrence rather than immediately
/// catching up on a past-due slot.
async fn save_settings(
    State(state): State<AppState>,
    current: AuthUser,
    Json(payload): Json<ReportSettings>,
) -> Result<Json<ReportSettings>, ApiError> {
    current.require_admin().map_err(ApiError::from)?;
    let mut settings = payload;
    settings.title = settings.title.trim().to_string();
    settings.footer_note = settings
        .footer_note
        .map(|note| note.trim().to_string())
        .filter(|note| !note.is_empty());
    settings.last_fired = if settings.schedule.enabled {
        Some(Utc::now())
    } else {
        None
    };
    settings.validate()?;
    store_settings(&state.db, &settings).await?;
    tracing::info!(
        title = %settings.title,
        schedule_enabled = settings.schedule.enabled,
        "report settings saved"
    );
    Ok(Json(settings))
}

/// `POST /api/v1/reports/send-now` — administrators only. Generates and
/// dispatches the report immediately with the schedule's window and scope,
/// without touching `last_fired` (the next scheduled occurrence still runs).
async fn send_now(
    State(state): State<AppState>,
    current: AuthUser,
) -> Result<Json<FiredReport>, ApiError> {
    current.require_admin().map_err(ApiError::from)?;
    let settings = load_settings(&state.db).await;
    Ok(Json(fire(&state.db, &settings, Utc::now()).await?))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn at(raw: &str) -> DateTime<Utc> {
        DateTime::parse_from_rfc3339(raw)
            .expect("test instant")
            .with_timezone(&Utc)
    }

    #[test]
    fn window_defaults_to_the_last_24_hours() {
        let now = at("2026-10-14T12:00:00Z");
        let (from, to) = window_bounds(None, None, now, Tz::UTC).unwrap();
        assert_eq!(to, now);
        assert_eq!(from, at("2026-10-13T12:00:00Z"));
    }

    #[test]
    fn a_bare_end_date_covers_that_whole_local_day() {
        let now = at("2026-10-14T12:00:00Z");
        let (from, to) =
            window_bounds(Some("2026-09-14"), Some("2026-10-14"), now, Tz::UTC)
                .unwrap();
        assert_eq!(from, at("2026-09-14T00:00:00Z"));
        assert_eq!(to, at("2026-10-15T00:00:00Z"));

        // The same dates in a UTC+7 zone start seven hours earlier in UTC.
        let (from, to) = window_bounds(
            Some("2026-10-14"),
            Some("2026-10-14"),
            now,
            chrono_tz::Asia::Phnom_Penh,
        )
        .unwrap();
        assert_eq!(from, at("2026-10-13T17:00:00Z"));
        assert_eq!(to, at("2026-10-14T17:00:00Z"));
    }

    #[test]
    fn windows_validate_order_and_the_cap() {
        let now = at("2026-10-14T12:00:00Z");
        assert!(window_bounds(
            Some("2026-10-14"),
            Some("2026-10-14"),
            now,
            Tz::UTC
        )
        .is_ok());
        assert!(window_bounds(
            Some("2026-10-15"),
            Some("2026-10-14"),
            now,
            Tz::UTC
        )
        .is_err());
        assert!(window_bounds(
            Some("2026-01-01"),
            Some("2026-10-14"),
            now,
            Tz::UTC
        )
        .is_err());
        assert!(window_bounds(Some("nonsense"), None, now, Tz::UTC).is_err());
    }
}
