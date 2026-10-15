//! Interception reports: a light summary for the dashboard and a
//! self-contained HTML report generated on demand.
//!
//! The dashboard only ever loads [`summary`]; the full report is built when
//! an operator asks for it and served as a download, so the console stays
//! light. Every aggregation is bounded: a range is capped at 92 days, the
//! ranking lists at 20 rows, and the daily series by the range itself.
//!
//! The HTML is built with inline styles only (no scripts, no external
//! assets) so it renders offline and prints to A4 cleanly. Every piece of
//! stored data - paths, IPs, rule names - is attacker-reachable, so it is
//! HTML-escaped on the way in.

use std::collections::HashMap;
use std::fmt::Write as _;

use axum::extract::{Query, State};
use axum::http::{header, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use chrono::{DateTime, Duration, NaiveDate, TimeZone, Utc};
use chrono_tz::Tz;
use sea_orm::{ActiveModelTrait, DatabaseConnection, EntityTrait, Value};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::api::common::{load_site_read, parse_uuid, query_all};
use crate::api::error::ApiError;
use crate::api::state::AppState;
use crate::auth::AuthUser;
use crate::notify::{self, AlertAttachment, AlertEvent};

/// Longest range a report may cover.
const MAX_RANGE_DAYS: i64 = 92;
/// Rows in each ranking list.
const TOP_ROWS: i64 = 20;

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

/// The action filter a report was generated with.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ActionFilter {
    All,
    Blocked,
    Monitor,
}

impl ActionFilter {
    fn parse(raw: Option<&str>) -> Result<Self, ApiError> {
        match raw.map(str::trim).filter(|raw| !raw.is_empty()) {
            None | Some("all") => Ok(Self::All),
            Some("blocked") => Ok(Self::Blocked),
            Some("monitor") => Ok(Self::Monitor),
            Some(other) => Err(ApiError::BadRequest(format!(
                "unknown action filter '{other}' (use all, blocked or monitor)"
            ))),
        }
    }
}

struct Window {
    from: DateTime<Utc>,
    to: DateTime<Utc>,
    site: Option<Uuid>,
    action: ActionFilter,
    /// Substring filter over client IP and path; `None` = no filter.
    q: Option<String>,
    /// The instance timezone: date-only bounds and daily buckets follow it.
    tz: Tz,
}

impl Window {
    /// `WHERE` fragment and bound values over `security_events`. Placeholders
    /// are numbered in insertion order, so every aggregation shares the exact
    /// same filter.
    fn filter(&self) -> (String, Vec<Value>) {
        let mut sql = String::from("timestamp >= $1 AND timestamp < $2");
        let mut values = vec![self.from.into(), self.to.into()];
        if let Some(site) = self.site {
            values.push(site.into());
            let _ = std::fmt::Write::write_fmt(
                &mut sql,
                format_args!(" AND site_id = ${}", values.len()),
            );
        }
        match self.action {
            ActionFilter::All => {},
            ActionFilter::Blocked => sql.push_str(" AND action = 'block'"),
            ActionFilter::Monitor => sql.push_str(" AND action <> 'block'"),
        }
        if let Some(q) = &self.q {
            values.push(q.clone().into());
            let _ = std::fmt::Write::write_fmt(
                &mut sql,
                format_args!(
                    " AND (position(lower(${n}) in lower(client_ip)) > 0 \
                     OR position(lower(${n}) in lower(coalesce(path, ''))) > 0)",
                    n = values.len(),
                ),
            );
        }
        (sql, values)
    }
}

/// Loads the operator's report settings (heading and footer note); defaults
/// when absent, like the other instance-setting blocks.
async fn load_settings(db: &sea_orm::DatabaseConnection) -> ReportSettings {
    use crate::models::instance_setting;

    let stored = instance_setting::Entity::find_by_id(SETTINGS_KEY)
        .one(db)
        .await
        .ok()
        .flatten();
    match stored {
        Some(row) => serde_json::from_str(&row.value).unwrap_or_default(),
        None => ReportSettings::default(),
    }
}

/// Key of the report settings row in `instance_settings`.
const SETTINGS_KEY: &str = "report_settings";

/// What an operator may customize about the generated report.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReportSettings {
    /// The heading printed on the cover and at the top of the file.
    #[serde(default = "default_title")]
    pub title: String,
    /// Optional operator note; printed above the data-source note.
    #[serde(default)]
    pub footer_note: Option<String>,
    /// Cron-style delivery schedule (UTC); disabled by default.
    #[serde(default)]
    pub schedule: ReportSchedule,
    /// When the schedule last fired. Set (armed) when the settings are
    /// saved with the schedule enabled; read-only in the UI.
    #[serde(default)]
    pub last_fired: Option<DateTime<Utc>>,
}

/// A cron-style delivery schedule: daily, weekly or monthly at HH:MM UTC.
/// The report covers `window_days` ending at the trigger time.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReportSchedule {
    #[serde(default)]
    pub enabled: bool,
    /// `daily` | `weekly` | `monthly`.
    #[serde(default = "default_interval")]
    pub interval: String,
    /// Trigger hour, 0-23 UTC.
    #[serde(default)]
    pub hour: u8,
    /// Trigger minute, 0-59.
    #[serde(default)]
    pub minute: u8,
    /// Weekly: 0 = Monday .. 6 = Sunday. Monthly: 1..=28 (every month has
    /// those days, so a 31-day month can never skip a firing).
    #[serde(default = "default_day")]
    pub day: u8,
    /// Days the report covers, ending at the trigger time (1..=92).
    #[serde(default = "default_window_days")]
    pub window_days: i64,
    /// Scope: `None`/empty = all sites.
    #[serde(default)]
    pub site_id: Option<String>,
    /// `all` | `blocked` | `monitor`.
    #[serde(default)]
    pub action: Option<String>,
}

fn default_title() -> String {
    "Interception report".to_string()
}

fn default_interval() -> String {
    "daily".to_string()
}

fn default_day() -> u8 {
    1
}

fn default_window_days() -> i64 {
    7
}

impl Default for ReportSettings {
    fn default() -> Self {
        Self {
            title: default_title(),
            footer_note: None,
            schedule: ReportSchedule::default(),
            last_fired: None,
        }
    }
}

impl Default for ReportSchedule {
    fn default() -> Self {
        Self {
            enabled: false,
            interval: default_interval(),
            hour: 0,
            minute: 0,
            day: default_day(),
            window_days: default_window_days(),
            site_id: None,
            action: None,
        }
    }
}

impl ReportSettings {
    fn validate(&self) -> Result<(), ApiError> {
        let title = self.title.trim();
        if title.is_empty() {
            return Err(ApiError::BadRequest(
                "title must not be empty".to_string(),
            ));
        }
        if title.chars().count() > 120 {
            return Err(ApiError::BadRequest(
                "title must be at most 120 characters".to_string(),
            ));
        }
        if let Some(note) = &self.footer_note {
            if note.chars().count() > 500 {
                return Err(ApiError::BadRequest(
                    "footer_note must be at most 500 characters".to_string(),
                ));
            }
        }
        self.schedule.validate()
    }
}

impl ReportSchedule {
    fn validate(&self) -> Result<(), ApiError> {
        match self.interval.as_str() {
            "daily" | "weekly" | "monthly" => {},
            other => {
                return Err(ApiError::BadRequest(format!(
                    "unknown interval '{other}' (use daily, weekly or monthly)"
                )))
            },
        }
        if self.hour > 23 {
            return Err(ApiError::BadRequest(
                "schedule hour must be 0-23".to_string(),
            ));
        }
        if self.minute > 59 {
            return Err(ApiError::BadRequest(
                "schedule minute must be 0-59".to_string(),
            ));
        }
        match self.interval.as_str() {
            "weekly" if self.day > 6 => {
                return Err(ApiError::BadRequest(
                    "weekly day must be 0 (Monday) to 6 (Sunday)".to_string(),
                ))
            },
            "monthly" if !(1..=28).contains(&self.day) => {
                return Err(ApiError::BadRequest(
                    "monthly day must be 1-28".to_string(),
                ))
            },
            _ => {},
        }
        if !(1..=MAX_RANGE_DAYS).contains(&self.window_days) {
            return Err(ApiError::BadRequest(format!(
                "window_days must be 1-{MAX_RANGE_DAYS}"
            )));
        }
        if let Some(raw) = self
            .site_id
            .as_deref()
            .map(str::trim)
            .filter(|raw| !raw.is_empty())
        {
            parse_uuid(raw, "site id")?;
        }
        ActionFilter::parse(self.action.as_deref())?;
        Ok(())
    }
}

/// The most recent instant the schedule came due at or before `now` (UTC);
/// `None` when disabled or misconfigured. Pure so it is unit-testable.
fn last_due(
    schedule: &ReportSchedule,
    now: DateTime<Utc>,
) -> Option<DateTime<Utc>> {
    use chrono::{Datelike, NaiveTime};

    if !schedule.enabled {
        return None;
    }
    let time = NaiveTime::from_hms_opt(
        u32::from(schedule.hour),
        u32::from(schedule.minute),
        0,
    )?;
    let today = now.date_naive();
    match schedule.interval.as_str() {
        "weekly" => {
            let target = u32::from(schedule.day.min(6));
            for back in 0..=7 {
                let date = today - Duration::days(back);
                if date.weekday().num_days_from_monday() == target {
                    let candidate = date.and_time(time).and_utc();
                    if candidate <= now {
                        return Some(candidate);
                    }
                }
            }
            None
        },
        "monthly" => {
            let day = u32::from(schedule.day.clamp(1, 28));
            let candidate = chrono::NaiveDate::from_ymd_opt(
                today.year(),
                today.month(),
                day,
            )?
            .and_time(time)
            .and_utc();
            if candidate <= now {
                return Some(candidate);
            }
            let (year, month) = if today.month() == 1 {
                (today.year() - 1, 12)
            } else {
                (today.year(), today.month() - 1)
            };
            chrono::NaiveDate::from_ymd_opt(year, month, day)
                .map(|date| date.and_time(time).and_utc())
        },
        _ => {
            let candidate = today.and_time(time).and_utc();
            if candidate <= now {
                Some(candidate)
            } else {
                Some(candidate - Duration::days(1))
            }
        },
    }
}

/// `GET /api/v1/reports/settings` — administrators only.
async fn show_settings(
    State(state): State<AppState>,
    current: AuthUser,
) -> Result<Json<ReportSettings>, ApiError> {
    current.require_admin().map_err(ApiError::from)?;
    Ok(Json(load_settings(&state.db).await))
}

/// Persists the settings row (used by the save handler and the scheduler's
/// `last_fired` bookkeeping).
async fn store_settings(
    db: &sea_orm::DatabaseConnection,
    settings: &ReportSettings,
) -> Result<(), ApiError> {
    use crate::models::instance_setting;

    let value = serde_json::to_string(settings)
        .map_err(|err| ApiError::Internal(err.to_string()))?;
    let existing = instance_setting::Entity::find_by_id(SETTINGS_KEY)
        .one(db)
        .await?;
    match existing {
        Some(row) => {
            let mut active: instance_setting::ActiveModel = row.into();
            active.value = sea_orm::Set(value);
            active.updated_at = sea_orm::Set(Utc::now());
            active.update(db).await?;
        },
        None => {
            instance_setting::ActiveModel {
                key: sea_orm::Set(SETTINGS_KEY.to_string()),
                value: sea_orm::Set(value),
                updated_at: sea_orm::Set(Utc::now()),
            }
            .insert(db)
            .await?;
        },
    }
    Ok(())
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

async fn resolve_window(
    state: &AppState,
    current: &AuthUser,
    query: &ReportQuery,
) -> Result<Window, ApiError> {
    let tz = crate::api::display::timezone(&state.db).await;
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

/* ── Aggregations ─────────────────────────────────────────────────── */

struct Totals {
    events: i64,
    blocked: i64,
    ips: i64,
    paths: i64,
}

#[derive(Debug, Serialize)]
pub struct LabelCount {
    pub label: String,
    pub count: i64,
}

#[derive(Debug, Serialize)]
pub struct DailyPoint {
    pub date: String,
    pub total: i64,
    pub blocked: i64,
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

async fn totals(
    db: &DatabaseConnection,
    window: &Window,
) -> Result<Totals, ApiError> {
    let (filter, values) = window.filter();
    let sql = format!(
        "SELECT COUNT(*) AS events, \
                COUNT(*) FILTER (WHERE action = 'block') AS blocked, \
                COUNT(DISTINCT client_ip) AS ips, \
                COUNT(DISTINCT path) AS paths \
         FROM security_events WHERE {filter}"
    );
    let row = query_all(db, &sql, values).await?.into_iter().next();
    let read = |name: &str| -> i64 {
        row.as_ref()
            .and_then(|row| row.try_get::<i64>("", name).ok())
            .unwrap_or(0)
    };
    Ok(Totals {
        events: read("events"),
        blocked: read("blocked"),
        ips: read("ips"),
        paths: read("paths"),
    })
}

/// Interception types: rule groups classified through the managed-rule
/// catalogue, merged by label and ranked.
async fn type_rows(
    db: &DatabaseConnection,
    window: &Window,
) -> Result<Vec<LabelCount>, ApiError> {
    let (filter, values) = window.filter();
    let sql = format!(
        "SELECT COALESCE(rule_id, '') AS rule_id, \
                COALESCE(rule_name, '') AS rule_name, \
                COUNT(*) AS n \
         FROM security_events WHERE {filter} \
         GROUP BY 1, 2 ORDER BY n DESC LIMIT 200"
    );
    let rows = query_all(db, &sql, values).await?;
    let catalogue = catalogue();
    let mut merged: HashMap<String, i64> = HashMap::new();
    for row in &rows {
        let rule_id: String = row.try_get("", "rule_id").unwrap_or_default();
        let rule_name: String =
            row.try_get("", "rule_name").unwrap_or_default();
        let count: i64 = row.try_get("", "n").unwrap_or_default();
        *merged
            .entry(type_label(&rule_id, &rule_name, &catalogue))
            .or_default() += count;
    }
    let mut out: Vec<LabelCount> = merged
        .into_iter()
        .map(|(label, count)| LabelCount { label, count })
        .collect();
    out.sort_by(|a, b| b.count.cmp(&a.count).then(a.label.cmp(&b.label)));
    out.truncate(TOP_ROWS as usize);
    Ok(out)
}

async fn top_country(
    db: &DatabaseConnection,
    window: &Window,
) -> Result<Option<LabelCount>, ApiError> {
    let (filter, values) = window.filter();
    let sql = format!(
        "SELECT country_code, COUNT(*) AS n FROM security_events \
         WHERE {filter} AND country_code IS NOT NULL AND country_code <> '' \
         GROUP BY 1 ORDER BY n DESC LIMIT 1"
    );
    let row = query_all(db, &sql, values).await?.into_iter().next();
    Ok(row.map(|row| LabelCount {
        label: row
            .try_get::<String>("", "country_code")
            .unwrap_or_default(),
        count: row.try_get::<i64>("", "n").unwrap_or_default(),
    }))
}

struct IpRow {
    ip: String,
    country: String,
    requests: i64,
    blocked: i64,
    last_seen: Option<DateTime<Utc>>,
}

async fn top_ips(
    db: &DatabaseConnection,
    window: &Window,
) -> Result<Vec<IpRow>, ApiError> {
    let (filter, values) = window.filter();
    let sql = format!(
        "SELECT client_ip, COUNT(*) AS requests, \
                COUNT(*) FILTER (WHERE action = 'block') AS blocked, \
                COALESCE(MAX(country_code), '') AS country, \
                MAX(timestamp) AS last_seen \
         FROM security_events WHERE {filter} \
         GROUP BY client_ip ORDER BY requests DESC LIMIT {TOP_ROWS}"
    );
    Ok(query_all(db, &sql, values)
        .await?
        .into_iter()
        .map(|row| IpRow {
            ip: row.try_get("", "client_ip").unwrap_or_default(),
            country: row.try_get("", "country").unwrap_or_default(),
            requests: row.try_get("", "requests").unwrap_or_default(),
            blocked: row.try_get("", "blocked").unwrap_or_default(),
            last_seen: row.try_get("", "last_seen").ok(),
        })
        .collect())
}

/// The attack-IP ranking: the same rows ordered by blocked count first, so
/// the "attack" list leads with addresses actually refused.
async fn top_ips_by_blocked(
    db: &DatabaseConnection,
    window: &Window,
) -> Result<Vec<IpRow>, ApiError> {
    let (filter, values) = window.filter();
    let sql = format!(
        "SELECT client_ip, COUNT(*) AS requests, \
                COUNT(*) FILTER (WHERE action = 'block') AS blocked, \
                COALESCE(MAX(country_code), '') AS country, \
                MAX(timestamp) AS last_seen \
         FROM security_events WHERE {filter} \
         GROUP BY client_ip ORDER BY blocked DESC, requests DESC \
         LIMIT {TOP_ROWS}"
    );
    Ok(query_all(db, &sql, values)
        .await?
        .into_iter()
        .map(|row| IpRow {
            ip: row.try_get("", "client_ip").unwrap_or_default(),
            country: row.try_get("", "country").unwrap_or_default(),
            requests: row.try_get("", "requests").unwrap_or_default(),
            blocked: row.try_get("", "blocked").unwrap_or_default(),
            last_seen: row.try_get("", "last_seen").ok(),
        })
        .collect())
}

struct PathRow {
    path: String,
    requests: i64,
    blocked: i64,
}

async fn top_paths(
    db: &DatabaseConnection,
    window: &Window,
) -> Result<Vec<PathRow>, ApiError> {
    let (filter, values) = window.filter();
    let sql = format!(
        "SELECT COALESCE(path, '') AS path, COUNT(*) AS requests, \
                COUNT(*) FILTER (WHERE action = 'block') AS blocked \
         FROM security_events WHERE {filter} \
         GROUP BY 1 ORDER BY requests DESC LIMIT {TOP_ROWS}"
    );
    Ok(query_all(db, &sql, values)
        .await?
        .into_iter()
        .map(|row| PathRow {
            path: row.try_get("", "path").unwrap_or_default(),
            requests: row.try_get("", "requests").unwrap_or_default(),
            blocked: row.try_get("", "blocked").unwrap_or_default(),
        })
        .collect())
}

async fn daily(
    db: &DatabaseConnection,
    window: &Window,
) -> Result<Vec<DailyPoint>, ApiError> {
    let (filter, mut values) = window.filter();
    values.push(window.tz.name().to_string().into());
    let sql = format!(
        "SELECT to_char(timestamp AT TIME ZONE ${}::text, 'YYYY-MM-DD') AS day, \
                COUNT(*) AS total, \
                COUNT(*) FILTER (WHERE action = 'block') AS blocked \
         FROM security_events WHERE {filter} GROUP BY 1 ORDER BY 1",
        values.len(),
    );
    Ok(query_all(db, &sql, values)
        .await?
        .into_iter()
        .map(|row| DailyPoint {
            date: row.try_get("", "day").unwrap_or_default(),
            total: row.try_get("", "total").unwrap_or_default(),
            blocked: row.try_get("", "blocked").unwrap_or_default(),
        })
        .collect())
}

/* ── Classification ───────────────────────────────────────────────── */

type Catalogue = HashMap<String, (Option<String>, String)>;

fn catalogue() -> Catalogue {
    varman_waf::managed_rule_catalogue(varman_waf::WafLevel::Strict)
        .into_iter()
        .map(|rule| (rule.id, (rule.category, rule.name)))
        .collect()
}

/// One label for a rule group: the managed catalogue's attack-family label
/// when the id is known, otherwise the recorded rule name, otherwise the
/// raw id; unattributed events get their own bucket.
fn type_label(rule_id: &str, rule_name: &str, catalogue: &Catalogue) -> String {
    if let Some((category, name)) = catalogue.get(rule_id) {
        return match category {
            Some(category) => category_label(category),
            None => name.clone(),
        };
    }
    match rule_id {
        "" => "Unattributed".to_string(),
        "bot_protection" => "Bot protection".to_string(),
        other => {
            if rule_name.is_empty() {
                other.to_string()
            } else {
                rule_name.to_string()
            }
        },
    }
}

/// Attack families, in the same vocabulary the console uses.
fn category_label(category: &str) -> String {
    match category {
        "sqli" => "SQL injection",
        "xss" => "Cross-site scripting",
        "rce" => "Remote code execution",
        "lfi" => "Local file inclusion",
        "ssrf" => "Server-side request forgery",
        "deser" => "Insecure deserialization",
        "crlf" => "CRLF injection",
        "xxe" => "XML external entity",
        "ssti" => "Server-side template injection",
        other => other,
    }
    .to_string()
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

    let totals = totals(&state.db, &window).await?;
    let types = type_rows(&state.db, &window).await?;
    let country = top_country(&state.db, &window).await?;
    let ips = top_ips(&state.db, &window).await?;
    let daily = daily(&state.db, &window).await?;

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

    let totals = totals(&state.db, &window).await?;
    let types = type_rows(&state.db, &window).await?;
    let ips = top_ips(&state.db, &window).await?;
    let ips_by_blocked = top_ips_by_blocked(&state.db, &window).await?;
    let paths = top_paths(&state.db, &window).await?;
    let daily = daily(&state.db, &window).await?;
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

    let html = render_report(ReportData {
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

/* ── Scheduled delivery ───────────────────────────────────────────── */

/// How often the scheduler checks for a due report.
const SCHEDULER_TICK: std::time::Duration = std::time::Duration::from_secs(60);

/// What a firing produced; returned by the send-now route and logged.
#[derive(Debug, Serialize)]
pub struct FiredReport {
    pub filename: String,
    pub from: String,
    pub to: String,
    pub events: i64,
    pub blocked: i64,
    pub monitored: i64,
}

/// Spawns the scheduled-report tick: every minute it checks the stored
/// schedule and, when one came due since it last fired, generates and
/// dispatches the report through the notification channels.
pub fn spawn(db: DatabaseConnection) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let mut ticker = tokio::time::interval(SCHEDULER_TICK);
        ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        loop {
            ticker.tick().await;
            match run_due(&db, Utc::now()).await {
                Ok(true) => {
                    tracing::info!("scheduled interception report dispatched")
                },
                Ok(false) => {},
                Err(err) => tracing::warn!(
                    error = %err,
                    "scheduled report check failed"
                ),
            }
        }
    })
}

/// Fires when the schedule came due after `last_fired`; records the firing
/// so one occurrence never dispatches twice.
async fn run_due(
    db: &DatabaseConnection,
    now: DateTime<Utc>,
) -> Result<bool, ApiError> {
    let settings = load_settings(db).await;
    let Some(due) = last_due(&settings.schedule, now) else {
        return Ok(false);
    };
    if settings.last_fired.is_some_and(|fired| fired >= due) {
        return Ok(false);
    }
    let fired = fire(db, &settings, now).await?;
    tracing::info!(
        filename = %fired.filename,
        events = fired.events,
        "scheduled report fired"
    );
    let mut updated = settings;
    updated.last_fired = Some(now);
    store_settings(db, &updated).await?;
    Ok(true)
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

/// Generates the report for the schedule's window/scope and dispatches it
/// through the notification channels (e-mail channels attach the HTML).
async fn fire(
    db: &DatabaseConnection,
    settings: &ReportSettings,
    now: DateTime<Utc>,
) -> Result<FiredReport, ApiError> {
    let schedule = &settings.schedule;
    let site = schedule
        .site_id
        .as_deref()
        .map(str::trim)
        .filter(|raw| !raw.is_empty())
        .map(|raw| parse_uuid(raw, "site id"))
        .transpose()?;
    let window = Window {
        from: now
            - Duration::days(schedule.window_days.clamp(1, MAX_RANGE_DAYS)),
        to: now,
        site,
        action: ActionFilter::parse(schedule.action.as_deref())?,
        q: None,
        tz: crate::api::display::timezone(db).await,
    };

    let totals = totals(db, &window).await?;
    let events = totals.events;
    let blocked = totals.blocked;
    let monitored = events - blocked;
    let types = type_rows(db, &window).await?;
    let ips = top_ips(db, &window).await?;
    let ips_by_blocked = top_ips_by_blocked(db, &window).await?;
    let paths = top_paths(db, &window).await?;
    let daily = daily(db, &window).await?;

    let scope = match window.site {
        Some(id) => crate::models::site::Entity::find_by_id(id)
            .one(db)
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

    let html = render_report(ReportData {
        from: window.from,
        to: window.to,
        scope,
        actor: "scheduled delivery".to_string(),
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
    let message = format!(
        "Interception report {from_label} to {to_label}: {events} \
         interceptions ({blocked} blocked, {monitored} monitor-only). The \
         full report is attached where the channel supports it."
    );
    notify::emit_with_attachment(
        AlertEvent {
            event_type: crate::models::event_type::REPORT_SCHEDULED.to_string(),
            severity: crate::models::severity::INFO,
            title: settings.title.clone(),
            message,
            details: Some(serde_json::json!({
                "from": from_label.to_string(),
                "to": to_label.to_string(),
                "filename": filename,
                "events": events,
                "blocked": blocked,
                "monitored": monitored,
            })),
            dedup_key: None,
        },
        AlertAttachment {
            filename: filename.clone(),
            html,
        },
    )
    .await;

    Ok(FiredReport {
        filename,
        from: from_label.to_string(),
        to: to_label.to_string(),
        events,
        blocked,
        monitored,
    })
}

/* ── HTML rendering ───────────────────────────────────────────────── */

struct ReportData {
    from: DateTime<Utc>,
    to: DateTime<Utc>,
    scope: String,
    actor: String,
    /// Operator-customizable heading (report settings).
    title: String,
    /// Optional operator note printed above the data-source note.
    footer_note: Option<String>,
    /// Instance timezone: the cover and filenames print local dates.
    tz: Tz,
    totals: Totals,
    types: Vec<LabelCount>,
    ips: Vec<IpRow>,
    /// Attack-IP ranking (ordered by blocked count).
    ips_by_blocked: Vec<IpRow>,
    paths: Vec<PathRow>,
    daily: Vec<DailyPoint>,
}

/// Escapes text for HTML text nodes and attributes. Report data (paths,
/// IPs, rule names) is attacker-reachable; nothing may skip this.
fn escape_html(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    for ch in value.chars() {
        match ch {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&#39;"),
            _ => out.push(ch),
        }
    }
    out
}

const STYLE: &str = "\
@page { size: A4 portrait; margin: 14mm; }
* { box-sizing: border-box; }
body { font-family: 'Segoe UI', 'Helvetica Neue', Arial, sans-serif; \
       color: #1c2530; margin: 0; padding: 24px; font-size: 12px; }
.brand { color: #0051c3; font-weight: 700; letter-spacing: .08em; \
         text-transform: uppercase; font-size: 11px; }
h1 { font-size: 26px; margin: 6px 0 2px; }
.meta { color: #5b6b7c; margin: 0 0 20px; }
h2 { font-size: 15px; margin: 26px 0 8px; color: #0051c3; }
.cards { display: flex; flex-wrap: wrap; gap: 10px; margin: 16px 0; }
.card { flex: 1 1 120px; border: 1px solid #d7dee6; border-radius: 8px; \
        padding: 10px 12px; }
.card .n { font-size: 20px; font-weight: 700; }
.card .l { color: #5b6b7c; font-size: 11px; }
table { border-collapse: collapse; width: 100%; }
th, td { border-bottom: 1px solid #d7dee6; padding: 5px 6px; \
         text-align: left; vertical-align: top; }
th { background: #eef3f9; font-size: 11px; color: #33465c; }
td.num, th.num { text-align: right; white-space: nowrap; }
.mono { font-family: Consolas, 'Courier New', monospace; font-size: 11px; \
        word-break: break-all; }
.bar { background: #0051c3; height: 8px; border-radius: 4px; min-width: 2px; }
.bar-track { background: #e7edf4; border-radius: 4px; width: 100%; }
.cols { display: flex; align-items: flex-end; gap: 3px; height: 90px; \
        margin: 8px 0 2px; }
.col { flex: 1; background: #cfe0f5; border-radius: 3px 3px 0 0; \
       position: relative; min-height: 2px; }
.col .blocked { position: absolute; left: 0; right: 0; bottom: 0; \
                background: #0051c3; border-radius: 3px 3px 0 0; }
.axis { display: flex; gap: 3px; color: #5b6b7c; font-size: 9px; }
.axis span { flex: 1; text-align: center; overflow: hidden; \
             white-space: nowrap; }
.legend { color: #5b6b7c; font-size: 10px; margin-top: 4px; }
.note { color: #5b6b7c; font-size: 10px; margin-top: 28px; \
        border-top: 1px solid #d7dee6; padding-top: 8px; }
.legend-swatch { display: inline-block; width: 9px; height: 9px; \
                 border-radius: 2px; margin: 0 4px 0 10px; }
.cover { padding: 96px 0 24px; page-break-after: always; }
.cover-title { font-size: 32px; margin: 10px 0 6px; }
.cover-range { font-size: 16px; color: #33465c; margin: 24px 0 0; }
@media print { .cover { padding-top: 160px; } }
";

fn render_report(data: ReportData) -> String {
    let mut html = String::with_capacity(32 * 1024);
    let from_label = data.from.with_timezone(&data.tz).date_naive();
    let to_label = (data.to - Duration::seconds(1))
        .with_timezone(&data.tz)
        .date_naive();
    let generated = Utc::now().format("%Y-%m-%d %H:%M UTC");

    let title = escape_html(&data.title);
    html.push_str(
        "<!DOCTYPE html>\n<html lang=\"en\"><head><meta charset=\"utf-8\">",
    );
    let _ = write!(
        html,
        "<title>VarmanWAF {title} {from_label} to {to_label}</title>\
         <style>{STYLE}</style></head><body>"
    );
    // Cover page: prints as its own page, mirroring the report shape
    // operators know (title, range, then the numbered sections).
    html.push_str("<section class=\"cover\">");
    html.push_str("<div class=\"brand\">VarmanWAF</div>");
    let _ = write!(html, "<h1 class=\"cover-title\">{title}</h1>");
    let _ = write!(
        html,
        "<p class=\"cover-range\">{from_label} to {to_label}</p>\
         <p class=\"meta\">Scope: {} &middot; Generated {generated} by {}</p>",
        escape_html(&data.scope),
        escape_html(&data.actor),
    );
    html.push_str("</section>");

    // Summary cards.
    html.push_str("<div class=\"cards\">");
    for (label, value) in [
        ("Interceptions", data.totals.events),
        ("Blocked", data.totals.blocked),
        ("Monitor-only", data.totals.events - data.totals.blocked),
        ("Unique IPs", data.totals.ips),
        ("Unique paths", data.totals.paths),
    ] {
        let _ = write!(
            html,
            "<div class=\"card\"><div class=\"n\">{value}</div>\
             <div class=\"l\">{label}</div></div>"
        );
    }
    html.push_str("</div>");

    // Interception types.
    html.push_str("<h2>1 Interception type</h2>");
    if data.types.is_empty() {
        html.push_str("<p class=\"meta\">No interceptions in this range.</p>");
    } else {
        let max = data.types.first().map(|row| row.count).unwrap_or(1).max(1);
        let total = data.totals.events.max(1);
        html.push_str(
            "<table><thead><tr><th>Type</th><th class=\"num\">Count</th>\
             <th class=\"num\">Share</th><th style=\"width:35%\"></th></tr>\
             </thead><tbody>",
        );
        for row in &data.types {
            let share = 100.0 * row.count as f64 / total as f64;
            let width = 100.0 * row.count as f64 / max as f64;
            let _ = write!(
                html,
                "<tr><td>{}</td><td class=\"num\">{}</td>\
                 <td class=\"num\">{share:.1}%</td>\
                 <td><div class=\"bar-track\">\
                 <div class=\"bar\" style=\"width:{width:.1}%\"></div>\
                 </div></td></tr>",
                escape_html(&row.label),
                row.count,
            );
        }
        html.push_str("</tbody></table>");
    }

    // Daily timeline.
    html.push_str("<h2>5 Daily timeline</h2>");
    if data.daily.is_empty() {
        html.push_str("<p class=\"meta\">No interceptions in this range.</p>");
    } else {
        let max = data
            .daily
            .iter()
            .map(|point| point.total)
            .max()
            .unwrap_or(1)
            .max(1);
        html.push_str("<div class=\"cols\">");
        for point in &data.daily {
            let height = 100.0 * point.total as f64 / max as f64;
            let blocked = if point.total > 0 {
                100.0 * point.blocked as f64 / point.total as f64
            } else {
                0.0
            };
            let _ = write!(
                html,
                "<div class=\"col\" style=\"height:{height:.1}%\" \
                 title=\"{}: {} total, {} blocked\">\
                 <div class=\"blocked\" style=\"height:{blocked:.1}%\"></div>\
                 </div>",
                escape_html(&point.date),
                point.total,
                point.blocked,
            );
        }
        html.push_str("</div><div class=\"axis\">");
        let step = (data.daily.len() / 12).max(1);
        for (index, point) in data.daily.iter().enumerate() {
            let label = if index % step == 0 {
                point.date.get(5..).unwrap_or(&point.date)
            } else {
                ""
            };
            let _ = write!(html, "<span>{}</span>", escape_html(label));
        }
        html.push_str(
            "</div><p class=\"legend\">\
             <span class=\"legend-swatch\" style=\"background:#cfe0f5\"></span>\
             interceptions \
             <span class=\"legend-swatch\" style=\"background:#0051c3\"></span>\
             blocked</p>",
        );
    }

    // Attack IP ranking (ordered by blocked count).
    html.push_str("<h2>2 Attack IP ranking TOP20</h2>");
    if data.ips_by_blocked.is_empty() {
        html.push_str(
            "<p class=\"meta\">No source addresses in this range.</p>",
        );
    } else {
        html.push_str(
            "<table><thead><tr><th class=\"num\">#</th><th>Client IP</th>\
             <th>Country</th><th class=\"num\">Blocked</th>\
             <th class=\"num\">Interceptions</th><th>Last seen</th></tr>\
             </thead><tbody>",
        );
        for (index, row) in data.ips_by_blocked.iter().enumerate() {
            let last = row
                .last_seen
                .map(|at| at.format("%Y-%m-%d %H:%M").to_string())
                .unwrap_or_else(|| "-".to_string());
            let _ = write!(
                html,
                "<tr><td class=\"num\">{}</td><td class=\"mono\">{}</td>\
                 <td>{}</td><td class=\"num\">{}</td>\
                 <td class=\"num\">{}</td><td>{}</td></tr>",
                index + 1,
                escape_html(&row.ip),
                escape_html(&row.country),
                row.blocked,
                row.requests,
                escape_html(&last),
            );
        }
        html.push_str("</tbody></table>");
    }

    // IP report: every tracked source address with its full split.
    html.push_str("<h2>3 IP report TOP20</h2>");
    if data.ips.is_empty() {
        html.push_str(
            "<p class=\"meta\">No source addresses in this range.</p>",
        );
    } else {
        html.push_str(
            "<table><thead><tr><th class=\"num\">#</th><th>Client IP</th>\
             <th>Country</th><th class=\"num\">Interceptions</th>\
             <th class=\"num\">Blocked</th>\
             <th class=\"num\">Monitor-only</th><th>Last seen</th></tr>\
             </thead><tbody>",
        );
        for (index, row) in data.ips.iter().enumerate() {
            let last = row
                .last_seen
                .map(|at| at.format("%Y-%m-%d %H:%M").to_string())
                .unwrap_or_else(|| "-".to_string());
            let monitored = (row.requests - row.blocked).max(0);
            let _ = write!(
                html,
                "<tr><td class=\"num\">{}</td><td class=\"mono\">{}</td>\
                 <td>{}</td><td class=\"num\">{}</td>\
                 <td class=\"num\">{}</td><td class=\"num\">{}</td>\
                 <td>{}</td></tr>",
                index + 1,
                escape_html(&row.ip),
                escape_html(&row.country),
                row.requests,
                row.blocked,
                monitored,
                escape_html(&last),
            );
        }
        html.push_str("</tbody></table>");
    }

    // URL report.
    html.push_str("<h2>4 URL report TOP20</h2>");
    if data.paths.is_empty() {
        html.push_str("<p class=\"meta\">No paths in this range.</p>");
    } else {
        html.push_str(
            "<table><thead><tr><th class=\"num\">#</th><th>Path</th>\
             <th class=\"num\">Interceptions</th>\
             <th class=\"num\">Blocked</th>\
             <th class=\"num\">Monitor-only</th></tr></thead><tbody>",
        );
        for (index, row) in data.paths.iter().enumerate() {
            let monitored = (row.requests - row.blocked).max(0);
            let _ = write!(
                html,
                "<tr><td class=\"num\">{}</td><td class=\"mono\">{}</td>\
                 <td class=\"num\">{}</td><td class=\"num\">{}</td>\
                 <td class=\"num\">{}</td></tr>",
                index + 1,
                escape_html(&row.path),
                row.requests,
                row.blocked,
                monitored,
            );
        }
        html.push_str("</tbody></table>");
    }

    if let Some(note) = &data.footer_note {
        let _ = write!(html, "<p class=\"note\">{}</p>", escape_html(note));
    }
    html.push_str(
        "<p class=\"note\">Counts come from the security events the edge \
         recorded in this range; monitor-only decisions are included and \
         labelled, so the total is every interception, not just blocked \
         ones. Countries appear when the edge resolved them. Generated by \
         the VarmanWAF control plane; nothing in this report is sampled or \
         estimated.</p>",
    );
    html.push_str("</body></html>");
    html
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

    #[test]
    fn type_labels_use_the_catalogue_then_fall_back() {
        let catalogue: Catalogue = HashMap::from([
            (
                "VARMAN-1002".to_string(),
                (Some("sqli".to_string()), "SQLi anomaly".to_string()),
            ),
            (
                "VARMAN-1001".to_string(),
                (None, "Protocol anomaly".to_string()),
            ),
        ]);
        assert_eq!(type_label("VARMAN-1002", "", &catalogue), "SQL injection");
        assert_eq!(
            type_label("VARMAN-1001", "", &catalogue),
            "Protocol anomaly"
        );
        assert_eq!(
            type_label("bot_protection", "", &catalogue),
            "Bot protection"
        );
        assert_eq!(type_label("", "", &catalogue), "Unattributed");
        assert_eq!(
            type_label("PT-001", "Custom probe rule", &catalogue),
            "Custom probe rule"
        );
        assert_eq!(
            type_label("sig.sqli.union_bare", "", &catalogue),
            "sig.sqli.union_bare"
        );
    }

    #[test]
    fn html_escaping_covers_the_dangerous_characters() {
        assert_eq!(
            escape_html("<script>alert('x')</script>"),
            "&lt;script&gt;alert(&#39;x&#39;)&lt;/script&gt;"
        );
        assert_eq!(escape_html("a & b"), "a &amp; b");
        assert_eq!(escape_html("\"quoted\""), "&quot;quoted&quot;");
    }

    fn schedule(
        interval: &str,
        hour: u8,
        minute: u8,
        day: u8,
    ) -> ReportSchedule {
        ReportSchedule {
            enabled: true,
            interval: interval.to_string(),
            hour,
            minute,
            day,
            window_days: 7,
            site_id: None,
            action: None,
        }
    }

    #[test]
    fn last_due_walks_back_to_the_most_recent_occurrence() {
        let now = at("2026-10-14T15:00:00Z"); // Wednesday
                                              // Daily at 08:30: today's slot already passed.
        assert_eq!(
            last_due(&schedule("daily", 8, 30, 1), now),
            Some(at("2026-10-14T08:30:00Z"))
        );
        // Daily at 20:00: today's slot is ahead, so yesterday's counts.
        assert_eq!(
            last_due(&schedule("daily", 20, 0, 1), now),
            Some(at("2026-10-13T20:00:00Z"))
        );
        // Weekly on Monday (0) at 06:00: the most recent Monday.
        assert_eq!(
            last_due(&schedule("weekly", 6, 0, 0), now),
            Some(at("2026-10-12T06:00:00Z"))
        );
        // Weekly on Wednesday (2) at 09:00: today.
        assert_eq!(
            last_due(&schedule("weekly", 9, 0, 2), now),
            Some(at("2026-10-14T09:00:00Z"))
        );
        // Monthly on the 20th at 00:00: this month's slot is ahead, so
        // September's.
        assert_eq!(
            last_due(&schedule("monthly", 0, 0, 20), now),
            Some(at("2026-09-20T00:00:00Z"))
        );
        // Monthly on the 5th: this month.
        assert_eq!(
            last_due(&schedule("monthly", 0, 0, 5), now),
            Some(at("2026-10-05T00:00:00Z"))
        );
    }

    #[test]
    fn last_due_respects_enabled_and_validates_bounds() {
        let now = at("2026-10-14T15:00:00Z");
        let mut disabled = schedule("daily", 8, 0, 1);
        disabled.enabled = false;
        assert_eq!(last_due(&disabled, now), None);

        let mut bad = schedule("daily", 8, 0, 1);
        bad.hour = 24;
        assert!(bad.validate().is_err());
        bad = schedule("hourly", 8, 0, 1);
        assert!(bad.validate().is_err());
        bad = schedule("weekly", 8, 0, 7);
        assert!(bad.validate().is_err());
        bad = schedule("monthly", 8, 0, 29);
        assert!(bad.validate().is_err());
        bad = schedule("daily", 8, 0, 1);
        bad.window_days = 200;
        assert!(bad.validate().is_err());
        let good = schedule("daily", 8, 0, 1);
        assert!(good.validate().is_ok());
    }

    #[test]
    fn the_action_filter_accepts_the_three_values_only() {
        assert_eq!(ActionFilter::parse(None).unwrap(), ActionFilter::All);
        assert_eq!(
            ActionFilter::parse(Some("all")).unwrap(),
            ActionFilter::All
        );
        assert_eq!(
            ActionFilter::parse(Some("blocked")).unwrap(),
            ActionFilter::Blocked
        );
        assert_eq!(
            ActionFilter::parse(Some("monitor")).unwrap(),
            ActionFilter::Monitor
        );
        assert!(ActionFilter::parse(Some("blockd")).is_err());
    }

    #[test]
    fn the_filter_keeps_placeholders_and_values_in_step() {
        let window = Window {
            from: at("2026-09-14T00:00:00Z"),
            to: at("2026-10-15T00:00:00Z"),
            site: Some(Uuid::new_v4()),
            action: ActionFilter::Blocked,
            q: Some("1.2.3".to_string()),
            tz: Tz::UTC,
        };
        let (sql, values) = window.filter();
        // from, to, site, q.
        assert_eq!(values.len(), 4);
        assert!(sql.contains("timestamp >= $1 AND timestamp < $2"));
        assert!(sql.contains("site_id = $3"));
        assert!(sql.contains("lower($4) in lower(client_ip)"));
        assert!(sql.contains("action = 'block'"));

        let bare = Window {
            from: at("2026-09-14T00:00:00Z"),
            to: at("2026-10-15T00:00:00Z"),
            site: None,
            action: ActionFilter::Monitor,
            q: None,
            tz: Tz::UTC,
        };
        let (sql, values) = bare.filter();
        assert_eq!(values.len(), 2);
        assert!(sql.contains("action <> 'block'"));
        assert!(!sql.contains("site_id"));
    }

    #[test]
    fn a_rendered_report_is_self_contained_and_escapes_data() {
        let html = render_report(ReportData {
            from: at("2026-09-14T00:00:00Z"),
            to: at("2026-10-15T00:00:00Z"),
            scope: "E2E Site".to_string(),
            actor: "admin@varman.local".to_string(),
            title: "Interception report".to_string(),
            footer_note: Some("Prepared for the weekly review.".to_string()),
            tz: Tz::UTC,
            totals: Totals {
                events: 3,
                blocked: 2,
                ips: 2,
                paths: 1,
            },
            types: vec![LabelCount {
                label: "SQL injection".to_string(),
                count: 3,
            }],
            ips: vec![IpRow {
                ip: "1.2.3.4".to_string(),
                country: "VN".to_string(),
                requests: 3,
                blocked: 2,
                last_seen: Some(at("2026-10-14T10:00:00Z")),
            }],
            ips_by_blocked: vec![IpRow {
                ip: "1.2.3.4".to_string(),
                country: "VN".to_string(),
                requests: 3,
                blocked: 2,
                last_seen: Some(at("2026-10-14T10:00:00Z")),
            }],
            paths: vec![PathRow {
                path: "/<script>alert(1)</script>".to_string(),
                requests: 3,
                blocked: 2,
            }],
            daily: vec![DailyPoint {
                date: "2026-10-14".to_string(),
                total: 3,
                blocked: 2,
            }],
        });
        assert!(html.starts_with("<!DOCTYPE html>"));
        assert!(html.contains("Interception report"));
        assert!(html.contains("E2E Site"));
        // The sample-shaped numbered sections are present.
        assert!(html.contains("1 Interception type"));
        assert!(html.contains("2 Attack IP ranking TOP20"));
        assert!(html.contains("3 IP report TOP20"));
        assert!(html.contains("4 URL report TOP20"));
        assert!(html.contains("5 Daily timeline"));
        assert!(html.contains("Prepared for the weekly review."));
        // No scripts and no external references: fully self-contained.
        assert!(!html.contains("<script"));
        assert!(!html.contains("http://"));
        assert!(!html.contains("https://"));
        // Attacker-reachable path text is escaped.
        assert!(html.contains("/&lt;script&gt;alert(1)&lt;/script&gt;"));
        assert!(!html.contains("<script>alert(1)</script>"));
    }

    #[test]
    fn a_custom_title_and_note_are_escaped_too() {
        let html = render_report(ReportData {
            from: at("2026-10-14T00:00:00Z"),
            to: at("2026-10-15T00:00:00Z"),
            scope: "All sites".to_string(),
            actor: "admin@varman.local".to_string(),
            title: "<b>Quarterly</b> review".to_string(),
            footer_note: Some("<i>note</i>".to_string()),
            tz: Tz::UTC,
            totals: Totals {
                events: 0,
                blocked: 0,
                ips: 0,
                paths: 0,
            },
            types: Vec::new(),
            ips: Vec::new(),
            ips_by_blocked: Vec::new(),
            paths: Vec::new(),
            daily: Vec::new(),
        });
        assert!(html.contains("&lt;b&gt;Quarterly&lt;/b&gt; review"));
        assert!(html.contains("&lt;i&gt;note&lt;/i&gt;"));
        assert!(!html.contains("<b>Quarterly</b>"));
    }
}
