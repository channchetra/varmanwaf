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
use axum::routing::get;
use axum::{Json, Router};
use chrono::{DateTime, Duration, NaiveDate, Utc};
use sea_orm::{EntityTrait, Value};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::api::common::{load_site_read, parse_uuid, query_all};
use crate::api::error::ApiError;
use crate::api::state::AppState;
use crate::auth::AuthUser;

/// Longest range a report may cover.
const MAX_RANGE_DAYS: i64 = 92;
/// Rows in each ranking list.
const TOP_ROWS: i64 = 20;

/// Routes contributed to `/api/v1`.
pub fn routes() -> Router<AppState> {
    Router::new()
        .route("/reports/summary", get(summary))
        .route("/reports/interception", get(interception_report))
}

#[derive(Debug, Deserialize)]
pub struct ReportQuery {
    /// Inclusive start: `YYYY-MM-DD` or RFC 3339. Defaults to 24h before `to`.
    pub from: Option<String>,
    /// End: `YYYY-MM-DD` (whole day) or RFC 3339. Defaults to now.
    pub to: Option<String>,
    /// One site; omitted aggregates every site the administrator can see.
    pub site_id: Option<String>,
}

struct Window {
    from: DateTime<Utc>,
    to: DateTime<Utc>,
    site: Option<Uuid>,
}

impl Window {
    /// `WHERE` fragment and bound values over `security_events`.
    fn filter(&self) -> (String, Vec<Value>) {
        let mut sql = String::from("timestamp >= $1 AND timestamp < $2");
        let mut values = vec![self.from.into(), self.to.into()];
        if let Some(site) = self.site {
            sql.push_str(" AND site_id = $3");
            values.push(site.into());
        }
        (sql, values)
    }
}

async fn resolve_window(
    state: &AppState,
    current: &AuthUser,
    query: &ReportQuery,
) -> Result<Window, ApiError> {
    let (from, to) =
        window_bounds(query.from.as_deref(), query.to.as_deref(), Utc::now())?;
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
    Ok(Window { from, to, site })
}

/// Resolves the requested bounds: date-only inputs, RFC 3339 instants, the
/// 24-hour default and the 92-day cap. Pure so it is unit-testable.
fn window_bounds(
    from: Option<&str>,
    to: Option<&str>,
    now: DateTime<Utc>,
) -> Result<(DateTime<Utc>, DateTime<Utc>), ApiError> {
    let to = match to.map(str::trim).filter(|raw| !raw.is_empty()) {
        Some(raw) => parse_bound(raw, true)?,
        None => now,
    };
    let from = match from.map(str::trim).filter(|raw| !raw.is_empty()) {
        Some(raw) => parse_bound(raw, false)?,
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

/// Parses one bound: RFC 3339, or a bare `YYYY-MM-DD` (an end date covers
/// that whole day).
fn parse_bound(raw: &str, is_end: bool) -> Result<DateTime<Utc>, ApiError> {
    if let Ok(instant) = DateTime::parse_from_rfc3339(raw) {
        return Ok(instant.with_timezone(&Utc));
    }
    if let Ok(day) = NaiveDate::parse_from_str(raw, "%Y-%m-%d") {
        let midnight = day
            .and_hms_opt(0, 0, 0)
            .expect("midnight is a valid time")
            .and_utc();
        return Ok(if is_end {
            midnight + Duration::days(1)
        } else {
            midnight
        });
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

async fn totals(state: &AppState, window: &Window) -> Result<Totals, ApiError> {
    let (filter, values) = window.filter();
    let sql = format!(
        "SELECT COUNT(*) AS events, \
                COUNT(*) FILTER (WHERE action = 'block') AS blocked, \
                COUNT(DISTINCT client_ip) AS ips, \
                COUNT(DISTINCT path) AS paths \
         FROM security_events WHERE {filter}"
    );
    let row = query_all(&state.db, &sql, values).await?.into_iter().next();
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
    state: &AppState,
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
    let rows = query_all(&state.db, &sql, values).await?;
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
    state: &AppState,
    window: &Window,
) -> Result<Option<LabelCount>, ApiError> {
    let (filter, values) = window.filter();
    let sql = format!(
        "SELECT country_code, COUNT(*) AS n FROM security_events \
         WHERE {filter} AND country_code IS NOT NULL AND country_code <> '' \
         GROUP BY 1 ORDER BY n DESC LIMIT 1"
    );
    let row = query_all(&state.db, &sql, values).await?.into_iter().next();
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
    state: &AppState,
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
    Ok(query_all(&state.db, &sql, values)
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
    state: &AppState,
    window: &Window,
) -> Result<Vec<PathRow>, ApiError> {
    let (filter, values) = window.filter();
    let sql = format!(
        "SELECT COALESCE(path, '') AS path, COUNT(*) AS requests, \
                COUNT(*) FILTER (WHERE action = 'block') AS blocked \
         FROM security_events WHERE {filter} \
         GROUP BY 1 ORDER BY requests DESC LIMIT {TOP_ROWS}"
    );
    Ok(query_all(&state.db, &sql, values)
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
    state: &AppState,
    window: &Window,
) -> Result<Vec<DailyPoint>, ApiError> {
    let (filter, values) = window.filter();
    let sql = format!(
        "SELECT to_char(timestamp AT TIME ZONE 'UTC', 'YYYY-MM-DD') AS day, \
                COUNT(*) AS total, \
                COUNT(*) FILTER (WHERE action = 'block') AS blocked \
         FROM security_events WHERE {filter} GROUP BY 1 ORDER BY 1"
    );
    Ok(query_all(&state.db, &sql, values)
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

    let totals = totals(&state, &window).await?;
    let types = type_rows(&state, &window).await?;
    let country = top_country(&state, &window).await?;
    let ips = top_ips(&state, &window).await?;
    let daily = daily(&state, &window).await?;

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

    let totals = totals(&state, &window).await?;
    let types = type_rows(&state, &window).await?;
    let ips = top_ips(&state, &window).await?;
    let paths = top_paths(&state, &window).await?;
    let daily = daily(&state, &window).await?;

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
        totals,
        types,
        ips,
        paths,
        daily,
    });

    let from_label = window.from.date_naive();
    let to_label = (window.to - Duration::seconds(1)).date_naive();
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

/* ── HTML rendering ───────────────────────────────────────────────── */

struct ReportData {
    from: DateTime<Utc>,
    to: DateTime<Utc>,
    scope: String,
    actor: String,
    totals: Totals,
    types: Vec<LabelCount>,
    ips: Vec<IpRow>,
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
";

fn render_report(data: ReportData) -> String {
    let mut html = String::with_capacity(32 * 1024);
    let from_label = data.from.date_naive();
    let to_label = (data.to - Duration::seconds(1)).date_naive();
    let generated = Utc::now().format("%Y-%m-%d %H:%M UTC");

    html.push_str(
        "<!DOCTYPE html>\n<html lang=\"en\"><head><meta charset=\"utf-8\">",
    );
    let _ = write!(
        html,
        "<title>VarmanWAF interception report {from_label} to {to_label}</title>\
         <style>{STYLE}</style></head><body>"
    );
    html.push_str("<div class=\"brand\">VarmanWAF</div>");
    let _ = write!(html, "<h1>Interception report</h1>");
    let _ = write!(
        html,
        "<p class=\"meta\">Range {from_label} to {to_label} &middot; Scope: \
         {} &middot; Generated {generated} by {}</p>",
        escape_html(&data.scope),
        escape_html(&data.actor),
    );

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
    html.push_str("<h2>Interception types</h2>");
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
    html.push_str("<h2>Daily timeline</h2>");
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

    // Attack IP ranking.
    html.push_str("<h2>Attack IP ranking (top 20)</h2>");
    if data.ips.is_empty() {
        html.push_str(
            "<p class=\"meta\">No source addresses in this range.</p>",
        );
    } else {
        html.push_str(
            "<table><thead><tr><th class=\"num\">#</th><th>Client IP</th>\
             <th>Country</th><th class=\"num\">Interceptions</th>\
             <th class=\"num\">Blocked</th><th>Last seen</th></tr></thead>\
             <tbody>",
        );
        for (index, row) in data.ips.iter().enumerate() {
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
                row.requests,
                row.blocked,
                escape_html(&last),
            );
        }
        html.push_str("</tbody></table>");
    }

    // URL ranking.
    html.push_str("<h2>URL ranking (top 20)</h2>");
    if data.paths.is_empty() {
        html.push_str("<p class=\"meta\">No paths in this range.</p>");
    } else {
        html.push_str(
            "<table><thead><tr><th class=\"num\">#</th><th>Path</th>\
             <th class=\"num\">Interceptions</th>\
             <th class=\"num\">Blocked</th></tr></thead><tbody>",
        );
        for (index, row) in data.paths.iter().enumerate() {
            let _ = write!(
                html,
                "<tr><td class=\"num\">{}</td><td class=\"mono\">{}</td>\
                 <td class=\"num\">{}</td><td class=\"num\">{}</td></tr>",
                index + 1,
                escape_html(&row.path),
                row.requests,
                row.blocked,
            );
        }
        html.push_str("</tbody></table>");
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
        let (from, to) = window_bounds(None, None, now).unwrap();
        assert_eq!(to, now);
        assert_eq!(from, at("2026-10-13T12:00:00Z"));
    }

    #[test]
    fn a_bare_end_date_covers_that_whole_day() {
        let now = at("2026-10-14T12:00:00Z");
        let (from, to) =
            window_bounds(Some("2026-09-14"), Some("2026-10-14"), now).unwrap();
        assert_eq!(from, at("2026-09-14T00:00:00Z"));
        assert_eq!(to, at("2026-10-15T00:00:00Z"));
    }

    #[test]
    fn windows_validate_order_and_the_cap() {
        let now = at("2026-10-14T12:00:00Z");
        assert!(
            window_bounds(Some("2026-10-14"), Some("2026-10-14"), now).is_ok()
        );
        assert!(
            window_bounds(Some("2026-10-15"), Some("2026-10-14"), now).is_err()
        );
        assert!(
            window_bounds(Some("2026-01-01"), Some("2026-10-14"), now).is_err()
        );
        assert!(window_bounds(Some("nonsense"), None, now).is_err());
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

    #[test]
    fn a_rendered_report_is_self_contained_and_escapes_data() {
        let html = render_report(ReportData {
            from: at("2026-09-14T00:00:00Z"),
            to: at("2026-10-15T00:00:00Z"),
            scope: "E2E Site".to_string(),
            actor: "admin@varman.local".to_string(),
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
        // No scripts and no external references: fully self-contained.
        assert!(!html.contains("<script"));
        assert!(!html.contains("http://"));
        assert!(!html.contains("https://"));
        // Attacker-reachable path text is escaped.
        assert!(html.contains("/&lt;script&gt;alert(1)&lt;/script&gt;"));
        assert!(!html.contains("<script>alert(1)</script>"));
    }
}
