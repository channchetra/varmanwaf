//! Interception report generation: the aggregations over `security_events`
//! and the self-contained HTML document.
//!
//! Nothing here touches a request or a response. The REST handlers in
//! [`crate::api::reports`] and the scheduled delivery in
//! [`crate::report_scheduler`] both call into this module, so a report
//! produced on demand and one produced on a schedule are the same document.
//!
//! Every aggregation is bounded: a range is capped at [`MAX_RANGE_DAYS`]
//! days, the ranking lists at [`TOP_ROWS`] rows, and the daily series by the
//! range itself.
//!
//! The HTML is built with inline styles only (no scripts, no external
//! assets) so it renders offline and prints to A4 cleanly. Every piece of
//! stored data - paths, IPs, rule names - is attacker-reachable, so it is
//! HTML-escaped on the way in.

use std::collections::HashMap;
use std::fmt::Write as _;

use chrono::{DateTime, Duration, Utc};
use chrono_tz::Tz;
use sea_orm::{DatabaseConnection, Value};
use serde::Serialize;
use uuid::Uuid;

use crate::api::common::query_all;
use crate::error::ApiError;

/// Longest range a report may cover.
pub(crate) const MAX_RANGE_DAYS: i64 = 92;
/// Rows in each ranking list.
const TOP_ROWS: i64 = 20;

/// The action filter a report was generated with.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ActionFilter {
    All,
    Blocked,
    Monitor,
}

impl ActionFilter {
    pub(crate) fn parse(raw: Option<&str>) -> Result<Self, ApiError> {
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

pub(crate) struct Window {
    pub(crate) from: DateTime<Utc>,
    pub(crate) to: DateTime<Utc>,
    pub(crate) site: Option<Uuid>,
    pub(crate) action: ActionFilter,
    /// Substring filter over client IP and path; `None` = no filter.
    pub(crate) q: Option<String>,
    /// The instance timezone: date-only bounds and daily buckets follow it.
    pub(crate) tz: Tz,
}

impl Window {
    /// `WHERE` fragment and bound values over `security_events`. Placeholders
    /// are numbered in insertion order, so every aggregation shares the exact
    /// same filter.
    pub(crate) fn filter(&self) -> (String, Vec<Value>) {
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

/* ── Aggregations ─────────────────────────────────────────────────── */

pub(crate) struct Totals {
    pub(crate) events: i64,
    pub(crate) blocked: i64,
    pub(crate) ips: i64,
    pub(crate) paths: i64,
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

pub(crate) async fn totals(
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
pub(crate) async fn type_rows(
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

pub(crate) async fn top_country(
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

pub(crate) struct IpRow {
    pub(crate) ip: String,
    pub(crate) country: String,
    pub(crate) requests: i64,
    pub(crate) blocked: i64,
    pub(crate) last_seen: Option<DateTime<Utc>>,
}

pub(crate) async fn top_ips(
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
pub(crate) async fn top_ips_by_blocked(
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

pub(crate) struct PathRow {
    pub(crate) path: String,
    pub(crate) requests: i64,
    pub(crate) blocked: i64,
}

pub(crate) async fn top_paths(
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

pub(crate) async fn daily(
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

/* ── HTML rendering ───────────────────────────────────────────────── */

pub(crate) struct ReportData {
    pub(crate) from: DateTime<Utc>,
    pub(crate) to: DateTime<Utc>,
    pub(crate) scope: String,
    pub(crate) actor: String,
    /// Operator-customizable heading (report settings).
    pub(crate) title: String,
    /// Optional operator note printed above the data-source note.
    pub(crate) footer_note: Option<String>,
    /// Instance timezone: the cover and filenames print local dates.
    pub(crate) tz: Tz,
    pub(crate) totals: Totals,
    pub(crate) types: Vec<LabelCount>,
    pub(crate) ips: Vec<IpRow>,
    /// Attack-IP ranking (ordered by blocked count).
    pub(crate) ips_by_blocked: Vec<IpRow>,
    pub(crate) paths: Vec<PathRow>,
    pub(crate) daily: Vec<DailyPoint>,
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

pub(crate) fn render_report(data: ReportData) -> String {
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
