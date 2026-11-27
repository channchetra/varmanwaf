//! Scheduled interception report delivery.
//!
//! The dashboard saves a cron-style schedule with the report settings; this
//! module owns that schedule and the tick that fires it. A due report is
//! generated through [`crate::report`] and dispatched through the
//! notification channels (e-mail channels attach the HTML).
//!
//! The REST handlers live in [`crate::api::reports`]; they read and write the
//! same settings row and can fire a report on demand with [`fire`].

use chrono::{DateTime, Duration, Utc};
use sea_orm::{ActiveModelTrait, DatabaseConnection, EntityTrait};
use serde::{Deserialize, Serialize};

use crate::api_util::parse_uuid;
use crate::error::ApiError;
use crate::models::instance_setting;
use crate::notify::{self, AlertAttachment, AlertEvent};
use crate::report::{self, ActionFilter, ReportData, Window, MAX_RANGE_DAYS};
use crate::time_util::timezone;

/// Key of the report settings row in `instance_settings`.
const SETTINGS_KEY: &str = "report_settings";

/// How often the scheduler checks for a due report.
const SCHEDULER_TICK: std::time::Duration = std::time::Duration::from_secs(60);

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
    pub(crate) fn validate(&self) -> Result<(), ApiError> {
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

/// Loads the operator's report settings (heading and footer note); defaults
/// when absent, like the other instance-setting blocks.
pub(crate) async fn load_settings(
    db: &sea_orm::DatabaseConnection,
) -> ReportSettings {
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

/// Persists the settings row (used by the save handler and the scheduler's
/// `last_fired` bookkeeping).
pub(crate) async fn store_settings(
    db: &sea_orm::DatabaseConnection,
    settings: &ReportSettings,
) -> Result<(), ApiError> {
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

/// Generates the report for the schedule's window/scope and dispatches it
/// through the notification channels (e-mail channels attach the HTML).
pub(crate) async fn fire(
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
        tz: timezone(db).await,
    };

    let totals = report::totals(db, &window).await?;
    let events = totals.events;
    let blocked = totals.blocked;
    let monitored = events - blocked;
    let types = report::type_rows(db, &window).await?;
    let ips = report::top_ips(db, &window).await?;
    let ips_by_blocked = report::top_ips_by_blocked(db, &window).await?;
    let paths = report::top_paths(db, &window).await?;
    let daily = report::daily(db, &window).await?;

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

    let html = report::render_report(ReportData {
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

#[cfg(test)]
mod tests {
    use super::*;

    fn at(raw: &str) -> DateTime<Utc> {
        DateTime::parse_from_rfc3339(raw)
            .expect("test instant")
            .with_timezone(&Utc)
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
}
