//! Security alert rules: threshold conditions over stored security events.
//!
//! Two metrics, both over a sliding window:
//!
//! - `event_count` - matching security events. Fires at
//!   `count >= threshold`.
//! - `blocked_ratio` - blocked events as a percentage of the requests seen
//!   in the same window (`access_logs` is the denominator). Fires at
//!   `ratio >= threshold` **once the window holds `min_samples` requests**,
//!   so a single blocked probe in a quiet minute cannot page anyone.
//!
//! Rules are evaluated on a tick. A firing rule raises a `security.alert`
//! notification through the notification manager (cooldown-limited, muted by
//! active silences), and its last observation is stored on the rule row so
//! the console can show what the last evaluation saw.

use std::time::Duration;

use chrono::{DateTime, Duration as ChronoDuration, Utc};
use sea_orm::{
    ActiveModelTrait, ColumnTrait, DatabaseConnection, DbErr, EntityTrait,
    PaginatorTrait, QueryFilter, QueryOrder, Set,
};
use serde_json::{json, Value};
use uuid::Uuid;

use crate::models::alerts::METRIC_BLOCKED_RATIO;
use crate::models::{
    access_log, alert_rule, alert_silence, event_type, security_event, severity,
};
use crate::notify::{self, AlertEvent};

/// How often enabled rules are evaluated.
pub const TICK: Duration = Duration::from_secs(30);
/// Window bounds in seconds.
pub const MIN_WINDOW: i32 = 60;
pub const MAX_WINDOW: i32 = 86_400;
/// Cooldown bounds in seconds.
pub const MIN_COOLDOWN: i32 = 60;
pub const MAX_COOLDOWN: i32 = 86_400;
/// Actions that count as blocked for the ratio metric. Mirrors the decision
/// vocabulary the edge records in `security_events.action`.
const BLOCKING_ACTIONS: [&str; 3] = ["block", "deny", "drop"];

/// One rule's observation for a window.
#[derive(Debug, Clone)]
pub struct Evaluation {
    /// Metric value: the event count, or the blocked ratio in percent.
    pub value: f64,
    /// Events counted (`event_count`) or blocked events (`blocked_ratio`).
    pub hits: i64,
    /// Requests seen in the window; equals `hits` for `event_count`.
    pub samples: i64,
    /// Whether the threshold (and minimum samples) is met.
    pub threshold_met: bool,
}

/// Pure threshold check; the tested heart of the evaluator.
pub fn threshold_met(
    metric: &str,
    value: f64,
    samples: i64,
    threshold: f64,
    min_samples: i64,
) -> bool {
    if !threshold.is_finite() {
        return false;
    }
    match metric {
        METRIC_BLOCKED_RATIO => samples >= min_samples && value >= threshold,
        _ => value >= threshold,
    }
}

/// The channel ids a rule binds (`channels` jsonb); invalid entries are
/// skipped - the API validates on write.
pub fn channel_ids(rule: &alert_rule::Model) -> Vec<Uuid> {
    rule.channels
        .as_array()
        .map(|items| {
            items
                .iter()
                .filter_map(Value::as_str)
                .filter_map(|raw| Uuid::parse_str(raw).ok())
                .collect()
        })
        .unwrap_or_default()
}

/// The active silence muting this rule's scope, if any.
///
/// A **global** silence (`site_id IS NULL`) mutes every rule. A **site**
/// silence mutes rules scoped to that site; it deliberately does not mute a
/// site-agnostic rule, whose value mixes every site and would otherwise hide
/// alerts about sites that are not in maintenance.
pub async fn silenced(
    db: &DatabaseConnection,
    site: Option<Uuid>,
    now: DateTime<Utc>,
) -> Result<Option<alert_silence::Model>, DbErr> {
    let scope = match site {
        Some(id) => sea_orm::Condition::any()
            .add(alert_silence::Column::SiteId.is_null())
            .add(alert_silence::Column::SiteId.eq(id)),
        None => sea_orm::Condition::any()
            .add(alert_silence::Column::SiteId.is_null()),
    };
    alert_silence::Entity::find()
        .filter(alert_silence::Column::StartsAt.lte(now))
        .filter(
            sea_orm::Condition::any()
                .add(alert_silence::Column::EndsAt.is_null())
                .add(alert_silence::Column::EndsAt.gte(now)),
        )
        .filter(scope)
        .one(db)
        .await
}

fn apply_filters(
    query: sea_orm::Select<security_event::Entity>,
    rule: &alert_rule::Model,
    since: DateTime<Utc>,
) -> sea_orm::Select<security_event::Entity> {
    let mut query = query.filter(security_event::Column::Timestamp.gte(since));
    if let Some(site) = rule.site_id {
        query = query.filter(security_event::Column::SiteId.eq(site));
    }
    if !rule.event_type.trim().is_empty() {
        query = query.filter(
            security_event::Column::EventType.eq(rule.event_type.trim()),
        );
    }
    if !rule.rule_id_contains.trim().is_empty() {
        query = query.filter(
            security_event::Column::RuleId
                .contains(rule.rule_id_contains.trim()),
        );
    }
    query
}

/// Evaluates one rule over its window. Never dispatches.
pub async fn evaluate(
    db: &DatabaseConnection,
    rule: &alert_rule::Model,
    now: DateTime<Utc>,
) -> Result<Evaluation, DbErr> {
    let since = now - ChronoDuration::seconds(rule.window_seconds as i64);
    match rule.metric.as_str() {
        METRIC_BLOCKED_RATIO => {
            let blocked = apply_filters(
                security_event::Entity::find().filter(
                    security_event::Column::Action.is_in(BLOCKING_ACTIONS),
                ),
                rule,
                since,
            )
            .count(db)
            .await? as i64;
            let mut requests = access_log::Entity::find()
                .filter(access_log::Column::Timestamp.gte(since));
            if let Some(site) = rule.site_id {
                requests = requests.filter(access_log::Column::SiteId.eq(site));
            }
            let samples = requests.count(db).await? as i64;
            let value = if samples == 0 {
                0.0
            } else {
                blocked as f64 / samples as f64 * 100.0
            };
            Ok(Evaluation {
                value,
                hits: blocked,
                samples,
                threshold_met: threshold_met(
                    &rule.metric,
                    value,
                    samples,
                    rule.threshold,
                    rule.min_samples as i64,
                ),
            })
        },
        _ => {
            let hits =
                apply_filters(security_event::Entity::find(), rule, since)
                    .count(db)
                    .await? as i64;
            let value = hits as f64;
            Ok(Evaluation {
                value,
                hits,
                samples: hits,
                threshold_met: threshold_met(
                    &rule.metric,
                    value,
                    hits,
                    rule.threshold,
                    rule.min_samples as i64,
                ),
            })
        },
    }
}

/// The most frequent rule id in the rule's window, for the alert message.
async fn top_rule(
    db: &DatabaseConnection,
    rule: &alert_rule::Model,
    since: DateTime<Utc>,
) -> Result<Option<(String, i64)>, DbErr> {
    use sea_orm::sea_query::{Alias, Expr};
    use sea_orm::QuerySelect;

    let mut query = security_event::Entity::find()
        .filter(security_event::Column::Timestamp.gte(since))
        .filter(security_event::Column::RuleId.is_not_null())
        .filter(security_event::Column::RuleId.ne(""));
    if let Some(site) = rule.site_id {
        query = query.filter(security_event::Column::SiteId.eq(site));
    }
    if !rule.event_type.trim().is_empty() {
        query = query.filter(
            security_event::Column::EventType.eq(rule.event_type.trim()),
        );
    }
    if !rule.rule_id_contains.trim().is_empty() {
        query = query.filter(
            security_event::Column::RuleId
                .contains(rule.rule_id_contains.trim()),
        );
    }
    let rows = query
        .select_only()
        .column(security_event::Column::RuleId)
        .column_as(security_event::Column::Id.count(), "hits")
        .group_by(security_event::Column::RuleId)
        .order_by_desc(Expr::col(Alias::new("hits")))
        .limit(1)
        .into_tuple::<(String, i64)>()
        .all(db)
        .await?;
    Ok(rows.into_iter().next())
}

/// Fires one rule: raises the notification and returns the message used.
async fn fire(
    db: &DatabaseConnection,
    rule: &alert_rule::Model,
    evaluation: &Evaluation,
    now: DateTime<Utc>,
) -> String {
    let since = now - ChronoDuration::seconds(rule.window_seconds as i64);
    let top = top_rule(db, rule, since).await.ok().flatten();

    let summary = if rule.metric == METRIC_BLOCKED_RATIO {
        format!(
            "{} of {} requests blocked ({:.1}%, threshold {:.1}%) in the last {}s",
            evaluation.hits, evaluation.samples, evaluation.value,
            rule.threshold, rule.window_seconds
        )
    } else {
        format!(
            "{} matching events in the last {}s (threshold {})",
            evaluation.hits, rule.window_seconds, rule.threshold
        )
    };
    let mut details = json!({
        "rule_id": rule.id,
        "rule_name": rule.name,
        "metric": rule.metric,
        "value": evaluation.value,
        "threshold": rule.threshold,
        "hits": evaluation.hits,
        "samples": evaluation.samples,
        "window_seconds": rule.window_seconds,
        "site_id": rule.site_id,
        "evaluated_at": now,
    });
    if let Some((rule_id, hits)) = &top {
        details["top_rule_id"] = json!(rule_id);
        details["top_rule_hits"] = json!(hits);
    }

    let severity = match rule.severity.as_str() {
        severity::INFO => severity::INFO,
        severity::CRITICAL => severity::CRITICAL,
        _ => severity::WARNING,
    };
    let channels = channel_ids(rule);
    notify::emit_to(
        AlertEvent {
            event_type: event_type::SECURITY_ALERT.to_string(),
            severity,
            title: format!("{}: {summary}", rule.name),
            message: summary.clone(),
            details: Some(details),
            dedup_key: Some(rule.id.to_string()),
        },
        if channels.is_empty() {
            None
        } else {
            Some(channels)
        },
    )
    .await;
    summary
}

/// Evaluates every enabled rule once: stores the observation and fires the
/// rules whose threshold is met, cooling down and silences permitting.
/// Returns how many rules fired.
pub async fn run_tick(
    db: &DatabaseConnection,
    now: DateTime<Utc>,
) -> Result<usize, DbErr> {
    let rules = alert_rule::Entity::find()
        .filter(alert_rule::Column::Enabled.eq(true))
        .order_by_asc(alert_rule::Column::Name)
        .all(db)
        .await?;
    let mut fired = 0;
    for rule in rules {
        let evaluation = evaluate(db, &rule, now).await?;
        let mut should_fire = evaluation.threshold_met;
        if should_fire {
            let cooled = rule.last_fired_at.is_none_or(|last| {
                now - last
                    >= ChronoDuration::seconds(rule.cooldown_seconds as i64)
            });
            if !cooled {
                should_fire = false;
            }
        }
        if should_fire {
            if let Some(silence) = silenced(db, rule.site_id, now).await? {
                tracing::info!(
                    rule = %rule.name,
                    silence = %silence.id,
                    "alert rule met its threshold inside a silence; not firing"
                );
                should_fire = false;
            }
        }

        let mut active: alert_rule::ActiveModel = rule.clone().into();
        active.last_value = Set(Some(evaluation.value));
        active.last_samples = Set(Some(evaluation.samples as i32));
        active.last_evaluated_at = Set(Some(now));
        if should_fire {
            let summary = fire(db, &rule, &evaluation, now).await;
            active.last_fired_at = Set(Some(now));
            fired += 1;
            tracing::info!(
                rule = %rule.name,
                summary = %summary,
                "security alert fired"
            );
        }
        active.update(db).await?;
    }
    Ok(fired)
}

/// Starts the evaluation loop; the returned handle is detached in
/// production but usable in tests.
pub fn spawn(db: DatabaseConnection) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let mut ticker = tokio::time::interval(TICK);
        ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        loop {
            ticker.tick().await;
            match run_tick(&db, Utc::now()).await {
                Ok(0) => {},
                Ok(fired) => {
                    tracing::info!(fired, "security alert rules evaluated")
                },
                Err(err) => tracing::warn!(
                    error = %err,
                    "security alert evaluation failed"
                ),
            }
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::alerts::METRIC_EVENT_COUNT;

    #[test]
    fn count_metric_fires_at_threshold() {
        assert!(threshold_met(METRIC_EVENT_COUNT, 5.0, 5, 5.0, 0));
        assert!(!threshold_met(METRIC_EVENT_COUNT, 4.0, 4, 5.0, 0));
    }

    #[test]
    fn ratio_metric_needs_minimum_samples() {
        // A single blocked request (100%) must not fire with min_samples 10.
        assert!(!threshold_met(METRIC_BLOCKED_RATIO, 100.0, 1, 20.0, 10));
        assert!(threshold_met(METRIC_BLOCKED_RATIO, 25.0, 10, 20.0, 10));
        assert!(!threshold_met(METRIC_BLOCKED_RATIO, 19.9, 100, 20.0, 10));
    }

    #[test]
    fn threshold_must_be_finite() {
        assert!(!threshold_met(METRIC_EVENT_COUNT, 10.0, 10, f64::NAN, 0));
        assert!(!threshold_met(
            METRIC_BLOCKED_RATIO,
            10.0,
            10,
            f64::INFINITY,
            0
        ));
    }

    #[test]
    fn channel_ids_skip_invalid_entries() {
        let rule = alert_rule::Model {
            id: Uuid::new_v4(),
            name: "test".to_string(),
            enabled: true,
            metric: METRIC_EVENT_COUNT.to_string(),
            threshold: 1.0,
            window_seconds: 300,
            min_samples: 0,
            site_id: None,
            event_type: String::new(),
            rule_id_contains: String::new(),
            severity: severity::WARNING.to_string(),
            channels: serde_json::json!([
                "8e7f8d38-2b4e-4f0a-9f1e-5b0e2c3f4a5b",
                "not-a-uuid",
                42
            ]),
            cooldown_seconds: 900,
            last_fired_at: None,
            last_value: None,
            last_samples: None,
            last_evaluated_at: None,
            created_at: Utc::now(),
            updated_at: Utc::now(),
        };
        let ids = channel_ids(&rule);
        assert_eq!(ids.len(), 1);
        assert_eq!(ids[0].to_string(), "8e7f8d38-2b4e-4f0a-9f1e-5b0e2c3f4a5b");
    }
}
