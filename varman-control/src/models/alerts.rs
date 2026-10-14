//! Alert-rule and silence entities.
//!
//! `alert_rules` watches security events over a sliding window (see
//! [`crate::alerts`]); `alert_silences` mutes firing during maintenance.

use sea_orm::entity::prelude::*;
use serde::{Deserialize, Serialize};

/// Metric a rule evaluates: raw count of matching security events.
pub const METRIC_EVENT_COUNT: &str = "event_count";
/// Metric a rule evaluates: blocked events as a percentage of requests.
pub const METRIC_BLOCKED_RATIO: &str = "blocked_ratio";

pub const METRICS: [&str; 2] = [METRIC_EVENT_COUNT, METRIC_BLOCKED_RATIO];

/// `alert_rules` - threshold rules over security events.
pub mod alert_rules {
    use super::*;

    #[derive(
        Clone, Debug, PartialEq, DeriveEntityModel, Serialize, Deserialize,
    )]
    #[sea_orm(table_name = "alert_rules")]
    pub struct Model {
        #[sea_orm(primary_key, auto_increment = false)]
        pub id: Uuid,
        pub name: String,
        pub enabled: bool,
        /// One of [`super::METRICS`].
        pub metric: String,
        /// Counts: fire at `>= threshold` events. Ratios: fire at
        /// `>= threshold` percent once the window holds `min_samples`
        /// requests.
        pub threshold: f64,
        pub window_seconds: i32,
        /// Minimum window samples for ratio metrics (minimum requests);
        /// ignored by `event_count`.
        pub min_samples: i32,
        /// Restrict to one site; NULL watches every site.
        pub site_id: Option<Uuid>,
        /// Restrict to one event type (`waf`, `rate_limit`, …); empty
        /// watches all.
        pub event_type: String,
        /// Restrict to events whose rule id contains this text (`:rl:`
        /// catches rate-limit rules, `virtual-patch:` imported CRS rules);
        /// empty watches all.
        pub rule_id_contains: String,
        /// Notification severity: `info`, `warning` or `critical`.
        pub severity: String,
        /// Notification channel ids to deliver to; empty delivers to every
        /// channel subscribed to `security.alert`.
        #[sea_orm(column_type = "JsonBinary")]
        pub channels: Json,
        /// Minimum seconds between two firings of this rule.
        pub cooldown_seconds: i32,
        pub last_fired_at: Option<DateTimeUtc>,
        /// Value and sample count seen at the last evaluation, for the
        /// console's "what did it see" column.
        pub last_value: Option<f64>,
        pub last_samples: Option<i32>,
        pub last_evaluated_at: Option<DateTimeUtc>,
        pub created_at: DateTimeUtc,
        pub updated_at: DateTimeUtc,
    }

    #[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
    pub enum Relation {}

    impl ActiveModelBehavior for ActiveModel {}
}

/// `alert_silences` - maintenance windows that mute alert rules.
pub mod alert_silences {
    use super::*;

    #[derive(
        Clone, Debug, PartialEq, DeriveEntityModel, Serialize, Deserialize,
    )]
    #[sea_orm(table_name = "alert_silences")]
    pub struct Model {
        #[sea_orm(primary_key, auto_increment = false)]
        pub id: Uuid,
        /// Mute only this site's rules; NULL mutes every rule.
        pub site_id: Option<Uuid>,
        pub reason: String,
        pub starts_at: DateTimeUtc,
        /// NULL means "until deleted".
        pub ends_at: Option<DateTimeUtc>,
        /// Actor that created the silence (audit trail).
        pub created_by: String,
        pub created_at: DateTimeUtc,
    }

    #[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
    pub enum Relation {}

    impl ActiveModelBehavior for ActiveModel {}
}
