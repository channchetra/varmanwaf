//! Alert rules and silences (`alert_rules`, `alert_silences`).
//!
//! A rule watches `security_events` (optionally scoped to one site and one
//! event type) over a sliding window and fires a notification when a metric
//! crosses its threshold — a ratio only counts once the window holds the
//! rule's minimum number of samples, so a quiet minute cannot page anyone.
//! Silences mute rules for a maintenance window (globally or per site).

use sea_orm_migration::prelude::*;

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .create_table(
                Table::create()
                    .table(AlertRules::Table)
                    .if_not_exists()
                    .col(
                        ColumnDef::new(AlertRules::Id)
                            .uuid()
                            .not_null()
                            .primary_key(),
                    )
                    .col(ColumnDef::new(AlertRules::Name).text().not_null())
                    .col(
                        ColumnDef::new(AlertRules::Enabled)
                            .boolean()
                            .not_null()
                            .default(true),
                    )
                    // `event_count` or `blocked_ratio`.
                    .col(
                        ColumnDef::new(AlertRules::Metric)
                            .string_len(32)
                            .not_null(),
                    )
                    .col(
                        ColumnDef::new(AlertRules::Threshold)
                            .double()
                            .not_null(),
                    )
                    .col(
                        ColumnDef::new(AlertRules::WindowSeconds)
                            .integer()
                            .not_null(),
                    )
                    .col(
                        ColumnDef::new(AlertRules::MinSamples)
                            .integer()
                            .not_null()
                            .default(0),
                    )
                    .col(ColumnDef::new(AlertRules::SiteId).uuid().null())
                    .col(
                        ColumnDef::new(AlertRules::EventType)
                            .text()
                            .not_null()
                            .default(""),
                    )
                    .col(
                        ColumnDef::new(AlertRules::RuleIdContains)
                            .text()
                            .not_null()
                            .default(""),
                    )
                    .col(
                        ColumnDef::new(AlertRules::Severity)
                            .string_len(16)
                            .not_null()
                            .default("warning"),
                    )
                    .col(
                        ColumnDef::new(AlertRules::Channels)
                            .json_binary()
                            .not_null()
                            .default(Expr::value("[]")),
                    )
                    .col(
                        ColumnDef::new(AlertRules::CooldownSeconds)
                            .integer()
                            .not_null()
                            .default(900),
                    )
                    .col(
                        ColumnDef::new(AlertRules::LastFiredAt)
                            .timestamp_with_time_zone()
                            .null(),
                    )
                    .col(ColumnDef::new(AlertRules::LastValue).double().null())
                    .col(
                        ColumnDef::new(AlertRules::LastSamples)
                            .integer()
                            .null(),
                    )
                    .col(
                        ColumnDef::new(AlertRules::LastEvaluatedAt)
                            .timestamp_with_time_zone()
                            .null(),
                    )
                    .col(
                        ColumnDef::new(AlertRules::CreatedAt)
                            .timestamp_with_time_zone()
                            .not_null(),
                    )
                    .col(
                        ColumnDef::new(AlertRules::UpdatedAt)
                            .timestamp_with_time_zone()
                            .not_null(),
                    )
                    .to_owned(),
            )
            .await?;

        manager
            .create_index(
                Index::create()
                    .name("idx_alert_rules_site")
                    .table(AlertRules::Table)
                    .col(AlertRules::SiteId)
                    .to_owned(),
            )
            .await?;

        manager
            .create_table(
                Table::create()
                    .table(AlertSilences::Table)
                    .if_not_exists()
                    .col(
                        ColumnDef::new(AlertSilences::Id)
                            .uuid()
                            .not_null()
                            .primary_key(),
                    )
                    .col(ColumnDef::new(AlertSilences::SiteId).uuid().null())
                    .col(
                        ColumnDef::new(AlertSilences::Reason)
                            .text()
                            .not_null()
                            .default(""),
                    )
                    .col(
                        ColumnDef::new(AlertSilences::StartsAt)
                            .timestamp_with_time_zone()
                            .not_null(),
                    )
                    .col(
                        ColumnDef::new(AlertSilences::EndsAt)
                            .timestamp_with_time_zone()
                            .null(),
                    )
                    .col(
                        ColumnDef::new(AlertSilences::CreatedBy)
                            .text()
                            .not_null()
                            .default(""),
                    )
                    .col(
                        ColumnDef::new(AlertSilences::CreatedAt)
                            .timestamp_with_time_zone()
                            .not_null(),
                    )
                    .to_owned(),
            )
            .await?;

        manager
            .create_index(
                Index::create()
                    .name("idx_alert_silences_site")
                    .table(AlertSilences::Table)
                    .col(AlertSilences::SiteId)
                    .to_owned(),
            )
            .await
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .drop_table(
                Table::drop()
                    .table(AlertSilences::Table)
                    .if_exists()
                    .to_owned(),
            )
            .await?;
        manager
            .drop_table(
                Table::drop()
                    .table(AlertRules::Table)
                    .if_exists()
                    .to_owned(),
            )
            .await
    }
}

#[derive(DeriveIden)]
enum AlertRules {
    Table,
    Id,
    Name,
    Enabled,
    Metric,
    Threshold,
    WindowSeconds,
    MinSamples,
    SiteId,
    EventType,
    RuleIdContains,
    Severity,
    Channels,
    CooldownSeconds,
    LastFiredAt,
    LastValue,
    LastSamples,
    LastEvaluatedAt,
    CreatedAt,
    UpdatedAt,
}

#[derive(DeriveIden)]
enum AlertSilences {
    Table,
    Id,
    SiteId,
    Reason,
    StartsAt,
    EndsAt,
    CreatedBy,
    CreatedAt,
}
