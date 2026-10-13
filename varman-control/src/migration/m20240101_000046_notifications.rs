//! Adds the notification tables.
//!
//! `notification_channels` holds the user-configured delivery targets (e-mail
//! via SMTP, WeCom / DingTalk / generic webhooks). `notification_events` is
//! the alert history the dashboard shows: one row per dispatched event,
//! regardless of how many channels received it.

use sea_orm_migration::prelude::*;

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .create_table(
                Table::create()
                    .table(NotificationChannels::Table)
                    .if_not_exists()
                    .col(
                        ColumnDef::new(NotificationChannels::Id)
                            .uuid()
                            .not_null()
                            .primary_key(),
                    )
                    .col(
                        ColumnDef::new(NotificationChannels::Name)
                            .string_len(100)
                            .not_null(),
                    )
                    .col(
                        ColumnDef::new(NotificationChannels::Kind)
                            .string_len(20)
                            .not_null(),
                    )
                    .col(
                        ColumnDef::new(NotificationChannels::Config)
                            .json()
                            .not_null(),
                    )
                    .col(
                        ColumnDef::new(NotificationChannels::Events)
                            .json()
                            .not_null(),
                    )
                    .col(
                        ColumnDef::new(NotificationChannels::Enabled)
                            .boolean()
                            .not_null()
                            .default(true),
                    )
                    .col(
                        ColumnDef::new(NotificationChannels::CreatedAt)
                            .timestamp_with_time_zone()
                            .not_null(),
                    )
                    .col(
                        ColumnDef::new(NotificationChannels::UpdatedAt)
                            .timestamp_with_time_zone()
                            .not_null(),
                    )
                    .to_owned(),
            )
            .await?;

        manager
            .create_table(
                Table::create()
                    .table(NotificationEvents::Table)
                    .if_not_exists()
                    .col(
                        ColumnDef::new(NotificationEvents::Id)
                            .uuid()
                            .not_null()
                            .primary_key(),
                    )
                    .col(
                        ColumnDef::new(NotificationEvents::EventType)
                            .string_len(50)
                            .not_null(),
                    )
                    .col(
                        ColumnDef::new(NotificationEvents::Severity)
                            .string_len(20)
                            .not_null(),
                    )
                    .col(
                        ColumnDef::new(NotificationEvents::Title)
                            .string_len(200)
                            .not_null(),
                    )
                    .col(
                        ColumnDef::new(NotificationEvents::Message)
                            .text()
                            .not_null(),
                    )
                    .col(
                        ColumnDef::new(NotificationEvents::Details)
                            .json()
                            .null(),
                    )
                    .col(
                        ColumnDef::new(NotificationEvents::CreatedAt)
                            .timestamp_with_time_zone()
                            .not_null(),
                    )
                    .to_owned(),
            )
            .await?;

        manager
            .create_index(
                Index::create()
                    .name("idx_notification_events_created_at")
                    .table(NotificationEvents::Table)
                    .col(NotificationEvents::CreatedAt)
                    .to_owned(),
            )
            .await
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .drop_table(
                Table::drop().table(NotificationEvents::Table).to_owned(),
            )
            .await?;
        manager
            .drop_table(
                Table::drop().table(NotificationChannels::Table).to_owned(),
            )
            .await
    }
}

#[derive(DeriveIden)]
enum NotificationChannels {
    Table,
    Id,
    Name,
    Kind,
    Config,
    Events,
    Enabled,
    CreatedAt,
    UpdatedAt,
}

#[derive(DeriveIden)]
enum NotificationEvents {
    Table,
    Id,
    EventType,
    Severity,
    Title,
    Message,
    Details,
    CreatedAt,
}
