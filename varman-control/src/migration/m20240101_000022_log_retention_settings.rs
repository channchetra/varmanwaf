//! Retention windows for the two log tables (`log_retention_settings`).
//!
//! One global row, like the other settings tables: administrators pick how
//! long access logs and security events are kept, separately, and a
//! background sweep on the control plane deletes anything older. The sweep
//! filters on `timestamp` alone, so both tables get a plain timestamp index
//! next to their per-site ones.

use sea_orm_migration::prelude::*;

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .create_table(
                Table::create()
                    .table(LogRetentionSettings::Table)
                    .if_not_exists()
                    .col(
                        ColumnDef::new(LogRetentionSettings::Id)
                            .integer()
                            .not_null()
                            .primary_key(),
                    )
                    .col(
                        ColumnDef::new(
                            LogRetentionSettings::AccessLogRetentionDays,
                        )
                        .integer()
                        .not_null()
                        .default(180),
                    )
                    .col(
                        ColumnDef::new(
                            LogRetentionSettings::SecurityEventRetentionDays,
                        )
                        .integer()
                        .not_null()
                        .default(180),
                    )
                    .col(
                        ColumnDef::new(LogRetentionSettings::UpdatedAt)
                            .timestamp_with_time_zone()
                            .not_null(),
                    )
                    .to_owned(),
            )
            .await?;

        // The per-site indexes lead with `site_id`, so the sweep's
        // "everything older than X" query cannot use them.
        let conn = manager.get_connection();
        conn.execute_unprepared(
            "CREATE INDEX IF NOT EXISTS idx_access_logs_timestamp \
             ON access_logs (timestamp)",
        )
        .await?;
        conn.execute_unprepared(
            "CREATE INDEX IF NOT EXISTS idx_security_events_timestamp \
             ON security_events (timestamp)",
        )
        .await?;

        Ok(())
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        let conn = manager.get_connection();
        conn.execute_unprepared(
            "DROP INDEX IF EXISTS idx_access_logs_timestamp",
        )
        .await?;
        conn.execute_unprepared(
            "DROP INDEX IF EXISTS idx_security_events_timestamp",
        )
        .await?;

        manager
            .drop_table(
                Table::drop()
                    .table(LogRetentionSettings::Table)
                    .if_exists()
                    .to_owned(),
            )
            .await
    }
}

#[derive(DeriveIden)]
enum LogRetentionSettings {
    Table,
    Id,
    AccessLogRetentionDays,
    SecurityEventRetentionDays,
    UpdatedAt,
}
