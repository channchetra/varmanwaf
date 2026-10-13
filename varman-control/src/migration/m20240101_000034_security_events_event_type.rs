//! Add `event_type` to `security_events`.
//!
//! Which protection produced the event (`managed` / `waf` / `ip_geo` / `bot`
//! / `rate_limit` / `challenge`). The dashboard uses it to deep-link the
//! rule column to the right settings page; NULL on rows recorded before this
//! column existed.

use sea_orm_migration::prelude::*;

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .alter_table(
                Table::alter()
                    .table(SecurityEvents::Table)
                    .add_column(
                        ColumnDef::new(SecurityEvents::EventType).text().null(),
                    )
                    .to_owned(),
            )
            .await
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .alter_table(
                Table::alter()
                    .table(SecurityEvents::Table)
                    .drop_column(SecurityEvents::EventType)
                    .to_owned(),
            )
            .await
    }
}

#[derive(DeriveIden)]
enum SecurityEvents {
    Table,
    EventType,
}
