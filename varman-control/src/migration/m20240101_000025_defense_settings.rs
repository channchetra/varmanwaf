//! Global defense settings (`defense_settings`).
//!
//! One single-row table, like the other settings tables. It currently holds
//! the observation mode switch: when it is on, the data plane keeps every
//! detection running (WAF, IP/geo rules, bot protection, rate limiting) but
//! only records what it would have blocked instead of answering with a
//! block page or challenge.

use sea_orm_migration::prelude::*;

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .create_table(
                Table::create()
                    .table(DefenseSettings::Table)
                    .if_not_exists()
                    .col(
                        ColumnDef::new(DefenseSettings::Id)
                            .integer()
                            .not_null()
                            .primary_key(),
                    )
                    .col(
                        ColumnDef::new(DefenseSettings::ObservationMode)
                            .boolean()
                            .not_null()
                            .default(false),
                    )
                    .col(
                        ColumnDef::new(DefenseSettings::UpdatedAt)
                            .timestamp_with_time_zone()
                            .not_null(),
                    )
                    .to_owned(),
            )
            .await
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .drop_table(
                Table::drop()
                    .table(DefenseSettings::Table)
                    .if_exists()
                    .to_owned(),
            )
            .await
    }
}

#[derive(DeriveIden)]
enum DefenseSettings {
    Table,
    Id,
    ObservationMode,
    UpdatedAt,
}
