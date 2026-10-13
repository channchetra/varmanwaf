//! Add `instance_settings`, a key-value table for state pinned at first boot.
//!
//! The JWT signing secret is generated and persisted here when the operator
//! did not configure one, so open-source deployments never run with the
//! built-in default and restarts never rotate the generated value.

use sea_orm_migration::prelude::*;

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .create_table(
                Table::create()
                    .table(InstanceSettings::Table)
                    .if_not_exists()
                    .col(
                        ColumnDef::new(InstanceSettings::Key)
                            .text()
                            .not_null()
                            .primary_key(),
                    )
                    .col(
                        ColumnDef::new(InstanceSettings::Value)
                            .text()
                            .not_null(),
                    )
                    .col(
                        ColumnDef::new(InstanceSettings::UpdatedAt)
                            .timestamp_with_time_zone()
                            .not_null(),
                    )
                    .to_owned(),
            )
            .await
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .drop_table(Table::drop().table(InstanceSettings::Table).to_owned())
            .await
    }
}

#[derive(DeriveIden)]
enum InstanceSettings {
    Table,
    Key,
    Value,
    UpdatedAt,
}
