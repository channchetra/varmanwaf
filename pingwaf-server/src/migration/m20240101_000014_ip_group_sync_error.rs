//! Remembers why the last subscription sync of an IP group failed, so the
//! dashboard can surface broken sources instead of silently serving stale
//! ranges.

use sea_orm_migration::prelude::*;

#[derive(DeriveMigrationName)]
pub struct Migration;

#[derive(DeriveIden)]
enum IpGroups {
    Table,
    LastSyncError,
}

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .alter_table(
                Table::alter()
                    .table(IpGroups::Table)
                    .add_column(
                        ColumnDef::new(IpGroups::LastSyncError).text().null(),
                    )
                    .to_owned(),
            )
            .await
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .alter_table(
                Table::alter()
                    .table(IpGroups::Table)
                    .drop_column(IpGroups::LastSyncError)
                    .to_owned(),
            )
            .await
    }
}
