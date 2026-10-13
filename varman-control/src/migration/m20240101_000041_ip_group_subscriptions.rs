//! Add subscription bookkeeping columns to `ip_groups`.
//!
//! IP groups gain a subscription kind (`builtin` for the compiled-in
//! vendor snapshots, `url` for operator-supplied sources, `NULL` for
//! fully manual groups) plus an enable switch so a subscription can be
//! paused without deleting the group.

use sea_orm_migration::prelude::*;

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .alter_table(
                Table::alter()
                    .table(IpGroups::Table)
                    .add_column(
                        ColumnDef::new(IpGroups::SubscriptionKind).text(),
                    )
                    .add_column(
                        ColumnDef::new(IpGroups::SubscriptionEnabled)
                            .boolean()
                            .not_null()
                            .default(true),
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
                    .drop_column(IpGroups::SubscriptionKind)
                    .drop_column(IpGroups::SubscriptionEnabled)
                    .to_owned(),
            )
            .await
    }
}

#[derive(DeriveIden)]
enum IpGroups {
    Table,
    SubscriptionKind,
    SubscriptionEnabled,
}
