//! Add `last_config_sync_at` / `last_policy_sync_at` to `agents`.
//!
//! Reported by the agent via heartbeat: when it last applied a full site
//! config and when it last applied a per-site rule bundle. Feeds the
//! dashboard's "last synced" column, replacing the old pending-commands
//! indicator.

use sea_orm_migration::prelude::*;

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .alter_table(
                Table::alter()
                    .table(Agents::Table)
                    .add_column(
                        ColumnDef::new(Agents::LastConfigSyncAt)
                            .timestamp_with_time_zone()
                            .null(),
                    )
                    .add_column(
                        ColumnDef::new(Agents::LastPolicySyncAt)
                            .timestamp_with_time_zone()
                            .null(),
                    )
                    .to_owned(),
            )
            .await
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .alter_table(
                Table::alter()
                    .table(Agents::Table)
                    .drop_column(Agents::LastConfigSyncAt)
                    .drop_column(Agents::LastPolicySyncAt)
                    .to_owned(),
            )
            .await
    }
}

#[derive(DeriveIden)]
enum Agents {
    Table,
    LastConfigSyncAt,
    LastPolicySyncAt,
}
