//! Per-site failover policy and the control-plane-wide default.
//!
//! `sites.failover_policy` (`inherit`/`open`/`closed`) decides how one site
//! behaves while the control plane is unreachable and the host has no synced
//! rule bundle; `defense_settings.default_fail_open` is what `inherit`
//! resolves to. Both travel to the agents inside every `RuleBundle`, so a
//! change here is picked up like any other configuration push.

use sea_orm_migration::prelude::*;

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .alter_table(
                Table::alter()
                    .table(Sites::Table)
                    .add_column(
                        ColumnDef::new(Sites::FailoverPolicy)
                            .text()
                            .not_null()
                            .default("inherit"),
                    )
                    .to_owned(),
            )
            .await?;
        manager
            .alter_table(
                Table::alter()
                    .table(DefenseSettings::Table)
                    .add_column(
                        ColumnDef::new(DefenseSettings::DefaultFailOpen)
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
                    .table(Sites::Table)
                    .drop_column(Sites::FailoverPolicy)
                    .to_owned(),
            )
            .await?;
        manager
            .alter_table(
                Table::alter()
                    .table(DefenseSettings::Table)
                    .drop_column(DefenseSettings::DefaultFailOpen)
                    .to_owned(),
            )
            .await
    }
}

#[derive(DeriveIden)]
enum Sites {
    Table,
    FailoverPolicy,
}

#[derive(DeriveIden)]
enum DefenseSettings {
    Table,
    DefaultFailOpen,
}
