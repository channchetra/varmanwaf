//! Add `trusted_proxy_group_ids` to `sites`.
//!
//! Besides hand-entered CIDR ranges, the trusted-proxy scope may reference
//! IP groups (e.g. the built-in Cloudflare subscription). The control plane
//! expands the referenced groups' ranges and merges them into
//! `trusted_proxy_ranges` when it builds the agent configuration, so agents
//! keep consuming a flat CIDR list.

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
                        ColumnDef::new(Sites::TrustedProxyGroupIds)
                            .array(ColumnType::Uuid)
                            .not_null()
                            .default(Expr::cust("'{}'::uuid[]")),
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
                    .drop_column(Sites::TrustedProxyGroupIds)
                    .to_owned(),
            )
            .await
    }
}

#[derive(DeriveIden)]
enum Sites {
    Table,
    TrustedProxyGroupIds,
}
