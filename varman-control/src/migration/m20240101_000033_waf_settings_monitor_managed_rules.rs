//! Add `monitor_managed_rules` to `waf_settings`.
//!
//! Per-site downgrade of individual built-in managed rules to monitor-only,
//! complementing the category/stack sets added in 000030. An empty array (the
//! default) keeps every managed rule enforced.

use sea_orm_migration::prelude::*;

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .alter_table(
                Table::alter()
                    .table(WafSettings::Table)
                    .add_column(
                        ColumnDef::new(WafSettings::MonitorManagedRules)
                            .array(ColumnType::Text)
                            .not_null()
                            .default(Expr::cust("'{}'::text[]")),
                    )
                    .to_owned(),
            )
            .await
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .alter_table(
                Table::alter()
                    .table(WafSettings::Table)
                    .drop_column(WafSettings::MonitorManagedRules)
                    .to_owned(),
            )
            .await
    }
}

#[derive(DeriveIden)]
enum WafSettings {
    Table,
    MonitorManagedRules,
}
