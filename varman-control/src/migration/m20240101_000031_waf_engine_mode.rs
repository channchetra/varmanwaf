//! Per-site WAF engine mode (`waf_settings.engine_mode`).
//!
//! `inherit` (the default) uses the process-wide `VARMAN_WAF_ENGINE`;
//! `legacy`, `shadow` and `varman` override it for this site. The value is
//! validated by the settings API, so the column stores a normalised string.

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
                        ColumnDef::new(WafSettings::EngineMode)
                            .string_len(16)
                            .not_null()
                            .default("inherit"),
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
                    .drop_column(WafSettings::EngineMode)
                    .to_owned(),
            )
            .await
    }
}

#[derive(DeriveIden)]
enum WafSettings {
    Table,
    EngineMode,
}
