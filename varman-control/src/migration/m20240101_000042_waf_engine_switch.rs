//! Add the explicit WAF engine switch to `waf_settings`.
//!
//! Historically the engine was implicitly on whenever any custom rule or
//! posture knob existed; a real on/off switch needs an explicit column.
//! Default `true` keeps every existing site's effective behavior unchanged.

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
                        ColumnDef::new(WafSettings::WafEnabled)
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
                    .table(WafSettings::Table)
                    .drop_column(WafSettings::WafEnabled)
                    .to_owned(),
            )
            .await
    }
}

#[derive(DeriveIden)]
enum WafSettings {
    Table,
    WafEnabled,
}
