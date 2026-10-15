//! `api_learned_schemas.mode` - the per-operation API control.
//!
//! How the OpenAPI validation layer treats one observed endpoint:
//! `off` skips it, `observe` records findings as monitor (the historical
//! behaviour, and the default), `enforce` escalates them to a block.

use sea_orm_migration::prelude::*;

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .alter_table(
                Table::alter()
                    .table(ApiLearnedSchemas::Table)
                    .add_column(
                        ColumnDef::new(ApiLearnedSchemas::Mode)
                            .string_len(16)
                            .not_null()
                            .default("observe"),
                    )
                    .to_owned(),
            )
            .await
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .alter_table(
                Table::alter()
                    .table(ApiLearnedSchemas::Table)
                    .drop_column(ApiLearnedSchemas::Mode)
                    .to_owned(),
            )
            .await
    }
}

#[derive(DeriveIden)]
enum ApiLearnedSchemas {
    Table,
    Mode,
}
