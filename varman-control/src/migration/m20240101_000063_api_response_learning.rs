//! `api_learned_schemas` gains the response side of the learning.
//!
//! Response bodies are merged per **status class** (`2xx`, `4xx`, `5xx`),
//! structures and counts only - the same discipline as the request side.
//! Bodies the agent did not capture (or that are truncated) are skipped and
//! counted, never guessed at.

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
                        ColumnDef::new(ApiLearnedSchemas::ResponseSchema)
                            .json_binary()
                            .null(),
                    )
                    .add_column(
                        ColumnDef::new(ApiLearnedSchemas::ResponseSamples)
                            .big_integer()
                            .not_null()
                            .default(0),
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
                    .drop_column(ApiLearnedSchemas::ResponseSchema)
                    .drop_column(ApiLearnedSchemas::ResponseSamples)
                    .to_owned(),
            )
            .await
    }
}

#[derive(DeriveIden)]
enum ApiLearnedSchemas {
    Table,
    ResponseSchema,
    ResponseSamples,
}
