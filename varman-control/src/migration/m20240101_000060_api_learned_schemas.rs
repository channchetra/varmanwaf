//! `api_learned_schemas` - bounded structural learning for API assets.
//!
//! One row per observed (method, path): the merged **structure** of the JSON
//! request bodies and query parameters - keys, types and counts, never
//! values. The OpenAPI draft is generated from these rows; a row is only
//! ever written by an explicit learn run.

use sea_orm_migration::prelude::*;

use super::m20240101_000002_create_sites::Sites;

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .create_table(
                Table::create()
                    .table(ApiLearnedSchemas::Table)
                    .if_not_exists()
                    .col(
                        ColumnDef::new(ApiLearnedSchemas::Id)
                            .uuid()
                            .not_null()
                            .primary_key(),
                    )
                    .col(
                        ColumnDef::new(ApiLearnedSchemas::SiteId)
                            .uuid()
                            .not_null(),
                    )
                    .col(
                        ColumnDef::new(ApiLearnedSchemas::Method)
                            .string_len(16)
                            .not_null(),
                    )
                    .col(
                        ColumnDef::new(ApiLearnedSchemas::Path)
                            .text()
                            .not_null(),
                    )
                    .col(
                        ColumnDef::new(ApiLearnedSchemas::RequestSchema)
                            .json_binary()
                            .null(),
                    )
                    .col(
                        ColumnDef::new(ApiLearnedSchemas::QuerySchema)
                            .json_binary()
                            .not_null()
                            .default(Expr::cust("'{}'::jsonb")),
                    )
                    .col(
                        ColumnDef::new(ApiLearnedSchemas::SampleCount)
                            .big_integer()
                            .not_null()
                            .default(0),
                    )
                    .col(
                        ColumnDef::new(ApiLearnedSchemas::FirstSeen)
                            .timestamp_with_time_zone()
                            .null(),
                    )
                    .col(
                        ColumnDef::new(ApiLearnedSchemas::LastSeen)
                            .timestamp_with_time_zone()
                            .null(),
                    )
                    .col(
                        ColumnDef::new(ApiLearnedSchemas::UpdatedAt)
                            .timestamp_with_time_zone()
                            .not_null()
                            .default(Expr::cust("now()")),
                    )
                    .foreign_key(
                        ForeignKey::create()
                            .from(
                                ApiLearnedSchemas::Table,
                                ApiLearnedSchemas::SiteId,
                            )
                            .to(Sites::Table, Sites::Id)
                            .on_delete(ForeignKeyAction::Cascade),
                    )
                    .to_owned(),
            )
            .await?;

        manager
            .create_index(
                Index::create()
                    .name("idx_api_learned_schemas_unique")
                    .table(ApiLearnedSchemas::Table)
                    .col(ApiLearnedSchemas::SiteId)
                    .col(ApiLearnedSchemas::Method)
                    .col(ApiLearnedSchemas::Path)
                    .unique()
                    .to_owned(),
            )
            .await
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .drop_table(
                Table::drop().table(ApiLearnedSchemas::Table).to_owned(),
            )
            .await
    }
}

#[derive(DeriveIden)]
enum ApiLearnedSchemas {
    Table,
    Id,
    SiteId,
    Method,
    Path,
    RequestSchema,
    QuerySchema,
    SampleCount,
    FirstSeen,
    LastSeen,
    UpdatedAt,
}
