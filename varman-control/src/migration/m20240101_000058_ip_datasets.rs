//! `ip_datasets` - IP range datasets synced from ipverse.
//!
//! One row per country (`kind = country`, `dataset_key = US`) or autonomous
//! system (`kind = asn`, `dataset_key = 13335`). The ranges are what the geo
//! policy and the client-IP analysis enforce with; a listed key without a
//! row is surfaced as missing and is not enforced.

use sea_orm_migration::prelude::*;

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .create_table(
                Table::create()
                    .table(IpDatasets::Table)
                    .if_not_exists()
                    .col(
                        ColumnDef::new(IpDatasets::Id)
                            .uuid()
                            .not_null()
                            .primary_key(),
                    )
                    .col(
                        ColumnDef::new(IpDatasets::Kind)
                            .string_len(10)
                            .not_null(),
                    )
                    .col(
                        ColumnDef::new(IpDatasets::DatasetKey)
                            .string_len(20)
                            .not_null(),
                    )
                    .col(
                        ColumnDef::new(IpDatasets::Ipv4Ranges)
                            .array(ColumnType::Text)
                            .not_null()
                            .default(Expr::cust("'{}'::text[]")),
                    )
                    .col(
                        ColumnDef::new(IpDatasets::Ipv6Ranges)
                            .array(ColumnType::Text)
                            .not_null()
                            .default(Expr::cust("'{}'::text[]")),
                    )
                    .col(
                        ColumnDef::new(IpDatasets::SourceUrl).text().not_null(),
                    )
                    .col(
                        ColumnDef::new(IpDatasets::RefreshIntervalMinutes)
                            .integer()
                            .null(),
                    )
                    .col(
                        ColumnDef::new(IpDatasets::LastSyncedAt)
                            .timestamp_with_time_zone()
                            .null(),
                    )
                    .col(ColumnDef::new(IpDatasets::LastError).text().null())
                    .col(
                        ColumnDef::new(IpDatasets::CreatedAt)
                            .timestamp_with_time_zone()
                            .not_null()
                            .default(Expr::cust("now()")),
                    )
                    .col(
                        ColumnDef::new(IpDatasets::UpdatedAt)
                            .timestamp_with_time_zone()
                            .not_null()
                            .default(Expr::cust("now()")),
                    )
                    .to_owned(),
            )
            .await?;

        manager
            .create_index(
                Index::create()
                    .name("idx_ip_datasets_kind_key")
                    .table(IpDatasets::Table)
                    .col(IpDatasets::Kind)
                    .col(IpDatasets::DatasetKey)
                    .unique()
                    .to_owned(),
            )
            .await
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .drop_table(Table::drop().table(IpDatasets::Table).to_owned())
            .await
    }
}

#[derive(DeriveIden)]
enum IpDatasets {
    Table,
    Id,
    Kind,
    DatasetKey,
    Ipv4Ranges,
    Ipv6Ranges,
    SourceUrl,
    RefreshIntervalMinutes,
    LastSyncedAt,
    LastError,
    CreatedAt,
    UpdatedAt,
}
