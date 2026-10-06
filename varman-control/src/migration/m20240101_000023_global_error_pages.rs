//! Makes custom error pages global (`error_pages`).
//!
//! They used to belong to a single site, which meant an operator with a dozen
//! sites had to keep a dozen copies of the same template in sync. The page a
//! visitor sees for a given status code is not site-specific, so the table is
//! rebuilt without `site_id` and `status_code` becomes the unique key.
//!
//! Site-level data is dropped on the way through: this project's policy is
//! that error pages are deployment-wide, so there is nothing to carry over.

use sea_orm_migration::prelude::*;

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .drop_table(
                Table::drop()
                    .table(ErrorPages::Table)
                    .if_exists()
                    .to_owned(),
            )
            .await?;

        manager
            .create_table(
                Table::create()
                    .table(ErrorPages::Table)
                    .if_not_exists()
                    .col(
                        ColumnDef::new(ErrorPages::Id)
                            .uuid()
                            .not_null()
                            .primary_key(),
                    )
                    .col(
                        ColumnDef::new(ErrorPages::StatusCode)
                            .integer()
                            .not_null(),
                    )
                    .col(
                        ColumnDef::new(ErrorPages::Name)
                            .string_len(200)
                            .not_null(),
                    )
                    .col(
                        ColumnDef::new(ErrorPages::ContentType)
                            .string_len(100)
                            .not_null()
                            .default("text/html"),
                    )
                    .col(
                        ColumnDef::new(ErrorPages::BodyTemplate)
                            .text()
                            .not_null(),
                    )
                    .col(
                        ColumnDef::new(ErrorPages::Enabled)
                            .boolean()
                            .not_null()
                            .default(true),
                    )
                    .col(
                        ColumnDef::new(ErrorPages::CreatedAt)
                            .timestamp_with_time_zone()
                            .not_null(),
                    )
                    .col(
                        ColumnDef::new(ErrorPages::UpdatedAt)
                            .timestamp_with_time_zone()
                            .not_null(),
                    )
                    .to_owned(),
            )
            .await?;

        manager
            .create_index(
                Index::create()
                    .if_not_exists()
                    .unique()
                    .name("idx_error_pages_status")
                    .table(ErrorPages::Table)
                    .col(ErrorPages::StatusCode)
                    .to_owned(),
            )
            .await
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .drop_table(
                Table::drop()
                    .table(ErrorPages::Table)
                    .if_exists()
                    .to_owned(),
            )
            .await?;

        manager
            .create_table(
                Table::create()
                    .table(ErrorPages::Table)
                    .if_not_exists()
                    .col(
                        ColumnDef::new(ErrorPages::Id)
                            .uuid()
                            .not_null()
                            .primary_key(),
                    )
                    .col(ColumnDef::new(ErrorPages::SiteId).uuid().not_null())
                    .col(
                        ColumnDef::new(ErrorPages::StatusCode)
                            .integer()
                            .not_null(),
                    )
                    .col(
                        ColumnDef::new(ErrorPages::Name)
                            .string_len(200)
                            .not_null(),
                    )
                    .col(
                        ColumnDef::new(ErrorPages::ContentType)
                            .string_len(100)
                            .not_null()
                            .default("text/html"),
                    )
                    .col(
                        ColumnDef::new(ErrorPages::BodyTemplate)
                            .text()
                            .not_null(),
                    )
                    .col(
                        ColumnDef::new(ErrorPages::Enabled)
                            .boolean()
                            .not_null()
                            .default(true),
                    )
                    .col(
                        ColumnDef::new(ErrorPages::CreatedAt)
                            .timestamp_with_time_zone()
                            .not_null(),
                    )
                    .col(
                        ColumnDef::new(ErrorPages::UpdatedAt)
                            .timestamp_with_time_zone()
                            .not_null(),
                    )
                    .foreign_key(
                        ForeignKey::create()
                            .name("fk_error_pages_site_id")
                            .from(ErrorPages::Table, ErrorPages::SiteId)
                            .to(Sites::Table, Sites::Id)
                            .on_delete(ForeignKeyAction::Cascade),
                    )
                    .to_owned(),
            )
            .await?;

        manager
            .create_index(
                Index::create()
                    .if_not_exists()
                    .unique()
                    .name("idx_error_pages_site_status")
                    .table(ErrorPages::Table)
                    .col(ErrorPages::SiteId)
                    .col(ErrorPages::StatusCode)
                    .to_owned(),
            )
            .await
    }
}

#[derive(DeriveIden)]
enum ErrorPages {
    Table,
    Id,
    SiteId,
    StatusCode,
    Name,
    ContentType,
    BodyTemplate,
    Enabled,
    CreatedAt,
    UpdatedAt,
}

/// Only needed to rebuild the foreign key in [`Migration::down`].
#[derive(DeriveIden)]
enum Sites {
    Table,
    Id,
}
