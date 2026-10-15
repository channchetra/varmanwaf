//! `exclusion_packages` + `site_exclusion_bindings` - named, path-scoped
//! rule-exclusion sets (the exclusion-packages surface).
//!
//! A package is a versioned set of entries: a rule id or a tag selector,
//! plus the request sources to exclude from that rule's evaluation. A
//! binding attaches one package to a site at a path prefix; only requests
//! whose path starts with the prefix are affected.

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
                    .table(ExclusionPackages::Table)
                    .if_not_exists()
                    .col(
                        ColumnDef::new(ExclusionPackages::Id)
                            .uuid()
                            .not_null()
                            .primary_key(),
                    )
                    .col(
                        ColumnDef::new(ExclusionPackages::Key)
                            .string_len(64)
                            .not_null()
                            .unique_key(),
                    )
                    .col(
                        ColumnDef::new(ExclusionPackages::Name)
                            .string_len(200)
                            .not_null(),
                    )
                    .col(
                        ColumnDef::new(ExclusionPackages::Description)
                            .text()
                            .not_null()
                            .default(""),
                    )
                    .col(
                        ColumnDef::new(ExclusionPackages::SourceUrl)
                            .text()
                            .not_null()
                            .default(""),
                    )
                    .col(
                        ColumnDef::new(ExclusionPackages::Version)
                            .string_len(32)
                            .not_null()
                            .default("1"),
                    )
                    .col(
                        ColumnDef::new(ExclusionPackages::Entries)
                            .json_binary()
                            .not_null()
                            .default(Expr::cust("'[]'::jsonb")),
                    )
                    .col(
                        ColumnDef::new(ExclusionPackages::Builtin)
                            .boolean()
                            .not_null()
                            .default(false),
                    )
                    .col(
                        ColumnDef::new(ExclusionPackages::CreatedAt)
                            .timestamp_with_time_zone()
                            .not_null()
                            .default(Expr::cust("now()")),
                    )
                    .col(
                        ColumnDef::new(ExclusionPackages::UpdatedAt)
                            .timestamp_with_time_zone()
                            .not_null()
                            .default(Expr::cust("now()")),
                    )
                    .to_owned(),
            )
            .await?;

        manager
            .create_table(
                Table::create()
                    .table(SiteExclusionBindings::Table)
                    .if_not_exists()
                    .col(
                        ColumnDef::new(SiteExclusionBindings::Id)
                            .uuid()
                            .not_null()
                            .primary_key(),
                    )
                    .col(
                        ColumnDef::new(SiteExclusionBindings::SiteId)
                            .uuid()
                            .not_null(),
                    )
                    .col(
                        ColumnDef::new(SiteExclusionBindings::PackageId)
                            .uuid()
                            .not_null(),
                    )
                    .col(
                        ColumnDef::new(SiteExclusionBindings::PathPrefix)
                            .string_len(256)
                            .not_null(),
                    )
                    .col(
                        ColumnDef::new(SiteExclusionBindings::Enabled)
                            .boolean()
                            .not_null()
                            .default(true),
                    )
                    .col(
                        ColumnDef::new(SiteExclusionBindings::InstalledVersion)
                            .string_len(32)
                            .not_null()
                            .default(""),
                    )
                    .col(
                        ColumnDef::new(SiteExclusionBindings::CreatedAt)
                            .timestamp_with_time_zone()
                            .not_null()
                            .default(Expr::cust("now()")),
                    )
                    .col(
                        ColumnDef::new(SiteExclusionBindings::UpdatedAt)
                            .timestamp_with_time_zone()
                            .not_null()
                            .default(Expr::cust("now()")),
                    )
                    .foreign_key(
                        ForeignKey::create()
                            .from(
                                SiteExclusionBindings::Table,
                                SiteExclusionBindings::SiteId,
                            )
                            .to(Sites::Table, Sites::Id)
                            .on_delete(ForeignKeyAction::Cascade),
                    )
                    .foreign_key(
                        ForeignKey::create()
                            .from(
                                SiteExclusionBindings::Table,
                                SiteExclusionBindings::PackageId,
                            )
                            .to(ExclusionPackages::Table, ExclusionPackages::Id)
                            .on_delete(ForeignKeyAction::Cascade),
                    )
                    .to_owned(),
            )
            .await?;

        manager
            .create_index(
                Index::create()
                    .name("idx_site_exclusion_bindings_unique")
                    .table(SiteExclusionBindings::Table)
                    .col(SiteExclusionBindings::SiteId)
                    .col(SiteExclusionBindings::PackageId)
                    .col(SiteExclusionBindings::PathPrefix)
                    .unique()
                    .to_owned(),
            )
            .await
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .drop_table(
                Table::drop().table(SiteExclusionBindings::Table).to_owned(),
            )
            .await?;
        manager
            .drop_table(
                Table::drop().table(ExclusionPackages::Table).to_owned(),
            )
            .await
    }
}

#[derive(DeriveIden)]
enum ExclusionPackages {
    Table,
    Id,
    Key,
    Name,
    Description,
    SourceUrl,
    Version,
    Entries,
    Builtin,
    CreatedAt,
    UpdatedAt,
}

#[derive(DeriveIden)]
enum SiteExclusionBindings {
    Table,
    Id,
    SiteId,
    PackageId,
    PathPrefix,
    Enabled,
    InstalledVersion,
    CreatedAt,
    UpdatedAt,
}
