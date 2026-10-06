//! Creates `ip_groups` and `ip_group_sites` tables for global/per-site IP
//! blacklist/whitelist management.

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
                    .table(IpGroups::Table)
                    .if_not_exists()
                    .col(
                        ColumnDef::new(IpGroups::Id)
                            .uuid()
                            .not_null()
                            .primary_key(),
                    )
                    .col(
                        ColumnDef::new(IpGroups::Name)
                            .string_len(200)
                            .not_null(),
                    )
                    .col(ColumnDef::new(IpGroups::Description).text().null())
                    .col(
                        ColumnDef::new(IpGroups::IpRanges)
                            .array(ColumnType::Text)
                            .not_null()
                            .default(Expr::cust("'{}'::text[]")),
                    )
                    .col(
                        ColumnDef::new(IpGroups::Action)
                            .string_len(20)
                            .not_null()
                            .default("block"),
                    )
                    .col(
                        ColumnDef::new(IpGroups::IsGlobal)
                            .boolean()
                            .not_null()
                            .default(false),
                    )
                    .col(ColumnDef::new(IpGroups::SourceUrl).text().null())
                    .col(
                        ColumnDef::new(IpGroups::SyncIntervalMinutes)
                            .integer()
                            .null(),
                    )
                    .col(
                        ColumnDef::new(IpGroups::LastSyncedAt)
                            .timestamp_with_time_zone()
                            .null(),
                    )
                    .col(
                        ColumnDef::new(IpGroups::Enabled)
                            .boolean()
                            .not_null()
                            .default(true),
                    )
                    .col(
                        ColumnDef::new(IpGroups::CreatedAt)
                            .timestamp_with_time_zone()
                            .not_null(),
                    )
                    .col(
                        ColumnDef::new(IpGroups::UpdatedAt)
                            .timestamp_with_time_zone()
                            .not_null(),
                    )
                    .to_owned(),
            )
            .await?;

        manager
            .create_table(
                Table::create()
                    .table(IpGroupSites::Table)
                    .if_not_exists()
                    .col(
                        ColumnDef::new(IpGroupSites::IpGroupId)
                            .uuid()
                            .not_null(),
                    )
                    .col(ColumnDef::new(IpGroupSites::SiteId).uuid().not_null())
                    .col(
                        ColumnDef::new(IpGroupSites::CreatedAt)
                            .timestamp_with_time_zone()
                            .not_null(),
                    )
                    .primary_key(
                        Index::create()
                            .col(IpGroupSites::IpGroupId)
                            .col(IpGroupSites::SiteId),
                    )
                    .foreign_key(
                        ForeignKey::create()
                            .name("fk_ip_group_sites_ip_group_id")
                            .from(IpGroupSites::Table, IpGroupSites::IpGroupId)
                            .to(IpGroups::Table, IpGroups::Id)
                            .on_delete(ForeignKeyAction::Cascade),
                    )
                    .foreign_key(
                        ForeignKey::create()
                            .name("fk_ip_group_sites_site_id")
                            .from(IpGroupSites::Table, IpGroupSites::SiteId)
                            .to(Sites::Table, Sites::Id)
                            .on_delete(ForeignKeyAction::Cascade),
                    )
                    .to_owned(),
            )
            .await?;

        Ok(())
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .drop_table(Table::drop().table(IpGroupSites::Table).to_owned())
            .await?;
        manager
            .drop_table(Table::drop().table(IpGroups::Table).to_owned())
            .await?;
        Ok(())
    }
}

#[derive(DeriveIden)]
enum IpGroups {
    Table,
    Id,
    Name,
    Description,
    IpRanges,
    Action,
    IsGlobal,
    SourceUrl,
    SyncIntervalMinutes,
    LastSyncedAt,
    Enabled,
    CreatedAt,
    UpdatedAt,
}

#[derive(DeriveIden)]
enum IpGroupSites {
    Table,
    IpGroupId,
    SiteId,
    CreatedAt,
}
