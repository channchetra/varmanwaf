//! Gates a `site_routes` row on an IP group: the data plane only matches the
//! location for client IPs inside the group's ranges.
//!
//! The foreign key restricts deletion: dropping a group that still gates a
//! route would silently turn an internal-only route into a public one, so the
//! control plane refuses it (and the API answers 400 with the route count).

use sea_orm_migration::prelude::*;

#[derive(DeriveMigrationName)]
pub struct Migration;

#[derive(DeriveIden)]
enum SiteRoutes {
    Table,
    IpGroupId,
}

#[derive(DeriveIden)]
enum IpGroups {
    Table,
    Id,
}

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .alter_table(
                Table::alter()
                    .table(SiteRoutes::Table)
                    .add_column(
                        ColumnDef::new(SiteRoutes::IpGroupId).uuid().null(),
                    )
                    .add_foreign_key(
                        TableForeignKey::new()
                            .name("fk_site_routes_ip_group")
                            .from_tbl(SiteRoutes::Table)
                            .from_col(SiteRoutes::IpGroupId)
                            .to_tbl(IpGroups::Table)
                            .to_col(IpGroups::Id)
                            .on_delete(ForeignKeyAction::Restrict),
                    )
                    .to_owned(),
            )
            .await?;
        manager
            .create_index(
                Index::create()
                    .if_not_exists()
                    .name("idx_site_routes_ip_group_id")
                    .table(SiteRoutes::Table)
                    .col(SiteRoutes::IpGroupId)
                    .to_owned(),
            )
            .await?;
        Ok(())
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .drop_index(
                Index::drop()
                    .name("idx_site_routes_ip_group_id")
                    .table(SiteRoutes::Table)
                    .to_owned(),
            )
            .await?;
        manager
            .alter_table(
                Table::alter()
                    .table(SiteRoutes::Table)
                    .drop_foreign_key(Alias::new("fk_site_routes_ip_group"))
                    .drop_column(SiteRoutes::IpGroupId)
                    .to_owned(),
            )
            .await?;
        Ok(())
    }
}
