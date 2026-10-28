//! TCP port forwards exposed by the edge.

use sea_orm_migration::prelude::*;

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .create_table(
                Table::create()
                    .table(PortForwards::Table)
                    .if_not_exists()
                    .col(
                        ColumnDef::new(PortForwards::Id)
                            .uuid()
                            .not_null()
                            .primary_key(),
                    )
                    .col(ColumnDef::new(PortForwards::SiteId).uuid().not_null())
                    .col(
                        ColumnDef::new(PortForwards::Name)
                            .string_len(100)
                            .not_null(),
                    )
                    .col(
                        ColumnDef::new(PortForwards::ListenPort)
                            .integer()
                            .not_null(),
                    )
                    .col(
                        ColumnDef::new(PortForwards::TargetHost)
                            .string_len(253)
                            .not_null(),
                    )
                    .col(
                        ColumnDef::new(PortForwards::TargetPort)
                            .integer()
                            .not_null(),
                    )
                    .col(
                        ColumnDef::new(PortForwards::AllowedCidrs)
                            .array(ColumnType::Text)
                            .not_null()
                            .default(Expr::cust("ARRAY[]::text[]")),
                    )
                    .col(
                        ColumnDef::new(PortForwards::Enabled)
                            .boolean()
                            .not_null()
                            .default(true),
                    )
                    .col(
                        ColumnDef::new(PortForwards::CreatedAt)
                            .timestamp_with_time_zone()
                            .not_null()
                            .default(Expr::current_timestamp()),
                    )
                    .col(
                        ColumnDef::new(PortForwards::UpdatedAt)
                            .timestamp_with_time_zone()
                            .not_null()
                            .default(Expr::current_timestamp()),
                    )
                    .foreign_key(
                        ForeignKey::create()
                            .name("fk_port_forwards_site")
                            .from(PortForwards::Table, PortForwards::SiteId)
                            .to(Sites::Table, Sites::Id)
                            .on_delete(ForeignKeyAction::Cascade),
                    )
                    .to_owned(),
            )
            .await?;
        manager
            .create_index(
                Index::create()
                    .name("idx_port_forwards_site")
                    .table(PortForwards::Table)
                    .col(PortForwards::SiteId)
                    .to_owned(),
            )
            .await?;
        manager
            .create_index(
                Index::create()
                    .name("idx_port_forwards_listen")
                    .table(PortForwards::Table)
                    .col(PortForwards::ListenPort)
                    .unique()
                    .to_owned(),
            )
            .await?;
        Ok(())
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .drop_table(Table::drop().table(PortForwards::Table).to_owned())
            .await
    }
}

#[derive(DeriveIden)]
enum PortForwards {
    Table,
    Id,
    SiteId,
    Name,
    ListenPort,
    TargetHost,
    TargetPort,
    AllowedCidrs,
    Enabled,
    CreatedAt,
    UpdatedAt,
}

#[derive(DeriveIden)]
enum Sites {
    Table,
    Id,
}
