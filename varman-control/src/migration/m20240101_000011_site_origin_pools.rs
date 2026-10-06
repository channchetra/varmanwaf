//! Creates `site_upstream_pools` and `site_routes`, and moves
//! `site_upstreams` rows under per-site origin pools.
//!
//! A pool groups origin nodes with a shared load-balancing algorithm and
//! TLS settings; routes map request paths to pools. Each site gets a
//! default pool during backfill so existing upstreams keep working.

use sea_orm_migration::prelude::*;

use super::m20240101_000002_create_sites::{SiteUpstreams, Sites};

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .create_table(
                Table::create()
                    .table(SiteUpstreamPools::Table)
                    .if_not_exists()
                    .col(
                        ColumnDef::new(SiteUpstreamPools::Id)
                            .uuid()
                            .not_null()
                            .primary_key(),
                    )
                    .col(
                        ColumnDef::new(SiteUpstreamPools::SiteId)
                            .uuid()
                            .not_null(),
                    )
                    .col(
                        ColumnDef::new(SiteUpstreamPools::Name)
                            .string_len(100)
                            .not_null(),
                    )
                    .col(
                        ColumnDef::new(SiteUpstreamPools::LbAlgorithm)
                            .string_len(64)
                            .not_null()
                            .default("round_robin"),
                    )
                    .col(
                        ColumnDef::new(SiteUpstreamPools::Sni)
                            .string_len(255)
                            .null(),
                    )
                    .col(
                        ColumnDef::new(SiteUpstreamPools::VerifyCert)
                            .boolean()
                            .null(),
                    )
                    .col(
                        ColumnDef::new(SiteUpstreamPools::IsDefault)
                            .boolean()
                            .not_null()
                            .default(false),
                    )
                    .col(
                        ColumnDef::new(SiteUpstreamPools::CreatedAt)
                            .timestamp_with_time_zone()
                            .not_null(),
                    )
                    .foreign_key(
                        ForeignKey::create()
                            .name("fk_site_upstream_pools_site_id")
                            .from(
                                SiteUpstreamPools::Table,
                                SiteUpstreamPools::SiteId,
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
                    .if_not_exists()
                    .name("idx_site_upstream_pools_site_id")
                    .table(SiteUpstreamPools::Table)
                    .col(SiteUpstreamPools::SiteId)
                    .to_owned(),
            )
            .await?;
        manager
            .create_index(
                Index::create()
                    .if_not_exists()
                    .unique()
                    .name("uq_site_upstream_pools_site_name")
                    .table(SiteUpstreamPools::Table)
                    .col(SiteUpstreamPools::SiteId)
                    .col(SiteUpstreamPools::Name)
                    .to_owned(),
            )
            .await?;

        manager
            .alter_table(
                Table::alter()
                    .table(SiteUpstreams::Table)
                    .add_column(
                        ColumnDef::new(SiteUpstreams::PoolId).uuid().null(),
                    )
                    .to_owned(),
            )
            .await?;

        manager
            .create_table(
                Table::create()
                    .table(SiteRoutes::Table)
                    .if_not_exists()
                    .col(
                        ColumnDef::new(SiteRoutes::Id)
                            .uuid()
                            .not_null()
                            .primary_key(),
                    )
                    .col(ColumnDef::new(SiteRoutes::SiteId).uuid().not_null())
                    .col(
                        ColumnDef::new(SiteRoutes::Name)
                            .string_len(100)
                            .not_null(),
                    )
                    .col(
                        ColumnDef::new(SiteRoutes::MatchType)
                            .string_len(16)
                            .not_null()
                            .default("prefix"),
                    )
                    .col(
                        ColumnDef::new(SiteRoutes::Path)
                            .string_len(512)
                            .not_null(),
                    )
                    .col(ColumnDef::new(SiteRoutes::Priority).integer().null())
                    .col(
                        ColumnDef::new(SiteRoutes::Enabled)
                            .boolean()
                            .not_null()
                            .default(true),
                    )
                    .col(ColumnDef::new(SiteRoutes::PoolId).uuid().not_null())
                    .col(
                        ColumnDef::new(SiteRoutes::CreatedAt)
                            .timestamp_with_time_zone()
                            .not_null(),
                    )
                    .foreign_key(
                        ForeignKey::create()
                            .name("fk_site_routes_site_id")
                            .from(SiteRoutes::Table, SiteRoutes::SiteId)
                            .to(Sites::Table, Sites::Id)
                            .on_delete(ForeignKeyAction::Cascade),
                    )
                    .foreign_key(
                        ForeignKey::create()
                            .name("fk_site_routes_pool_id")
                            .from(SiteRoutes::Table, SiteRoutes::PoolId)
                            .to(SiteUpstreamPools::Table, SiteUpstreamPools::Id)
                            .on_delete(ForeignKeyAction::Cascade),
                    )
                    .to_owned(),
            )
            .await?;

        manager
            .create_index(
                Index::create()
                    .if_not_exists()
                    .name("idx_site_routes_site_id")
                    .table(SiteRoutes::Table)
                    .col(SiteRoutes::SiteId)
                    .to_owned(),
            )
            .await?;

        // One default pool per site (even sites without upstreams), then
        // move every existing upstream row into its site's default pool.
        let conn = manager.get_connection();
        conn.execute_unprepared(
            "INSERT INTO site_upstream_pools \
             (id, site_id, name, lb_algorithm, is_default, created_at) \
             SELECT gen_random_uuid(), s.id, 'default', 'round_robin', true, now() \
             FROM sites s \
             WHERE NOT EXISTS (\
                 SELECT 1 FROM site_upstream_pools p WHERE p.site_id = s.id\
             )",
        )
        .await?;
        conn.execute_unprepared(
            "UPDATE site_upstreams u SET pool_id = p.id \
             FROM site_upstream_pools p \
             WHERE p.site_id = u.site_id AND p.is_default AND u.pool_id IS NULL",
        )
        .await?;

        manager
            .alter_table(
                Table::alter()
                    .table(SiteUpstreams::Table)
                    .modify_column(
                        ColumnDef::new(SiteUpstreams::PoolId).uuid().not_null(),
                    )
                    .to_owned(),
            )
            .await?;

        manager
            .create_index(
                Index::create()
                    .if_not_exists()
                    .name("idx_site_upstreams_pool_id")
                    .table(SiteUpstreams::Table)
                    .col(SiteUpstreams::PoolId)
                    .to_owned(),
            )
            .await?;

        Ok(())
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .drop_table(
                Table::drop()
                    .table(SiteRoutes::Table)
                    .if_exists()
                    .to_owned(),
            )
            .await?;
        manager
            .alter_table(
                Table::alter()
                    .table(SiteUpstreams::Table)
                    .drop_column(SiteUpstreams::PoolId)
                    .to_owned(),
            )
            .await?;
        manager
            .drop_table(
                Table::drop()
                    .table(SiteUpstreamPools::Table)
                    .if_exists()
                    .to_owned(),
            )
            .await?;
        Ok(())
    }
}

#[derive(DeriveIden)]
pub enum SiteUpstreamPools {
    Table,
    Id,
    SiteId,
    Name,
    LbAlgorithm,
    Sni,
    VerifyCert,
    IsDefault,
    CreatedAt,
}

#[derive(DeriveIden)]
pub enum SiteRoutes {
    Table,
    Id,
    SiteId,
    Name,
    MatchType,
    Path,
    Priority,
    Enabled,
    PoolId,
    CreatedAt,
}
