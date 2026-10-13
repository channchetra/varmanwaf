//! Adds `config_versions`, the version history of the WAF configuration.
//!
//! Every configuration change that reaches the agents records a snapshot of
//! the affected scope here: `site_id` is `NULL` for deployment-wide settings
//! (defense mode, global error pages) and the site's UUID for site policies.
//! The console and the `pingwaf config` CLI list these rows and restore a
//! chosen snapshot back onto the policy tables.

use sea_orm_migration::prelude::*;

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .create_table(
                Table::create()
                    .table(ConfigVersions::Table)
                    .if_not_exists()
                    .col(
                        ColumnDef::new(ConfigVersions::Id)
                            .big_integer()
                            .not_null()
                            .auto_increment()
                            .primary_key(),
                    )
                    .col(ColumnDef::new(ConfigVersions::SiteId).uuid().null())
                    .col(
                        ColumnDef::new(ConfigVersions::ConfigHash)
                            .string_len(64)
                            .not_null()
                            .default(""),
                    )
                    .col(
                        ColumnDef::new(ConfigVersions::Source)
                            .string_len(30)
                            .not_null(),
                    )
                    .col(
                        ColumnDef::new(ConfigVersions::Actor)
                            .string_len(255)
                            .null(),
                    )
                    .col(ColumnDef::new(ConfigVersions::Summary).json().null())
                    .col(
                        ColumnDef::new(ConfigVersions::Snapshot)
                            .json()
                            .not_null(),
                    )
                    .col(
                        ColumnDef::new(ConfigVersions::CreatedAt)
                            .timestamp_with_time_zone()
                            .not_null(),
                    )
                    .to_owned(),
            )
            .await?;

        manager
            .create_index(
                Index::create()
                    .name("idx_config_versions_scope")
                    .table(ConfigVersions::Table)
                    .col(ConfigVersions::SiteId)
                    .col(ConfigVersions::Id)
                    .to_owned(),
            )
            .await
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .drop_table(Table::drop().table(ConfigVersions::Table).to_owned())
            .await
    }
}

#[derive(DeriveIden)]
enum ConfigVersions {
    Table,
    Id,
    SiteId,
    ConfigHash,
    Source,
    Actor,
    Summary,
    Snapshot,
    CreatedAt,
}
