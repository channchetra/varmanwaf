//! Creates the `agents` table.
//!
//! One row per registered pingwaf agent instance. `site_id` is nullable because
//! an agent can front several sites; it records the site selected at
//! registration time and is nulled out (not deleted) when that site goes away.

use sea_orm_migration::prelude::*;

use super::m20240101_000001_create_users::ApiKeys;
use super::m20240101_000002_create_sites::Sites;

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .create_table(
                Table::create()
                    .table(Agents::Table)
                    .if_not_exists()
                    .col(
                        ColumnDef::new(Agents::Id)
                            .uuid()
                            .not_null()
                            .primary_key(),
                    )
                    .col(ColumnDef::new(Agents::SiteId).uuid().null())
                    .col(
                        ColumnDef::new(Agents::Hostname)
                            .string_len(255)
                            .not_null(),
                    )
                    .col(
                        ColumnDef::new(Agents::IpAddress)
                            .string_len(45)
                            .not_null(),
                    )
                    .col(ColumnDef::new(Agents::Version).string_len(20).null())
                    .col(ColumnDef::new(Agents::OsInfo).string_len(100).null())
                    .col(ColumnDef::new(Agents::CpuCores).integer().null())
                    .col(
                        ColumnDef::new(Agents::MemoryBytes)
                            .big_integer()
                            .null(),
                    )
                    .col(
                        ColumnDef::new(Agents::Status)
                            .string_len(20)
                            .not_null()
                            .default("offline"),
                    )
                    .col(ColumnDef::new(Agents::ApiKeyId).uuid().null())
                    .col(
                        ColumnDef::new(Agents::ConfigHash)
                            .string_len(64)
                            .null(),
                    )
                    .col(
                        ColumnDef::new(Agents::LastHeartbeat)
                            .timestamp_with_time_zone()
                            .null(),
                    )
                    .col(
                        ColumnDef::new(Agents::RegisteredAt)
                            .timestamp_with_time_zone()
                            .not_null(),
                    )
                    .foreign_key(
                        ForeignKey::create()
                            .name("fk_agents_site_id")
                            .from(Agents::Table, Agents::SiteId)
                            .to(Sites::Table, Sites::Id)
                            .on_delete(ForeignKeyAction::SetNull),
                    )
                    .foreign_key(
                        ForeignKey::create()
                            .name("fk_agents_api_key_id")
                            .from(Agents::Table, Agents::ApiKeyId)
                            .to(ApiKeys::Table, ApiKeys::Id)
                            .on_delete(ForeignKeyAction::SetNull),
                    )
                    .to_owned(),
            )
            .await?;

        manager
            .create_index(
                Index::create()
                    .if_not_exists()
                    .name("idx_agents_site_id")
                    .table(Agents::Table)
                    .col(Agents::SiteId)
                    .to_owned(),
            )
            .await?;
        manager
            .create_index(
                Index::create()
                    .if_not_exists()
                    .name("idx_agents_status")
                    .table(Agents::Table)
                    .col(Agents::Status)
                    .to_owned(),
            )
            .await?;
        // The same host re-registering (restart, new container) must be
        // idempotent, so lookups go through hostname + ip.
        manager
            .create_index(
                Index::create()
                    .if_not_exists()
                    .name("idx_agents_hostname_ip")
                    .table(Agents::Table)
                    .col(Agents::Hostname)
                    .col(Agents::IpAddress)
                    .to_owned(),
            )
            .await?;

        Ok(())
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .drop_table(
                Table::drop().table(Agents::Table).if_exists().to_owned(),
            )
            .await?;
        Ok(())
    }
}

#[derive(DeriveIden)]
pub enum Agents {
    Table,
    Id,
    SiteId,
    Hostname,
    IpAddress,
    Version,
    OsInfo,
    CpuCores,
    MemoryBytes,
    Status,
    ApiKeyId,
    ConfigHash,
    LastHeartbeat,
    RegisteredAt,
}
