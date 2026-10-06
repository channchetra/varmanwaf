//! Adds `agent_blocked_ips`: the control plane's mirror of the dynamic IP
//! blocks each agent currently enforces at the edge.
//!
//! Every heartbeat carries the agent's full block list, so the ingest
//! reconciles by replacement: rows the agent no longer reports are deleted
//! and new ones inserted. The unique key is `(agent_id, site_id, ip)`.

use sea_orm_migration::prelude::*;

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .create_table(
                Table::create()
                    .table(AgentBlockedIps::Table)
                    .if_not_exists()
                    .col(
                        ColumnDef::new(AgentBlockedIps::Id)
                            .big_integer()
                            .not_null()
                            .auto_increment()
                            .primary_key(),
                    )
                    .col(
                        ColumnDef::new(AgentBlockedIps::AgentId)
                            .uuid()
                            .not_null(),
                    )
                    .col(
                        ColumnDef::new(AgentBlockedIps::SiteId)
                            .uuid()
                            .not_null(),
                    )
                    .col(
                        ColumnDef::new(AgentBlockedIps::Ip)
                            .string_len(45)
                            .not_null(),
                    )
                    .col(ColumnDef::new(AgentBlockedIps::Reason).text().null())
                    .col(
                        ColumnDef::new(AgentBlockedIps::BlockedAt)
                            .timestamp_with_time_zone()
                            .not_null(),
                    )
                    .col(
                        ColumnDef::new(AgentBlockedIps::ExpiresAt)
                            .timestamp_with_time_zone()
                            .null(),
                    )
                    .col(
                        ColumnDef::new(AgentBlockedIps::CreatedAt)
                            .timestamp_with_time_zone()
                            .not_null(),
                    )
                    .col(
                        ColumnDef::new(AgentBlockedIps::UpdatedAt)
                            .timestamp_with_time_zone()
                            .not_null(),
                    )
                    .foreign_key(
                        ForeignKey::create()
                            .name("fk_agent_blocked_ips_agent_id")
                            .from(
                                AgentBlockedIps::Table,
                                AgentBlockedIps::AgentId,
                            )
                            .to(Agents::Table, Agents::Id)
                            .on_delete(ForeignKeyAction::Cascade),
                    )
                    .foreign_key(
                        ForeignKey::create()
                            .name("fk_agent_blocked_ips_site_id")
                            .from(
                                AgentBlockedIps::Table,
                                AgentBlockedIps::SiteId,
                            )
                            .to(Sites::Table, Sites::Id)
                            .on_delete(ForeignKeyAction::Cascade),
                    )
                    .to_owned(),
            )
            .await?;

        manager
            .get_connection()
            .execute_unprepared(
                "CREATE UNIQUE INDEX IF NOT EXISTS \
                 idx_agent_blocked_ips_unique \
                 ON agent_blocked_ips (agent_id, site_id, ip)",
            )
            .await?;

        // The dashboard lists blocks per site ordered by recency.
        manager
            .get_connection()
            .execute_unprepared(
                "CREATE INDEX IF NOT EXISTS idx_agent_blocked_ips_site_time \
                 ON agent_blocked_ips (site_id, blocked_at DESC)",
            )
            .await?;

        Ok(())
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .drop_table(
                Table::drop()
                    .table(AgentBlockedIps::Table)
                    .if_exists()
                    .to_owned(),
            )
            .await?;

        Ok(())
    }
}

#[derive(DeriveIden)]
enum Agents {
    Table,
    Id,
}

#[derive(DeriveIden)]
enum Sites {
    Table,
    Id,
}

#[derive(DeriveIden)]
enum AgentBlockedIps {
    Table,
    Id,
    AgentId,
    SiteId,
    Ip,
    Reason,
    BlockedAt,
    ExpiresAt,
    CreatedAt,
    UpdatedAt,
}
