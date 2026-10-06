//! Adds the host probe tables: `host_samples` plus the two address columns on
//! `agents`.
//!
//! `host_samples` is append-only and written in batches every heartbeat (the
//! agent buffers its 5-second samples locally and ships them together), so the
//! index is `(agent_id, sampled_at DESC)` to match the dashboard query.

use sea_orm_migration::prelude::*;

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .create_table(
                Table::create()
                    .table(HostSamples::Table)
                    .if_not_exists()
                    .col(
                        ColumnDef::new(HostSamples::Id)
                            .big_integer()
                            .not_null()
                            .auto_increment()
                            .primary_key(),
                    )
                    .col(ColumnDef::new(HostSamples::AgentId).uuid().not_null())
                    .col(
                        ColumnDef::new(HostSamples::SampledAt)
                            .timestamp_with_time_zone()
                            .not_null(),
                    )
                    .col(
                        ColumnDef::new(HostSamples::CpuUsagePercent)
                            .double()
                            .null(),
                    )
                    .col(ColumnDef::new(HostSamples::Load1).double().null())
                    .col(ColumnDef::new(HostSamples::Load5).double().null())
                    .col(ColumnDef::new(HostSamples::Load15).double().null())
                    .col(
                        ColumnDef::new(HostSamples::MemoryTotalBytes)
                            .big_integer()
                            .null(),
                    )
                    .col(
                        ColumnDef::new(HostSamples::MemoryUsedBytes)
                            .big_integer()
                            .null(),
                    )
                    .col(
                        ColumnDef::new(HostSamples::MemoryAvailableBytes)
                            .big_integer()
                            .null(),
                    )
                    .col(
                        ColumnDef::new(HostSamples::SwapTotalBytes)
                            .big_integer()
                            .null(),
                    )
                    .col(
                        ColumnDef::new(HostSamples::SwapUsedBytes)
                            .big_integer()
                            .null(),
                    )
                    .col(
                        ColumnDef::new(HostSamples::DiskTotalBytes)
                            .big_integer()
                            .null(),
                    )
                    .col(
                        ColumnDef::new(HostSamples::DiskUsedBytes)
                            .big_integer()
                            .null(),
                    )
                    .col(
                        ColumnDef::new(HostSamples::NetRxBytes)
                            .big_integer()
                            .null(),
                    )
                    .col(
                        ColumnDef::new(HostSamples::NetTxBytes)
                            .big_integer()
                            .null(),
                    )
                    .col(
                        ColumnDef::new(HostSamples::DiskReadBytes)
                            .big_integer()
                            .null(),
                    )
                    .col(
                        ColumnDef::new(HostSamples::DiskWriteBytes)
                            .big_integer()
                            .null(),
                    )
                    .col(
                        ColumnDef::new(HostSamples::ProcessCount)
                            .integer()
                            .null(),
                    )
                    .col(
                        ColumnDef::new(HostSamples::TcpConnections)
                            .integer()
                            .null(),
                    )
                    .col(
                        ColumnDef::new(HostSamples::UptimeSecs)
                            .big_integer()
                            .null(),
                    )
                    .col(
                        ColumnDef::new(HostSamples::CreatedAt)
                            .timestamp_with_time_zone()
                            .not_null(),
                    )
                    .foreign_key(
                        ForeignKey::create()
                            .name("fk_host_samples_agent_id")
                            .from(HostSamples::Table, HostSamples::AgentId)
                            .to(Agents::Table, Agents::Id)
                            .on_delete(ForeignKeyAction::Cascade),
                    )
                    .to_owned(),
            )
            .await?;

        manager
            .get_connection()
            .execute_unprepared(
                "CREATE INDEX IF NOT EXISTS idx_host_samples_agent_time \
                 ON host_samples (agent_id, sampled_at DESC)",
            )
            .await?;

        manager
            .alter_table(
                Table::alter()
                    .table(Agents::Table)
                    .add_column(
                        ColumnDef::new(Agents::PublicIp).string_len(45).null(),
                    )
                    .add_column(
                        ColumnDef::new(Agents::PrivateIp).string_len(45).null(),
                    )
                    .to_owned(),
            )
            .await?;

        Ok(())
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .alter_table(
                Table::alter()
                    .table(Agents::Table)
                    .drop_column(Agents::PublicIp)
                    .drop_column(Agents::PrivateIp)
                    .to_owned(),
            )
            .await?;

        manager
            .drop_table(
                Table::drop()
                    .table(HostSamples::Table)
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
    PublicIp,
    PrivateIp,
}

#[derive(DeriveIden)]
enum HostSamples {
    Table,
    Id,
    AgentId,
    SampledAt,
    CpuUsagePercent,
    Load1,
    Load5,
    Load15,
    MemoryTotalBytes,
    MemoryUsedBytes,
    MemoryAvailableBytes,
    SwapTotalBytes,
    SwapUsedBytes,
    DiskTotalBytes,
    DiskUsedBytes,
    NetRxBytes,
    NetTxBytes,
    DiskReadBytes,
    DiskWriteBytes,
    ProcessCount,
    TcpConnections,
    UptimeSecs,
    CreatedAt,
}
