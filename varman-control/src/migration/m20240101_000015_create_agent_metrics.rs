//! Creates the `agent_metrics` table for edge metrics shipped by agents.
//!
//! Append-only time series written in batches from the `ShipMetrics` stream
//! and read back by `GET /api/v1/agents/{id}/metrics`, so the index matches
//! the `(agent_id, name, recorded_at)` query shape. Retention is handled by
//! an hourly sweep (default 7 days).

use sea_orm_migration::prelude::*;

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .create_table(
                Table::create()
                    .table(AgentMetrics::Table)
                    .if_not_exists()
                    .col(
                        ColumnDef::new(AgentMetrics::Id)
                            .big_integer()
                            .not_null()
                            .auto_increment()
                            .primary_key(),
                    )
                    .col(
                        ColumnDef::new(AgentMetrics::AgentId).uuid().not_null(),
                    )
                    .col(ColumnDef::new(AgentMetrics::Name).string().not_null())
                    .col(
                        ColumnDef::new(AgentMetrics::Labels)
                            .json_binary()
                            .not_null()
                            .default("{}".to_string()),
                    )
                    .col(
                        ColumnDef::new(AgentMetrics::Value).double().not_null(),
                    )
                    .col(
                        ColumnDef::new(AgentMetrics::MetricType)
                            .integer()
                            .not_null()
                            .default(0),
                    )
                    .col(
                        ColumnDef::new(AgentMetrics::RecordedAt)
                            .timestamp_with_time_zone()
                            .not_null(),
                    )
                    .col(
                        ColumnDef::new(AgentMetrics::CreatedAt)
                            .timestamp_with_time_zone()
                            .not_null(),
                    )
                    .foreign_key(
                        ForeignKey::create()
                            .name("fk_agent_metrics_agent_id")
                            .from(AgentMetrics::Table, AgentMetrics::AgentId)
                            .to(Agents::Table, Agents::Id)
                            .on_delete(ForeignKeyAction::Cascade),
                    )
                    .to_owned(),
            )
            .await?;

        manager
            .get_connection()
            .execute_unprepared(
                "CREATE INDEX IF NOT EXISTS idx_agent_metrics_agent_name_time \
                 ON agent_metrics (agent_id, name, recorded_at)",
            )
            .await?;

        Ok(())
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .drop_table(
                Table::drop()
                    .table(AgentMetrics::Table)
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
enum AgentMetrics {
    Table,
    Id,
    AgentId,
    Name,
    Labels,
    Value,
    MetricType,
    RecordedAt,
    CreatedAt,
}
