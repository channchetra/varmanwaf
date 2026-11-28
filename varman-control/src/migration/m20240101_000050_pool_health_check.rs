//! Origin pool health check configuration.
//!
//! Historically the control plane never configured origin health checks:
//! every pool's upstream was pushed to agents with `health_check: None`, so
//! the data plane fell back to a bare TCP probe — a 5xx-soft-failing origin
//! (process up, business broken) was never removed from rotation. These
//! columns carry the operator's HTTP health check posture per pool; the
//! agent synthesizes the data-plane check URL from them.

use sea_orm_migration::prelude::*;

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .alter_table(
                Table::alter()
                    .table(SiteUpstreamPools::Table)
                    .add_column(
                        ColumnDef::new(SiteUpstreamPools::HealthCheckEnabled)
                            .boolean()
                            .not_null()
                            .default(false),
                    )
                    .add_column(
                        ColumnDef::new(SiteUpstreamPools::HealthCheckPath)
                            .string_len(255)
                            .not_null()
                            .default("/"),
                    )
                    .add_column(
                        ColumnDef::new(
                            SiteUpstreamPools::HealthCheckIntervalSeconds,
                        )
                        .integer()
                        .not_null()
                        .default(10),
                    )
                    .add_column(
                        ColumnDef::new(SiteUpstreamPools::HealthCheckTimeoutMs)
                            .integer()
                            .not_null()
                            .default(3000),
                    )
                    .add_column(
                        ColumnDef::new(
                            SiteUpstreamPools::HealthCheckUnhealthyThreshold,
                        )
                        .integer()
                        .not_null()
                        .default(2),
                    )
                    .add_column(
                        ColumnDef::new(
                            SiteUpstreamPools::HealthCheckHealthyThreshold,
                        )
                        .integer()
                        .not_null()
                        .default(1),
                    )
                    .to_owned(),
            )
            .await
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .alter_table(
                Table::alter()
                    .table(SiteUpstreamPools::Table)
                    .drop_column(SiteUpstreamPools::HealthCheckHealthyThreshold)
                    .drop_column(
                        SiteUpstreamPools::HealthCheckUnhealthyThreshold,
                    )
                    .drop_column(SiteUpstreamPools::HealthCheckTimeoutMs)
                    .drop_column(SiteUpstreamPools::HealthCheckIntervalSeconds)
                    .drop_column(SiteUpstreamPools::HealthCheckPath)
                    .drop_column(SiteUpstreamPools::HealthCheckEnabled)
                    .to_owned(),
            )
            .await
    }
}

#[derive(DeriveIden)]
enum SiteUpstreamPools {
    Table,
    HealthCheckEnabled,
    HealthCheckPath,
    HealthCheckIntervalSeconds,
    HealthCheckTimeoutMs,
    HealthCheckUnhealthyThreshold,
    HealthCheckHealthyThreshold,
}
