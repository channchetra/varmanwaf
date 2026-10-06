//! Creates the high volume log tables: `security_events` and `access_logs`.
//!
//! Both are append-only and queried by `(site_id, timestamp DESC)`, which is why
//! the composite indexes are created with raw SQL: sea-query's `Index` builder
//! cannot express a sort direction per column. In a production deployment these
//! tables are partitioned by day; the layout here is deliberately simple so a
//! single-node install works out of the box.

use sea_orm_migration::prelude::*;

use super::m20240101_000002_create_sites::Sites;
use super::m20240101_000004_create_agents::Agents;

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .create_table(
                Table::create()
                    .table(SecurityEvents::Table)
                    .if_not_exists()
                    .col(
                        ColumnDef::new(SecurityEvents::Id)
                            .big_integer()
                            .not_null()
                            .auto_increment()
                            .primary_key(),
                    )
                    .col(ColumnDef::new(SecurityEvents::SiteId).uuid().null())
                    .col(ColumnDef::new(SecurityEvents::AgentId).uuid().null())
                    .col(
                        ColumnDef::new(SecurityEvents::RequestId)
                            .string_len(36)
                            .null(),
                    )
                    .col(
                        ColumnDef::new(SecurityEvents::Timestamp)
                            .timestamp_with_time_zone()
                            .not_null(),
                    )
                    .col(
                        ColumnDef::new(SecurityEvents::ClientIp)
                            .string_len(45)
                            .not_null(),
                    )
                    .col(
                        ColumnDef::new(SecurityEvents::Method)
                            .string_len(10)
                            .not_null(),
                    )
                    .col(
                        ColumnDef::new(SecurityEvents::Host)
                            .string_len(255)
                            .null(),
                    )
                    .col(ColumnDef::new(SecurityEvents::Path).text().null())
                    .col(
                        ColumnDef::new(SecurityEvents::RuleId)
                            .string_len(100)
                            .null(),
                    )
                    .col(
                        ColumnDef::new(SecurityEvents::RuleName)
                            .string_len(200)
                            .null(),
                    )
                    .col(
                        ColumnDef::new(SecurityEvents::Action)
                            .string_len(30)
                            .not_null(),
                    )
                    .col(ColumnDef::new(SecurityEvents::Score).integer().null())
                    .col(
                        ColumnDef::new(SecurityEvents::WafDetails)
                            .text()
                            .null(),
                    )
                    .col(
                        ColumnDef::new(SecurityEvents::CountryCode)
                            .string_len(2)
                            .null(),
                    )
                    .col(
                        ColumnDef::new(SecurityEvents::UserAgent).text().null(),
                    )
                    .col(
                        ColumnDef::new(SecurityEvents::CreatedAt)
                            .timestamp_with_time_zone()
                            .not_null(),
                    )
                    .foreign_key(
                        ForeignKey::create()
                            .name("fk_security_events_site_id")
                            .from(SecurityEvents::Table, SecurityEvents::SiteId)
                            .to(Sites::Table, Sites::Id)
                            .on_delete(ForeignKeyAction::SetNull),
                    )
                    .foreign_key(
                        ForeignKey::create()
                            .name("fk_security_events_agent_id")
                            .from(
                                SecurityEvents::Table,
                                SecurityEvents::AgentId,
                            )
                            .to(Agents::Table, Agents::Id)
                            .on_delete(ForeignKeyAction::SetNull),
                    )
                    .to_owned(),
            )
            .await?;

        manager
            .create_table(
                Table::create()
                    .table(AccessLogs::Table)
                    .if_not_exists()
                    .col(
                        ColumnDef::new(AccessLogs::Id)
                            .big_integer()
                            .not_null()
                            .auto_increment()
                            .primary_key(),
                    )
                    .col(ColumnDef::new(AccessLogs::SiteId).uuid().null())
                    .col(ColumnDef::new(AccessLogs::AgentId).uuid().null())
                    .col(
                        ColumnDef::new(AccessLogs::RequestId)
                            .string_len(36)
                            .null(),
                    )
                    .col(
                        ColumnDef::new(AccessLogs::Timestamp)
                            .timestamp_with_time_zone()
                            .not_null(),
                    )
                    .col(
                        ColumnDef::new(AccessLogs::ClientIp)
                            .string_len(45)
                            .not_null(),
                    )
                    .col(
                        ColumnDef::new(AccessLogs::Method)
                            .string_len(10)
                            .not_null(),
                    )
                    .col(
                        ColumnDef::new(AccessLogs::Host).string_len(255).null(),
                    )
                    .col(ColumnDef::new(AccessLogs::Path).text().null())
                    .col(ColumnDef::new(AccessLogs::QueryString).text().null())
                    .col(
                        ColumnDef::new(AccessLogs::StatusCode).integer().null(),
                    )
                    .col(
                        ColumnDef::new(AccessLogs::ResponseSize)
                            .big_integer()
                            .null(),
                    )
                    .col(
                        ColumnDef::new(AccessLogs::UpstreamAddr)
                            .string_len(255)
                            .null(),
                    )
                    .col(
                        ColumnDef::new(AccessLogs::UpstreamLatencyMs)
                            .big_integer()
                            .null(),
                    )
                    .col(
                        ColumnDef::new(AccessLogs::TotalLatencyMs)
                            .big_integer()
                            .null(),
                    )
                    .col(
                        ColumnDef::new(AccessLogs::CacheStatus)
                            .string_len(20)
                            .null(),
                    )
                    .col(ColumnDef::new(AccessLogs::UserAgent).text().null())
                    .col(ColumnDef::new(AccessLogs::Referer).text().null())
                    .col(
                        ColumnDef::new(AccessLogs::CountryCode)
                            .string_len(2)
                            .null(),
                    )
                    .col(
                        ColumnDef::new(AccessLogs::TlsVersion)
                            .string_len(10)
                            .null(),
                    )
                    .foreign_key(
                        ForeignKey::create()
                            .name("fk_access_logs_site_id")
                            .from(AccessLogs::Table, AccessLogs::SiteId)
                            .to(Sites::Table, Sites::Id)
                            .on_delete(ForeignKeyAction::SetNull),
                    )
                    .foreign_key(
                        ForeignKey::create()
                            .name("fk_access_logs_agent_id")
                            .from(AccessLogs::Table, AccessLogs::AgentId)
                            .to(Agents::Table, Agents::Id)
                            .on_delete(ForeignKeyAction::SetNull),
                    )
                    .to_owned(),
            )
            .await?;

        let conn = manager.get_connection();
        conn.execute_unprepared(
            "CREATE INDEX IF NOT EXISTS idx_security_events_site_time \
             ON security_events (site_id, timestamp DESC)",
        )
        .await?;
        conn.execute_unprepared(
            "CREATE INDEX IF NOT EXISTS idx_security_events_ip_time \
             ON security_events (client_ip, timestamp DESC)",
        )
        .await?;
        conn.execute_unprepared(
            "CREATE INDEX IF NOT EXISTS idx_security_events_action \
             ON security_events (site_id, action)",
        )
        .await?;
        conn.execute_unprepared(
            "CREATE INDEX IF NOT EXISTS idx_access_logs_site_time \
             ON access_logs (site_id, timestamp DESC)",
        )
        .await?;
        conn.execute_unprepared(
            "CREATE INDEX IF NOT EXISTS idx_access_logs_status_time \
             ON access_logs (site_id, status_code, timestamp DESC)",
        )
        .await?;

        Ok(())
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .drop_table(
                Table::drop()
                    .table(AccessLogs::Table)
                    .if_exists()
                    .to_owned(),
            )
            .await?;
        manager
            .drop_table(
                Table::drop()
                    .table(SecurityEvents::Table)
                    .if_exists()
                    .to_owned(),
            )
            .await?;
        Ok(())
    }
}

#[derive(DeriveIden)]
pub enum SecurityEvents {
    Table,
    Id,
    SiteId,
    AgentId,
    RequestId,
    Timestamp,
    ClientIp,
    Method,
    Host,
    Path,
    RuleId,
    RuleName,
    Action,
    Score,
    WafDetails,
    CountryCode,
    UserAgent,
    CreatedAt,
}

#[derive(DeriveIden)]
pub enum AccessLogs {
    Table,
    Id,
    SiteId,
    AgentId,
    RequestId,
    Timestamp,
    ClientIp,
    Method,
    Host,
    Path,
    QueryString,
    StatusCode,
    ResponseSize,
    UpstreamAddr,
    UpstreamLatencyMs,
    TotalLatencyMs,
    CacheStatus,
    UserAgent,
    Referer,
    CountryCode,
    TlsVersion,
}
