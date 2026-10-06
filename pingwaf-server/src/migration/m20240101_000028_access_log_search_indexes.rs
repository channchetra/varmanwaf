//! Search indexes for the access log's investigation dimensions.
//!
//! `security_events` already carries `(client_ip, timestamp DESC)` for tracing
//! an attacker back through history; the access log lacked the same index, so
//! "what did this IP request" and the top-IPs panel filtered on the time index
//! alone. Host filtering (multi-site deployments slicing the log by domain)
//! had no index at all. Both columns pair with `timestamp DESC` so a windowed
//! search stays an index scan.

use sea_orm_migration::prelude::*;

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        let conn = manager.get_connection();
        conn.execute_unprepared(
            "CREATE INDEX IF NOT EXISTS idx_access_logs_ip_time \
             ON access_logs (client_ip, timestamp DESC)",
        )
        .await?;
        conn.execute_unprepared(
            "CREATE INDEX IF NOT EXISTS idx_access_logs_host_time \
             ON access_logs (host, timestamp DESC) WHERE host IS NOT NULL",
        )
        .await?;
        Ok(())
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        let conn = manager.get_connection();
        conn.execute_unprepared("DROP INDEX IF EXISTS idx_access_logs_ip_time")
            .await?;
        conn.execute_unprepared(
            "DROP INDEX IF EXISTS idx_access_logs_host_time",
        )
        .await?;
        Ok(())
    }
}
