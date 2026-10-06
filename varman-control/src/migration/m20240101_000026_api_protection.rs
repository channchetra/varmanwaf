//! Control plane self-protection (`api_protection_settings`) and its access
//! log (`control_plane_access_logs`).
//!
//! The 9080 listener is the console itself: these settings decide whether it
//! records its own HTTP traffic, restricts callers to an IP allowlist (inline
//! ranges and/or a referenced `ip_groups` row) and inspects requests with the
//! embedded WAF engine. The log table is append-only, written by the
//! middleware on the request path and swept by the retention scheduler.

use sea_orm_migration::prelude::*;

#[derive(DeriveMigrationName)]
pub struct Migration;

/// Reference to the `ip_groups` table created by an earlier migration.
#[derive(DeriveIden)]
enum IpGroups {
    Table,
    Id,
}

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .create_table(
                Table::create()
                    .table(ApiProtectionSettings::Table)
                    .if_not_exists()
                    .col(
                        ColumnDef::new(ApiProtectionSettings::Id)
                            .integer()
                            .not_null()
                            .primary_key(),
                    )
                    .col(
                        ColumnDef::new(ApiProtectionSettings::AccessLogEnabled)
                            .boolean()
                            .not_null()
                            .default(true),
                    )
                    .col(
                        ColumnDef::new(
                            ApiProtectionSettings::AccessLogRetentionDays,
                        )
                        .integer()
                        .not_null()
                        .default(30),
                    )
                    .col(
                        ColumnDef::new(
                            ApiProtectionSettings::IpAllowlistEnabled,
                        )
                        .boolean()
                        .not_null()
                        .default(false),
                    )
                    .col(
                        ColumnDef::new(
                            ApiProtectionSettings::IpAllowlistRanges,
                        )
                        .array(ColumnType::Text)
                        .not_null()
                        .default(Expr::cust("'{}'::text[]")),
                    )
                    .col(
                        ColumnDef::new(
                            ApiProtectionSettings::IpAllowlistGroupId,
                        )
                        .uuid()
                        .null(),
                    )
                    .col(
                        ColumnDef::new(ApiProtectionSettings::WafEnabled)
                            .boolean()
                            .not_null()
                            .default(false),
                    )
                    .col(
                        ColumnDef::new(ApiProtectionSettings::WafMode)
                            .string_len(20)
                            .not_null()
                            .default("block"),
                    )
                    .col(
                        ColumnDef::new(ApiProtectionSettings::UpdatedAt)
                            .timestamp_with_time_zone()
                            .not_null(),
                    )
                    .foreign_key(
                        ForeignKey::create()
                            .name("fk_api_protection_ip_allowlist_group")
                            .from(
                                ApiProtectionSettings::Table,
                                ApiProtectionSettings::IpAllowlistGroupId,
                            )
                            .to(IpGroups::Table, IpGroups::Id)
                            .on_delete(ForeignKeyAction::SetNull),
                    )
                    .to_owned(),
            )
            .await?;

        manager
            .create_table(
                Table::create()
                    .table(ControlPlaneAccessLogs::Table)
                    .if_not_exists()
                    .col(
                        ColumnDef::new(ControlPlaneAccessLogs::Id)
                            .big_integer()
                            .not_null()
                            .auto_increment()
                            .primary_key(),
                    )
                    .col(
                        ColumnDef::new(ControlPlaneAccessLogs::RequestId)
                            .string_len(64)
                            .null(),
                    )
                    .col(
                        ColumnDef::new(ControlPlaneAccessLogs::Timestamp)
                            .timestamp_with_time_zone()
                            .not_null(),
                    )
                    .col(
                        ColumnDef::new(ControlPlaneAccessLogs::ClientIp)
                            .string_len(64)
                            .not_null(),
                    )
                    .col(
                        ColumnDef::new(ControlPlaneAccessLogs::Method)
                            .string_len(16)
                            .not_null(),
                    )
                    .col(
                        ColumnDef::new(ControlPlaneAccessLogs::Host)
                            .string_len(255)
                            .null(),
                    )
                    .col(
                        ColumnDef::new(ControlPlaneAccessLogs::Path)
                            .text()
                            .not_null(),
                    )
                    .col(
                        ColumnDef::new(ControlPlaneAccessLogs::QueryString)
                            .text()
                            .null(),
                    )
                    .col(
                        ColumnDef::new(ControlPlaneAccessLogs::Scheme)
                            .string_len(8)
                            .null(),
                    )
                    .col(
                        ColumnDef::new(ControlPlaneAccessLogs::Protocol)
                            .string_len(16)
                            .null(),
                    )
                    .col(
                        ColumnDef::new(ControlPlaneAccessLogs::StatusCode)
                            .integer()
                            .null(),
                    )
                    .col(
                        ColumnDef::new(ControlPlaneAccessLogs::LatencyMs)
                            .big_integer()
                            .null(),
                    )
                    .col(
                        ColumnDef::new(ControlPlaneAccessLogs::UserAgent)
                            .text()
                            .null(),
                    )
                    .col(
                        ColumnDef::new(ControlPlaneAccessLogs::Referer)
                            .text()
                            .null(),
                    )
                    .col(
                        ColumnDef::new(ControlPlaneAccessLogs::UserId)
                            .uuid()
                            .null(),
                    )
                    .col(
                        ColumnDef::new(ControlPlaneAccessLogs::UserEmail)
                            .string_len(255)
                            .null(),
                    )
                    // `allowed` | `blocked_allowlist` | `blocked_waf` |
                    // `observed_waf`
                    .col(
                        ColumnDef::new(ControlPlaneAccessLogs::Action)
                            .string_len(32)
                            .not_null()
                            .default("allowed"),
                    )
                    .col(
                        ColumnDef::new(ControlPlaneAccessLogs::Reason)
                            .text()
                            .null(),
                    )
                    .to_owned(),
            )
            .await?;

        let conn = manager.get_connection();
        conn.execute_unprepared(
            "CREATE INDEX IF NOT EXISTS idx_control_plane_access_logs_timestamp \
             ON control_plane_access_logs (timestamp)",
        )
        .await?;
        conn.execute_unprepared(
            "CREATE INDEX IF NOT EXISTS idx_control_plane_access_logs_client_ip \
             ON control_plane_access_logs (client_ip, timestamp)",
        )
        .await?;

        Ok(())
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        let conn = manager.get_connection();
        conn.execute_unprepared(
            "DROP INDEX IF EXISTS idx_control_plane_access_logs_client_ip",
        )
        .await?;
        conn.execute_unprepared(
            "DROP INDEX IF EXISTS idx_control_plane_access_logs_timestamp",
        )
        .await?;

        manager
            .drop_table(
                Table::drop()
                    .table(ControlPlaneAccessLogs::Table)
                    .if_exists()
                    .to_owned(),
            )
            .await?;
        manager
            .drop_table(
                Table::drop()
                    .table(ApiProtectionSettings::Table)
                    .if_exists()
                    .to_owned(),
            )
            .await
    }
}

#[derive(DeriveIden)]
enum ApiProtectionSettings {
    Table,
    Id,
    AccessLogEnabled,
    AccessLogRetentionDays,
    IpAllowlistEnabled,
    IpAllowlistRanges,
    IpAllowlistGroupId,
    WafEnabled,
    WafMode,
    UpdatedAt,
}

#[derive(DeriveIden)]
enum ControlPlaneAccessLogs {
    Table,
    Id,
    RequestId,
    Timestamp,
    ClientIp,
    Method,
    Host,
    Path,
    QueryString,
    Scheme,
    Protocol,
    StatusCode,
    LatencyMs,
    UserAgent,
    Referer,
    UserId,
    UserEmail,
    Action,
    Reason,
}
