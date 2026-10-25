//! Add the single-row `management_certificate` table.
//!
//! The management dashboard can present a Let's Encrypt certificate for a
//! domain or an IP address instead of a self-signed/uploaded one. The request
//! and its lifecycle live here; the issued material is stored with every
//! other active control-plane certificate in `control_plane_certificates`
//! (source `acme`). `installed_fingerprint` makes the install idempotent
//! across restarts and renewals.

use sea_orm_migration::prelude::*;

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .create_table(
                Table::create()
                    .table(ManagementCertificate::Table)
                    .col(
                        ColumnDef::new(ManagementCertificate::Id)
                            .integer()
                            .not_null()
                            .primary_key(),
                    )
                    .col(
                        ColumnDef::new(ManagementCertificate::Identity)
                            .text()
                            .not_null()
                            .default(""),
                    )
                    .col(
                        ColumnDef::new(ManagementCertificate::Email)
                            .text()
                            .not_null()
                            .default(""),
                    )
                    .col(
                        ColumnDef::new(ManagementCertificate::Challenge)
                            .text()
                            .not_null()
                            .default("http-01"),
                    )
                    .col(
                        ColumnDef::new(ManagementCertificate::Enabled)
                            .boolean()
                            .not_null()
                            .default(false),
                    )
                    .col(
                        ColumnDef::new(ManagementCertificate::Status)
                            .text()
                            .not_null()
                            .default("disabled"),
                    )
                    .col(
                        ColumnDef::new(ManagementCertificate::FailureReason)
                            .text(),
                    )
                    .col(
                        ColumnDef::new(ManagementCertificate::RequestedAt)
                            .timestamp_with_time_zone(),
                    )
                    .col(
                        ColumnDef::new(
                            ManagementCertificate::InstalledFingerprint,
                        )
                        .text(),
                    )
                    .col(
                        ColumnDef::new(ManagementCertificate::UpdatedAt)
                            .timestamp_with_time_zone()
                            .not_null()
                            .default(Expr::current_timestamp()),
                    )
                    .to_owned(),
            )
            .await
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .drop_table(
                Table::drop().table(ManagementCertificate::Table).to_owned(),
            )
            .await
    }
}

#[derive(DeriveIden)]
enum ManagementCertificate {
    Table,
    Id,
    Identity,
    Email,
    Challenge,
    Enabled,
    Status,
    FailureReason,
    RequestedAt,
    InstalledFingerprint,
    UpdatedAt,
}
