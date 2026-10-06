//! Certificate the control plane itself serves the dashboard with
//! (`control_plane_certificates`).
//!
//! One row is active at a time; older rows are kept so an operator can see what
//! was replaced and roll back by activating a previous entry. The private key
//! lives here in plain text (same trade-off as the mTLS material) because the
//! listener has to reload it without an operator on the box.

use sea_orm_migration::prelude::*;

use super::m20240101_000001_create_users::Users;

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .create_table(
                Table::create()
                    .table(ControlPlaneCertificates::Table)
                    .if_not_exists()
                    .col(
                        ColumnDef::new(ControlPlaneCertificates::Id)
                            .uuid()
                            .not_null()
                            .primary_key(),
                    )
                    // `self_signed` (generated here) or `uploaded`.
                    .col(
                        ColumnDef::new(ControlPlaneCertificates::Source)
                            .string_len(20)
                            .not_null()
                            .default("self_signed"),
                    )
                    // Full PEM chain: the leaf first, then any intermediates.
                    .col(
                        ColumnDef::new(ControlPlaneCertificates::CertPem)
                            .text()
                            .not_null(),
                    )
                    .col(
                        ColumnDef::new(ControlPlaneCertificates::KeyPem)
                            .text()
                            .not_null(),
                    )
                    .col(
                        ColumnDef::new(ControlPlaneCertificates::SubjectDn)
                            .string_len(500)
                            .not_null(),
                    )
                    .col(
                        ColumnDef::new(ControlPlaneCertificates::CommonName)
                            .string_len(255)
                            .null(),
                    )
                    // Subject alternative names as reported by the certificate.
                    .col(
                        ColumnDef::new(ControlPlaneCertificates::Sans)
                            .json_binary()
                            .not_null(),
                    )
                    .col(
                        ColumnDef::new(ControlPlaneCertificates::Serial)
                            .string_len(128)
                            .not_null(),
                    )
                    .col(
                        ColumnDef::new(
                            ControlPlaneCertificates::FingerprintSha256,
                        )
                        .string_len(64)
                        .not_null(),
                    )
                    .col(
                        ColumnDef::new(ControlPlaneCertificates::NotBefore)
                            .timestamp_with_time_zone()
                            .not_null(),
                    )
                    .col(
                        ColumnDef::new(ControlPlaneCertificates::NotAfter)
                            .timestamp_with_time_zone()
                            .not_null(),
                    )
                    .col(
                        ColumnDef::new(ControlPlaneCertificates::IsActive)
                            .boolean()
                            .not_null()
                            .default(false),
                    )
                    // Nulled rather than cascaded: the certificate stays even
                    // when the account that uploaded it is removed.
                    .col(
                        ColumnDef::new(ControlPlaneCertificates::CreatedBy)
                            .uuid()
                            .null(),
                    )
                    .col(
                        ColumnDef::new(ControlPlaneCertificates::CreatedAt)
                            .timestamp_with_time_zone()
                            .not_null(),
                    )
                    .foreign_key(
                        ForeignKey::create()
                            .name("fk_control_plane_certificates_created_by")
                            .from(
                                ControlPlaneCertificates::Table,
                                ControlPlaneCertificates::CreatedBy,
                            )
                            .to(Users::Table, Users::Id)
                            .on_delete(ForeignKeyAction::SetNull),
                    )
                    .to_owned(),
            )
            .await?;

        manager
            .create_index(
                Index::create()
                    .name("idx_control_plane_certificates_active")
                    .table(ControlPlaneCertificates::Table)
                    .col(ControlPlaneCertificates::IsActive)
                    .to_owned(),
            )
            .await?;

        Ok(())
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .drop_table(
                Table::drop()
                    .table(ControlPlaneCertificates::Table)
                    .to_owned(),
            )
            .await
    }
}

#[derive(DeriveIden)]
enum ControlPlaneCertificates {
    Table,
    Id,
    Source,
    CertPem,
    KeyPem,
    SubjectDn,
    CommonName,
    Sans,
    Serial,
    FingerprintSha256,
    NotBefore,
    NotAfter,
    IsActive,
    CreatedBy,
    CreatedAt,
}
