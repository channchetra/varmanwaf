//! mTLS material managed by the control plane: the certificate authorities a
//! site trusts (`mtls_cas`) and the client certificates issued from them
//! (`mtls_client_certificates`), plus the site-level switches that decide how a
//! presented certificate is checked.

use sea_orm_migration::prelude::*;

use super::m20240101_000002_create_sites::Sites;

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .create_table(
                Table::create()
                    .table(MtlsCas::Table)
                    .if_not_exists()
                    .col(
                        ColumnDef::new(MtlsCas::Id)
                            .uuid()
                            .not_null()
                            .primary_key(),
                    )
                    .col(ColumnDef::new(MtlsCas::SiteId).uuid().not_null())
                    .col(
                        ColumnDef::new(MtlsCas::Name)
                            .string_len(200)
                            .not_null(),
                    )
                    // `generated` CAs keep their private key here; `imported`
                    // ones only carry the certificate.
                    .col(
                        ColumnDef::new(MtlsCas::Source)
                            .string_len(20)
                            .not_null()
                            .default("generated"),
                    )
                    .col(ColumnDef::new(MtlsCas::CertPem).text().not_null())
                    .col(ColumnDef::new(MtlsCas::KeyPem).text().null())
                    .col(
                        ColumnDef::new(MtlsCas::SubjectDn)
                            .string_len(500)
                            .not_null(),
                    )
                    .col(
                        ColumnDef::new(MtlsCas::Serial)
                            .string_len(128)
                            .not_null(),
                    )
                    .col(
                        ColumnDef::new(MtlsCas::FingerprintSha256)
                            .string_len(64)
                            .not_null(),
                    )
                    // Organization every client certificate must carry; the
                    // edge rejects certificates issued by another CA for the
                    // same trust store when it is set.
                    .col(
                        ColumnDef::new(MtlsCas::ExpectedOrganization)
                            .string_len(255)
                            .null(),
                    )
                    .col(
                        ColumnDef::new(MtlsCas::NotBefore)
                            .timestamp_with_time_zone()
                            .not_null(),
                    )
                    .col(
                        ColumnDef::new(MtlsCas::NotAfter)
                            .timestamp_with_time_zone()
                            .not_null(),
                    )
                    .col(
                        ColumnDef::new(MtlsCas::IsActive)
                            .boolean()
                            .not_null()
                            .default(true),
                    )
                    .col(
                        ColumnDef::new(MtlsCas::CreatedAt)
                            .timestamp_with_time_zone()
                            .not_null(),
                    )
                    .foreign_key(
                        ForeignKey::create()
                            .name("fk_mtls_cas_site_id")
                            .from(MtlsCas::Table, MtlsCas::SiteId)
                            .to(Sites::Table, Sites::Id)
                            .on_delete(ForeignKeyAction::Cascade),
                    )
                    .to_owned(),
            )
            .await?;

        manager
            .create_index(
                Index::create()
                    .name("idx_mtls_cas_site_id")
                    .table(MtlsCas::Table)
                    .col(MtlsCas::SiteId)
                    .to_owned(),
            )
            .await?;

        manager
            .create_table(
                Table::create()
                    .table(MtlsClientCertificates::Table)
                    .if_not_exists()
                    .col(
                        ColumnDef::new(MtlsClientCertificates::Id)
                            .uuid()
                            .not_null()
                            .primary_key(),
                    )
                    .col(
                        ColumnDef::new(MtlsClientCertificates::SiteId)
                            .uuid()
                            .not_null(),
                    )
                    .col(
                        ColumnDef::new(MtlsClientCertificates::CaId)
                            .uuid()
                            .not_null(),
                    )
                    .col(
                        ColumnDef::new(MtlsClientCertificates::Name)
                            .string_len(200)
                            .not_null(),
                    )
                    .col(
                        ColumnDef::new(MtlsClientCertificates::CommonName)
                            .string_len(255)
                            .not_null(),
                    )
                    .col(
                        ColumnDef::new(MtlsClientCertificates::Organization)
                            .string_len(255)
                            .null(),
                    )
                    .col(
                        ColumnDef::new(MtlsClientCertificates::Serial)
                            .string_len(128)
                            .not_null(),
                    )
                    .col(
                        ColumnDef::new(
                            MtlsClientCertificates::FingerprintSha256,
                        )
                        .string_len(64)
                        .not_null(),
                    )
                    .col(
                        ColumnDef::new(MtlsClientCertificates::CertPem)
                            .text()
                            .not_null(),
                    )
                    // The key of a generated certificate; download-only and
                    // cleared by the operator once it is installed.
                    .col(
                        ColumnDef::new(MtlsClientCertificates::KeyPem)
                            .text()
                            .null(),
                    )
                    .col(
                        ColumnDef::new(MtlsClientCertificates::NotBefore)
                            .timestamp_with_time_zone()
                            .not_null(),
                    )
                    .col(
                        ColumnDef::new(MtlsClientCertificates::NotAfter)
                            .timestamp_with_time_zone()
                            .not_null(),
                    )
                    .col(
                        ColumnDef::new(MtlsClientCertificates::Status)
                            .string_len(20)
                            .not_null()
                            .default("active"),
                    )
                    .col(
                        ColumnDef::new(MtlsClientCertificates::RevokedAt)
                            .timestamp_with_time_zone()
                            .null(),
                    )
                    .col(
                        ColumnDef::new(
                            MtlsClientCertificates::RevocationReason,
                        )
                        .string_len(255)
                        .null(),
                    )
                    .col(
                        ColumnDef::new(MtlsClientCertificates::CreatedAt)
                            .timestamp_with_time_zone()
                            .not_null(),
                    )
                    .foreign_key(
                        ForeignKey::create()
                            .name("fk_mtls_client_certificates_site_id")
                            .from(
                                MtlsClientCertificates::Table,
                                MtlsClientCertificates::SiteId,
                            )
                            .to(Sites::Table, Sites::Id)
                            .on_delete(ForeignKeyAction::Cascade),
                    )
                    // Restrict: the API refuses to drop a CA that still has
                    // certificates, and the database keeps that guarantee when
                    // a row is removed out of band.
                    .foreign_key(
                        ForeignKey::create()
                            .name("fk_mtls_client_certificates_ca_id")
                            .from(
                                MtlsClientCertificates::Table,
                                MtlsClientCertificates::CaId,
                            )
                            .to(MtlsCas::Table, MtlsCas::Id)
                            .on_delete(ForeignKeyAction::Restrict),
                    )
                    .to_owned(),
            )
            .await?;

        manager
            .create_index(
                Index::create()
                    .name("idx_mtls_client_certificates_site_id")
                    .table(MtlsClientCertificates::Table)
                    .col(MtlsClientCertificates::SiteId)
                    .to_owned(),
            )
            .await?;

        manager
            .create_index(
                Index::create()
                    .name("idx_mtls_client_certificates_ca_id")
                    .table(MtlsClientCertificates::Table)
                    .col(MtlsClientCertificates::CaId)
                    .to_owned(),
            )
            .await?;

        manager
            .create_index(
                Index::create()
                    .name("idx_mtls_client_certificates_fingerprint")
                    .table(MtlsClientCertificates::Table)
                    .col(MtlsClientCertificates::FingerprintSha256)
                    .unique()
                    .to_owned(),
            )
            .await?;

        // The expected organization and the require-certificate switch describe
        // how a presented certificate is checked, so they live next to the
        // other mTLS posture fields.
        manager
            .alter_table(
                Table::alter()
                    .table(SiteSsl::Table)
                    .add_column(
                        ColumnDef::new(SiteSsl::MtlsOrganization)
                            .string_len(255)
                            .null(),
                    )
                    .add_column(
                        ColumnDef::new(SiteSsl::MtlsRequireClientCert)
                            .boolean()
                            .not_null()
                            .default(false),
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
                    .table(SiteSsl::Table)
                    .drop_column(SiteSsl::MtlsOrganization)
                    .drop_column(SiteSsl::MtlsRequireClientCert)
                    .to_owned(),
            )
            .await?;

        manager
            .drop_table(
                Table::drop()
                    .table(MtlsClientCertificates::Table)
                    .to_owned(),
            )
            .await?;
        manager
            .drop_table(Table::drop().table(MtlsCas::Table).to_owned())
            .await?;
        Ok(())
    }
}

#[derive(DeriveIden)]
enum MtlsCas {
    Table,
    Id,
    SiteId,
    Name,
    Source,
    CertPem,
    KeyPem,
    SubjectDn,
    Serial,
    FingerprintSha256,
    ExpectedOrganization,
    NotBefore,
    NotAfter,
    IsActive,
    CreatedAt,
}

#[derive(DeriveIden)]
enum MtlsClientCertificates {
    Table,
    Id,
    SiteId,
    CaId,
    Name,
    CommonName,
    Organization,
    Serial,
    FingerprintSha256,
    CertPem,
    KeyPem,
    NotBefore,
    NotAfter,
    Status,
    RevokedAt,
    RevocationReason,
    CreatedAt,
}

#[derive(DeriveIden)]
enum SiteSsl {
    Table,
    MtlsOrganization,
    MtlsRequireClientCert,
}
