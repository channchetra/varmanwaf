//! Adds the site-wide cache quota and the per-site TLS posture.
//!
//! The cache quota belongs to the site, not to an individual cache rule: it
//! caps what the agents keep on disk for the whole domain, so it lives on
//! `sites`. The TLS switches — HTTPS on/off, mTLS, protocol bounds, HSTS —
//! describe how the domain is served and sit next to its certificate in
//! `site_ssl`.

use sea_orm_migration::prelude::*;

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .alter_table(
                Table::alter()
                    .table(Sites::Table)
                    .add_column(
                        ColumnDef::new(Sites::CacheQuotaMb)
                            .integer()
                            .not_null()
                            .default(1024),
                    )
                    .to_owned(),
            )
            .await?;

        manager
            .alter_table(
                Table::alter()
                    .table(SiteSsl::Table)
                    .add_column(
                        ColumnDef::new(SiteSsl::HttpsEnabled)
                            .boolean()
                            .not_null()
                            .default(false),
                    )
                    .add_column(
                        ColumnDef::new(SiteSsl::MinTlsVersion)
                            .string_len(10)
                            .not_null()
                            .default("1.2"),
                    )
                    .add_column(
                        ColumnDef::new(SiteSsl::MaxTlsVersion)
                            .string_len(10)
                            .null(),
                    )
                    .add_column(
                        ColumnDef::new(SiteSsl::SelfSigned)
                            .boolean()
                            .not_null()
                            .default(false),
                    )
                    .add_column(
                        ColumnDef::new(SiteSsl::CertificateId).uuid().null(),
                    )
                    .add_column(
                        ColumnDef::new(SiteSsl::MtlsEnabled)
                            .boolean()
                            .not_null()
                            .default(false),
                    )
                    .add_column(
                        ColumnDef::new(SiteSsl::MtlsClientCa).text().null(),
                    )
                    .add_column(
                        ColumnDef::new(SiteSsl::HstsEnabled)
                            .boolean()
                            .not_null()
                            .default(false),
                    )
                    .add_column(
                        ColumnDef::new(SiteSsl::HstsMaxAge)
                            .integer()
                            .not_null()
                            .default(0),
                    )
                    .add_column(
                        ColumnDef::new(SiteSsl::AlwaysUseHttps)
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
                    .table(Sites::Table)
                    .drop_column(Sites::CacheQuotaMb)
                    .to_owned(),
            )
            .await?;

        manager
            .alter_table(
                Table::alter()
                    .table(SiteSsl::Table)
                    .drop_column(SiteSsl::HttpsEnabled)
                    .drop_column(SiteSsl::MinTlsVersion)
                    .drop_column(SiteSsl::MaxTlsVersion)
                    .drop_column(SiteSsl::SelfSigned)
                    .drop_column(SiteSsl::CertificateId)
                    .drop_column(SiteSsl::MtlsEnabled)
                    .drop_column(SiteSsl::MtlsClientCa)
                    .drop_column(SiteSsl::HstsEnabled)
                    .drop_column(SiteSsl::HstsMaxAge)
                    .drop_column(SiteSsl::AlwaysUseHttps)
                    .to_owned(),
            )
            .await?;

        Ok(())
    }
}

#[derive(DeriveIden)]
enum Sites {
    Table,
    CacheQuotaMb,
}

#[derive(DeriveIden)]
enum SiteSsl {
    Table,
    HttpsEnabled,
    MinTlsVersion,
    MaxTlsVersion,
    SelfSigned,
    CertificateId,
    MtlsEnabled,
    MtlsClientCa,
    HstsEnabled,
    HstsMaxAge,
    AlwaysUseHttps,
}
