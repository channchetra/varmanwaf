//! Gives a site more than one hostname.
//!
//! A modern application is usually served on several hostnames — the apex
//! plus `www`, `api` or a wildcard — and they should share one site so its
//! WAF, cache, routing and certificate settings apply to all of them. The
//! primary hostname stays in `sites.domain`; every additional one lands in
//! `alternate_domains`.
//!
//! `site_certificates.domain` widens to TEXT in the same migration: a
//! certificate row now describes the whole hostname list, which can exceed
//! the old 255 character bound.

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
                        ColumnDef::new(Sites::AlternateDomains)
                            .array(ColumnType::Text)
                            .not_null()
                            .default(Expr::cust("'{}'::text[]")),
                    )
                    .to_owned(),
            )
            .await?;

        manager
            .alter_table(
                Table::alter()
                    .table(SiteCertificates::Table)
                    .modify_column(
                        ColumnDef::new(SiteCertificates::Domain)
                            .text()
                            .not_null(),
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
                    .drop_column(Sites::AlternateDomains)
                    .to_owned(),
            )
            .await?;

        manager
            .alter_table(
                Table::alter()
                    .table(SiteCertificates::Table)
                    .modify_column(
                        ColumnDef::new(SiteCertificates::Domain)
                            .string_len(255)
                            .not_null(),
                    )
                    .to_owned(),
            )
            .await?;

        Ok(())
    }
}

#[derive(DeriveIden)]
enum Sites {
    Table,
    AlternateDomains,
}

#[derive(DeriveIden)]
enum SiteCertificates {
    Table,
    Domain,
}
