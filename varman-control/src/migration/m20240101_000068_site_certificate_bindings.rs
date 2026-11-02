//! `site_certificate_bindings` — lets one imported certificate serve several
//! sites without copying its private key into each site's posture row.
//!
//! The certificate row's `site_id` stays the owner (the site that uploaded it
//! or owns its ACME order). A binding grants another site the right to select
//! that certificate in its TLS posture. ACME-managed certificates are not
//! shareable: their private key never reaches the control plane, so only
//! imported PEM pairs can be bound to more than one site.

use sea_orm_migration::prelude::*;

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .create_table(
                Table::create()
                    .table(SiteCertificateBindings::Table)
                    .if_not_exists()
                    .col(
                        ColumnDef::new(SiteCertificateBindings::Id)
                            .uuid()
                            .not_null()
                            .primary_key(),
                    )
                    .col(
                        ColumnDef::new(SiteCertificateBindings::CertificateId)
                            .uuid()
                            .not_null(),
                    )
                    .col(
                        ColumnDef::new(SiteCertificateBindings::SiteId)
                            .uuid()
                            .not_null(),
                    )
                    .col(
                        ColumnDef::new(SiteCertificateBindings::CreatedAt)
                            .timestamp_with_time_zone()
                            .not_null(),
                    )
                    .foreign_key(
                        ForeignKey::create()
                            .name("fk_site_certificate_bindings_certificate")
                            .from(
                                SiteCertificateBindings::Table,
                                SiteCertificateBindings::CertificateId,
                            )
                            .to(SiteCertificates::Table, SiteCertificates::Id)
                            .on_delete(ForeignKeyAction::Cascade),
                    )
                    .foreign_key(
                        ForeignKey::create()
                            .name("fk_site_certificate_bindings_site")
                            .from(
                                SiteCertificateBindings::Table,
                                SiteCertificateBindings::SiteId,
                            )
                            .to(Sites::Table, Sites::Id)
                            .on_delete(ForeignKeyAction::Cascade),
                    )
                    .to_owned(),
            )
            .await?;
        manager
            .create_index(
                Index::create()
                    .name("idx_site_certificate_bindings_unique")
                    .table(SiteCertificateBindings::Table)
                    .col(SiteCertificateBindings::CertificateId)
                    .col(SiteCertificateBindings::SiteId)
                    .unique()
                    .to_owned(),
            )
            .await?;
        manager
            .create_index(
                Index::create()
                    .name("idx_site_certificate_bindings_site")
                    .table(SiteCertificateBindings::Table)
                    .col(SiteCertificateBindings::SiteId)
                    .to_owned(),
            )
            .await
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .drop_table(
                Table::drop()
                    .table(SiteCertificateBindings::Table)
                    .if_exists()
                    .to_owned(),
            )
            .await
    }
}

#[derive(DeriveIden)]
enum SiteCertificateBindings {
    Table,
    Id,
    CertificateId,
    SiteId,
    CreatedAt,
}

#[derive(DeriveIden)]
enum SiteCertificates {
    Table,
    Id,
}

#[derive(DeriveIden)]
enum Sites {
    Table,
    Id,
}
