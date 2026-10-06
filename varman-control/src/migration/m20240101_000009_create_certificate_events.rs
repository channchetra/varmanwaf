//! Creates the `certificate_events` table for tracking ACME certificate
//! lifecycle events (issuance, renewal, failure, retry).

use sea_orm_migration::prelude::*;

use super::m20240101_000002_create_sites::Sites;
use super::m20240101_000006_create_additional_tables::SiteCertificates;

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .create_table(
                Table::create()
                    .table(CertificateEvents::Table)
                    .if_not_exists()
                    .col(
                        ColumnDef::new(CertificateEvents::Id)
                            .uuid()
                            .not_null()
                            .primary_key(),
                    )
                    .col(
                        ColumnDef::new(CertificateEvents::CertificateId)
                            .uuid()
                            .not_null(),
                    )
                    .col(
                        ColumnDef::new(CertificateEvents::SiteId).uuid().null(),
                    )
                    .col(
                        ColumnDef::new(CertificateEvents::EventType)
                            .string_len(30)
                            .not_null(),
                    )
                    .col(
                        ColumnDef::new(CertificateEvents::Message)
                            .text()
                            .not_null(),
                    )
                    .col(
                        ColumnDef::new(CertificateEvents::Details)
                            .json_binary()
                            .null(),
                    )
                    .col(
                        ColumnDef::new(CertificateEvents::CreatedAt)
                            .timestamp_with_time_zone()
                            .not_null(),
                    )
                    .foreign_key(
                        ForeignKey::create()
                            .name("fk_certificate_events_certificate_id")
                            .from(
                                CertificateEvents::Table,
                                CertificateEvents::CertificateId,
                            )
                            .to(SiteCertificates::Table, SiteCertificates::Id)
                            .on_delete(ForeignKeyAction::Cascade),
                    )
                    .foreign_key(
                        ForeignKey::create()
                            .name("fk_certificate_events_site_id")
                            .from(
                                CertificateEvents::Table,
                                CertificateEvents::SiteId,
                            )
                            .to(Sites::Table, Sites::Id)
                            .on_delete(ForeignKeyAction::SetNull),
                    )
                    .to_owned(),
            )
            .await?;

        manager
            .create_index(
                Index::create()
                    .if_not_exists()
                    .name("idx_certificate_events_certificate_id")
                    .table(CertificateEvents::Table)
                    .col(CertificateEvents::CertificateId)
                    .to_owned(),
            )
            .await?;

        manager
            .create_index(
                Index::create()
                    .if_not_exists()
                    .name("idx_certificate_events_site_id")
                    .table(CertificateEvents::Table)
                    .col(CertificateEvents::SiteId)
                    .to_owned(),
            )
            .await?;

        manager
            .create_index(
                Index::create()
                    .if_not_exists()
                    .name("idx_certificate_events_created_at")
                    .table(CertificateEvents::Table)
                    .col(CertificateEvents::CreatedAt)
                    .to_owned(),
            )
            .await?;

        Ok(())
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .drop_table(
                Table::drop()
                    .table(CertificateEvents::Table)
                    .if_exists()
                    .to_owned(),
            )
            .await
    }
}

#[derive(DeriveIden)]
pub enum CertificateEvents {
    Table,
    Id,
    CertificateId,
    SiteId,
    EventType,
    Message,
    Details,
    CreatedAt,
}
