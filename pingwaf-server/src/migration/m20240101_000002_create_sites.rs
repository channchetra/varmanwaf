//! Creates the `sites`, `site_upstreams` and `site_ssl` tables.
//!
//! A site is one protected domain owned by a user. Upstreams are the origin
//! servers the agents proxy to, and `site_ssl` carries either an uploaded
//! certificate pair or the ACME settings used to obtain one.

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
                    .table(Sites::Table)
                    .if_not_exists()
                    .col(
                        ColumnDef::new(Sites::Id)
                            .uuid()
                            .not_null()
                            .primary_key(),
                    )
                    .col(ColumnDef::new(Sites::UserId).uuid().not_null())
                    .col(ColumnDef::new(Sites::Name).string_len(100).not_null())
                    .col(
                        ColumnDef::new(Sites::Domain)
                            .string_len(255)
                            .not_null()
                            .unique_key(),
                    )
                    .col(
                        ColumnDef::new(Sites::Status)
                            .string_len(20)
                            .not_null()
                            .default("active"),
                    )
                    .col(
                        ColumnDef::new(Sites::Plan)
                            .string_len(20)
                            .not_null()
                            .default("free"),
                    )
                    .col(
                        ColumnDef::new(Sites::CreatedAt)
                            .timestamp_with_time_zone()
                            .not_null(),
                    )
                    .col(
                        ColumnDef::new(Sites::UpdatedAt)
                            .timestamp_with_time_zone()
                            .not_null(),
                    )
                    .foreign_key(
                        ForeignKey::create()
                            .name("fk_sites_user_id")
                            .from(Sites::Table, Sites::UserId)
                            .to(Users::Table, Users::Id)
                            .on_delete(ForeignKeyAction::Cascade),
                    )
                    .to_owned(),
            )
            .await?;

        manager
            .create_table(
                Table::create()
                    .table(SiteUpstreams::Table)
                    .if_not_exists()
                    .col(
                        ColumnDef::new(SiteUpstreams::Id)
                            .uuid()
                            .not_null()
                            .primary_key(),
                    )
                    .col(
                        ColumnDef::new(SiteUpstreams::SiteId).uuid().not_null(),
                    )
                    .col(
                        ColumnDef::new(SiteUpstreams::Name)
                            .string_len(100)
                            .not_null(),
                    )
                    .col(
                        ColumnDef::new(SiteUpstreams::Address)
                            .string_len(255)
                            .not_null(),
                    )
                    .col(
                        ColumnDef::new(SiteUpstreams::Weight)
                            .integer()
                            .not_null()
                            .default(1),
                    )
                    .col(
                        ColumnDef::new(SiteUpstreams::Tls)
                            .boolean()
                            .not_null()
                            .default(false),
                    )
                    .col(
                        ColumnDef::new(SiteUpstreams::HealthStatus)
                            .string_len(20)
                            .not_null()
                            .default("unknown"),
                    )
                    .col(
                        ColumnDef::new(SiteUpstreams::CreatedAt)
                            .timestamp_with_time_zone()
                            .not_null(),
                    )
                    .foreign_key(
                        ForeignKey::create()
                            .name("fk_site_upstreams_site_id")
                            .from(SiteUpstreams::Table, SiteUpstreams::SiteId)
                            .to(Sites::Table, Sites::Id)
                            .on_delete(ForeignKeyAction::Cascade),
                    )
                    .to_owned(),
            )
            .await?;

        manager
            .create_table(
                Table::create()
                    .table(SiteSsl::Table)
                    .if_not_exists()
                    .col(
                        ColumnDef::new(SiteSsl::Id)
                            .uuid()
                            .not_null()
                            .primary_key(),
                    )
                    .col(
                        ColumnDef::new(SiteSsl::SiteId)
                            .uuid()
                            .not_null()
                            .unique_key(),
                    )
                    .col(ColumnDef::new(SiteSsl::CertPem).text().null())
                    .col(ColumnDef::new(SiteSsl::KeyPem).text().null())
                    .col(ColumnDef::new(SiteSsl::Issuer).string_len(100).null())
                    .col(
                        ColumnDef::new(SiteSsl::Domain)
                            .string_len(255)
                            .not_null(),
                    )
                    .col(
                        ColumnDef::new(SiteSsl::ExpiresAt)
                            .timestamp_with_time_zone()
                            .null(),
                    )
                    .col(
                        ColumnDef::new(SiteSsl::AutoRenew)
                            .boolean()
                            .not_null()
                            .default(true),
                    )
                    .col(
                        ColumnDef::new(SiteSsl::AcmeEmail)
                            .string_len(255)
                            .null(),
                    )
                    .col(
                        ColumnDef::new(SiteSsl::AcmeChallengeType)
                            .string_len(20)
                            .null()
                            .default("http-01"),
                    )
                    .col(
                        ColumnDef::new(SiteSsl::AcmeDnsProvider)
                            .string_len(50)
                            .null(),
                    )
                    .col(
                        ColumnDef::new(SiteSsl::AcmeDnsConfig)
                            .json_binary()
                            .null(),
                    )
                    .col(
                        ColumnDef::new(SiteSsl::CreatedAt)
                            .timestamp_with_time_zone()
                            .not_null(),
                    )
                    .foreign_key(
                        ForeignKey::create()
                            .name("fk_site_ssl_site_id")
                            .from(SiteSsl::Table, SiteSsl::SiteId)
                            .to(Sites::Table, Sites::Id)
                            .on_delete(ForeignKeyAction::Cascade),
                    )
                    .to_owned(),
            )
            .await?;

        manager
            .create_index(
                Index::create()
                    .if_not_exists()
                    .name("idx_sites_user_id")
                    .table(Sites::Table)
                    .col(Sites::UserId)
                    .to_owned(),
            )
            .await?;
        manager
            .create_index(
                Index::create()
                    .if_not_exists()
                    .name("idx_sites_domain")
                    .table(Sites::Table)
                    .col(Sites::Domain)
                    .to_owned(),
            )
            .await?;
        manager
            .create_index(
                Index::create()
                    .if_not_exists()
                    .name("idx_site_upstreams_site_id")
                    .table(SiteUpstreams::Table)
                    .col(SiteUpstreams::SiteId)
                    .to_owned(),
            )
            .await?;

        Ok(())
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .drop_table(
                Table::drop().table(SiteSsl::Table).if_exists().to_owned(),
            )
            .await?;
        manager
            .drop_table(
                Table::drop()
                    .table(SiteUpstreams::Table)
                    .if_exists()
                    .to_owned(),
            )
            .await?;
        manager
            .drop_table(
                Table::drop().table(Sites::Table).if_exists().to_owned(),
            )
            .await?;
        Ok(())
    }
}

#[derive(DeriveIden)]
pub enum Sites {
    Table,
    Id,
    UserId,
    Name,
    Domain,
    Status,
    Plan,
    CreatedAt,
    UpdatedAt,
}

#[derive(DeriveIden)]
pub enum SiteUpstreams {
    Table,
    Id,
    SiteId,
    // Column added by m20240101_000011; listed here so later migrations can
    // reference it through the shared identifier enum.
    PoolId,
    Name,
    Address,
    Weight,
    Tls,
    HealthStatus,
    CreatedAt,
}

#[derive(DeriveIden)]
pub enum SiteSsl {
    Table,
    Id,
    SiteId,
    CertPem,
    KeyPem,
    Issuer,
    Domain,
    ExpiresAt,
    AutoRenew,
    AcmeEmail,
    AcmeChallengeType,
    AcmeDnsProvider,
    AcmeDnsConfig,
    CreatedAt,
}
