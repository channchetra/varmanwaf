//! Per-site HTTP basic authentication (`site_basic_auth`).
//!
//! One row per site, like the challenge and bot settings next to it. The
//! credentials are stored as a JSON array of `{username, password}` objects.
//! Passwords are kept in the clear — the project stores mTLS keys and the
//! Elasticsearch password the same way — and become the `Authorization`
//! payload when the bundle is built for the data plane.

use sea_orm_migration::prelude::*;

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .create_table(
                Table::create()
                    .table(SiteBasicAuth::Table)
                    .if_not_exists()
                    .col(
                        ColumnDef::new(SiteBasicAuth::Id)
                            .uuid()
                            .not_null()
                            .primary_key(),
                    )
                    .col(
                        ColumnDef::new(SiteBasicAuth::SiteId)
                            .uuid()
                            .not_null()
                            .unique_key(),
                    )
                    .col(
                        ColumnDef::new(SiteBasicAuth::Enabled)
                            .boolean()
                            .not_null()
                            .default(false),
                    )
                    .col(
                        ColumnDef::new(SiteBasicAuth::Realm)
                            .string_len(200)
                            .not_null()
                            .default("Restricted"),
                    )
                    .col(
                        ColumnDef::new(SiteBasicAuth::Credentials)
                            .json_binary()
                            .not_null()
                            .default(Expr::cust("'[]'::jsonb")),
                    )
                    .col(
                        ColumnDef::new(SiteBasicAuth::DelaySeconds)
                            .integer()
                            .not_null()
                            .default(1),
                    )
                    .col(
                        ColumnDef::new(SiteBasicAuth::HideCredentials)
                            .boolean()
                            .not_null()
                            .default(false),
                    )
                    .col(
                        ColumnDef::new(SiteBasicAuth::CreatedAt)
                            .timestamp_with_time_zone()
                            .not_null(),
                    )
                    .col(
                        ColumnDef::new(SiteBasicAuth::UpdatedAt)
                            .timestamp_with_time_zone()
                            .not_null(),
                    )
                    .foreign_key(
                        ForeignKey::create()
                            .name("fk_site_basic_auth_site_id")
                            .from(SiteBasicAuth::Table, SiteBasicAuth::SiteId)
                            .to(Sites::Table, Sites::Id)
                            .on_delete(ForeignKeyAction::Cascade),
                    )
                    .to_owned(),
            )
            .await
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .drop_table(
                Table::drop()
                    .table(SiteBasicAuth::Table)
                    .if_exists()
                    .to_owned(),
            )
            .await
    }
}

#[derive(DeriveIden)]
enum SiteBasicAuth {
    Table,
    Id,
    SiteId,
    Enabled,
    Realm,
    Credentials,
    DelaySeconds,
    HideCredentials,
    CreatedAt,
    UpdatedAt,
}

#[derive(DeriveIden)]
enum Sites {
    Table,
    Id,
}
