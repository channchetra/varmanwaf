//! Add proxy-trust columns to `sites`.
//!
//! When a site sits behind a CDN or reverse proxy the real client IP used by
//! IP access control, rate limiting, challenges and logs must come from a
//! forwarded header instead of the direct TCP peer. `trusted_header` holds the
//! lower-case header name (empty = `x-forwarded-for`); `trust_last_hop` takes
//! the last XFF entry — the one the nearest proxy appended — instead of the
//! client-supplied first entry.

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
                        ColumnDef::new(Sites::TrustProxyHeaders)
                            .boolean()
                            .not_null()
                            .default(false),
                    )
                    .add_column(
                        ColumnDef::new(Sites::TrustedHeader)
                            .text()
                            .not_null()
                            .default("x-forwarded-for"),
                    )
                    .add_column(
                        ColumnDef::new(Sites::TrustLastHop)
                            .boolean()
                            .not_null()
                            .default(true),
                    )
                    .to_owned(),
            )
            .await
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .alter_table(
                Table::alter()
                    .table(Sites::Table)
                    .drop_column(Sites::TrustProxyHeaders)
                    .drop_column(Sites::TrustedHeader)
                    .drop_column(Sites::TrustLastHop)
                    .to_owned(),
            )
            .await
    }
}

#[derive(DeriveIden)]
enum Sites {
    Table,
    TrustProxyHeaders,
    TrustedHeader,
    TrustLastHop,
}
