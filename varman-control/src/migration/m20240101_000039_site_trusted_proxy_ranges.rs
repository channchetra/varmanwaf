//! Add `trusted_proxy_ranges` to `sites`.
//!
//! Trusting forwarded headers becomes scoped: only connections whose direct
//! peer falls inside one of these CIDR ranges may influence the resolved
//! client IP. An empty list means no proxy is trusted — forwarded headers are
//! ignored and the TCP peer is used, which tightens the behaviour of sites
//! that previously enabled `trust_proxy_headers` without any scoping.

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
                        ColumnDef::new(Sites::TrustedProxyRanges)
                            .array(ColumnType::Text)
                            .not_null()
                            .default(Expr::cust("'{}'::text[]")),
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
                    .drop_column(Sites::TrustedProxyRanges)
                    .to_owned(),
            )
            .await
    }
}

#[derive(DeriveIden)]
enum Sites {
    Table,
    TrustedProxyRanges,
}
