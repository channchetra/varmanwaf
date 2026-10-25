//! Add the control plane's IP denylist to `api_protection_settings`.
//!
//! The allowlist answers "who may reach the console at all"; the denylist is
//! the narrower "refuse these addresses even when the allowlist would let
//! them in". Both are checked on the TCP peer, denials win over the
//! allowlist, and health probes stay exempt.

use sea_orm_migration::prelude::*;

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .alter_table(
                Table::alter()
                    .table(ApiProtectionSettings::Table)
                    .add_column(
                        ColumnDef::new(
                            ApiProtectionSettings::IpDenylistEnabled,
                        )
                        .boolean()
                        .not_null()
                        .default(false),
                    )
                    .add_column(
                        ColumnDef::new(ApiProtectionSettings::IpDenylistRanges)
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
                    .table(ApiProtectionSettings::Table)
                    .drop_column(ApiProtectionSettings::IpDenylistEnabled)
                    .drop_column(ApiProtectionSettings::IpDenylistRanges)
                    .to_owned(),
            )
            .await
    }
}

#[derive(DeriveIden)]
enum ApiProtectionSettings {
    Table,
    IpDenylistEnabled,
    IpDenylistRanges,
}
