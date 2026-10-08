//! Per-site virtual patches and OpenAPI spec (`waf_settings`).
//!
//! `virtual_patches` holds a SecLang rule source (the same dialect as OWASP
//! CRS) evaluated by the native SecLang engine at the edge: operators paste a
//! rule for a fresh CVE and it enforces without a release. `openapi_spec`
//! holds a JSON OpenAPI document used for request-shape validation
//! (unknown operation, method not allowed, missing required query parameter).
//!
//! Both default to the empty string = feature off.

use sea_orm_migration::prelude::*;

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .alter_table(
                Table::alter()
                    .table(WafSettings::Table)
                    .add_column(
                        ColumnDef::new(WafSettings::VirtualPatches)
                            .text()
                            .not_null()
                            .default(""),
                    )
                    .add_column(
                        ColumnDef::new(WafSettings::OpenapiSpec)
                            .text()
                            .not_null()
                            .default(""),
                    )
                    .to_owned(),
            )
            .await
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .alter_table(
                Table::alter()
                    .table(WafSettings::Table)
                    .drop_column(WafSettings::VirtualPatches)
                    .drop_column(WafSettings::OpenapiSpec)
                    .to_owned(),
            )
            .await
    }
}

#[derive(DeriveIden)]
enum WafSettings {
    Table,
    VirtualPatches,
    OpenapiSpec,
}
