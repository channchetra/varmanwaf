//! `exclusion_packages` gains the SecLang import columns.
//!
//! A package is either `entries` (our target-exclusion model, the default)
//! or `seclang` (an upstream exclusion file's source, appended to the
//! site's virtual patches where `SecRuleUpdateTargetById` and
//! `SecRuleRemoveById` are applied natively). `import_report` records what
//! the import recognised and what it did not.

use sea_orm_migration::prelude::*;

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .alter_table(
                Table::alter()
                    .table(ExclusionPackages::Table)
                    .add_column(
                        ColumnDef::new(ExclusionPackages::Kind)
                            .string_len(16)
                            .not_null()
                            .default("entries"),
                    )
                    .add_column(
                        ColumnDef::new(ExclusionPackages::Source).text().null(),
                    )
                    .add_column(
                        ColumnDef::new(ExclusionPackages::ImportReport)
                            .json_binary()
                            .null(),
                    )
                    .to_owned(),
            )
            .await
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .alter_table(
                Table::alter()
                    .table(ExclusionPackages::Table)
                    .drop_column(ExclusionPackages::Kind)
                    .drop_column(ExclusionPackages::Source)
                    .drop_column(ExclusionPackages::ImportReport)
                    .to_owned(),
            )
            .await
    }
}

#[derive(DeriveIden)]
enum ExclusionPackages {
    Table,
    Kind,
    Source,
    ImportReport,
}
