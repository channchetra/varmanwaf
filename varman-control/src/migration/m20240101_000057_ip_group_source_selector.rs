//! `ip_groups.source_selector` - JSON path selectors for subscription
//! sources.
//!
//! A source may be a JSON document with several lists inside it (the
//! ipverse bot lists carry one entry per crawler; their country documents
//! carry `prefixes.ipv4`/`prefixes.ipv6`). The selector names the dotted
//! paths to collect, comma separated; an empty selector keeps the
//! auto-detection the fetcher always had.

use sea_orm_migration::prelude::*;

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .alter_table(
                Table::alter()
                    .table(IpGroups::Table)
                    .add_column(
                        ColumnDef::new(IpGroups::SourceSelector)
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
                    .table(IpGroups::Table)
                    .drop_column(IpGroups::SourceSelector)
                    .to_owned(),
            )
            .await
    }
}

#[derive(DeriveIden)]
enum IpGroups {
    Table,
    SourceSelector,
}
