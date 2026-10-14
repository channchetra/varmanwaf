//! Imported CRS rulesets (`crs_rulesets`) and their parsed rule catalogue
//! (`crs_rules`).
//!
//! An import stores the archive fingerprint plus one row per logical
//! statement found in the imported `rules/*.conf` files: compiled SecLang
//! rules (with file/line provenance and extracted metadata) and directives
//! that are recorded but not compiled. Unsupported rules keep their parser
//! error, so "what did not make it" is always visible instead of silently
//! skipped. Policies bind a ruleset through the `crs_import` layer, and the
//! edge receives the supported rules as SecLang source.

use sea_orm_migration::prelude::*;

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .create_table(
                Table::create()
                    .table(CrsRulesets::Table)
                    .if_not_exists()
                    .col(
                        ColumnDef::new(CrsRulesets::Id)
                            .uuid()
                            .not_null()
                            .primary_key(),
                    )
                    .col(ColumnDef::new(CrsRulesets::Name).text().not_null())
                    .col(
                        ColumnDef::new(CrsRulesets::Version)
                            .text()
                            .not_null()
                            .default(""),
                    )
                    .col(
                        ColumnDef::new(CrsRulesets::Source)
                            .text()
                            .not_null()
                            .default(""),
                    )
                    .col(
                        ColumnDef::new(CrsRulesets::Fingerprint)
                            .string_len(64)
                            .not_null()
                            .default(""),
                    )
                    .col(
                        ColumnDef::new(CrsRulesets::RuleCount)
                            .integer()
                            .not_null()
                            .default(0),
                    )
                    .col(
                        ColumnDef::new(CrsRulesets::SupportedCount)
                            .integer()
                            .not_null()
                            .default(0),
                    )
                    .col(
                        ColumnDef::new(CrsRulesets::UnsupportedCount)
                            .integer()
                            .not_null()
                            .default(0),
                    )
                    .col(
                        ColumnDef::new(CrsRulesets::DirectiveCount)
                            .integer()
                            .not_null()
                            .default(0),
                    )
                    .col(
                        ColumnDef::new(CrsRulesets::ImportedAt)
                            .timestamp_with_time_zone()
                            .not_null(),
                    )
                    .to_owned(),
            )
            .await?;

        manager
            .create_index(
                Index::create()
                    .name("idx_crs_rulesets_fingerprint")
                    .table(CrsRulesets::Table)
                    .col(CrsRulesets::Fingerprint)
                    .to_owned(),
            )
            .await?;

        manager
            .create_table(
                Table::create()
                    .table(CrsRules::Table)
                    .if_not_exists()
                    .col(
                        ColumnDef::new(CrsRules::Id)
                            .uuid()
                            .not_null()
                            .primary_key(),
                    )
                    .col(ColumnDef::new(CrsRules::RulesetId).uuid().not_null())
                    .col(
                        ColumnDef::new(CrsRules::RuleId)
                            .text()
                            .not_null()
                            .default(""),
                    )
                    // `rule` or `directive`.
                    .col(
                        ColumnDef::new(CrsRules::Kind)
                            .string_len(16)
                            .not_null()
                            .default("rule"),
                    )
                    .col(
                        ColumnDef::new(CrsRules::File)
                            .text()
                            .not_null()
                            .default(""),
                    )
                    .col(
                        ColumnDef::new(CrsRules::Line)
                            .integer()
                            .not_null()
                            .default(0),
                    )
                    .col(ColumnDef::new(CrsRules::Phase).integer().null())
                    .col(
                        ColumnDef::new(CrsRules::Severity)
                            .text()
                            .not_null()
                            .default(""),
                    )
                    .col(
                        ColumnDef::new(CrsRules::ParanoiaLevel)
                            .integer()
                            .null(),
                    )
                    .col(
                        ColumnDef::new(CrsRules::Category)
                            .text()
                            .not_null()
                            .default(""),
                    )
                    .col(
                        ColumnDef::new(CrsRules::Message)
                            .text()
                            .not_null()
                            .default(""),
                    )
                    .col(ColumnDef::new(CrsRules::Source).text().not_null())
                    .col(
                        ColumnDef::new(CrsRules::Supported)
                            .boolean()
                            .not_null()
                            .default(false),
                    )
                    .col(
                        ColumnDef::new(CrsRules::Error)
                            .text()
                            .not_null()
                            .default(""),
                    )
                    .foreign_key(
                        ForeignKey::create()
                            .name("fk_crs_rules_ruleset")
                            .from(CrsRules::Table, CrsRules::RulesetId)
                            .to(CrsRulesets::Table, CrsRulesets::Id)
                            .on_delete(ForeignKeyAction::Cascade),
                    )
                    .to_owned(),
            )
            .await?;

        manager
            .create_index(
                Index::create()
                    .name("idx_crs_rules_ruleset")
                    .table(CrsRules::Table)
                    .col(CrsRules::RulesetId)
                    .col(CrsRules::RuleId)
                    .to_owned(),
            )
            .await?;

        manager
            .create_index(
                Index::create()
                    .name("idx_crs_rules_supported")
                    .table(CrsRules::Table)
                    .col(CrsRules::RulesetId)
                    .col(CrsRules::Supported)
                    .to_owned(),
            )
            .await
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .drop_table(
                Table::drop().table(CrsRules::Table).if_exists().to_owned(),
            )
            .await?;
        manager
            .drop_table(
                Table::drop()
                    .table(CrsRulesets::Table)
                    .if_exists()
                    .to_owned(),
            )
            .await
    }
}

#[derive(DeriveIden)]
enum CrsRulesets {
    Table,
    Id,
    Name,
    Version,
    Source,
    Fingerprint,
    RuleCount,
    SupportedCount,
    UnsupportedCount,
    DirectiveCount,
    ImportedAt,
}

#[derive(DeriveIden)]
enum CrsRules {
    Table,
    Id,
    RulesetId,
    RuleId,
    Kind,
    File,
    Line,
    Phase,
    Severity,
    ParanoiaLevel,
    Category,
    Message,
    Source,
    Supported,
    Error,
}
