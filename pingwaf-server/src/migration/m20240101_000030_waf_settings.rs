//! Per-site WAF posture settings (`waf_settings`).
//!
//! One row per site, holding the site-level detection knobs that are not
//! derivable from the rules table: the advanced (strict + body inspection)
//! mode switch and the monitor-only downgrade sets for attack categories and
//! backend stacks. A missing row keeps the historical behavior — everything
//! enforced, normal level, no body inspection.

use sea_orm_migration::prelude::*;

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .create_table(
                Table::create()
                    .table(WafSettings::Table)
                    .if_not_exists()
                    .col(
                        ColumnDef::new(WafSettings::Id)
                            .uuid()
                            .not_null()
                            .primary_key(),
                    )
                    .col(
                        ColumnDef::new(WafSettings::SiteId)
                            .uuid()
                            .not_null()
                            .unique_key(),
                    )
                    .col(
                        ColumnDef::new(WafSettings::AdvancedMode)
                            .boolean()
                            .not_null()
                            .default(false),
                    )
                    .col(
                        ColumnDef::new(WafSettings::MonitorCategories)
                            .array(ColumnType::Text)
                            .not_null()
                            .default(Expr::cust("'{}'::text[]")),
                    )
                    .col(
                        ColumnDef::new(WafSettings::MonitorStacks)
                            .array(ColumnType::Text)
                            .not_null()
                            .default(Expr::cust("'{}'::text[]")),
                    )
                    .col(
                        ColumnDef::new(WafSettings::CreatedAt)
                            .timestamp_with_time_zone()
                            .not_null(),
                    )
                    .col(
                        ColumnDef::new(WafSettings::UpdatedAt)
                            .timestamp_with_time_zone()
                            .not_null(),
                    )
                    .foreign_key(
                        ForeignKey::create()
                            .name("fk_waf_settings_site_id")
                            .from(WafSettings::Table, WafSettings::SiteId)
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
                    .table(WafSettings::Table)
                    .if_exists()
                    .to_owned(),
            )
            .await
    }
}

#[derive(DeriveIden)]
enum WafSettings {
    Table,
    Id,
    SiteId,
    AdvancedMode,
    MonitorCategories,
    MonitorStacks,
    CreatedAt,
    UpdatedAt,
}

#[derive(DeriveIden)]
enum Sites {
    Table,
    Id,
}
