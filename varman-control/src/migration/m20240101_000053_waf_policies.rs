//! WAF policies (`waf_policies`), their typed layers (`waf_policy_layers`),
//! site assignments (`site_waf_policies`) and per-site overlays
//! (`site_waf_policy_overrides`).
//!
//! A policy is a named, revisioned document shared by many sites: the
//! `engine` layer carries the posture knobs of `waf_settings`, the `crs`
//! layer the managed-rule monitor list and the `custom_rules` layer a
//! reusable rule list. A site either keeps its own settings (no assignment)
//! or points at one policy; the overlay table then carries that site's
//! sparse deltas. Resolution precedence: overlay > policy > the site's own
//! `waf_settings` / rules, so unassigned sites behave exactly as before.

use sea_orm_migration::prelude::*;

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .create_table(
                Table::create()
                    .table(WafPolicies::Table)
                    .if_not_exists()
                    .col(
                        ColumnDef::new(WafPolicies::Id)
                            .uuid()
                            .not_null()
                            .primary_key(),
                    )
                    .col(
                        ColumnDef::new(WafPolicies::Name)
                            .string_len(120)
                            .not_null(),
                    )
                    .col(
                        ColumnDef::new(WafPolicies::Description)
                            .text()
                            .not_null()
                            .default(""),
                    )
                    .col(
                        ColumnDef::new(WafPolicies::Enabled)
                            .boolean()
                            .not_null()
                            .default(true),
                    )
                    .col(
                        ColumnDef::new(WafPolicies::Revision)
                            .integer()
                            .not_null()
                            .default(1),
                    )
                    .col(
                        ColumnDef::new(WafPolicies::CreatedAt)
                            .timestamp_with_time_zone()
                            .not_null(),
                    )
                    .col(
                        ColumnDef::new(WafPolicies::UpdatedAt)
                            .timestamp_with_time_zone()
                            .not_null(),
                    )
                    .to_owned(),
            )
            .await?;

        manager
            .create_index(
                Index::create()
                    .name("idx_waf_policies_name")
                    .table(WafPolicies::Table)
                    .col(WafPolicies::Name)
                    .unique()
                    .to_owned(),
            )
            .await?;

        manager
            .create_table(
                Table::create()
                    .table(WafPolicyLayers::Table)
                    .if_not_exists()
                    .col(
                        ColumnDef::new(WafPolicyLayers::Id)
                            .uuid()
                            .not_null()
                            .primary_key(),
                    )
                    .col(ColumnDef::new(WafPolicyLayers::PolicyId).uuid().not_null())
                    .col(
                        ColumnDef::new(WafPolicyLayers::Kind)
                            .string_len(40)
                            .not_null(),
                    )
                    .col(ColumnDef::new(WafPolicyLayers::Config).json_binary().not_null())
                    .col(
                        ColumnDef::new(WafPolicyLayers::UpdatedAt)
                            .timestamp_with_time_zone()
                            .not_null(),
                    )
                    .foreign_key(
                        ForeignKey::create()
                            .name("fk_waf_policy_layers_policy")
                            .from(WafPolicyLayers::Table, WafPolicyLayers::PolicyId)
                            .to(WafPolicies::Table, WafPolicies::Id)
                            .on_delete(ForeignKeyAction::Cascade),
                    )
                    .to_owned(),
            )
            .await?;

        // One row per (policy, kind): a layer is replaced, never duplicated.
        manager
            .create_index(
                Index::create()
                    .name("idx_waf_policy_layers_policy_kind")
                    .table(WafPolicyLayers::Table)
                    .col(WafPolicyLayers::PolicyId)
                    .col(WafPolicyLayers::Kind)
                    .unique()
                    .to_owned(),
            )
            .await?;

        manager
            .create_table(
                Table::create()
                    .table(SiteWafPolicies::Table)
                    .if_not_exists()
                    .col(
                        ColumnDef::new(SiteWafPolicies::SiteId)
                            .uuid()
                            .not_null()
                            .primary_key(),
                    )
                    .col(
                        ColumnDef::new(SiteWafPolicies::PolicyId)
                            .uuid()
                            .not_null(),
                    )
                    .col(
                        ColumnDef::new(SiteWafPolicies::UpdatedAt)
                            .timestamp_with_time_zone()
                            .not_null(),
                    )
                    .foreign_key(
                        ForeignKey::create()
                            .name("fk_site_waf_policies_site")
                            .from(SiteWafPolicies::Table, SiteWafPolicies::SiteId)
                            .to(Sites::Table, Sites::Id)
                            .on_delete(ForeignKeyAction::Cascade),
                    )
                    .foreign_key(
                        ForeignKey::create()
                            .name("fk_site_waf_policies_policy")
                            .from(SiteWafPolicies::Table, SiteWafPolicies::PolicyId)
                            .to(WafPolicies::Table, WafPolicies::Id)
                            .on_delete(ForeignKeyAction::Cascade),
                    )
                    .to_owned(),
            )
            .await?;

        manager
            .create_index(
                Index::create()
                    .name("idx_site_waf_policies_policy")
                    .table(SiteWafPolicies::Table)
                    .col(SiteWafPolicies::PolicyId)
                    .to_owned(),
            )
            .await?;

        manager
            .create_table(
                Table::create()
                    .table(SiteWafPolicyOverrides::Table)
                    .if_not_exists()
                    .col(
                        ColumnDef::new(SiteWafPolicyOverrides::SiteId)
                            .uuid()
                            .not_null()
                            .primary_key(),
                    )
                    .col(
                        ColumnDef::new(SiteWafPolicyOverrides::Config)
                            .json_binary()
                            .not_null(),
                    )
                    .col(
                        ColumnDef::new(SiteWafPolicyOverrides::UpdatedAt)
                            .timestamp_with_time_zone()
                            .not_null(),
                    )
                    .foreign_key(
                        ForeignKey::create()
                            .name("fk_site_waf_policy_overrides_site")
                            .from(
                                SiteWafPolicyOverrides::Table,
                                SiteWafPolicyOverrides::SiteId,
                            )
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
                    .table(SiteWafPolicyOverrides::Table)
                    .if_exists()
                    .to_owned(),
            )
            .await?;
        manager
            .drop_table(
                Table::drop().table(SiteWafPolicies::Table).if_exists().to_owned(),
            )
            .await?;
        manager
            .drop_table(
                Table::drop()
                    .table(WafPolicyLayers::Table)
                    .if_exists()
                    .to_owned(),
            )
            .await?;
        manager
            .drop_table(Table::drop().table(WafPolicies::Table).if_exists().to_owned())
            .await
    }
}

#[derive(DeriveIden)]
enum WafPolicies {
    Table,
    Id,
    Name,
    Description,
    Enabled,
    Revision,
    CreatedAt,
    UpdatedAt,
}

#[derive(DeriveIden)]
enum WafPolicyLayers {
    Table,
    Id,
    PolicyId,
    Kind,
    Config,
    UpdatedAt,
}

#[derive(DeriveIden)]
enum SiteWafPolicies {
    Table,
    SiteId,
    PolicyId,
    UpdatedAt,
}

#[derive(DeriveIden)]
enum SiteWafPolicyOverrides {
    Table,
    SiteId,
    Config,
    UpdatedAt,
}

#[derive(DeriveIden)]
enum Sites {
    Table,
    Id,
}
