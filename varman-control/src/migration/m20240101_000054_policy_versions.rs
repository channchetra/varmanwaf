//! Policy version history (`waf_policy_versions`) and the applied policy
//! revision reported by agents (`agents.policy_revision`).
//!
//! Every policy mutation records an immutable version: the policy's fields
//! plus a snapshot of its layers, a content hash and the actor. Rollback
//! restores a version's content as a **new** version, so history is never
//! rewritten. `agents.policy_revision` carries the revision of the last
//! bundle the agent applied, which lets the dashboard compare published and
//! applied state per node.

use sea_orm_migration::prelude::*;

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .create_table(
                Table::create()
                    .table(WafPolicyVersions::Table)
                    .if_not_exists()
                    .col(
                        ColumnDef::new(WafPolicyVersions::Id)
                            .big_integer()
                            .not_null()
                            .auto_increment()
                            .primary_key(),
                    )
                    .col(
                        ColumnDef::new(WafPolicyVersions::PolicyId)
                            .uuid()
                            .not_null(),
                    )
                    .col(
                        ColumnDef::new(WafPolicyVersions::Revision)
                            .integer()
                            .not_null(),
                    )
                    .col(
                        ColumnDef::new(WafPolicyVersions::ConfigHash)
                            .string_len(64)
                            .not_null()
                            .default(""),
                    )
                    .col(
                        ColumnDef::new(WafPolicyVersions::Source)
                            .string_len(20)
                            .not_null(),
                    )
                    .col(
                        ColumnDef::new(WafPolicyVersions::Actor)
                            .string_len(255)
                            .null(),
                    )
                    .col(
                        ColumnDef::new(WafPolicyVersions::Summary)
                            .json_binary()
                            .null(),
                    )
                    .col(
                        ColumnDef::new(WafPolicyVersions::Snapshot)
                            .json_binary()
                            .not_null(),
                    )
                    .col(
                        ColumnDef::new(WafPolicyVersions::CreatedAt)
                            .timestamp_with_time_zone()
                            .not_null(),
                    )
                    .foreign_key(
                        ForeignKey::create()
                            .name("fk_waf_policy_versions_policy")
                            .from(
                                WafPolicyVersions::Table,
                                WafPolicyVersions::PolicyId,
                            )
                            .to(WafPolicies::Table, WafPolicies::Id)
                            .on_delete(ForeignKeyAction::Cascade),
                    )
                    .to_owned(),
            )
            .await?;

        manager
            .create_index(
                Index::create()
                    .name("idx_waf_policy_versions_policy")
                    .table(WafPolicyVersions::Table)
                    .col(WafPolicyVersions::PolicyId)
                    .col(WafPolicyVersions::Id)
                    .to_owned(),
            )
            .await?;

        manager
            .alter_table(
                Table::alter()
                    .table(Agents::Table)
                    .add_column(
                        ColumnDef::new(Agents::PolicyRevision).integer().null(),
                    )
                    .to_owned(),
            )
            .await
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .alter_table(
                Table::alter()
                    .table(Agents::Table)
                    .drop_column(Agents::PolicyRevision)
                    .to_owned(),
            )
            .await?;
        manager
            .drop_table(
                Table::drop()
                    .table(WafPolicyVersions::Table)
                    .if_exists()
                    .to_owned(),
            )
            .await
    }
}

#[derive(DeriveIden)]
enum WafPolicyVersions {
    Table,
    Id,
    PolicyId,
    Revision,
    ConfigHash,
    Source,
    Actor,
    Summary,
    Snapshot,
    CreatedAt,
}

#[derive(DeriveIden)]
enum WafPolicies {
    Table,
    Id,
}

#[derive(DeriveIden)]
enum Agents {
    Table,
    PolicyRevision,
}
