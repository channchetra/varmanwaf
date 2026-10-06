//! Relaxes `certificate_events.certificate_id` to nullable — the agent streams
//! raw ACME log lines before any `site_certificates` row may reference them —
//! and lets an `ip_access_rules` row reference an `ip_groups` row so that a
//! group update propagates to every site that uses it.

use sea_orm_migration::prelude::*;

#[derive(DeriveMigrationName)]
pub struct Migration;

#[derive(DeriveIden)]
enum CertificateEvents {
    Table,
    CertificateId,
}

#[derive(DeriveIden)]
enum IpAccessRules {
    Table,
    GroupId,
}

#[derive(DeriveIden)]
enum IpGroups {
    Table,
    Id,
}

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .alter_table(
                Table::alter()
                    .table(CertificateEvents::Table)
                    .modify_column(
                        ColumnDef::new(CertificateEvents::CertificateId)
                            .uuid()
                            .null(),
                    )
                    .to_owned(),
            )
            .await?;

        manager
            .alter_table(
                Table::alter()
                    .table(IpAccessRules::Table)
                    .add_column(
                        ColumnDef::new(IpAccessRules::GroupId).uuid().null(),
                    )
                    .to_owned(),
            )
            .await?;
        manager
            .create_foreign_key(
                ForeignKey::create()
                    .name("fk_ip_access_rules_group_id")
                    .from(IpAccessRules::Table, IpAccessRules::GroupId)
                    .to(IpGroups::Table, IpGroups::Id)
                    .on_delete(ForeignKeyAction::SetNull)
                    .to_owned(),
            )
            .await?;
        manager
            .create_index(
                Index::create()
                    .if_not_exists()
                    .name("idx_ip_access_rules_group_id")
                    .table(IpAccessRules::Table)
                    .col(IpAccessRules::GroupId)
                    .to_owned(),
            )
            .await?;
        Ok(())
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .drop_index(
                Index::drop()
                    .name("idx_ip_access_rules_group_id")
                    .table(IpAccessRules::Table)
                    .to_owned(),
            )
            .await?;
        manager
            .drop_foreign_key(
                ForeignKey::drop()
                    .name("fk_ip_access_rules_group_id")
                    .table(IpAccessRules::Table)
                    .to_owned(),
            )
            .await?;
        manager
            .alter_table(
                Table::alter()
                    .table(IpAccessRules::Table)
                    .drop_column(IpAccessRules::GroupId)
                    .to_owned(),
            )
            .await?;
        manager
            .alter_table(
                Table::alter()
                    .table(CertificateEvents::Table)
                    .modify_column(
                        ColumnDef::new(CertificateEvents::CertificateId)
                            .uuid()
                            .not_null(),
                    )
                    .to_owned(),
            )
            .await?;
        Ok(())
    }
}
