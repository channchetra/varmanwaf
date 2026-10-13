//! Add bot IP and DNS verification columns to `bot_protection`.
//!
//! Verified-bot classification becomes IP-backed: sites may reference an IP
//! group whose ranges are treated as verified bot networks, and whitelisted
//! bot user agents may be confirmed through reverse DNS before being trusted.

use sea_orm_migration::prelude::*;

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .alter_table(
                Table::alter()
                    .table(BotProtection::Table)
                    .add_column(
                        ColumnDef::new(BotProtection::VerifiedIpGroupId).uuid(),
                    )
                    .add_column(
                        ColumnDef::new(BotProtection::IpVerificationEnabled)
                            .boolean()
                            .not_null()
                            .default(false),
                    )
                    .add_column(
                        ColumnDef::new(BotProtection::DnsVerificationEnabled)
                            .boolean()
                            .not_null()
                            .default(false),
                    )
                    .to_owned(),
            )
            .await
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .alter_table(
                Table::alter()
                    .table(BotProtection::Table)
                    .drop_column(BotProtection::VerifiedIpGroupId)
                    .drop_column(BotProtection::IpVerificationEnabled)
                    .drop_column(BotProtection::DnsVerificationEnabled)
                    .to_owned(),
            )
            .await
    }
}

#[derive(DeriveIden)]
enum BotProtection {
    Table,
    VerifiedIpGroupId,
    IpVerificationEnabled,
    DnsVerificationEnabled,
}
