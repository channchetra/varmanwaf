//! Remove the retired `port_forwards` table.
//!
//! TCP port forwarding was removed from the WAF's scope: a WAF is an HTTP(S)
//! reverse proxy, and arbitrary TCP exposure belongs to the host firewall or a
//! VPN/bastion. The table was empty when this migration shipped.

use sea_orm_migration::prelude::*;

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .drop_table(
                Table::drop()
                    .table(PortForwards::Table)
                    .if_exists()
                    .to_owned(),
            )
            .await
    }

    async fn down(&self, _manager: &SchemaManager) -> Result<(), DbErr> {
        // Deliberately not recreated: rolling back past this migration would
        // reintroduce a feature the product no longer exposes. Restore from a
        // backup if the historical table is ever needed.
        Ok(())
    }
}

#[derive(DeriveIden)]
enum PortForwards {
    Table,
}
