//! Adds the `login_history` table.
//!
//! One row per successful control-plane login (password and passkey), with
//! the resolved client IP and — best effort — its geolocation. The anomaly
//! detector compares a login's country against the most recent resolved
//! entries of the same account, and the dashboard reads the rows back for
//! the login audit view.

use sea_orm_migration::prelude::*;

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .create_table(
                Table::create()
                    .table(LoginHistory::Table)
                    .if_not_exists()
                    .col(
                        ColumnDef::new(LoginHistory::Id)
                            .uuid()
                            .not_null()
                            .primary_key(),
                    )
                    .col(ColumnDef::new(LoginHistory::UserId).uuid().not_null())
                    .col(ColumnDef::new(LoginHistory::Email).text().not_null())
                    .col(ColumnDef::new(LoginHistory::Ip).text().not_null())
                    .col(ColumnDef::new(LoginHistory::UserAgent).text().null())
                    .col(
                        ColumnDef::new(LoginHistory::CountryCode)
                            .string_len(8)
                            .null(),
                    )
                    .col(ColumnDef::new(LoginHistory::Region).text().null())
                    .col(ColumnDef::new(LoginHistory::City).text().null())
                    .col(
                        ColumnDef::new(LoginHistory::GeoSource)
                            .string_len(16)
                            .not_null(),
                    )
                    .col(
                        ColumnDef::new(LoginHistory::CreatedAt)
                            .timestamp_with_time_zone()
                            .not_null(),
                    )
                    .to_owned(),
            )
            .await?;

        manager
            .create_index(
                Index::create()
                    .name("idx_login_history_user_created")
                    .table(LoginHistory::Table)
                    .col(LoginHistory::UserId)
                    .col(LoginHistory::CreatedAt)
                    .to_owned(),
            )
            .await
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .drop_table(Table::drop().table(LoginHistory::Table).to_owned())
            .await
    }
}

#[derive(DeriveIden)]
enum LoginHistory {
    Table,
    Id,
    UserId,
    Email,
    Ip,
    UserAgent,
    CountryCode,
    Region,
    City,
    GeoSource,
    CreatedAt,
}
