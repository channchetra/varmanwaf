//! Creates the `users` and `api_keys` tables.
//!
//! `users` holds dashboard credentials; `api_keys` holds the hashed keys the
//! agents authenticate with. The plaintext key is never stored: only a bcrypt
//! hash plus the first 8 characters, which are enough to recognise a key in the
//! UI and to narrow the candidate rows before the (deliberately slow) bcrypt
//! comparison.

use sea_orm_migration::prelude::*;

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .create_table(
                Table::create()
                    .table(Users::Table)
                    .if_not_exists()
                    .col(
                        ColumnDef::new(Users::Id)
                            .uuid()
                            .not_null()
                            .primary_key(),
                    )
                    .col(
                        ColumnDef::new(Users::Email)
                            .string_len(255)
                            .not_null()
                            .unique_key(),
                    )
                    .col(
                        ColumnDef::new(Users::PasswordHash)
                            .string_len(255)
                            .not_null(),
                    )
                    .col(ColumnDef::new(Users::Name).string_len(100).null())
                    .col(
                        ColumnDef::new(Users::Role)
                            .string_len(20)
                            .not_null()
                            .default("admin"),
                    )
                    .col(
                        ColumnDef::new(Users::CreatedAt)
                            .timestamp_with_time_zone()
                            .not_null(),
                    )
                    .col(
                        ColumnDef::new(Users::UpdatedAt)
                            .timestamp_with_time_zone()
                            .not_null(),
                    )
                    .to_owned(),
            )
            .await?;

        manager
            .create_table(
                Table::create()
                    .table(ApiKeys::Table)
                    .if_not_exists()
                    .col(
                        ColumnDef::new(ApiKeys::Id)
                            .uuid()
                            .not_null()
                            .primary_key(),
                    )
                    .col(ColumnDef::new(ApiKeys::UserId).uuid().not_null())
                    .col(
                        ColumnDef::new(ApiKeys::Name)
                            .string_len(100)
                            .not_null(),
                    )
                    .col(
                        ColumnDef::new(ApiKeys::KeyHash)
                            .string_len(255)
                            .not_null(),
                    )
                    .col(
                        ColumnDef::new(ApiKeys::KeyPrefix)
                            .string_len(8)
                            .not_null(),
                    )
                    .col(
                        ColumnDef::new(ApiKeys::Permissions)
                            .array(ColumnType::Text)
                            .not_null()
                            .default(Expr::cust("'{}'::text[]")),
                    )
                    .col(
                        ColumnDef::new(ApiKeys::ExpiresAt)
                            .timestamp_with_time_zone()
                            .null(),
                    )
                    .col(
                        ColumnDef::new(ApiKeys::LastUsedAt)
                            .timestamp_with_time_zone()
                            .null(),
                    )
                    .col(
                        ColumnDef::new(ApiKeys::CreatedAt)
                            .timestamp_with_time_zone()
                            .not_null(),
                    )
                    .foreign_key(
                        ForeignKey::create()
                            .name("fk_api_keys_user_id")
                            .from(ApiKeys::Table, ApiKeys::UserId)
                            .to(Users::Table, Users::Id)
                            .on_delete(ForeignKeyAction::Cascade),
                    )
                    .to_owned(),
            )
            .await?;

        manager
            .create_index(
                Index::create()
                    .if_not_exists()
                    .name("idx_api_keys_key_prefix")
                    .table(ApiKeys::Table)
                    .col(ApiKeys::KeyPrefix)
                    .to_owned(),
            )
            .await?;
        manager
            .create_index(
                Index::create()
                    .if_not_exists()
                    .name("idx_api_keys_user_id")
                    .table(ApiKeys::Table)
                    .col(ApiKeys::UserId)
                    .to_owned(),
            )
            .await?;

        Ok(())
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .drop_table(
                Table::drop().table(ApiKeys::Table).if_exists().to_owned(),
            )
            .await?;
        manager
            .drop_table(
                Table::drop().table(Users::Table).if_exists().to_owned(),
            )
            .await?;
        Ok(())
    }
}

#[derive(DeriveIden)]
pub enum Users {
    Table,
    Id,
    Email,
    PasswordHash,
    Name,
    Role,
    CreatedAt,
    UpdatedAt,
}

#[derive(DeriveIden)]
pub enum ApiKeys {
    Table,
    Id,
    UserId,
    Name,
    KeyHash,
    KeyPrefix,
    Permissions,
    ExpiresAt,
    LastUsedAt,
    CreatedAt,
}
