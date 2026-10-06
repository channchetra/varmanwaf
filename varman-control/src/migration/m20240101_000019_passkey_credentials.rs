//! WebAuthn passkeys bound to dashboard accounts (`passkey_credentials`) and the
//! short-lived ceremony state a registration or login consumes
//! (`passkey_states`).
//!
//! Ceremony state lives in the database rather than in process memory so that a
//! multi-replica deployment does not need sticky sessions: whichever replica
//! answers `finish` can read the challenge the other replica issued.

use sea_orm_migration::prelude::*;

use super::m20240101_000001_create_users::Users;

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .create_table(
                Table::create()
                    .table(PasskeyCredentials::Table)
                    .if_not_exists()
                    .col(
                        ColumnDef::new(PasskeyCredentials::Id)
                            .uuid()
                            .not_null()
                            .primary_key(),
                    )
                    .col(
                        ColumnDef::new(PasskeyCredentials::UserId)
                            .uuid()
                            .not_null(),
                    )
                    // Base64url-encoded credential ID as it appears on the wire.
                    // Authenticators use a few dozen bytes; the column is sized
                    // for the WebAuthn ceiling so an exotic one still fits.
                    .col(
                        ColumnDef::new(PasskeyCredentials::CredId)
                            .string_len(1024)
                            .not_null(),
                    )
                    .col(
                        ColumnDef::new(PasskeyCredentials::PublicKey)
                            .text()
                            .not_null(),
                    )
                    .col(
                        ColumnDef::new(PasskeyCredentials::Name)
                            .string_len(200)
                            .not_null(),
                    )
                    // Signature counter used for clone detection; authenticators
                    // that do not implement one always report zero.
                    .col(
                        ColumnDef::new(PasskeyCredentials::Counter)
                            .big_integer()
                            .not_null()
                            .default(0),
                    )
                    .col(
                        ColumnDef::new(PasskeyCredentials::CreatedAt)
                            .timestamp_with_time_zone()
                            .not_null(),
                    )
                    .col(
                        ColumnDef::new(PasskeyCredentials::LastUsedAt)
                            .timestamp_with_time_zone()
                            .not_null(),
                    )
                    .foreign_key(
                        ForeignKey::create()
                            .name("fk_passkey_credentials_user_id")
                            .from(
                                PasskeyCredentials::Table,
                                PasskeyCredentials::UserId,
                            )
                            .to(Users::Table, Users::Id)
                            .on_delete(ForeignKeyAction::Cascade),
                    )
                    .to_owned(),
            )
            .await?;

        manager
            .create_index(
                Index::create()
                    .name("idx_passkey_credentials_user_id")
                    .table(PasskeyCredentials::Table)
                    .col(PasskeyCredentials::UserId)
                    .to_owned(),
            )
            .await?;

        // A credential ID identifies one authenticator globally, so it is the
        // natural lookup key for the assertion that comes back at login.
        manager
            .create_index(
                Index::create()
                    .name("idx_passkey_credentials_cred_id")
                    .table(PasskeyCredentials::Table)
                    .col(PasskeyCredentials::CredId)
                    .unique()
                    .to_owned(),
            )
            .await?;

        manager
            .create_table(
                Table::create()
                    .table(PasskeyStates::Table)
                    .if_not_exists()
                    .col(
                        ColumnDef::new(PasskeyStates::Id)
                            .string_len(255)
                            .not_null()
                            .primary_key(),
                    )
                    .col(
                        ColumnDef::new(PasskeyStates::StateJson)
                            .text()
                            .not_null(),
                    )
                    .col(
                        ColumnDef::new(PasskeyStates::ExpiresAt)
                            .timestamp_with_time_zone()
                            .not_null(),
                    )
                    .to_owned(),
            )
            .await?;

        // Rows are only ever looked up by primary key and swept by expiry.
        manager
            .create_index(
                Index::create()
                    .name("idx_passkey_states_expires_at")
                    .table(PasskeyStates::Table)
                    .col(PasskeyStates::ExpiresAt)
                    .to_owned(),
            )
            .await?;

        Ok(())
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .drop_table(Table::drop().table(PasskeyStates::Table).to_owned())
            .await?;
        manager
            .drop_table(
                Table::drop().table(PasskeyCredentials::Table).to_owned(),
            )
            .await?;
        Ok(())
    }
}

#[derive(DeriveIden)]
enum PasskeyCredentials {
    Table,
    Id,
    UserId,
    CredId,
    PublicKey,
    Name,
    Counter,
    CreatedAt,
    LastUsedAt,
}

#[derive(DeriveIden)]
enum PasskeyStates {
    Table,
    Id,
    StateJson,
    ExpiresAt,
}
