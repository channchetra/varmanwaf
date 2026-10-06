//! Built-in AI assistant: its settings (`ai_settings`), chat history
//! (`ai_conversations`) and individual turns (`ai_messages`).
//!
//! `ai_settings` is a single global row holding the provider endpoint the
//! operator points the assistant at (any OpenAI-compatible API), the model,
//! the credentials and the guardrails (round cap, write tools). The
//! conversation tables persist the console chat: one row per conversation and
//! one row per user/assistant/tool message, including the raw tool calls so a
//! stored conversation can be replayed into the model verbatim.

use sea_orm_migration::prelude::*;

#[derive(DeriveMigrationName)]
pub struct Migration;

/// Reference to the `users` table created by an earlier migration.
#[derive(DeriveIden)]
enum Users {
    Table,
    Id,
}

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .create_table(
                Table::create()
                    .table(AiSettings::Table)
                    .if_not_exists()
                    .col(
                        ColumnDef::new(AiSettings::Id)
                            .integer()
                            .not_null()
                            .primary_key(),
                    )
                    .col(
                        ColumnDef::new(AiSettings::Enabled)
                            .boolean()
                            .not_null()
                            .default(false),
                    )
                    .col(
                        ColumnDef::new(AiSettings::BaseUrl)
                            .string_len(500)
                            .not_null()
                            .default("https://api.openai.com/v1"),
                    )
                    .col(
                        ColumnDef::new(AiSettings::ApiKey)
                            .text()
                            .not_null()
                            .default(""),
                    )
                    .col(
                        ColumnDef::new(AiSettings::Model)
                            .string_len(200)
                            .not_null()
                            .default("gpt-4o-mini"),
                    )
                    .col(
                        ColumnDef::new(AiSettings::SystemPrompt)
                            .text()
                            .not_null()
                            .default(""),
                    )
                    .col(
                        ColumnDef::new(AiSettings::Temperature)
                            .double()
                            .not_null()
                            .default(0.2),
                    )
                    .col(
                        ColumnDef::new(AiSettings::MaxToolRounds)
                            .integer()
                            .not_null()
                            .default(5),
                    )
                    .col(
                        ColumnDef::new(AiSettings::AllowWriteTools)
                            .boolean()
                            .not_null()
                            .default(false),
                    )
                    .col(
                        ColumnDef::new(AiSettings::UpdatedAt)
                            .timestamp_with_time_zone()
                            .not_null(),
                    )
                    .to_owned(),
            )
            .await?;

        manager
            .create_table(
                Table::create()
                    .table(AiConversations::Table)
                    .if_not_exists()
                    .col(
                        ColumnDef::new(AiConversations::Id)
                            .uuid()
                            .not_null()
                            .primary_key(),
                    )
                    .col(
                        ColumnDef::new(AiConversations::UserId)
                            .uuid()
                            .not_null(),
                    )
                    .col(
                        ColumnDef::new(AiConversations::Title)
                            .string_len(200)
                            .not_null(),
                    )
                    .col(
                        ColumnDef::new(AiConversations::CreatedAt)
                            .timestamp_with_time_zone()
                            .not_null(),
                    )
                    .col(
                        ColumnDef::new(AiConversations::UpdatedAt)
                            .timestamp_with_time_zone()
                            .not_null(),
                    )
                    .foreign_key(
                        ForeignKey::create()
                            .name("fk_ai_conversations_user")
                            .from(
                                AiConversations::Table,
                                AiConversations::UserId,
                            )
                            .to(Users::Table, Users::Id)
                            .on_delete(ForeignKeyAction::Cascade),
                    )
                    .to_owned(),
            )
            .await?;

        manager
            .create_table(
                Table::create()
                    .table(AiMessages::Table)
                    .if_not_exists()
                    .col(
                        ColumnDef::new(AiMessages::Id)
                            .uuid()
                            .not_null()
                            .primary_key(),
                    )
                    .col(
                        ColumnDef::new(AiMessages::ConversationId)
                            .uuid()
                            .not_null(),
                    )
                    // `user` | `assistant` | `tool`
                    .col(
                        ColumnDef::new(AiMessages::Role)
                            .string_len(20)
                            .not_null(),
                    )
                    .col(
                        ColumnDef::new(AiMessages::Content)
                            .text()
                            .not_null()
                            .default(""),
                    )
                    .col(
                        ColumnDef::new(AiMessages::ToolCalls)
                            .json_binary()
                            .null(),
                    )
                    .col(
                        ColumnDef::new(AiMessages::ToolCallId)
                            .string_len(64)
                            .null(),
                    )
                    .col(
                        ColumnDef::new(AiMessages::ToolName)
                            .string_len(64)
                            .null(),
                    )
                    .col(
                        ColumnDef::new(AiMessages::CreatedAt)
                            .timestamp_with_time_zone()
                            .not_null(),
                    )
                    .foreign_key(
                        ForeignKey::create()
                            .name("fk_ai_messages_conversation")
                            .from(AiMessages::Table, AiMessages::ConversationId)
                            .to(AiConversations::Table, AiConversations::Id)
                            .on_delete(ForeignKeyAction::Cascade),
                    )
                    .to_owned(),
            )
            .await?;

        let conn = manager.get_connection();
        conn.execute_unprepared(
            "CREATE INDEX IF NOT EXISTS idx_ai_conversations_user \
             ON ai_conversations (user_id, updated_at)",
        )
        .await?;
        conn.execute_unprepared(
            "CREATE INDEX IF NOT EXISTS idx_ai_messages_conversation \
             ON ai_messages (conversation_id, created_at)",
        )
        .await?;

        Ok(())
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        let conn = manager.get_connection();
        conn.execute_unprepared(
            "DROP INDEX IF EXISTS idx_ai_messages_conversation",
        )
        .await?;
        conn.execute_unprepared(
            "DROP INDEX IF EXISTS idx_ai_conversations_user",
        )
        .await?;

        manager
            .drop_table(
                Table::drop()
                    .table(AiMessages::Table)
                    .if_exists()
                    .to_owned(),
            )
            .await?;
        manager
            .drop_table(
                Table::drop()
                    .table(AiConversations::Table)
                    .if_exists()
                    .to_owned(),
            )
            .await?;
        manager
            .drop_table(
                Table::drop()
                    .table(AiSettings::Table)
                    .if_exists()
                    .to_owned(),
            )
            .await
    }
}

#[derive(DeriveIden)]
enum AiSettings {
    Table,
    Id,
    Enabled,
    BaseUrl,
    ApiKey,
    Model,
    SystemPrompt,
    Temperature,
    MaxToolRounds,
    AllowWriteTools,
    UpdatedAt,
}

#[derive(DeriveIden)]
enum AiConversations {
    Table,
    Id,
    UserId,
    Title,
    CreatedAt,
    UpdatedAt,
}

#[derive(DeriveIden)]
enum AiMessages {
    Table,
    Id,
    ConversationId,
    Role,
    Content,
    ToolCalls,
    ToolCallId,
    ToolName,
    CreatedAt,
}
