//! Entities for the built-in AI assistant: provider settings, chat
//! conversations and their messages.

use sea_orm::entity::prelude::*;
use serde::{Deserialize, Serialize};

/// `ai_settings` — one global row holding the assistant configuration.
///
/// `api_key` is the operator's provider credential; it is masked with `***`
/// in every API response (see `crate::api::ai`).
pub mod ai_settings {
    use super::*;

    #[derive(
        Clone, Debug, PartialEq, DeriveEntityModel, Serialize, Deserialize,
    )]
    #[sea_orm(table_name = "ai_settings")]
    pub struct Model {
        /// Always `1`: the settings are global, not per-site or per-user.
        #[sea_orm(primary_key, auto_increment = false)]
        pub id: i32,
        /// Master switch: the console hides the assistant when off and the
        /// chat endpoint refuses with `409`.
        pub enabled: bool,
        /// OpenAI-compatible API root, e.g. `https://api.openai.com/v1`.
        pub base_url: String,
        pub api_key: String,
        pub model: String,
        /// Empty means the built-in default prompt is used.
        pub system_prompt: String,
        pub temperature: f64,
        /// Upper bound on tool-calling iterations per user message.
        pub max_tool_rounds: i32,
        /// When false the assistant may only call read-only tools.
        pub allow_write_tools: bool,
        pub updated_at: DateTimeUtc,
    }

    #[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
    pub enum Relation {}

    impl ActiveModelBehavior for ActiveModel {}
}

/// `ai_conversations` — one console chat thread per row.
pub mod ai_conversations {
    use super::*;

    #[derive(
        Clone, Debug, PartialEq, DeriveEntityModel, Serialize, Deserialize,
    )]
    #[sea_orm(table_name = "ai_conversations")]
    pub struct Model {
        #[sea_orm(primary_key, auto_increment = false)]
        pub id: Uuid,
        pub user_id: Uuid,
        pub title: String,
        pub created_at: DateTimeUtc,
        pub updated_at: DateTimeUtc,
    }

    #[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
    pub enum Relation {}

    impl ActiveModelBehavior for ActiveModel {}
}

/// `ai_messages` — one user, assistant or tool turn.
///
/// Assistant rows carry the tool calls they requested in `tool_calls` (the
/// raw OpenAI `tool_calls` array); tool rows carry the `tool_call_id` they
/// answer. Together those columns rebuild the provider context verbatim.
pub mod ai_messages {
    use super::*;

    #[derive(
        Clone, Debug, PartialEq, DeriveEntityModel, Serialize, Deserialize,
    )]
    #[sea_orm(table_name = "ai_messages")]
    pub struct Model {
        #[sea_orm(primary_key, auto_increment = false)]
        pub id: Uuid,
        pub conversation_id: Uuid,
        pub role: String,
        #[sea_orm(column_type = "Text")]
        pub content: String,
        #[sea_orm(column_type = "JsonBinary")]
        pub tool_calls: Option<Json>,
        pub tool_call_id: Option<String>,
        pub tool_name: Option<String>,
        pub created_at: DateTimeUtc,
    }

    #[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
    pub enum Relation {}

    impl ActiveModelBehavior for ActiveModel {}
}

/// Roles stored in `ai_messages.role`.
pub mod message_role {
    pub const USER: &str = "user";
    pub const ASSISTANT: &str = "assistant";
    pub const TOOL: &str = "tool";
}

/// Defaults applied when the settings row is created and mirrored by the
/// dashboard form.
pub mod ai_defaults {
    pub const BASE_URL: &str = "https://api.openai.com/v1";
    pub const MODEL: &str = "gpt-4o-mini";
    pub const TEMPERATURE: f64 = 0.2;
    pub const MAX_TOOL_ROUNDS: i32 = 5;
}

/// Hard ceiling on [`ai_settings::Model::max_tool_rounds`].
pub const MAX_TOOL_ROUNDS_LIMIT: i32 = 10;

/// Truncation length of a conversation title derived from its first message.
pub const TITLE_MAX_CHARS: usize = 60;
