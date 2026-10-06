//! The built-in AI assistant.
//!
//! One shared tool registry ([`crate::mcp::tools`]) backs both the hosted MCP
//! endpoint and this assistant, so every capability is implemented once. This
//! module adds what is specific to the console chat: provider settings
//! storage, an OpenAI-compatible client ([`provider`]) and the streaming chat
//! loop with its tool-calling rounds ([`agent`]).

pub mod agent;
pub mod provider;

pub use agent::{run_turn, ChatEvent, TurnRequest};
pub use provider::{Provider, ProviderError};

use chrono::Utc;
use sea_orm::sea_query::OnConflict;
use sea_orm::{DatabaseConnection, DbErr, EntityTrait, Set};

use crate::api::error::ApiError;
use crate::models::ai::TITLE_MAX_CHARS;
use crate::models::{ai_defaults, ai_setting};

/// Primary key of the single settings row.
const SETTINGS_ID: i32 = 1;

/// Instruction used when the operator left the system prompt empty.
///
/// The tool descriptions carry most of the contract; this text adds the
/// working style an ops assistant needs and the guardrail around write tools.
pub const DEFAULT_SYSTEM_PROMPT: &str = "\
You are the built-in assistant of PingWAF, a reverse-proxy and web application \
firewall console. You help operators troubleshoot incidents, produce traffic \
and security reports, and answer questions about this deployment.

Ground every factual claim in the provided tools: before answering questions \
about sites, agents, certificates, logs, WAF events, traffic or defense \
settings, call the matching tool and cite the concrete numbers, hostnames and \
time windows from its result. Never invent data; when a tool returns nothing \
for a window, say so explicitly. Prefer several focused tool calls over one \
broad guess. For reports, use compact markdown tables and lead with the most \
important change. Write tools modify the live configuration: use them only \
when the user explicitly asks for the change, and state clearly afterwards \
what was changed. Answer in the language the user writes in.";

/// Loads the settings row, creating it with the defaults when missing.
pub async fn load_settings(
    db: &DatabaseConnection,
) -> Result<ai_setting::Model, ApiError> {
    if let Some(row) =
        ai_setting::Entity::find_by_id(SETTINGS_ID).one(db).await?
    {
        return Ok(row);
    }

    let insert = ai_setting::ActiveModel {
        id: Set(SETTINGS_ID),
        enabled: Set(false),
        base_url: Set(ai_defaults::BASE_URL.to_string()),
        api_key: Set(String::new()),
        model: Set(ai_defaults::MODEL.to_string()),
        system_prompt: Set(String::new()),
        temperature: Set(ai_defaults::TEMPERATURE),
        max_tool_rounds: Set(ai_defaults::MAX_TOOL_ROUNDS),
        allow_write_tools: Set(false),
        updated_at: Set(Utc::now()),
    };
    let ignore_conflict = OnConflict::column(ai_setting::Column::Id)
        .do_nothing()
        .to_owned();
    match ai_setting::Entity::insert(insert)
        .on_conflict(ignore_conflict)
        .exec(db)
        .await
    {
        Ok(_) | Err(DbErr::RecordNotInserted) => {},
        Err(err) => return Err(err.into()),
    }

    ai_setting::Entity::find_by_id(SETTINGS_ID)
        .one(db)
        .await?
        .ok_or_else(|| {
            ApiError::Internal("AI settings row vanished".to_string())
        })
}

/// The system prompt actually sent to the provider.
pub fn effective_system_prompt(settings: &ai_setting::Model) -> String {
    let custom = settings.system_prompt.trim();
    if custom.is_empty() {
        DEFAULT_SYSTEM_PROMPT.to_string()
    } else {
        custom.to_string()
    }
}

/// Derives a conversation title from its first user message: the first
/// non-empty line, truncated at a char boundary.
pub fn conversation_title(message: &str) -> String {
    let line = message
        .lines()
        .map(str::trim)
        .find(|line| !line.is_empty())
        .unwrap_or("")
        .to_string();
    let mut chars = line.chars();
    let head: String = chars.by_ref().take(TITLE_MAX_CHARS).collect();
    if chars.next().is_some() {
        format!("{head}…")
    } else {
        head
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn titles_come_from_the_first_non_empty_line() {
        assert_eq!(
            conversation_title("  why is shop down?\nmore"),
            "why is shop down?"
        );
        assert_eq!(conversation_title("\n\n  second line"), "second line");
        assert_eq!(conversation_title("   "), "");
    }

    #[test]
    fn long_titles_are_truncated_on_a_char_boundary() {
        let message = "中".repeat(TITLE_MAX_CHARS + 5);
        let title = conversation_title(&message);
        assert_eq!(title.chars().count(), TITLE_MAX_CHARS + 1);
        assert!(title.ends_with('…'));

        let exact = "a".repeat(TITLE_MAX_CHARS);
        assert_eq!(conversation_title(&exact), exact);
    }

    #[test]
    fn the_default_prompt_is_used_only_while_unset() {
        let mut settings = ai_setting::Model {
            id: 1,
            enabled: true,
            base_url: "https://api.example.com/v1".to_string(),
            api_key: "sk".to_string(),
            model: "m".to_string(),
            system_prompt: "  ".to_string(),
            temperature: 0.2,
            max_tool_rounds: 5,
            allow_write_tools: false,
            updated_at: Utc::now(),
        };
        assert_eq!(effective_system_prompt(&settings), DEFAULT_SYSTEM_PROMPT);
        settings.system_prompt = "custom".to_string();
        assert_eq!(effective_system_prompt(&settings), "custom");
    }
}
