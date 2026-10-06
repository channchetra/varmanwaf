//! A minimal OpenAI-compatible chat-completions client.
//!
//! Everything the assistant needs fits in two calls: a streaming one for the
//! chat loop (SSE deltas assembled into content and tool calls) and a
//! non-streaming one for the settings page's "test connection" button. Any
//! OpenAI-compatible endpoint works — the base URL points at whatever the
//! operator configured (`https://api.openai.com/v1`, a gateway, a local
//! server, …).

use std::time::Duration;

use futures_util::StreamExt;
use serde_json::{json, Value};
use tokio::sync::mpsc;

use crate::models::ai_setting;

/// Total time budget of one completion, streaming included.
const REQUEST_TIMEOUT: Duration = Duration::from_secs(300);
/// Connect phase budget.
const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
/// How much of a provider error body is kept in the message.
const ERROR_BODY_LIMIT: usize = 512;

/// A tool call requested by the model.
#[derive(Debug, Clone, PartialEq)]
pub struct ToolCall {
    pub id: String,
    pub name: String,
    /// Raw JSON string as produced by the model.
    pub arguments: String,
}

impl ToolCall {
    /// The call in OpenAI wire format, as stored and replayed.
    pub fn to_wire(&self) -> Value {
        json!({
            "id": self.id,
            "type": "function",
            "function": { "name": self.name, "arguments": self.arguments },
        })
    }
}

/// One completed assistant turn.
#[derive(Debug, Clone, Default)]
pub struct ChatCompletion {
    pub content: String,
    pub tool_calls: Vec<ToolCall>,
}

/// Everything that can go wrong while talking to the provider.
#[derive(Debug)]
pub enum ProviderError {
    /// The settings do not form a usable provider (disabled, no key…).
    Config(String),
    /// Network-level failure.
    Transport(String),
    /// The provider answered with a non-success status.
    Status { status: u16, body: String },
    /// The response was not the expected shape.
    Protocol(String),
}

impl std::fmt::Display for ProviderError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ProviderError::Config(message) => write!(f, "{message}"),
            ProviderError::Transport(message) => {
                write!(f, "could not reach the AI provider: {message}")
            },
            ProviderError::Status { status, body } => {
                write!(f, "the AI provider answered {status}: {body}")
            },
            ProviderError::Protocol(message) => {
                write!(f, "unexpected response from the AI provider: {message}")
            },
        }
    }
}

impl std::error::Error for ProviderError {}

/// Client bound to one settings snapshot.
pub struct Provider {
    client: reqwest::Client,
    base_url: String,
    api_key: String,
    model: String,
}

impl Provider {
    /// Builds a client from the stored settings, refusing unusable ones.
    pub fn new(settings: &ai_setting::Model) -> Result<Self, ProviderError> {
        if !settings.enabled {
            return Err(ProviderError::Config(
                "the AI assistant is disabled".to_string(),
            ));
        }
        let base_url = settings.base_url.trim().trim_end_matches('/');
        if base_url.is_empty()
            || !(base_url.starts_with("http://")
                || base_url.starts_with("https://"))
        {
            return Err(ProviderError::Config(
                "base_url must be an http(s) URL".to_string(),
            ));
        }
        if settings.api_key.trim().is_empty() {
            return Err(ProviderError::Config(
                "no API key is configured".to_string(),
            ));
        }
        if settings.model.trim().is_empty() {
            return Err(ProviderError::Config(
                "no model is configured".to_string(),
            ));
        }

        let client = reqwest::Client::builder()
            .connect_timeout(CONNECT_TIMEOUT)
            .timeout(REQUEST_TIMEOUT)
            .build()
            .map_err(|err| ProviderError::Transport(err.to_string()))?;

        Ok(Self {
            client,
            base_url: base_url.to_string(),
            api_key: settings.api_key.trim().to_string(),
            model: settings.model.trim().to_string(),
        })
    }

    pub fn model(&self) -> &str {
        &self.model
    }

    fn endpoint(&self) -> String {
        format!("{}/chat/completions", self.base_url)
    }

    fn request(
        &self,
        messages: &[Value],
        tools: &[Value],
        temperature: f64,
        stream: bool,
        max_tokens: Option<u32>,
    ) -> serde_json::Map<String, Value> {
        let mut body = json!({
            "model": self.model,
            "messages": messages,
            "temperature": temperature,
            "stream": stream,
        });
        if !tools.is_empty() {
            body["tools"] = json!(tools);
            body["tool_choice"] = json!("auto");
        }
        if let Some(max) = max_tokens {
            body["max_tokens"] = json!(max);
        }
        body.as_object().cloned().unwrap_or_default()
    }

    /// One streaming completion. Text deltas are forwarded to `delta_tx`
    /// (best effort: a disconnected consumer must not abort the turn, the
    /// caller still persists the final message).
    ///
    /// Providers that ignore `stream: true` and answer with a plain JSON body
    /// are handled too — the whole message arrives as a single delta.
    pub async fn chat_stream(
        &self,
        messages: &[Value],
        tools: &[Value],
        temperature: f64,
        delta_tx: Option<&mpsc::Sender<String>>,
    ) -> Result<ChatCompletion, ProviderError> {
        let response = self
            .client
            .post(self.endpoint())
            .bearer_auth(&self.api_key)
            .json(&self.request(messages, tools, temperature, true, None))
            .send()
            .await
            .map_err(|err| ProviderError::Transport(err.to_string()))?;

        let status = response.status();
        if !status.is_success() {
            let body = response.text().await.unwrap_or_default();
            return Err(ProviderError::Status {
                status: status.as_u16(),
                body: clip(&body, ERROR_BODY_LIMIT),
            });
        }

        let is_sse = response
            .headers()
            .get(reqwest::header::CONTENT_TYPE)
            .and_then(|value| value.to_str().ok())
            .is_some_and(|value| value.contains("text/event-stream"));
        if !is_sse {
            // A provider that answered with a whole JSON body despite
            // `stream: true`.
            let body = response
                .text()
                .await
                .map_err(|err| ProviderError::Transport(err.to_string()))?;
            let completion = parse_completion(&body)?;
            if let (Some(tx), false) = (delta_tx, completion.content.is_empty())
            {
                let _ = tx.send(completion.content.clone()).await;
            }
            return Ok(completion);
        }

        let mut stream = response.bytes_stream();
        let mut buffer = String::new();
        let mut completion = ChatCompletion::default();
        let mut finished = false;

        while let Some(chunk) = stream.next().await {
            let chunk = chunk
                .map_err(|err| ProviderError::Transport(err.to_string()))?;
            buffer.push_str(&String::from_utf8_lossy(&chunk));
            while let Some(position) = buffer.find('\n') {
                let line =
                    buffer[..position].trim_end_matches('\r').to_string();
                buffer.drain(..=position);
                let Some(data) = line.strip_prefix("data:") else {
                    continue;
                };
                let data = data.trim();
                if data.is_empty() {
                    continue;
                }
                if data == "[DONE]" {
                    finished = true;
                    continue;
                }
                let value: Value =
                    serde_json::from_str(data).map_err(|err| {
                        ProviderError::Protocol(format!(
                            "unreadable stream chunk: {err}"
                        ))
                    })?;
                apply_delta(&value, &mut completion, delta_tx).await;
            }
        }

        if !finished {
            return Err(ProviderError::Protocol(
                "the stream ended before [DONE]".to_string(),
            ));
        }
        Ok(completion)
    }

    /// One non-streaming completion, used by the connection test.
    pub async fn complete(
        &self,
        messages: &[Value],
        temperature: f64,
        max_tokens: Option<u32>,
    ) -> Result<ChatCompletion, ProviderError> {
        let response = self
            .client
            .post(self.endpoint())
            .bearer_auth(&self.api_key)
            .json(&self.request(messages, &[], temperature, false, max_tokens))
            .send()
            .await
            .map_err(|err| ProviderError::Transport(err.to_string()))?;

        let status = response.status();
        let body = response
            .text()
            .await
            .map_err(|err| ProviderError::Transport(err.to_string()))?;
        if !status.is_success() {
            return Err(ProviderError::Status {
                status: status.as_u16(),
                body: clip(&body, ERROR_BODY_LIMIT),
            });
        }
        parse_completion(&body)
    }
}

/// Applies one `choices[0].delta` onto the completion under construction.
async fn apply_delta(
    value: &Value,
    completion: &mut ChatCompletion,
    delta_tx: Option<&mpsc::Sender<String>>,
) {
    let Some(delta) = value
        .get("choices")
        .and_then(|c| c.get(0))
        .map(|c| &c["delta"])
    else {
        return;
    };

    if let Some(text) = delta.get("content").and_then(Value::as_str) {
        if !text.is_empty() {
            completion.content.push_str(text);
            if let Some(tx) = delta_tx {
                let _ = tx.send(text.to_string()).await;
            }
        }
    }

    // Tool calls arrive as indexed fragments; id/name come once, arguments
    // stream in pieces.
    if let Some(calls) = delta.get("tool_calls").and_then(Value::as_array) {
        for call in calls {
            let index =
                call.get("index").and_then(Value::as_u64).unwrap_or(0) as usize;
            while completion.tool_calls.len() <= index {
                completion.tool_calls.push(ToolCall {
                    id: String::new(),
                    name: String::new(),
                    arguments: String::new(),
                });
            }
            let slot = &mut completion.tool_calls[index];
            if let Some(id) = call.get("id").and_then(Value::as_str) {
                slot.id = id.to_string();
            }
            if let Some(name) = call
                .get("function")
                .and_then(|f| f.get("name"))
                .and_then(Value::as_str)
            {
                slot.name.push_str(name);
            }
            if let Some(args) = call
                .get("function")
                .and_then(|f| f.get("arguments"))
                .and_then(Value::as_str)
            {
                slot.arguments.push_str(args);
            }
        }
    }
}

/// Parses a whole non-streaming completion body.
fn parse_completion(body: &str) -> Result<ChatCompletion, ProviderError> {
    let value: Value = serde_json::from_str(body).map_err(|err| {
        ProviderError::Protocol(format!("body is not JSON: {err}"))
    })?;
    if let Some(error) = value.get("error") {
        let message = error
            .get("message")
            .and_then(Value::as_str)
            .unwrap_or("unknown provider error");
        return Err(ProviderError::Status {
            status: 200,
            body: clip(message, ERROR_BODY_LIMIT),
        });
    }
    let message = value
        .get("choices")
        .and_then(|choices| choices.get(0))
        .map(|choice| &choice["message"])
        .ok_or_else(|| {
            ProviderError::Protocol("no choices in the response".to_string())
        })?;

    let mut completion = ChatCompletion {
        content: message
            .get("content")
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_string(),
        tool_calls: Vec::new(),
    };
    if let Some(calls) = message.get("tool_calls").and_then(Value::as_array) {
        for call in calls {
            completion.tool_calls.push(ToolCall {
                id: call
                    .get("id")
                    .and_then(Value::as_str)
                    .unwrap_or_default()
                    .to_string(),
                name: call
                    .get("function")
                    .and_then(|f| f.get("name"))
                    .and_then(Value::as_str)
                    .unwrap_or_default()
                    .to_string(),
                arguments: call
                    .get("function")
                    .and_then(|f| f.get("arguments"))
                    .and_then(Value::as_str)
                    .unwrap_or_default()
                    .to_string(),
            });
        }
    }
    Ok(completion)
}

/// Truncates at a char boundary; errors from providers are shown to the
/// operator, so a wall of HTML must not drown the message.
fn clip(value: &str, max: usize) -> String {
    if value.len() <= max {
        return value.to_string();
    }
    let mut end = max;
    while end > 0 && !value.is_char_boundary(end) {
        end -= 1;
    }
    format!("{}…", &value[..end])
}

#[cfg(test)]
mod tests {
    use super::*;

    fn settings() -> ai_setting::Model {
        ai_setting::Model {
            id: 1,
            enabled: true,
            base_url: "https://api.example.com/v1/".to_string(),
            api_key: "sk-test".to_string(),
            model: "test-model".to_string(),
            system_prompt: String::new(),
            temperature: 0.2,
            max_tool_rounds: 5,
            allow_write_tools: false,
            updated_at: chrono::Utc::now(),
        }
    }

    #[test]
    fn construction_validates_the_settings() {
        assert!(Provider::new(&settings()).is_ok());

        let mut disabled = settings();
        disabled.enabled = false;
        assert!(matches!(
            Provider::new(&disabled),
            Err(ProviderError::Config(_))
        ));

        let mut keyless = settings();
        keyless.api_key = "  ".into();
        assert!(matches!(
            Provider::new(&keyless),
            Err(ProviderError::Config(_))
        ));

        let mut schema_less = settings();
        schema_less.base_url = "api.example.com".into();
        assert!(matches!(
            Provider::new(&schema_less),
            Err(ProviderError::Config(_))
        ));
    }

    #[test]
    fn the_base_url_is_normalised_and_the_endpoint_built() {
        let provider = Provider::new(&settings()).unwrap();
        assert_eq!(
            provider.endpoint(),
            "https://api.example.com/v1/chat/completions"
        );
        assert_eq!(provider.model(), "test-model");
    }

    #[test]
    fn requests_grow_tools_and_limits_only_when_present() {
        let provider = Provider::new(&settings()).unwrap();
        let bare =
            provider.request(&[json!({"role": "user"})], &[], 0.2, true, None);
        assert!(bare.get("tools").is_none());
        assert!(bare.get("tool_choice").is_none());
        assert!(bare.get("max_tokens").is_none());
        assert_eq!(bare["stream"], true);

        let full = provider.request(
            &[json!({"role": "user"})],
            &[json!({"type": "function"})],
            0.5,
            false,
            Some(16),
        );
        assert_eq!(full["tool_choice"], "auto");
        assert_eq!(full["max_tokens"], 16);
        assert_eq!(full["stream"], false);
    }

    #[tokio::test]
    async fn deltas_assemble_content_and_tool_calls() {
        let mut completion = ChatCompletion::default();
        let (tx, mut rx) = mpsc::channel(16);

        apply_delta(
            &json!({ "choices": [{ "delta": { "content": "He" } }] }),
            &mut completion,
            Some(&tx),
        )
        .await;
        apply_delta(
            &json!({ "choices": [{ "delta": { "content": "llo" } }] }),
            &mut completion,
            Some(&tx),
        )
        .await;
        apply_delta(
            &json!({ "choices": [{ "delta": { "tool_calls": [
                { "index": 0, "id": "call_1", "function": { "name": "list_", "arguments": "{\"a\"" } }
            ] } }] }),
            &mut completion,
            Some(&tx),
        )
        .await;
        apply_delta(
            &json!({ "choices": [{ "delta": { "tool_calls": [
                { "index": 0, "function": { "name": "sites", "arguments": ":1}" } }
            ] } }] }),
            &mut completion,
            Some(&tx),
        )
        .await;

        assert_eq!(completion.content, "Hello");
        assert_eq!(completion.tool_calls.len(), 1);
        assert_eq!(completion.tool_calls[0].id, "call_1");
        assert_eq!(completion.tool_calls[0].name, "list_sites");
        assert_eq!(completion.tool_calls[0].arguments, "{\"a\":1}");
        assert_eq!(rx.try_recv().unwrap(), "He");
        assert_eq!(rx.try_recv().unwrap(), "llo");
        assert!(rx.try_recv().is_err());
    }

    #[tokio::test]
    async fn a_dropped_delta_consumer_does_not_abort_the_turn() {
        let (tx, rx) = mpsc::channel(1);
        drop(rx);
        let mut completion = ChatCompletion::default();
        apply_delta(
            &json!({ "choices": [{ "delta": { "content": "still here" } }] }),
            &mut completion,
            Some(&tx),
        )
        .await;
        assert_eq!(completion.content, "still here");
    }

    #[test]
    fn whole_body_responses_parse_with_tool_calls() {
        let completion = parse_completion(
            &json!({
                "choices": [{ "message": {
                    "role": "assistant",
                    "content": "hi",
                    "tool_calls": [{ "id": "c1", "type": "function",
                        "function": { "name": "list_sites", "arguments": "{}" } }]
                } }]
            })
            .to_string(),
        )
        .unwrap();
        assert_eq!(completion.content, "hi");
        assert_eq!(completion.tool_calls[0].name, "list_sites");

        let error = parse_completion(
            &json!({ "error": { "message": "invalid api key" } }).to_string(),
        )
        .unwrap_err();
        assert!(error.to_string().contains("invalid api key"));

        assert!(matches!(
            parse_completion("not json"),
            Err(ProviderError::Protocol(_))
        ));
        assert!(matches!(
            parse_completion(&json!({ "nope": true }).to_string()),
            Err(ProviderError::Protocol(_))
        ));
    }

    #[test]
    fn wire_format_round_trips_a_tool_call() {
        let call = ToolCall {
            id: "call_1".into(),
            name: "list_sites".into(),
            arguments: "{\"limit\":5}".into(),
        };
        let wire = call.to_wire();
        assert_eq!(wire["type"], "function");
        assert_eq!(wire["function"]["name"], "list_sites");
        assert_eq!(wire["function"]["arguments"], "{\"limit\":5}");
    }

    #[test]
    fn clipping_respects_char_boundaries() {
        assert_eq!(clip("short", 10), "short");
        // 7 bytes fall inside the third 3-byte character, so the clip steps
        // back to the 6-byte boundary.
        let clipped = clip("中文中文中文", 7);
        assert!(clipped.ends_with('…'));
        assert_eq!(clipped, "中文…");
    }
}
