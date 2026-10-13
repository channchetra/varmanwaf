//! SMTP e-mail sender for the notification system, on top of `lettre`.

use lettre::{
    message::Mailbox, transport::smtp::authentication::Credentials,
    AsyncSmtpTransport, AsyncTransport, Tokio1Executor,
};
use serde_json::Value;

use super::AlertEvent;

/// The channel `config` JSON object.
#[derive(Debug, Clone, PartialEq)]
pub struct EmailConfig {
    pub smtp_host: String,
    pub smtp_port: u16,
    pub smtp_user: String,
    pub smtp_pass: String,
    /// `ssl` (implicit TLS, usually port 465), `starttls` (usually 587) or
    /// `none` for a local relay without TLS.
    pub tls: String,
    pub from: String,
    pub to: Vec<String>,
}

impl EmailConfig {
    /// Parses and validates the stored channel config.
    pub fn from_json(config: &Value) -> Result<Self, String> {
        let get_str = |key: &str| {
            config
                .get(key)
                .and_then(Value::as_str)
                .map(str::trim)
                .filter(|value| !value.is_empty())
                .map(str::to_string)
        };
        let smtp_host = get_str("smtp_host")
            .ok_or("missing 'smtp_host' in the channel config")?;
        let smtp_port = config
            .get("smtp_port")
            .and_then(Value::as_u64)
            .unwrap_or(465);
        let smtp_port =
            u16::try_from(smtp_port).map_err(|_| "invalid 'smtp_port'")?;
        let from =
            get_str("from").ok_or("missing 'from' in the channel config")?;
        let to: Vec<String> = config
            .get("to")
            .and_then(Value::as_array)
            .map(|items| {
                items
                    .iter()
                    .filter_map(Value::as_str)
                    .map(str::trim)
                    .filter(|value| !value.is_empty())
                    .map(str::to_string)
                    .collect()
            })
            .unwrap_or_default();
        if to.is_empty() {
            return Err(
                "missing 'to' recipients in the channel config".to_string()
            );
        }
        Ok(Self {
            smtp_host,
            smtp_port,
            smtp_user: get_str("smtp_user").unwrap_or_default(),
            smtp_pass: get_str("smtp_pass").unwrap_or_default(),
            tls: get_str("tls").unwrap_or_else(|| "ssl".to_string()),
            from,
            to,
        })
    }
}

/// Sends the alert as a plain-text e-mail to every configured recipient.
pub async fn send(
    _http: &reqwest::Client,
    config: &Value,
    event: &AlertEvent,
) -> Result<(), String> {
    let config = EmailConfig::from_json(config)?;

    let from: Mailbox = config
        .from
        .parse()
        .map_err(|err| format!("invalid 'from' address: {err}"))?;
    // `Message` stamps the `Date` header itself when the builder omits it.
    let mut builder = lettre::message::Message::builder()
        .from(from)
        .subject(&event.title);
    for recipient in &config.to {
        let mailbox: Mailbox = recipient
            .parse()
            .map_err(|err| format!("invalid recipient '{recipient}': {err}"))?;
        builder = builder.to(mailbox);
    }
    let body = format!(
        "{}\n\nseverity: {}\ntime: {}\n\n-- \nSent by VarmanWAF",
        event.message,
        event.severity,
        chrono::Utc::now().format("%Y-%m-%d %H:%M:%S UTC"),
    );
    let message = builder
        .body(body)
        .map_err(|err| format!("cannot build the e-mail: {err}"))?;

    let transport = build_transport(&config)?;
    transport
        .send(message)
        .await
        .map(|_| ())
        .map_err(|err| format!("SMTP delivery failed: {err}"))
}

/// Builds the SMTP transport for the configured TLS mode.
fn build_transport(
    config: &EmailConfig,
) -> Result<AsyncSmtpTransport<Tokio1Executor>, String> {
    let builder = match config.tls.as_str() {
        "starttls" => AsyncSmtpTransport::<Tokio1Executor>::starttls_relay(
            &config.smtp_host,
        )
        .map_err(|err| format!("cannot configure STARTTLS: {err}"))?,
        "none" => AsyncSmtpTransport::<Tokio1Executor>::builder_dangerous(
            &config.smtp_host,
        ),
        // Default and unknown values use the safe option: implicit TLS.
        _ => AsyncSmtpTransport::<Tokio1Executor>::relay(&config.smtp_host)
            .map_err(|err| format!("cannot configure TLS: {err}"))?,
    };
    let mut builder = builder.port(config.smtp_port);
    if !config.smtp_user.is_empty() {
        builder = builder.credentials(Credentials::new(
            config.smtp_user.clone(),
            config.smtp_pass.clone(),
        ));
    }
    Ok(builder.build())
}
