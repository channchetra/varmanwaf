//! Webhook senders: WeCom (企业微信), DingTalk (钉钉) and a generic JSON
//! webhook.
//!
//! Both chat platforms receive a Markdown-formatted message; DingTalk
//! additionally supports the "signing key" secret mode, where every request
//! must carry a timestamp plus an HMAC-SHA256 signature of `"{timestamp}\n
//! {secret}"`, base64-encoded and URL-escaped.

use base64::Engine as _;
use hmac::digest::KeyInit as _;
use hmac::Mac;
use serde_json::{json, Value};

use super::AlertEvent;

/// Markdown content is hard-capped by both platforms; keep under it.
const MAX_CONTENT_BYTES: usize = 4000;

/// Renders the alert as Markdown text shared by the chat platforms.
fn markdown(event: &AlertEvent) -> String {
    let details = event
        .details
        .as_ref()
        .map(|details| {
            serde_json::to_string_pretty(details).unwrap_or_default()
        })
        .unwrap_or_default();
    let mut body = format!(
        "**{}**\n\n{}\n\nseverity: `{}`\ntime: `{}`",
        event.title,
        event.message,
        event.severity,
        chrono::Utc::now().format("%Y-%m-%d %H:%M:%S UTC"),
    );
    if !details.is_empty() && details != "null" {
        body.push_str(&format!("\n\n```\n{details}\n```"));
    }
    truncate_chars(&body, MAX_CONTENT_BYTES)
}

/// Cuts on a character boundary so multi-byte text never panics.
fn truncate_chars(text: &str, max_bytes: usize) -> String {
    if text.len() <= max_bytes {
        return text.to_string();
    }
    let mut end = max_bytes;
    while end > 0 && !text.is_char_boundary(end) {
        end -= 1;
    }
    format!("{}\n…", &text[..end])
}

/// POSTs a JSON payload, mapping transport errors and non-2xx replies into a
/// readable message. The remote body is never echoed back: a webhook the
/// operator controls could otherwise be pointed at an internal service and
/// smuggle its reply into the API response (SSRF read primitive).
async fn post_json(
    http: &reqwest::Client,
    url: &str,
    payload: &Value,
) -> Result<(), String> {
    ensure_public_webhook(url).await?;
    let response = http
        .post(url)
        .header("Content-Type", "application/json")
        .json(payload)
        .send()
        .await
        .map_err(|err| format!("request failed: {err}"))?;
    let status = response.status();
    if !status.is_success() {
        return Err(format!("webhook replied {status}"));
    }
    Ok(())
}

/// SSRF guard for operator-configured webhook URLs: the control plane POSTs
/// attacker-reachable JSON here (any admin with channel-write access), so the
/// URL must be a public http(s) endpoint. The host is resolved and every
/// answer checked — loopback, RFC 1918/4193, link-local (which includes the
/// cloud metadata service `169.254.169.254`), CGNAT and IPv4-mapped IPv6 are
/// all refused. Redirects are disabled on the shared client, closing the
/// "public URL that 302s inward" bypass.
///
/// Residual risk: DNS rebinding between this check and the connection is not
/// covered (that needs a per-connection connector); the resolution check
/// blocks every static misconfiguration cheaply.
pub async fn ensure_public_webhook(url: &str) -> Result<(), String> {
    let parsed = reqwest::Url::parse(url)
        .map_err(|_| "webhook URL is not a valid absolute URL".to_string())?;
    match parsed.scheme() {
        "http" | "https" => {},
        other => {
            return Err(format!(
                "webhook scheme '{other}' is not allowed; use http or https"
            ))
        },
    }
    let Some(host) = parsed.host_str() else {
        return Err("webhook URL has no host".to_string());
    };
    // A literal IP skips DNS entirely.
    if let Ok(ip) = host.trim_matches(['[', ']']).parse::<std::net::IpAddr>() {
        if is_blocked_ip(ip) {
            return Err(
                "webhook host is a private, loopback or link-local address"
                    .to_string(),
            );
        }
        return Ok(());
    }
    let addrs =
        tokio::net::lookup_host((host, 443u16))
            .await
            .map_err(|err| {
                format!("cannot resolve webhook host '{host}': {err}")
            })?;
    for addr in addrs {
        if is_blocked_ip(addr.ip()) {
            return Err(
                "webhook host resolves to a private, loopback or link-local \
                 address"
                    .to_string(),
            );
        }
    }
    Ok(())
}

/// True for addresses a webhook must never reach: unspecified, loopback,
/// RFC 1918, CGNAT, link-local (cloud metadata), benchmarking, broadcast,
/// IPv6 unique-local / link-local and IPv4-mapped IPv6 (judged by the
/// embedded IPv4).
fn is_blocked_ip(ip: std::net::IpAddr) -> bool {
    match ip {
        std::net::IpAddr::V4(v4) => {
            let [a, b, _, _] = v4.octets();
            a == 0 // "this network"
                || a == 10 // RFC 1918
                || a == 127 // loopback
                || (a == 100 && (64..=127).contains(&b)) // CGNAT
                || (a == 169 && b == 254) // link-local / cloud metadata
                || (a == 172 && (16..=31).contains(&b)) // RFC 1918
                || (a == 192 && b == 168) // RFC 1918
                || (a == 198 && (b == 18 || b == 19)) // benchmarking
                || a == 255 // broadcast
        },
        std::net::IpAddr::V6(v6) => {
            if v6.is_loopback() || v6.is_unspecified() {
                return true;
            }
            if let Some(v4) = v6.to_ipv4_mapped() {
                return is_blocked_ip(std::net::IpAddr::V4(v4));
            }
            let segments = v6.segments();
            (segments[0] & 0xfe00) == 0xfc00 // unique local fc00::/7
                || (segments[0] & 0xffc0) == 0xfe80 // link-local fe80::/10
        },
    }
}

/// WeCom group-bot webhook: `{"msgtype":"markdown","markdown":{...}}`.
pub async fn send_wecom(
    http: &reqwest::Client,
    config: &Value,
    event: &AlertEvent,
) -> Result<(), String> {
    let url = config
        .get("url")
        .and_then(Value::as_str)
        .filter(|url| !url.trim().is_empty())
        .ok_or_else(|| "missing 'url' in the channel config".to_string())?;
    let payload = json!({
        "msgtype": "markdown",
        "markdown": { "content": markdown(event) },
    });
    post_json(http, url.trim(), &payload).await
}

/// DingTalk custom-bot webhook, with optional HMAC-SHA256 signing.
pub async fn send_dingtalk(
    http: &reqwest::Client,
    config: &Value,
    event: &AlertEvent,
) -> Result<(), String> {
    let mut url = config
        .get("url")
        .and_then(Value::as_str)
        .filter(|url| !url.trim().is_empty())
        .ok_or_else(|| "missing 'url' in the channel config".to_string())?
        .trim()
        .to_string();

    if let Some(secret) = config
        .get("secret")
        .and_then(Value::as_str)
        .filter(|secret| !secret.trim().is_empty())
    {
        let signed = sign_url(&url, secret.trim())
            .map_err(|err| format!("cannot sign the webhook URL: {err}"))?;
        url = signed;
    }

    let payload = json!({
        "msgtype": "markdown",
        "markdown": {
            "title": event.title,
            "text": markdown(event),
        },
    });
    post_json(http, &url, &payload).await
}

/// Appends `timestamp` and `sign` query parameters to a DingTalk webhook URL.
pub fn sign_url(url: &str, secret: &str) -> Result<String, String> {
    let timestamp = chrono::Utc::now().timestamp_millis();
    let string_to_sign = format!("{timestamp}\n{secret}");

    type HmacSha256 = hmac::Hmac<sha2::Sha256>;
    let mut mac = HmacSha256::new_from_slice(secret.as_bytes())
        .map_err(|err| err.to_string())?;
    hmac::digest::Update::update(&mut mac, string_to_sign.as_bytes());
    let signature = mac.finalize().into_bytes();
    let encoded = base64::engine::general_purpose::STANDARD.encode(signature);

    let separator = if url.contains('?') { '&' } else { '?' };
    Ok(format!(
        "{url}{separator}timestamp={timestamp}&sign={}",
        urlencode(&encoded)
    ))
}

/// Percent-encodes everything outside the RFC 3986 unreserved set.
fn urlencode(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    for byte in value.bytes() {
        match byte {
            b'A'..=b'Z'
            | b'a'..=b'z'
            | b'0'..=b'9'
            | b'-'
            | b'_'
            | b'.'
            | b'~' => out.push(byte as char),
            other => out.push_str(&format!("%{other:02X}")),
        }
    }
    out
}

/// Generic webhook: the alert is POSTed as JSON, optionally with a
/// `X-VarmanWAF-Token` header for simple shared-secret protection.
pub async fn send_generic(
    http: &reqwest::Client,
    config: &Value,
    event: &AlertEvent,
) -> Result<(), String> {
    let url = config
        .get("url")
        .and_then(Value::as_str)
        .filter(|url| !url.trim().is_empty())
        .ok_or_else(|| "missing 'url' in the channel config".to_string())?;
    ensure_public_webhook(url.trim()).await?;

    let mut request = http
        .post(url.trim())
        .header("Content-Type", "application/json")
        .header("User-Agent", "VarmanWAF/notifications");
    if let Some(token) = config
        .get("secret_token")
        .and_then(Value::as_str)
        .filter(|token| !token.trim().is_empty())
    {
        request = request.header("X-VarmanWAF-Token", token.trim());
    }

    let payload = json!({
        "event": event.event_type,
        "severity": event.severity,
        "title": event.title,
        "message": event.message,
        "details": event.details,
        "timestamp": chrono::Utc::now().to_rfc3339(),
    });
    let response = request
        .json(&payload)
        .send()
        .await
        .map_err(|err| format!("request failed: {err}"))?;
    let status = response.status();
    if !status.is_success() {
        return Err(format!("webhook replied {status}"));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn truncation_respects_char_boundaries() {
        let text = "告警信息".repeat(2000);
        let cut = truncate_chars(&text, 100);
        assert!(cut.len() <= 110);
        assert!(cut.ends_with('…'));
        // No panic is the real assertion; the cut is valid UTF-8 by type.
    }

    #[test]
    fn truncation_keeps_short_text() {
        assert_eq!(truncate_chars("hello", 100), "hello");
    }

    #[test]
    fn signing_appends_timestamp_and_sign() {
        let signed = sign_url(
            "https://oapi.dingtalk.com/robot/send?access_token=x",
            "SEC123",
        )
        .unwrap();
        assert!(signed.starts_with(
            "https://oapi.dingtalk.com/robot/send?access_token=x&timestamp="
        ));
        assert!(signed.contains("&sign="));
        // The signature is base64, percent-encoded for the query string.
        let sign = signed.rsplit("sign=").next().unwrap_or_default();
        assert!(!sign.contains('=') || sign.contains('%'));
    }

    #[test]
    fn signing_reuses_the_existing_query_separator() {
        let signed = sign_url("https://example.com/hook", "s").unwrap();
        assert!(signed.contains("/hook?timestamp="));
    }

    #[test]
    fn private_addresses_are_blocked() {
        use std::net::IpAddr;
        let blocked = [
            "127.0.0.1",
            "10.1.2.3",
            "172.16.0.9",
            "172.31.255.1",
            "192.168.1.1",
            "169.254.169.254",
            "0.0.0.0",
            "100.64.0.1",
            "255.255.255.255",
            "::1",
            "::",
            "fe80::1",
            "fc00::1",
            "fd12::1",
            "::ffff:10.0.0.5",
            "::ffff:169.254.169.254",
        ];
        for ip in blocked {
            assert!(
                is_blocked_ip(ip.parse::<IpAddr>().unwrap()),
                "{ip} must be blocked"
            );
        }
        let allowed = [
            "8.8.8.8",
            "172.32.0.1",
            "100.128.0.1",
            "2606:4700::1111",
            "2001:4860:4860::8888",
        ];
        for ip in allowed {
            assert!(
                !is_blocked_ip(ip.parse::<IpAddr>().unwrap()),
                "{ip} must be allowed"
            );
        }
    }

    #[test]
    fn loopback_literals_are_rejected_without_dns() {
        // Public literal passes; private literals fail fast with no lookup.
        assert!(is_blocked_ip(
            "127.0.0.1".parse::<std::net::IpAddr>().unwrap()
        ));
    }

    #[tokio::test]
    async fn url_guard_rejects_private_and_bad_schemes() {
        // Literal loopback / RFC 1918 / metadata: rejected with no DNS.
        for url in [
            "http://127.0.0.1/hook",
            "http://[::1]:8080/hook",
            "https://192.168.5.5/hook",
            "http://169.254.169.254/latest/meta-data/",
            "https://10.0.0.1/hook",
        ] {
            let err = ensure_public_webhook(url).await.unwrap_err();
            assert!(err.contains("private"), "{url}: {err}");
        }
        // Bad scheme / unparsable: rejected before any I/O.
        for url in ["file:///etc/passwd", "ftp://example.com/hook", "not a url"]
        {
            assert!(ensure_public_webhook(url).await.is_err(), "{url}");
        }
    }
}
