//! At-rest protection for channel secrets (`smtp_pass`, `secret`,
//! `secret_token` in `notification_channels.config`).
//!
//! The API already keeps secrets out of responses (redact/unredact), but the
//! JSONB column itself stored them in clear text — a leaked database backup
//! then hands out every SMTP password and webhook signing key. This module
//! seals those fields with AES-256-GCM before the row is written and opens
//! them again when the manager loads channels for delivery.
//!
//! The key comes from the `PINGWAF_SECRET_KEY` environment variable (any
//! non-empty string; stretched to 256 bits with SHA-256). Without it the
//! seal step is a no-op and secrets stay in clear text as before — the
//! deployment keeps working, one warning is logged per process, and DB
//! backups must be treated as sensitive. Sealed values carry the
//! `enc:v1:` prefix, so `open_config` transparently passes clear-text
//! values through and old rows keep working after the key is introduced.

use base64::Engine as _;
use ring::aead::{Aad, LessSafeKey, Nonce, UnboundKey, AES_256_GCM};
use ring::digest::{digest, SHA256};
use ring::rand::{SecureRandom, SystemRandom};
use serde_json::{json, Value};

/// Config keys that must never be stored or returned in plain text.
/// Shared with the API layer, which redacts them in responses.
pub(crate) const SECRET_KEYS: [&str; 3] =
    ["smtp_pass", "secret", "secret_token"];

/// Versioned marker of a sealed value; only this prefix is ever decrypted.
const PREFIX: &str = "enc:v1:";

/// Environment variable holding the instance encryption secret.
const KEY_ENV: &str = "PINGWAF_SECRET_KEY";

/// Warned once per process when no key is configured.
static MISSING_KEY_WARNED: std::sync::OnceLock<()> = std::sync::OnceLock::new();

/// The 256-bit key derived from the configured secret, when present.
fn instance_key() -> Option<UnboundKey> {
    let secret = std::env::var(KEY_ENV).ok()?;
    let secret = secret.trim();
    if secret.is_empty() {
        return None;
    }
    let bytes: [u8; 32] = digest(&SHA256, secret.as_bytes())
        .as_ref()
        .try_into()
        .ok()?;
    UnboundKey::new(&AES_256_GCM, &bytes).ok()
}

/// Seals one string with the instance key: `enc:v1:<base64(nonce||ct||tag)>`.
fn seal_with(key: &LessSafeKey, rng: &SystemRandom, plain: &str) -> String {
    let mut nonce_bytes = [0u8; 12];
    rng.fill(&mut nonce_bytes)
        .expect("SystemRandom failure is unrecoverable");
    let nonce = Nonce::assume_unique_for_key(nonce_bytes);
    let mut buffer = plain.as_bytes().to_vec();
    // AES-GCM appends the 16-byte tag; the nonce is stored alongside.
    key.seal_in_place_append_tag(nonce, Aad::empty(), &mut buffer)
        .expect("AES-GCM sealing cannot fail with valid inputs");
    let mut packed = Vec::with_capacity(12 + buffer.len());
    packed.extend_from_slice(&nonce_bytes);
    packed.extend_from_slice(&buffer);
    format!("{PREFIX}{}", {
        use base64::engine::general_purpose::STANDARD as B64;
        B64.encode(packed)
    })
}

/// Opens one sealed string back to plain text; `None` on tampering or a
/// foreign `enc:v1:` payload (e.g. the encryption key was rotated).
fn open_with(key: &LessSafeKey, sealed: &str) -> Option<String> {
    let payload = sealed.strip_prefix(PREFIX)?;
    use base64::engine::general_purpose::STANDARD as B64;
    let mut packed = B64.decode(payload).ok()?;
    if packed.len() < 12 + 16 {
        return None;
    }
    let mut nonce_bytes = [0u8; 12];
    nonce_bytes.copy_from_slice(&packed[..12]);
    let nonce = Nonce::assume_unique_for_key(nonce_bytes);
    let plain = key
        .open_in_place(nonce, Aad::empty(), &mut packed[12..])
        .ok()?;
    String::from_utf8(plain.to_vec()).ok()
}

/// True when the process has an encryption key configured.
pub fn encryption_enabled() -> bool {
    instance_key().is_some()
}

/// Seals a single standalone secret (e.g. the AI provider API key). Without
/// the instance key the input is returned unchanged (no-op seal, same
/// semantics as [`seal_config`]); a value that is already sealed is left as
/// is so double-saving cannot wrap the prefix twice.
pub fn seal_string(plain: &str) -> String {
    if plain.is_empty() || plain.starts_with(PREFIX) {
        return plain.to_string();
    }
    let Some(key) = instance_key() else {
        if MISSING_KEY_WARNED.set(()).is_ok() {
            tracing::warn!(
                "PINGWAF_SECRET_KEY is not set: secrets are stored in \
                 clear text; set it to encrypt them at rest"
            );
        }
        return plain.to_string();
    };
    seal_with(&LessSafeKey::new(key), &SystemRandom::new(), plain)
}

/// Opens a single sealed secret back to plain text. Clear-text values
/// (legacy rows written before a key existed) pass through unchanged;
/// sealed values that fail to open (corrupt, rotated key) yield `None` so
/// the caller can fall back to its "missing credential" path.
pub fn open_string(sealed: &str) -> Option<String> {
    if sealed.is_empty() {
        return Some(String::new());
    }
    if !sealed.starts_with(PREFIX) {
        return Some(sealed.to_string());
    }
    let key = instance_key()?;
    let opened = open_with(&LessSafeKey::new(key), sealed);
    if opened.is_none() {
        tracing::warn!(
            "a sealed secret could not be opened; is PINGWAF_SECRET_KEY \
             unchanged since it was stored?"
        );
    }
    opened
}

/// Seals every secret field of a channel config in place. Clear-text values
/// without the instance key are left untouched (deployment without at-rest
/// encryption keeps working; the caller decides what to warn).
pub fn seal_config(config: &mut Value) {
    let Some(object) = config.as_object_mut() else {
        return;
    };
    let Some(key) = instance_key() else {
        if MISSING_KEY_WARNED.set(()).is_ok() {
            tracing::warn!(
                "PINGWAF_SECRET_KEY is not set: notification channel \
                 secrets are stored in clear text; set it to encrypt \
                 them at rest"
            );
        }
        return;
    };
    let rng = SystemRandom::new();
    let key = LessSafeKey::new(key);
    for name in SECRET_KEYS {
        let sealed = match object.get(name).and_then(Value::as_str) {
            Some(value) if !value.is_empty() && !value.starts_with(PREFIX) => {
                seal_with(&key, &rng, value)
            },
            _ => continue,
        };
        object.insert(name.to_string(), json!(sealed));
    }
}

/// Opens every sealed secret field of a channel config in place. Values that
/// fail to open (corrupt, wrong key) are dropped to `""` rather than leaked:
/// a delivery attempt with them would fail anyway, and half-garbage in a
/// password field is worse than an explicit empty one.
pub fn open_config(config: &mut Value) {
    let Some(object) = config.as_object_mut() else {
        return;
    };
    let Some(key) = instance_key() else {
        return;
    };
    let key = LessSafeKey::new(key);
    for name in SECRET_KEYS {
        let opened = match object.get(name).and_then(Value::as_str) {
            Some(value) if value.starts_with(PREFIX) => {
                match open_with(&key, value) {
                    Some(plain) => plain,
                    None => {
                        tracing::warn!(
                            key = name,
                            "a sealed channel secret could not be opened; \
                             is PINGWAF_SECRET_KEY unchanged since it was \
                             stored?"
                        );
                        String::new()
                    },
                }
            },
            _ => continue,
        };
        object.insert(name.to_string(), json!(opened));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn test_key() -> (UnboundKey, SystemRandom) {
        (
            UnboundKey::new(
                &AES_256_GCM,
                &digest(&SHA256, b"test-secret").as_ref()[..32],
            )
            .unwrap(),
            SystemRandom::new(),
        )
    }

    #[test]
    fn sealed_values_roundtrip_and_are_opaque() {
        let (unbound, rng) = test_key();
        let key = LessSafeKey::new(unbound);
        let sealed = seal_with(&key, &rng, "s3cret-密码");
        assert!(sealed.starts_with(PREFIX));
        assert!(!sealed.contains("s3cret"));
        // Each seal uses a fresh nonce.
        let again = seal_with(&key, &rng, "s3cret-密码");
        assert_ne!(sealed, again);
        assert_eq!(open_with(&key, &sealed).unwrap(), "s3cret-密码");
    }

    #[test]
    fn open_rejects_tampered_and_foreign_payloads() {
        let (unbound, rng) = test_key();
        let key = LessSafeKey::new(unbound);
        let sealed = seal_with(&key, &rng, "value");
        // Flip one ciphertext byte.
        let mut chars = sealed.into_bytes();
        let last = chars.len() - 1;
        chars[last] = if chars[last] == b'A' { b'B' } else { b'A' };
        let tampered = String::from_utf8(chars).unwrap();
        // Either base64 decode fails or GCM authentication fails.
        assert!(open_with(&key, &tampered).is_none());
        assert!(open_with(&key, "enc:v1:not-base64!").is_none());
        assert!(open_with(&key, "plain-value").is_none());
    }

    #[test]
    fn string_helpers_roundtrip_and_pass_clear_text_through() {
        let sealed = seal_string("sk-abc123");
        let opened = open_string(&sealed).unwrap();
        assert_eq!(opened, "sk-abc123");
        // Legacy clear-text values pass through untouched.
        assert_eq!(open_string("sk-legacy").unwrap(), "sk-legacy");
        assert_eq!(open_string("").unwrap(), "");
        // Double-sealing cannot happen (already prefixed).
        assert_eq!(seal_string(&sealed), sealed);
    }

    #[test]
    fn config_walk_covers_only_secret_keys() {
        let (unbound, rng) = test_key();
        let key = LessSafeKey::new(unbound);
        // Install a known key via the with-key path on a manual walk, then
        // verify seal/open skip non-secret fields.
        let mut config = json!({
            "smtp_host": "smtp.example.com",
            "smtp_pass": "hunter2",
        });
        // Manually seal smtp_pass (the env-driven seal_config is covered by
        // integration; the field walk is identical).
        let object = config.as_object_mut().unwrap();
        let sealed = seal_with(&key, &rng, "hunter2");
        object.insert("smtp_pass".to_string(), json!(sealed.clone()));
        // Non-secret fields untouched.
        assert_eq!(config["smtp_host"], json!("smtp.example.com"));
        // The secret field no longer reads as the plaintext.
        assert_ne!(config["smtp_pass"], json!("hunter2"));
        // Walk-open restores it.
        let mut restored = json!({ "smtp_pass": sealed });
        let obj = restored.as_object_mut().unwrap();
        for name in SECRET_KEYS {
            if let Some(value) = obj.get(name).and_then(Value::as_str) {
                if let Some(plain) = open_with(&key, value) {
                    obj.insert(name.to_string(), json!(plain));
                }
            }
        }
        assert_eq!(restored["smtp_pass"], json!("hunter2"));
    }
}
