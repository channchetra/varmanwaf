use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use chrono::Utc;
use hmac::{Hmac, KeyInit, Mac};
use rand::RngExt;
use serde::{Deserialize, Serialize};
use sha2::Sha256;

type HmacSha256 = Hmac<Sha256>;

/// Cookie holding a solved challenge's clearance. Consumers outside this
/// crate (e.g. the WAF plugin's rate limiter) validate it by name.
pub const CLEARANCE_COOKIE_NAME: &str = "__pingwaf_clearance";

/// Challenge clearance levels (higher level bypasses lower)
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize,
)]
pub enum ClearanceLevel {
    None = 0,
    /// JS Challenge passed
    NonInteractive = 1,
    /// Managed challenge passed
    Managed = 2,
    /// Full CAPTCHA passed
    Interactive = 3,
}

/// Payload stored in the clearance cookie
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClearancePayload {
    /// Unique session ID
    pub session_id: String,
    /// Clearance level achieved
    pub level: ClearanceLevel,
    /// When this was issued (Unix timestamp)
    pub issued_at: i64,
    /// When this expires (Unix timestamp)
    pub expires_at: i64,
    /// Device fingerprint hash (partial, for binding)
    pub fingerprint_hash: String,
    /// Site ID this clearance is valid for
    pub site_id: String,
    /// Nonce to prevent replay
    pub nonce: String,
}

/// Errors that can occur during cookie validation
#[derive(Debug)]
pub enum CookieError {
    InvalidFormat,
    SignatureMismatch,
    Expired,
    InvalidPayload,
}

impl std::fmt::Display for CookieError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidFormat => write!(f, "invalid cookie format"),
            Self::SignatureMismatch => write!(f, "signature mismatch"),
            Self::Expired => write!(f, "clearance expired"),
            Self::InvalidPayload => write!(f, "invalid payload"),
        }
    }
}

impl std::error::Error for CookieError {}

/// Cookie manager handles creation and validation of clearance cookies
pub struct CookieManager {
    /// HMAC signing key
    secret: Vec<u8>,
    /// Default clearance duration in seconds
    default_duration_secs: i64,
    /// Cookie name
    cookie_name: String,
}

impl CookieManager {
    /// Create a new CookieManager with the given secret and duration
    pub fn new(secret: &[u8], duration_secs: i64) -> Self {
        Self {
            secret: secret.to_vec(),
            default_duration_secs: duration_secs,
            cookie_name: CLEARANCE_COOKIE_NAME.to_string(),
        }
    }

    /// Create a new CookieManager with a custom cookie name
    pub fn with_name(secret: &[u8], duration_secs: i64, name: &str) -> Self {
        Self {
            secret: secret.to_vec(),
            default_duration_secs: duration_secs,
            cookie_name: name.to_string(),
        }
    }

    /// Create a signed clearance cookie value.
    /// Format: base64(json_payload).base64(hmac_signature)
    pub fn issue_clearance(
        &self,
        level: ClearanceLevel,
        site_id: &str,
        fingerprint_hash: &str,
    ) -> String {
        let now = Utc::now().timestamp();
        let session_id = generate_random_hex(16);
        let nonce = generate_random_hex(8);

        let payload = ClearancePayload {
            session_id,
            level,
            issued_at: now,
            expires_at: now + self.default_duration_secs,
            fingerprint_hash: fingerprint_hash.to_string(),
            site_id: site_id.to_string(),
            nonce,
        };

        self.encode_payload(&payload)
    }

    /// Issue a clearance cookie and return both the value and the payload
    pub fn issue_clearance_with_payload(
        &self,
        level: ClearanceLevel,
        site_id: &str,
        fingerprint_hash: &str,
    ) -> (String, ClearancePayload) {
        let now = Utc::now().timestamp();
        let session_id = generate_random_hex(16);
        let nonce = generate_random_hex(8);

        let payload = ClearancePayload {
            session_id,
            level,
            issued_at: now,
            expires_at: now + self.default_duration_secs,
            fingerprint_hash: fingerprint_hash.to_string(),
            site_id: site_id.to_string(),
            nonce,
        };

        let value = self.encode_payload(&payload);
        (value, payload)
    }

    /// Validate a clearance cookie value, returns payload if valid
    pub fn validate_clearance(
        &self,
        cookie_value: &str,
    ) -> Result<ClearancePayload, CookieError> {
        // Split on '.' to get payload and signature
        let parts: Vec<&str> = cookie_value.splitn(2, '.').collect();
        if parts.len() != 2 {
            return Err(CookieError::InvalidFormat);
        }

        let payload_b64 = parts[0];
        let signature_b64 = parts[1];

        // Decode signature
        let signature = URL_SAFE_NO_PAD
            .decode(signature_b64)
            .map_err(|_| CookieError::InvalidFormat)?;

        // Verify HMAC using constant-time comparison
        let mut mac = HmacSha256::new_from_slice(&self.secret)
            .map_err(|_| CookieError::InvalidPayload)?;
        mac.update(payload_b64.as_bytes());

        // Constant-time verification
        mac.verify_slice(&signature)
            .map_err(|_| CookieError::SignatureMismatch)?;

        // Decode payload
        let payload_json = URL_SAFE_NO_PAD
            .decode(payload_b64)
            .map_err(|_| CookieError::InvalidFormat)?;

        let payload: ClearancePayload =
            serde_json::from_slice(&payload_json)
                .map_err(|_| CookieError::InvalidPayload)?;

        // Check expiration
        if !self.is_valid(&payload) {
            return Err(CookieError::Expired);
        }

        Ok(payload)
    }

    /// Check if clearance is still valid (not expired)
    pub fn is_valid(&self, payload: &ClearancePayload) -> bool {
        let now = Utc::now().timestamp();
        now < payload.expires_at
    }

    /// Check if clearance level is sufficient for the required level
    pub fn level_sufficient(
        &self,
        payload: &ClearancePayload,
        required: ClearanceLevel,
    ) -> bool {
        payload.level >= required
    }

    /// Get the cookie name
    pub fn cookie_name(&self) -> &str {
        &self.cookie_name
    }

    /// Set the cookie name
    pub fn set_cookie_name(&mut self, name: &str) {
        self.cookie_name = name.to_string();
    }

    /// Generate cookie attributes string (HttpOnly, Secure, SameSite, Path, Max-Age)
    pub fn cookie_attributes(&self, payload: &ClearancePayload) -> String {
        let max_age = payload.expires_at - Utc::now().timestamp();
        let max_age = if max_age < 0 { 0 } else { max_age };
        format!("Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age={max_age}")
    }

    /// Encode a payload into the signed cookie format
    fn encode_payload(&self, payload: &ClearancePayload) -> String {
        let json = serde_json::to_vec(payload).unwrap_or_default();
        let payload_b64 = URL_SAFE_NO_PAD.encode(&json);

        let mut mac =
            HmacSha256::new_from_slice(&self.secret).expect("HMAC key error");
        mac.update(payload_b64.as_bytes());
        let signature = mac.finalize().into_bytes();
        let signature_b64 = URL_SAFE_NO_PAD.encode(signature);

        format!("{payload_b64}.{signature_b64}")
    }
}

/// Generate a random hex string of the specified byte length
fn generate_random_hex(byte_len: usize) -> String {
    let mut rng = rand::rng();
    let bytes: Vec<u8> = (0..byte_len).map(|_| rng.random()).collect();
    hex::encode(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_issue_and_validate() {
        let manager = CookieManager::new(b"test-secret-key", 1800);
        let cookie_value = manager.issue_clearance(
            ClearanceLevel::NonInteractive,
            "site-1",
            "fp-hash-abc",
        );

        let payload = manager.validate_clearance(&cookie_value);
        assert!(payload.is_ok());
        let payload = payload.unwrap();
        assert_eq!(payload.level, ClearanceLevel::NonInteractive);
        assert_eq!(payload.site_id, "site-1");
        assert_eq!(payload.fingerprint_hash, "fp-hash-abc");
    }

    #[test]
    fn test_invalid_signature() {
        let manager1 = CookieManager::new(b"secret-1", 1800);
        let manager2 = CookieManager::new(b"secret-2", 1800);

        let cookie_value = manager1.issue_clearance(
            ClearanceLevel::NonInteractive,
            "site-1",
            "fp-hash",
        );

        let result = manager2.validate_clearance(&cookie_value);
        assert!(matches!(result, Err(CookieError::SignatureMismatch)));
    }

    #[test]
    fn test_expired_cookie() {
        let manager = CookieManager::new(b"test-secret", -1); // Already expired
        let cookie_value = manager.issue_clearance(
            ClearanceLevel::NonInteractive,
            "site-1",
            "fp-hash",
        );

        let result = manager.validate_clearance(&cookie_value);
        assert!(matches!(result, Err(CookieError::Expired)));
    }

    #[test]
    fn test_invalid_format() {
        let manager = CookieManager::new(b"test-secret", 1800);
        let result = manager.validate_clearance("not-a-valid-cookie");
        assert!(matches!(result, Err(CookieError::InvalidFormat)));
    }

    #[test]
    fn test_level_sufficient() {
        let manager = CookieManager::new(b"test-secret", 1800);
        let cookie_value = manager.issue_clearance(
            ClearanceLevel::Managed,
            "site-1",
            "fp-hash",
        );
        let payload = manager.validate_clearance(&cookie_value).unwrap();

        assert!(manager.level_sufficient(&payload, ClearanceLevel::None));
        assert!(
            manager.level_sufficient(&payload, ClearanceLevel::NonInteractive)
        );
        assert!(manager.level_sufficient(&payload, ClearanceLevel::Managed));
        assert!(
            !manager.level_sufficient(&payload, ClearanceLevel::Interactive)
        );
    }

    #[test]
    fn test_cookie_attributes() {
        let manager = CookieManager::new(b"test-secret", 1800);
        let (_, payload) = manager.issue_clearance_with_payload(
            ClearanceLevel::NonInteractive,
            "site-1",
            "fp-hash",
        );
        let attrs = manager.cookie_attributes(&payload);
        assert!(attrs.contains("HttpOnly"));
        assert!(attrs.contains("Secure"));
        assert!(attrs.contains("SameSite=Lax"));
        assert!(attrs.contains("Path=/"));
        assert!(attrs.contains("Max-Age="));
    }

    #[test]
    fn test_cookie_name() {
        let manager = CookieManager::new(b"test-secret", 1800);
        assert_eq!(manager.cookie_name(), "__pingwaf_clearance");

        let manager2 =
            CookieManager::with_name(b"test-secret", 1800, "my_cookie");
        assert_eq!(manager2.cookie_name(), "my_cookie");
    }
}
