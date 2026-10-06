use sha2::{Digest, Sha256};

use crate::fingerprint::BrowserFingerprint;

/// Result of browser integrity check
#[derive(Debug, Clone, PartialEq)]
pub enum IntegrityResult {
    /// Browser passed integrity checks
    Passed,
    /// Browser shows suspicious indicators but not definitively a bot
    Suspicious(String),
    /// Browser failed integrity checks — likely automated
    Failed(String),
}

/// Known bot/automation user agent patterns
const BOT_UA_PATTERNS: &[&str] = &[
    "bot",
    "crawler",
    "spider",
    "slurp",
    "curl",
    "wget",
    "python-requests",
    "httpie",
    "scrapy",
    "headlesschrome",
    "phantomjs",
    "selenium",
    "puppeteer",
    "playwright",
    "googlebot",
    "bingbot",
    "yandex",
    "baiduspider",
    "facebookexternalhit",
    "twitterbot",
    "linkedinbot",
    "whatsapp",
    "telegrambot",
    "discordbot",
    "slackbot",
    "apache-httpclient",
    "java/",
    "okhttp",
    "go-http-client",
    "node-fetch",
    "axios",
    "libwww",
    "lwp-trivial",
    "mechanize",
    "httpclient",
    "restsharp",
    "postmanruntime",
];

/// Legitimate search engine bots that should generally be allowed
const GOOD_BOT_PATTERNS: &[&str] = &[
    "googlebot",
    "bingbot",
    "yandex",
    "baiduspider",
    "duckduckbot",
    "applebot",
];

/// Verify the proof-of-work solution.
/// SHA-256(challenge_nonce + solution) must have `difficulty` leading zero bits.
pub fn verify_proof_of_work(
    challenge_nonce: &str,
    solution: &str,
    difficulty: u32,
) -> bool {
    let mut hasher = Sha256::new();
    hasher.update(challenge_nonce.as_bytes());
    hasher.update(solution.as_bytes());
    let hash = hasher.finalize();

    has_leading_zero_bits(&hash, difficulty)
}

/// Check if a hash has the specified number of leading zero bits
fn has_leading_zero_bits(hash: &[u8], bits: u32) -> bool {
    let full_bytes = (bits / 8) as usize;
    let remaining_bits = bits % 8;

    // Check full zero bytes
    for byte in hash.iter().take(full_bytes) {
        if *byte != 0 {
            return false;
        }
    }

    // Check remaining bits in the next byte
    if remaining_bits > 0 {
        if full_bytes >= hash.len() {
            return false;
        }
        let mask = 0xFF << (8 - remaining_bits);
        if hash[full_bytes] & mask != 0 {
            return false;
        }
    }

    true
}

/// Verify the timestamp is within acceptable window (prevent replay attacks).
/// Returns true if `submitted_at` is within `max_age_secs` of now.
pub fn verify_timestamp(submitted_at: i64, max_age_secs: i64) -> bool {
    let now = chrono::Utc::now().timestamp();
    let age = now - submitted_at;
    // Allow some clock skew (5 seconds in the future)
    age >= -5 && age <= max_age_secs
}

/// Check for automation indicators in the browser fingerprint and user agent.
/// Returns an IntegrityResult indicating pass, suspicious, or fail.
pub fn check_browser_integrity(
    fingerprint: &BrowserFingerprint,
    user_agent: &str,
) -> IntegrityResult {
    let ua_lower = user_agent.to_lowercase();

    // Check for known automation tools
    let automation_indicators = [
        "headlesschrome",
        "phantomjs",
        "selenium",
        "puppeteer",
        "playwright",
        "webdriver",
    ];

    for indicator in &automation_indicators {
        if ua_lower.contains(indicator) {
            return IntegrityResult::Failed(format!(
                "automation tool detected: {indicator}"
            ));
        }
    }

    // Check for non-browser user agents (curl, wget, python, etc.)
    let non_browser = [
        "curl",
        "wget",
        "python-requests",
        "httpie",
        "scrapy",
        "go-http-client",
        "node-fetch",
        "java/",
        "libwww",
        "postmanruntime",
        "restsharp",
    ];

    for pattern in &non_browser {
        if ua_lower.contains(pattern) {
            return IntegrityResult::Failed(format!(
                "non-browser user agent: {pattern}"
            ));
        }
    }

    // Check for empty/suspicious fingerprint data
    if fingerprint.user_agent.is_empty() {
        return IntegrityResult::Failed(
            "empty user agent in fingerprint".to_string(),
        );
    }

    if fingerprint.screen_width == 0 || fingerprint.screen_height == 0 {
        return IntegrityResult::Suspicious(
            "zero screen dimensions".to_string(),
        );
    }

    if fingerprint.hardware_concurrency == 0 {
        return IntegrityResult::Suspicious(
            "zero hardware concurrency".to_string(),
        );
    }

    if fingerprint.canvas_hash.is_empty() {
        return IntegrityResult::Suspicious("empty canvas hash".to_string());
    }

    // Check for generic bot patterns
    for pattern in BOT_UA_PATTERNS {
        if ua_lower.contains(pattern) {
            // Some bots are legitimate (search engines)
            let is_good_bot =
                GOOD_BOT_PATTERNS.iter().any(|good| ua_lower.contains(good));
            if is_good_bot {
                return IntegrityResult::Passed;
            }
            return IntegrityResult::Suspicious(format!(
                "bot user agent pattern: {pattern}"
            ));
        }
    }

    // All checks passed
    IntegrityResult::Passed
}

/// Check if a user agent matches known good bots (search engines)
pub fn is_known_good_bot(user_agent: &str) -> bool {
    let ua_lower = user_agent.to_lowercase();
    GOOD_BOT_PATTERNS
        .iter()
        .any(|pattern| ua_lower.contains(pattern))
}

/// Check if a user agent matches known automation/bot patterns
pub fn is_known_bot(user_agent: &str) -> bool {
    let ua_lower = user_agent.to_lowercase();
    BOT_UA_PATTERNS
        .iter()
        .any(|pattern| ua_lower.contains(pattern))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_verify_proof_of_work_valid() {
        // Use difficulty 0 — any solution passes
        assert!(verify_proof_of_work("nonce123", "anything", 0));
    }

    #[test]
    fn test_verify_proof_of_work_invalid() {
        // Use very high difficulty — random solution almost certainly fails
        assert!(!verify_proof_of_work("nonce123", "wrong", 32));
    }

    #[test]
    fn test_has_leading_zero_bits() {
        let hash = [0x00, 0x00, 0x0F, 0xFF];
        assert!(has_leading_zero_bits(&hash, 0));
        assert!(has_leading_zero_bits(&hash, 8));
        assert!(has_leading_zero_bits(&hash, 16));
        assert!(has_leading_zero_bits(&hash, 20));
        assert!(!has_leading_zero_bits(&hash, 21));

        let hash2 = [0x00, 0x01, 0x00, 0x00];
        assert!(has_leading_zero_bits(&hash2, 8));
        assert!(!has_leading_zero_bits(&hash2, 16));
    }

    #[test]
    fn test_verify_timestamp_valid() {
        let now = chrono::Utc::now().timestamp();
        assert!(verify_timestamp(now, 300));
        assert!(verify_timestamp(now - 100, 300));
    }

    #[test]
    fn test_verify_timestamp_expired() {
        let old = chrono::Utc::now().timestamp() - 600;
        assert!(!verify_timestamp(old, 300));
    }

    #[test]
    fn test_verify_timestamp_future() {
        let future = chrono::Utc::now().timestamp() + 100;
        // Allow 5 seconds of clock skew
        assert!(!verify_timestamp(future, 300));
    }

    #[test]
    fn test_check_browser_integrity_passed() {
        let fp = BrowserFingerprint {
            user_agent: "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36".to_string(),
            screen_width: 1920,
            screen_height: 1080,
            timezone_offset: -480,
            language: "en-US".to_string(),
            platform: "Win32".to_string(),
            canvas_hash: "abc123".to_string(),
            webgl_vendor: "Google Inc.".to_string(),
            webgl_renderer: "ANGLE".to_string(),
            plugins_count: 3,
            touch_support: false,
            hardware_concurrency: 8,
            device_memory: Some(8.0),
        };
        let result = check_browser_integrity(&fp, &fp.user_agent);
        assert_eq!(result, IntegrityResult::Passed);
    }

    #[test]
    fn test_check_browser_integrity_headless() {
        let fp = BrowserFingerprint {
            user_agent: "Mozilla/5.0 HeadlessChrome/120.0".to_string(),
            screen_width: 1920,
            screen_height: 1080,
            timezone_offset: 0,
            language: "en-US".to_string(),
            platform: "Linux".to_string(),
            canvas_hash: "abc".to_string(),
            webgl_vendor: "".to_string(),
            webgl_renderer: "".to_string(),
            plugins_count: 0,
            touch_support: false,
            hardware_concurrency: 4,
            device_memory: None,
        };
        let result = check_browser_integrity(&fp, &fp.user_agent);
        assert!(matches!(result, IntegrityResult::Failed(_)));
    }

    #[test]
    fn test_check_browser_integrity_curl() {
        let fp = BrowserFingerprint {
            user_agent: "curl/7.88.0".to_string(),
            screen_width: 0,
            screen_height: 0,
            timezone_offset: 0,
            language: "".to_string(),
            platform: "".to_string(),
            canvas_hash: "".to_string(),
            webgl_vendor: "".to_string(),
            webgl_renderer: "".to_string(),
            plugins_count: 0,
            touch_support: false,
            hardware_concurrency: 0,
            device_memory: None,
        };
        let result = check_browser_integrity(&fp, &fp.user_agent);
        assert!(matches!(result, IntegrityResult::Failed(_)));
    }

    #[test]
    fn test_is_known_good_bot() {
        assert!(is_known_good_bot(
            "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)"
        ));
        assert!(is_known_good_bot(
            "Mozilla/5.0 (compatible; bingbot/2.0; +http://www.bing.com/bingbot.htm)"
        ));
        assert!(!is_known_good_bot(
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120.0"
        ));
    }

    #[test]
    fn test_is_known_bot() {
        assert!(is_known_bot("python-requests/2.28.0"));
        assert!(is_known_bot("curl/7.88.0"));
        assert!(is_known_bot("Scrapy/2.8.0"));
        assert!(!is_known_bot(
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120.0"
        ));
    }
}
