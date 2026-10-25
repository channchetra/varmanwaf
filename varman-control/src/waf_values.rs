//! String values stored in WAF and policy rows.
//!
//! The REST validators, the policy compiler and the gRPC config builder must
//! agree on these spellings. Keeping them in a non-API module stops the config
//! builder (and the policy model) from depending on the HTTP layer.

/// Valid challenge levels.
pub mod challenge_level {
    pub const NONE: &str = "none";
    pub const NON_INTERACTIVE: &str = "non_interactive";
    pub const MANAGED: &str = "managed";
    pub const INTERACTIVE: &str = "interactive";

    pub fn is_valid(level: &str) -> bool {
        matches!(level, NONE | NON_INTERACTIVE | MANAGED | INTERACTIVE)
    }

    /// Maps to proto `ChallengeLevel` enum.
    pub fn to_proto(level: &str) -> i32 {
        match level {
            NONE => 0,
            NON_INTERACTIVE => 1,
            MANAGED => 2,
            INTERACTIVE => 3,
            _ => 1,
        }
    }
}

/// Valid IP access actions.
pub mod ip_action {
    pub const BLOCK: &str = "block";
    pub const CHALLENGE: &str = "challenge";
    pub const JS_CHALLENGE: &str = "js_challenge";
    pub const ALLOW: &str = "allow";
    /// Ask for basic authentication; the credentials come from the site's
    /// basic auth settings.
    pub const BASIC_AUTH: &str = "basic_auth";

    pub fn is_valid(action: &str) -> bool {
        matches!(
            action,
            BLOCK | CHALLENGE | JS_CHALLENGE | ALLOW | BASIC_AUTH
        )
    }

    /// Maps to the proto `IpAccessAction` enum.
    pub fn to_proto(action: &str) -> i32 {
        match action {
            BLOCK => 0,
            CHALLENGE => 1,
            JS_CHALLENGE => 2,
            ALLOW => 3,
            BASIC_AUTH => 4,
            _ => 0,
        }
    }
}

/// Attack categories a site can downgrade to monitor-only.
pub const CATEGORIES: [&str; 9] = [
    "sqli", "xss", "rce", "lfi", "ssrf", "deser", "crlf", "xxe", "ssti",
];

/// Backend stacks a site can downgrade to monitor-only. Must stay in sync
/// with `StackSet::parse_name` in `varman-waf`.
pub const STACKS: [&str; 4] = ["java", "php", "python", "node"];

/// Built-in managed rules a site can downgrade to monitor-only, by id.
/// Mirrors `varman_waf::MANAGED_RULE_IDS` (whitelisted through the crate so
/// a new managed rule cannot be configured before the engine knows it).
pub const MANAGED_RULES: [&str; 14] = varman_waf::MANAGED_RULE_IDS;

/// Engine modes a site can select. `inherit` keeps the process-wide
/// `VARMAN_WAF_ENGINE`; the others override it for this site.
pub const ENGINE_MODES: [&str; 4] = ["inherit", "legacy", "shadow", "varman"];
