//! Attack categories shared by every detector.
//!
//! The legacy engine has its own `rules::signatures::AttackCategory` tied to
//! the signature tables. The pipeline category is the **Varman-native**
//! taxonomy: detectors identify a category from this list, findings carry it,
//! and policy (monitor-by-category, per-stack downgrades) keys off it. The
//! list follows the mandate (§18) and stays intentionally finite — new
//! categories are a deliberate change, not an accident of a detector.

use serde::{Deserialize, Serialize};

/// Vulnerability / abuse family a finding belongs to.
#[derive(
    Debug,
    Clone,
    Copy,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Hash,
    Serialize,
    Deserialize,
)]
#[serde(rename_all = "snake_case")]
pub enum AttackCategory {
    /// SQL injection (structural and syntax analysis).
    SqlInjection,
    /// Cross-site scripting (reflected / DOM construction).
    Xss,
    /// OS command injection.
    CommandInjection,
    /// Path traversal (`../`, encoded variants).
    PathTraversal,
    /// Local/remote file inclusion.
    LfiRfi,
    /// Server-side request forgery.
    Ssrf,
    /// XML external entity expansion.
    Xxe,
    /// Server-side template injection.
    Ssti,
    /// NoSQL injection (operator/JSON shapes).
    NosqlInjection,
    /// LDAP injection.
    LdapInjection,
    /// XPath injection.
    XPathInjection,
    /// Unsafe deserialization payloads.
    Deserialization,
    /// JavaScript prototype pollution.
    PrototypePollution,
    /// Log4Shell / JNDI lookup injection.
    Log4Shell,
    /// CRLF / header injection (response splitting).
    CrlfInjection,
    /// HTTP request smuggling / protocol ambiguity.
    HttpSmuggling,
    /// Open redirect.
    OpenRedirect,
    /// GraphQL-specific abuse (depth, batching, introspection abuse).
    GraphqlAbuse,
    /// Generic API abuse (parameter tampering, mass assignment, …).
    ApiAbuse,
    /// Credential abuse (stuffing, brute force, spraying).
    CredentialAbuse,
    /// Automated / bot activity that is not plain credential abuse.
    BotActivity,
    /// Sensitive data exposure (DLP-class findings).
    SensitiveDataExposure,
    /// Protocol-level violation that is not a smuggling attempt.
    ProtocolViolation,
    /// Category not yet assigned (weak signals, heuristics in progress).
    Unknown,
}

impl AttackCategory {
    /// Stable lowercase name used in findings, events and policy keys.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::SqlInjection => "sql_injection",
            Self::Xss => "xss",
            Self::CommandInjection => "command_injection",
            Self::PathTraversal => "path_traversal",
            Self::LfiRfi => "lfi_rfi",
            Self::Ssrf => "ssrf",
            Self::Xxe => "xxe",
            Self::Ssti => "ssti",
            Self::NosqlInjection => "nosql_injection",
            Self::LdapInjection => "ldap_injection",
            Self::XPathInjection => "xpath_injection",
            Self::Deserialization => "deserialization",
            Self::PrototypePollution => "prototype_pollution",
            Self::Log4Shell => "log4shell",
            Self::CrlfInjection => "crlf_injection",
            Self::HttpSmuggling => "http_smuggling",
            Self::OpenRedirect => "open_redirect",
            Self::GraphqlAbuse => "graphql_abuse",
            Self::ApiAbuse => "api_abuse",
            Self::CredentialAbuse => "credential_abuse",
            Self::BotActivity => "bot_activity",
            Self::SensitiveDataExposure => "sensitive_data_exposure",
            Self::ProtocolViolation => "protocol_violation",
            Self::Unknown => "unknown",
        }
    }
}

impl AttackCategory {
    /// Parse a policy/config name (the value of [`AttackCategory::as_str`])
    /// back into a category, case-insensitively.
    pub fn parse(name: &str) -> Option<Self> {
        let lowered = name.trim().to_ascii_lowercase();
        [
            Self::SqlInjection,
            Self::Xss,
            Self::CommandInjection,
            Self::PathTraversal,
            Self::LfiRfi,
            Self::Ssrf,
            Self::Xxe,
            Self::Ssti,
            Self::NosqlInjection,
            Self::LdapInjection,
            Self::XPathInjection,
            Self::Deserialization,
            Self::PrototypePollution,
            Self::Log4Shell,
            Self::CrlfInjection,
            Self::HttpSmuggling,
            Self::OpenRedirect,
            Self::GraphqlAbuse,
            Self::ApiAbuse,
            Self::CredentialAbuse,
            Self::BotActivity,
            Self::SensitiveDataExposure,
            Self::ProtocolViolation,
            Self::Unknown,
        ]
        .into_iter()
        .find(|category| category.as_str() == lowered.as_str())
    }
}

impl std::fmt::Display for AttackCategory {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

#[cfg(test)]
mod tests {
    use super::AttackCategory;

    #[test]
    fn parse_round_trips_every_name() {
        let all = [
            AttackCategory::SqlInjection,
            AttackCategory::Xss,
            AttackCategory::CommandInjection,
            AttackCategory::PathTraversal,
            AttackCategory::LfiRfi,
            AttackCategory::Ssrf,
            AttackCategory::Xxe,
            AttackCategory::Ssti,
            AttackCategory::NosqlInjection,
            AttackCategory::LdapInjection,
            AttackCategory::XPathInjection,
            AttackCategory::Deserialization,
            AttackCategory::PrototypePollution,
            AttackCategory::Log4Shell,
            AttackCategory::CrlfInjection,
            AttackCategory::HttpSmuggling,
            AttackCategory::OpenRedirect,
            AttackCategory::GraphqlAbuse,
            AttackCategory::ApiAbuse,
            AttackCategory::CredentialAbuse,
            AttackCategory::BotActivity,
            AttackCategory::SensitiveDataExposure,
            AttackCategory::ProtocolViolation,
            AttackCategory::Unknown,
        ];
        for category in all {
            assert_eq!(
                AttackCategory::parse(category.as_str()),
                Some(category)
            );
        }
        assert_eq!(
            AttackCategory::parse(" SQL_INJECTION "),
            Some(AttackCategory::SqlInjection)
        );
        assert_eq!(AttackCategory::parse("nonsense"), None);
    }

    #[test]
    fn names_are_unique() {
        let all = [
            AttackCategory::SqlInjection,
            AttackCategory::Xss,
            AttackCategory::CommandInjection,
            AttackCategory::PathTraversal,
            AttackCategory::LfiRfi,
            AttackCategory::Ssrf,
            AttackCategory::Xxe,
            AttackCategory::Ssti,
            AttackCategory::NosqlInjection,
            AttackCategory::LdapInjection,
            AttackCategory::XPathInjection,
            AttackCategory::Deserialization,
            AttackCategory::PrototypePollution,
            AttackCategory::Log4Shell,
            AttackCategory::CrlfInjection,
            AttackCategory::HttpSmuggling,
            AttackCategory::OpenRedirect,
            AttackCategory::GraphqlAbuse,
            AttackCategory::ApiAbuse,
            AttackCategory::CredentialAbuse,
            AttackCategory::BotActivity,
            AttackCategory::SensitiveDataExposure,
            AttackCategory::ProtocolViolation,
            AttackCategory::Unknown,
        ];
        let mut names: Vec<&str> = all.iter().map(|c| c.as_str()).collect();
        names.sort_unstable();
        let unique = names.len();
        names.dedup();
        assert_eq!(names.len(), unique, "duplicate category names");
    }
}
