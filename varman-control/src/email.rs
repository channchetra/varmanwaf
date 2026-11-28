//! E-mail address normalization shared by the REST API and the maintenance
//! CLI.
//!
//! An account created by `varman user add-admin` must be able to sign in
//! through the API, so both paths have to accept exactly the same addresses.
//! The rule lives here rather than in either caller for that reason.

/// Maximum length of the local part of an address (RFC 5321).
const MAX_LOCAL_PART_LEN: usize = 64;

/// Maximum length of a domain name in presentation form (RFC 1035).
const MAX_DOMAIN_LEN: usize = 253;

/// Why an e-mail address was rejected.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct InvalidEmail;

impl std::fmt::Display for InvalidEmail {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("invalid e-mail address")
    }
}

impl std::error::Error for InvalidEmail {}

/// Lower-cases and structurally validates an e-mail address.
///
/// The address is trimmed and lower-cased before the checks, so an operator
/// may type `  Ops@Example.COM ` and the account is stored (and signs in) as
/// `ops@example.com`.
///
/// # Errors
///
/// Returns [`InvalidEmail`] when there is no `@`, the local part is empty or
/// longer than 64 bytes, or the domain is empty, longer than 253 bytes, or
/// does not look like a domain name.
pub fn normalize_email(raw: &str) -> Result<String, InvalidEmail> {
    let email = raw.trim().to_lowercase();
    // Surrounding whitespace is trimmed; a space inside the address is not
    // part of an unquoted mailbox and is rejected.
    if email.chars().any(char::is_whitespace) {
        return Err(InvalidEmail);
    }
    let (local, domain) = email.split_once('@').ok_or(InvalidEmail)?;
    if local.is_empty() || local.len() > MAX_LOCAL_PART_LEN {
        return Err(InvalidEmail);
    }
    if domain.is_empty()
        || domain.len() > MAX_DOMAIN_LEN
        || !domain.contains('.')
        || domain.starts_with('.')
        || domain.ends_with('.')
    {
        return Err(InvalidEmail);
    }
    Ok(email)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_valid_address_is_accepted() {
        assert_eq!(
            normalize_email("ops@example.com").unwrap(),
            "ops@example.com"
        );
        assert_eq!(
            normalize_email("ops+alerts@sub.example.com").unwrap(),
            "ops+alerts@sub.example.com"
        );
    }

    #[test]
    fn an_address_without_an_at_sign_is_rejected() {
        assert_eq!(normalize_email("no-at-sign"), Err(InvalidEmail));
        assert_eq!(normalize_email(""), Err(InvalidEmail));
    }

    #[test]
    fn a_local_part_longer_than_64_bytes_is_rejected() {
        let boundary = format!("{}@example.com", "a".repeat(64));
        assert!(normalize_email(&boundary).is_ok());
        let too_long = format!("{}@example.com", "a".repeat(65));
        assert_eq!(normalize_email(&too_long), Err(InvalidEmail));
    }

    #[test]
    fn a_domain_longer_than_253_bytes_is_rejected() {
        let boundary = format!("ops@{}", "a".repeat(249) + ".com");
        assert!(normalize_email(&boundary).is_ok());
        let too_long = format!("ops@{}", "a".repeat(250) + ".com");
        assert_eq!(normalize_email(&too_long), Err(InvalidEmail));
        let way_too_long = format!("ops@{}", "a".repeat(255) + ".com");
        assert_eq!(normalize_email(&way_too_long), Err(InvalidEmail));
    }

    #[test]
    fn a_domain_must_contain_a_dot_but_not_start_or_end_with_one() {
        assert_eq!(normalize_email("ops@example"), Err(InvalidEmail));
        assert_eq!(normalize_email("ops@.example.com"), Err(InvalidEmail));
        assert_eq!(normalize_email("ops@example.com."), Err(InvalidEmail));
        assert_eq!(normalize_email("@example.com"), Err(InvalidEmail));
    }

    #[test]
    fn an_inner_space_is_rejected() {
        assert_eq!(normalize_email("a b@example.com"), Err(InvalidEmail));
    }

    #[test]
    fn uppercase_is_normalized_and_surrounding_whitespace_trimmed() {
        assert_eq!(
            normalize_email("  Ops@Example.COM  ").unwrap(),
            "ops@example.com"
        );
    }
}
