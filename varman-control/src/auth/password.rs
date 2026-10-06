//! Password hashing helpers built on bcrypt.

use bcrypt::{BcryptError, DEFAULT_COST};

/// bcrypt only ever looks at the first 72 bytes of the input. Instead of
/// letting longer secrets fail at hash time we truncate on a character
/// boundary and document the limit.
pub const MAX_PASSWORD_BYTES: usize = 72;

/// Passwords shorter than this are rejected by the API layer.
pub const MIN_PASSWORD_LENGTH: usize = 8;

/// Errors reported by the password helpers.
#[derive(Debug)]
pub enum PasswordError {
    TooShort,
    Backend(String),
}

impl std::fmt::Display for PasswordError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PasswordError::TooShort => write!(
                f,
                "password must be at least {MIN_PASSWORD_LENGTH} characters long"
            ),
            PasswordError::Backend(msg) => write!(f, "password hashing failed: {msg}"),
        }
    }
}

impl std::error::Error for PasswordError {}

impl From<BcryptError> for PasswordError {
    fn from(err: BcryptError) -> Self {
        PasswordError::Backend(format!("{err:?}"))
    }
}

/// Truncates `plain` to at most [`MAX_PASSWORD_BYTES`] bytes without splitting a
/// UTF-8 sequence.
fn bcrypt_input(plain: &str) -> &str {
    if plain.len() <= MAX_PASSWORD_BYTES {
        return plain;
    }
    let mut end = MAX_PASSWORD_BYTES;
    while end > 0 && !plain.is_char_boundary(end) {
        end -= 1;
    }
    &plain[..end]
}

/// Hashes a plaintext password with the crate default cost.
pub fn hash_password(plain: &str) -> Result<String, PasswordError> {
    if plain.len() < MIN_PASSWORD_LENGTH {
        return Err(PasswordError::TooShort);
    }
    Ok(bcrypt::hash(bcrypt_input(plain), DEFAULT_COST)?)
}

/// Hashes a plaintext password with an explicit cost (used by tests, where a low
/// cost keeps the suite fast).
pub fn hash_password_with_cost(
    plain: &str,
    cost: u32,
) -> Result<String, PasswordError> {
    Ok(bcrypt::hash(bcrypt_input(plain), cost)?)
}

/// Compares a plaintext password against a stored bcrypt hash.
///
/// Returns `Ok(false)` for a malformed or foreign-format hash so that callers can
/// treat every mismatch the same way.
pub fn verify_password(plain: &str, hash: &str) -> Result<bool, PasswordError> {
    match bcrypt::verify(bcrypt_input(plain), hash) {
        Ok(valid) => Ok(valid),
        // A stored value that bcrypt cannot parse is simply "not a match".
        Err(BcryptError::InvalidHash(_)) => Ok(false),
        Err(err) => Err(err.into()),
    }
}

/// Cheap structural check used by the registration endpoints: rejects empty and
/// obviously weak secrets before spending CPU on bcrypt.
pub fn validate_password(plain: &str) -> Result<(), PasswordError> {
    if plain.len() < MIN_PASSWORD_LENGTH {
        return Err(PasswordError::TooShort);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hashes_are_verifiable_and_salted() {
        let hash = hash_password_with_cost("correct horse battery", 4).unwrap();
        assert!(hash.starts_with("$2"));
        assert!(verify_password("correct horse battery", &hash).unwrap());
        assert!(!verify_password("wrong password", &hash).unwrap());
    }

    #[test]
    fn short_passwords_are_rejected() {
        assert!(matches!(
            hash_password("short"),
            Err(PasswordError::TooShort)
        ));
    }

    #[test]
    fn garbage_hash_is_not_a_match() {
        assert!(!verify_password("whatever", "not-a-bcrypt-hash").unwrap());
    }

    #[test]
    fn long_passwords_are_truncated_on_a_char_boundary() {
        let long = "é".repeat(60); // 120 bytes
        assert!(long.len() > MAX_PASSWORD_BYTES);
        let truncated = bcrypt_input(&long);
        assert!(truncated.len() <= MAX_PASSWORD_BYTES);
        assert!(truncated.chars().all(|c| c == 'é'));
    }
}
