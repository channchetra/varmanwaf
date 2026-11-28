//! Small text helpers shared by plugins.

/// ASCII case-insensitive substring match.
pub fn contains_ignore_case(haystack: &str, needle: &str) -> bool {
    let haystack = haystack.as_bytes();
    let needle = needle.as_bytes();
    !needle.is_empty()
        && haystack.len() >= needle.len()
        && haystack.windows(needle.len()).any(|window| {
            window
                .iter()
                .zip(needle)
                .all(|(a, b)| a.eq_ignore_ascii_case(b))
        })
}

#[cfg(test)]
mod tests {
    use super::contains_ignore_case;

    #[test]
    fn matches_substrings_and_ignores_ascii_case() {
        assert!(contains_ignore_case("curl/8.4.0", "CURL/"));
        assert!(contains_ignore_case("Curl/8.4.0", "curl/"));
        assert!(!contains_ignore_case("curl/8.4.0", "wget/"));
        assert!(!contains_ignore_case("ab", "abc"));
        assert!(!contains_ignore_case("anything", ""));
    }
}
