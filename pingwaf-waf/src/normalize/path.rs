//! Path normalization: collapse `//`, resolve `.` and `..`, strip trailing
//! dot segments. This is what signature matching runs against, so traversal
//! attempts like `/a/../../etc/passwd` resolve to `/etc/passwd` before the
//! Aho-Corasick automaton sees them.

/// Normalize a URL path. The fragment (`#...`) is dropped, query strings are
/// expected to be split off by the caller.
pub fn normalize(path: &str) -> String {
    if path.is_empty() {
        return "/".to_string();
    }
    // Strip fragment first — it never reaches the server but attackers use it
    // to hide payloads from naive log inspection.
    let path = match path.split_once('#') {
        Some((p, _)) => p,
        None => path,
    };

    let starts_with_slash = path.starts_with('/');
    let mut segments: Vec<&str> = Vec::with_capacity(8);
    for seg in path.split('/') {
        match seg {
            "" | "." => continue,
            ".." => {
                segments.pop();
            },
            other => segments.push(other),
        }
    }

    let mut out = String::with_capacity(path.len());
    if starts_with_slash {
        out.push('/');
    }
    for (i, seg) in segments.iter().enumerate() {
        if i > 0 {
            out.push('/');
        }
        out.push_str(seg);
    }
    if out.is_empty() {
        out.push('/');
    } else if path.ends_with('/') && !out.ends_with('/') {
        // Preserve a trailing slash from the original path.
        out.push('/');
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn collapses_dots() {
        assert_eq!(normalize("/a/./b/../c"), "/a/c");
    }

    #[test]
    fn collapses_double_slashes() {
        assert_eq!(normalize("//a///b//"), "/a/b/");
    }

    #[test]
    fn traversal_resolves_to_root() {
        assert_eq!(normalize("/a/../../etc/passwd"), "/etc/passwd");
    }

    #[test]
    fn empty_becomes_root() {
        assert_eq!(normalize(""), "/");
    }

    #[test]
    fn fragment_stripped() {
        assert_eq!(normalize("/a/b#frag"), "/a/b");
    }

    #[test]
    fn relative_preserved() {
        assert_eq!(normalize("a/b/../c"), "a/c");
    }

    #[test]
    fn root_unchanged() {
        assert_eq!(normalize("/"), "/");
    }
}
