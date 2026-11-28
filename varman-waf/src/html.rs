//! HTML escaping shared by every crate that renders attacker-reachable text
//! into a page.

/// Escapes text for HTML text nodes and attribute values.
///
/// Report data (paths, IPs, rule names) and challenge details are
/// attacker-reachable; nothing embedded in a page may skip this.
pub fn escape_html(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    for ch in value.chars() {
        match ch {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&#39;"),
            _ => out.push(ch),
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn escapes_every_markup_character() {
        assert_eq!("&amp;&lt;&gt;&quot;&#39;", escape_html("&<>\"'"));
        assert_eq!("plain text", escape_html("plain text"));
    }
}
