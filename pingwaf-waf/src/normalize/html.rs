//! HTML entity decoding.
//!
//! We deliberately do NOT pull in a heavyweight HTML5 entity table — the WAF
//! only needs to see through the entities an attacker would actually use to
//! obfuscate `<`, `>`, `&`, quotes, and a handful of named entities. Anything
//! rarer is left alone, which keeps the decode pass allocation-free for the
//! common case.

use ahash::AHashMap;
use once_cell::sync::Lazy;

/// Named entities we recognize. Keys are stored without the leading `&` and
/// without the trailing `;` so a single hash lookup covers both `&lt` and
/// `&lt;` forms.
static NAMED_ENTITIES: Lazy<AHashMap<&'static str, char>> = Lazy::new(|| {
    let pairs: &[(&str, char)] = &[
        ("lt", '<'),
        ("gt", '>'),
        ("amp", '&'),
        ("quot", '"'),
        ("apos", '\''),
        ("nbsp", '\u{00a0}'),
        ("copy", '\u{00a9}'),
        ("reg", '\u{00ae}'),
        ("trade", '\u{2122}'),
        ("hellip", '\u{2026}'),
        ("mdash", '\u{2014}'),
        ("ndash", '\u{2013}'),
        ("laquo", '\u{00ab}'),
        ("raquo", '\u{00bb}'),
        ("lsquo", '\u{2018}'),
        ("rsquo", '\u{2019}'),
        ("ldquo", '\u{201c}'),
        ("rdquo", '\u{201d}'),
        ("cent", '\u{00a2}'),
        ("pound", '\u{00a3}'),
        ("yen", '\u{00a5}'),
        ("euro", '\u{20ac}'),
        ("sect", '\u{00a7}'),
        ("para", '\u{00b6}'),
        ("deg", '\u{00b0}'),
        ("plusmn", '\u{00b1}'),
        ("times", '\u{00d7}'),
        ("divide", '\u{00f7}'),
        ("frac12", '\u{00bd}'),
        ("frac14", '\u{00bc}'),
        ("frac34", '\u{00be}'),
        ("sup2", '\u{00b2}'),
        ("sup3", '\u{00b3}'),
        ("micro", '\u{00b5}'),
        ("middot", '\u{00b7}'),
        ("bull", '\u{2022}'),
        ("dagger", '\u{2020}'),
        ("permil", '\u{2030}'),
        ("prime", '\u{2032}'),
        ("Prime", '\u{2033}'),
        ("lsaquo", '\u{2039}'),
        ("rsaquo", '\u{203a}'),
        ("frasl", '\u{2044}'),
        // Punctuation/symbol entities attackers use to split keywords inside
        // a payload (`javascript&colon;alert(1)`, `&sol;&lpar;…`) while the
        // browser still executes the resolved value.
        ("colon", ':'),
        ("semi", ';'),
        ("comma", ','),
        ("period", '.'),
        ("sol", '/'),
        ("bsol", '\\'),
        ("lpar", '('),
        ("rpar", ')'),
        ("lbrack", '['),
        ("rbrack", ']'),
        ("lbrace", '{'),
        ("rbrace", '}'),
        ("num", '#'),
        ("percnt", '%'),
        ("plus", '+'),
        ("minus", '-'),
        ("ast", '*'),
        ("equals", '='),
        ("quest", '?'),
        ("excl", '!'),
        ("grave", '`'),
        ("dollar", '$'),
        ("Tab", '\t'),
        ("NewLine", '\n'),
    ];
    pairs.iter().copied().collect()
});

/// Decode HTML named and numeric entities in `input`. Returns the input
/// untouched when it contains no `&`. Slicing happens only at ASCII `&`
/// boundaries so multi-byte UTF-8 sequences pass through verbatim.
pub fn decode_entities(input: &str) -> String {
    if !input.contains('&') {
        return input.to_string();
    }
    let mut out = String::with_capacity(input.len());
    let mut remaining = input;
    while let Some(amp_pos) = remaining.find('&') {
        out.push_str(&remaining[..amp_pos]);
        let after = &remaining[amp_pos + 1..];
        match try_decode_entity(after) {
            Some((c, consumed)) => {
                out.push(c);
                remaining = &after[consumed..];
            },
            None => {
                out.push('&');
                remaining = after;
            },
        }
    }
    out.push_str(remaining);
    out
}

/// Try to parse an entity body starting at `after` (the text following `&`).
/// Returns the decoded character plus how many bytes of `after` it consumed.
fn try_decode_entity(after: &str) -> Option<(char, usize)> {
    let bytes = after.as_bytes();
    // Semicolon form, up to 10 chars (e.g. `&#x10FFFF;`).
    let scan_end = bytes.len().min(10);
    for j in 0..scan_end {
        if bytes[j] == b';' {
            if let Some(c) = decode_entity_body(&after[..j]) {
                return Some((c, j + 1));
            }
            return None;
        }
        if !(bytes[j].is_ascii_alphanumeric() || bytes[j] == b'#') {
            break;
        }
    }
    // No-semicolon form (HTML5 allows `&lt` in text). Take the longest match.
    let scan_end = bytes.len().min(8);
    let mut best: Option<(char, usize)> = None;
    for j in 0..scan_end {
        let b = bytes[j];
        if !(b.is_ascii_alphanumeric() || b == b'#') {
            break;
        }
        if let Some(c) = decode_entity_body(&after[..=j]) {
            best = Some((c, j + 1));
        }
    }
    best
}

fn decode_entity_body(body: &str) -> Option<char> {
    if body.is_empty() {
        return None;
    }
    if let Some(rest) = body.strip_prefix('#') {
        let (radix, digits) = if let Some(hex) = rest.strip_prefix(['x', 'X']) {
            (16, hex)
        } else {
            (10, rest)
        };
        if digits.is_empty() {
            return None;
        }
        let n = u32::from_str_radix(digits, radix).ok()?;
        return char::from_u32(n);
    }
    NAMED_ENTITIES.get(body).copied()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decodes_named_entities() {
        assert_eq!(decode_entities("&lt;script&gt;"), "<script>");
        assert_eq!(decode_entities("&amp;&quot;"), "&\"");
    }

    #[test]
    fn decodes_decimal_and_hex() {
        assert_eq!(decode_entities("&#60;&#62;"), "<>");
        assert_eq!(decode_entities("&#x3C;&#X3e;"), "<>");
    }

    #[test]
    fn decodes_apos() {
        assert_eq!(decode_entities("&apos;OR&apos;"), "'OR'");
    }

    #[test]
    fn passthrough_when_no_amp() {
        assert_eq!(decode_entities("plain text"), "plain text");
    }

    #[test]
    fn unknown_entity_preserved() {
        assert_eq!(decode_entities("&unknownentity;"), "&unknownentity;");
    }

    #[test]
    fn handles_no_semicolon_form() {
        // HTML5 allows &lt without trailing semicolon in text.
        assert_eq!(decode_entities("&ltdiv&gt"), "<div>");
    }

    #[test]
    fn decodes_symbolic_entities() {
        // Symbolic entities are the obfuscation cut-points attackers splice
        // keywords with (`java&colon;alert` etc.), so the table must see
        // through them just like the alphanumeric ones.
        assert_eq!(decode_entities("java&colon;alert"), "java:alert");
        assert_eq!(decode_entities("&sol;&sol;evil"), "//evil");
        assert_eq!(decode_entities("&lpar;&rpar;"), "()");
        assert_eq!(decode_entities("&bsol;&bsol;"), "\\\\");
        assert_eq!(decode_entities("&Tab;"), "\t");
        assert_eq!(decode_entities("&NewLine;"), "\n");
        assert_eq!(decode_entities("&excl;&quest;"), "!?");
    }
}
