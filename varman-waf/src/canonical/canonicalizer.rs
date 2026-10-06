//! Request canonicalization (Phase 3).
//!
//! Turns raw wire parts into the [`CanonicalRequest`] every subsystem
//! consumes. This is a **security boundary** (mandate §10): the router, the
//! WAF, the cache and upstream forwarding must all derive their view of the
//! request from this one function, so `/open/../admin` cannot mean different
//! paths to different components.
//!
//! # Policy
//!
//! 1. **Target split** — the fragment is dropped (it never reaches an origin);
//!    the path and the query are separated at the first `?`.
//! 2. **Percent decoding is bounded** — `max_decode_layers` passes (default
//!    [`DEFAULT_DECODE_LAYERS`]). Each pass is byte-wise and restores
//!    overlong UTF-8 so payloads behind malformed bytes stay visible. This
//!    re-uses the legacy `normalize::url::multi_decode` so both engines see
//!    identical decoding until the legacy module retires.
//! 3. **Path** — decoded first, then dot segments collapsed and empty
//!    segments removed (`/open/../admin` → `/admin`). HTML entities are
//!    *not* decoded here: an origin routes on the percent-decoded bytes, and
//!    an entity-decoded path would route differently from the bytes on the
//!    wire. Entity decoding is an *inspection* transformation applied
//!    uniformly by the pipeline, never by a detector re-inventing its own.
//! 4. **Query** — `+` means space (form-encoding convention; the legacy
//!    engine missed this and its own review calls it out), then the bounded
//!    percent decode. Names and values are stored decoded, in wire order,
//!    duplicates preserved.
//! 5. **Cookies** — parsed from every `Cookie` header, values percent-decoded
//!    and unquoted, names kept verbatim.
//! 6. **Headers and authority** — header names lowercased and trimmed, values
//!    preserved exactly (duplicates and wire order kept: smuggling checks
//!    depend on it). The authority is trimmed, lowercased, and stripped of a
//!    single trailing dot (FQDN root); ports are preserved — without the
//!    request scheme there is no “default port” to drop, and two authorities
//!    differing only by port may legitimately route differently.
//!
//! The raw path and raw query stay on the model (`raw_path` / `raw_query`)
//! for logging and forwarding decisions.

use super::{CanonicalRequest, ClientIdentity, QueryParam};

use crate::normalize::url::multi_decode;
use crate::WafLevel;

/// Decoding passes applied by default. Matches the legacy engine's normal
/// level; strict mode adds one more pass via [`Canonicalizer::for_level`].
pub const DEFAULT_DECODE_LAYERS: u8 = 2;

/// Decoding passes for the strict profile.
pub const STRICT_DECODE_LAYERS: u8 = 3;

/// Apply the shared bounded decode policy to an arbitrary string.
///
/// Exposed so fast-lane detectors inspect exactly the decoded view the
/// canonicalizer used, instead of re-implementing decoding per detector
/// (mandate §10). Byte-wise with overlong-UTF-8 restoration, same as the
/// path/query/cookie decoding.
pub fn decode_layers(input: &str, layers: u8) -> String {
    multi_decode(input, layers as usize)
}

/// Raw wire parts of one request, as received by the data plane.
#[derive(Debug, Clone)]
pub struct RequestParts {
    pub method: String,
    pub authority: String,
    /// Request target as received: path plus an optional `?query`.
    pub target: String,
    /// Headers in wire order (duplicates preserved).
    pub headers: Vec<(String, String)>,
    pub body: Option<Vec<u8>>,
    pub client: ClientIdentity,
    /// HTTP version as received (`None` means `HTTP/1.1`).
    pub http_version: Option<String>,
}

impl RequestParts {
    pub fn new(
        method: impl Into<String>,
        authority: impl Into<String>,
        target: impl Into<String>,
    ) -> Self {
        Self {
            method: method.into(),
            authority: authority.into(),
            target: target.into(),
            headers: Vec::new(),
            body: None,
            client: ClientIdentity::default(),
            http_version: None,
        }
    }

    pub fn with_header(
        mut self,
        name: impl Into<String>,
        value: impl Into<String>,
    ) -> Self {
        self.headers.push((name.into(), value.into()));
        self
    }

    pub fn with_body(mut self, body: impl Into<Vec<u8>>) -> Self {
        self.body = Some(body.into());
        self
    }

    pub fn with_client(mut self, client: ClientIdentity) -> Self {
        self.client = client;
        self
    }

    /// HTTP version as received (`"HTTP/1.1"` when omitted).
    pub fn with_http_version(mut self, version: impl Into<String>) -> Self {
        self.http_version = Some(version.into());
        self
    }
}

/// Builds [`CanonicalRequest`]s from wire parts under one decoding policy.
#[derive(Debug, Clone, Copy)]
pub struct Canonicalizer {
    max_decode_layers: u8,
}

impl Canonicalizer {
    pub const fn new(max_decode_layers: u8) -> Self {
        Self { max_decode_layers }
    }

    /// Layer budget matching a detection profile: `Normal` →
    /// [`DEFAULT_DECODE_LAYERS`], `Strict` → [`STRICT_DECODE_LAYERS`].
    pub const fn for_level(level: WafLevel) -> Self {
        match level {
            WafLevel::Normal => Self::new(DEFAULT_DECODE_LAYERS),
            WafLevel::Strict => Self::new(STRICT_DECODE_LAYERS),
        }
    }

    pub const fn max_decode_layers(self) -> u8 {
        self.max_decode_layers
    }

    pub fn canonicalize(&self, parts: RequestParts) -> CanonicalRequest {
        let RequestParts {
            method,
            authority,
            target,
            headers,
            body,
            client,
            http_version,
        } = parts;

        let (raw_path, raw_query) = split_target(&target);
        let authority = canonical_authority(&authority);
        let headers = normalize_headers(headers);
        let path = canonical_path(raw_path, self.max_decode_layers);
        let query = parse_query(raw_query, self.max_decode_layers);
        let cookies = parse_cookies(&headers, self.max_decode_layers);

        CanonicalRequest::from_canonical_parts(
            method,
            authority,
            raw_path.to_string(),
            raw_query.to_string(),
            path,
            query,
            headers,
            cookies,
            body,
            client,
            http_version.unwrap_or_else(|| "HTTP/1.1".to_string()),
        )
    }
}

impl Default for Canonicalizer {
    fn default() -> Self {
        Self::new(DEFAULT_DECODE_LAYERS)
    }
}

/// Strip the fragment and split the target at the first `?`.
///
/// A `?` that appears after a `#` belongs to the fragment and is dropped with
/// it (a client never sends that, an attacker may).
fn split_target(target: &str) -> (&str, &str) {
    let without_fragment = match target.split_once('#') {
        Some((before, _)) => before,
        None => target,
    };
    match without_fragment.split_once('?') {
        Some((path, query)) => (path, query),
        None => (without_fragment, ""),
    }
}

fn normalize_headers(headers: Vec<(String, String)>) -> Vec<(String, String)> {
    headers
        .into_iter()
        .map(|(name, value)| {
            let mut name = name.trim().to_string();
            name.make_ascii_lowercase();
            (name, value)
        })
        .collect()
}

/// Canonical authority: trimmed, lowercased, one trailing dot removed.
fn canonical_authority(raw: &str) -> String {
    let trimmed = raw.trim();
    let without_dot = trimmed.strip_suffix('.').unwrap_or(trimmed);
    without_dot.to_ascii_lowercase()
}

/// Canonical path: bounded percent decode, then dot-segment resolution.
///
/// Re-uses the legacy path normalizer on purpose: it is the exact algorithm
/// the currently-enforcing engine runs, so the two engines cannot disagree
/// during the transition. It moves into this module when the legacy engine
/// retires.
fn canonical_path(raw_path: &str, layers: u8) -> String {
    let decoded = multi_decode(raw_path, layers as usize);
    crate::normalize::path::normalize(&decoded)
}

fn parse_query(raw_query: &str, layers: u8) -> Vec<QueryParam> {
    if raw_query.is_empty() {
        return Vec::new();
    }
    let mut params = Vec::new();
    for pair in raw_query.split('&') {
        if pair.is_empty() {
            continue;
        }
        let (name, value) = match pair.split_once('=') {
            Some((name, value)) => (name, value),
            None => (pair, ""),
        };
        params.push(QueryParam {
            name: decode_query_component(name, layers),
            value: decode_query_component(value, layers),
        });
    }
    params
}

/// Query components use form encoding: `+` is a space, then bounded percent
/// decoding.
fn decode_query_component(component: &str, layers: u8) -> String {
    let plus_decoded = component.replace('+', " ");
    multi_decode(&plus_decoded, layers as usize)
}

fn parse_cookies(
    headers: &[(String, String)],
    layers: u8,
) -> Vec<(String, String)> {
    let mut cookies = Vec::new();
    for (name, value) in headers {
        if name != "cookie" {
            continue;
        }
        for pair in value.split(';') {
            let pair = pair.trim();
            if pair.is_empty() {
                continue;
            }
            let (key, raw_value) = match pair.split_once('=') {
                Some((key, value)) => (key.trim(), value.trim()),
                None => (pair, ""),
            };
            if key.is_empty() {
                continue;
            }
            let unquoted = raw_value
                .strip_prefix('"')
                .and_then(|v| v.strip_suffix('"'))
                .unwrap_or(raw_value);
            cookies.push((
                key.to_string(),
                multi_decode(unquoted, layers as usize),
            ));
        }
    }
    cookies
}

#[cfg(test)]
mod tests {
    use super::{Canonicalizer, RequestParts, DEFAULT_DECODE_LAYERS};

    fn req(target: &str) -> super::CanonicalRequest {
        Canonicalizer::default().canonicalize(RequestParts::new(
            "GET",
            "example.com",
            target,
        ))
    }

    // ── Path canonicalization (mandate §10 bypass cases) ───────────────────

    #[test]
    fn dot_segments_resolve_before_any_consumer_sees_the_path() {
        // The canonical bypass example: /open/../admin must be /admin for the
        // router, the WAF, the cache and the origin alike.
        let request = req("/open/../admin");
        assert_eq!(request.path(), "/admin");
        assert_eq!(request.raw_path(), "/open/../admin");
    }

    #[test]
    fn encoded_dot_segments_resolve() {
        assert_eq!(req("/%2e%2e/%2e%2e/etc/passwd").path(), "/etc/passwd");
        assert_eq!(req("/..%2f..%2fetc/passwd").path(), "/etc/passwd");
    }

    #[test]
    fn double_encoded_traversal_resolves_within_the_layer_budget() {
        assert_eq!(
            req("/%252e%252e/%252e%252e/etc/passwd").path(),
            "/etc/passwd"
        );
    }

    #[test]
    fn single_layer_budget_intentionally_keeps_encoded_form() {
        // With only one decode pass the traversal stays visible to detectors
        // in its encoded form; it must not silently become a clean path.
        let request = Canonicalizer::new(1).canonicalize(RequestParts::new(
            "GET",
            "example.com",
            "/%252e%252e/etc/passwd",
        ));
        assert_eq!(request.path(), "/%2e%2e/etc/passwd");
    }

    #[test]
    fn empty_and_root_targets() {
        assert_eq!(req("").path(), "/");
        assert_eq!(req("/").path(), "/");
        assert_eq!(req("//a///b//").path(), "/a/b/");
    }

    #[test]
    fn fragment_is_dropped_with_everything_after_it() {
        let request = req("/a#frag?x=1");
        assert_eq!(request.path(), "/a");
        assert!(request.query().is_empty());
    }

    #[test]
    fn invalid_escape_is_preserved_not_dropped() {
        assert_eq!(req("/a%zz/b").path(), "/a%zz/b");
    }

    // ── Query canonicalization ─────────────────────────────────────────────

    #[test]
    fn query_plus_is_a_space_and_percent_is_decoded() {
        let request = req("/?id=1+OR+1%3D1");
        assert_eq!(request.query().len(), 1);
        assert_eq!(request.query()[0].name, "id");
        assert_eq!(request.query()[0].value, "1 OR 1=1");
    }

    #[test]
    fn query_duplicates_are_preserved_in_order() {
        let request = req("/?a=1&a=2&b");
        assert_eq!(request.query().len(), 3);
        assert_eq!(request.query()[0].name, "a");
        assert_eq!(request.query()[0].value, "1");
        assert_eq!(request.query()[1].value, "2");
        assert_eq!(request.query()[2].name, "b");
        assert_eq!(request.query()[2].value, "");
    }

    #[test]
    fn double_encoded_query_values_decode_with_budget() {
        let request = req("/?q=%2541");
        assert_eq!(request.query()[0].value, "A");
    }

    #[test]
    fn raw_query_is_preserved_for_logging() {
        let request = req("/p?id=1+OR+1%3D1");
        assert_eq!(request.raw_query(), "id=1+OR+1%3D1");
    }

    // ── Headers and cookies ────────────────────────────────────────────────

    #[test]
    fn header_names_are_lowercased_and_values_untouched() {
        let request = Canonicalizer::default().canonicalize(
            RequestParts::new("GET", "example.com", "/")
                .with_header("X-Forwarded-For", "  1.2.3.4 , 5.6.7.8"),
        );
        assert_eq!(
            request.header("x-forwarded-for"),
            Some("  1.2.3.4 , 5.6.7.8")
        );
    }

    #[test]
    fn cookies_are_parsed_decoded_and_unquoted() {
        let request = Canonicalizer::default().canonicalize(
            RequestParts::new("GET", "example.com", "/")
                .with_header("Cookie", "a=1; b=%32; c=\"quoted\"; d"),
        );
        assert_eq!(request.cookie("a"), Some("1"));
        assert_eq!(request.cookie("b"), Some("2"));
        assert_eq!(request.cookie("c"), Some("quoted"));
        assert_eq!(request.cookie("d"), Some(""));
    }

    #[test]
    fn multiple_cookie_headers_are_all_parsed() {
        let request = Canonicalizer::default().canonicalize(
            RequestParts::new("GET", "example.com", "/")
                .with_header("Cookie", "a=1")
                .with_header("cookie", "b=2"),
        );
        assert_eq!(request.cookie("a"), Some("1"));
        assert_eq!(request.cookie("b"), Some("2"));
    }

    #[test]
    fn default_layer_count_is_stable() {
        assert_eq!(DEFAULT_DECODE_LAYERS, 2);
        assert_eq!(
            Canonicalizer::default().max_decode_layers(),
            DEFAULT_DECODE_LAYERS
        );
    }

    // ── Authority and profile policy ───────────────────────────────────────

    #[test]
    fn authority_is_lowercased_and_trailing_dot_stripped() {
        let auth = |raw: &str| {
            Canonicalizer::default()
                .canonicalize(RequestParts::new("GET", raw, "/"))
                .authority()
                .to_string()
        };
        assert_eq!(auth("EXAMPLE.com."), "example.com");
        assert_eq!(auth(" example.COM:8443 "), "example.com:8443");
        assert_eq!(auth("localhost"), "localhost");
    }

    #[test]
    fn strict_profile_uses_one_more_decode_layer() {
        // %25252e decodes to '.' only on the third pass:
        // %25252e → %252e → %2e → '.'
        let target = "/%25252e%25252e/etc/passwd";
        let normal = Canonicalizer::for_level(crate::WafLevel::Normal)
            .canonicalize(RequestParts::new("GET", "example.com", target));
        let strict = Canonicalizer::for_level(crate::WafLevel::Strict)
            .canonicalize(RequestParts::new("GET", "example.com", target));
        assert_eq!(normal.path(), "/%2e%2e/etc/passwd");
        assert_eq!(strict.path(), "/etc/passwd");
    }

    // ── Idempotence ────────────────────────────────────────────────────────

    /// Re-canonicalize a request from its canonical form (path + decoded
    /// query pairs re-serialized). Values that legitimately contained `&` or
    /// `=` are not exercised here; the corpus does that.
    fn recanonicalize(
        once: &super::CanonicalRequest,
    ) -> super::CanonicalRequest {
        let query = once
            .query()
            .iter()
            .map(|p| format!("{}={}", p.name, p.value))
            .collect::<Vec<_>>()
            .join("&");
        let target = if query.is_empty() {
            once.path().to_string()
        } else {
            format!("{}?{}", once.path(), query)
        };
        Canonicalizer::default().canonicalize(RequestParts::new(
            "GET",
            once.authority(),
            target,
        ))
    }

    #[test]
    fn canonical_form_is_idempotent() {
        let cases = [
            "/a/b",
            "/a%20b?x=1%202",
            "/open/../admin",
            "/?id=1+OR+1%3D1",
            "/%252e%252e/etc/passwd",
            "/?q=%2541&q=2",
        ];
        for target in cases {
            let once = Canonicalizer::default()
                .canonicalize(RequestParts::new("GET", "example.com", target));
            let twice = recanonicalize(&once);
            assert_eq!(
                twice.path(),
                once.path(),
                "path not idempotent for {target}"
            );
            assert_eq!(
                twice.query(),
                once.query(),
                "query not idempotent for {target}"
            );
        }
    }
}
