//! The canonical request model.
//!
//! **Status: canonicalization landed (Phase 3).** Wire input goes through
//! [`Canonicalizer::canonicalize`], which produces the decoded path, query
//! pairs, cookies and normalized headers defined in
//! [`canonicalizer`]'s policy. Hand-built [`CanonicalRequest`]s (tests,
//! non-wire callers) use [`CanonicalRequest::new`] and the `with_*` builders.
//!
//! Security invariant (mandate §10): normalization is a security boundary.
//! Every subsystem — router, WAF, cache, upstream forwarding — must consume
//! *one* canonical representation, so `/open/../admin` cannot mean different
//! paths to different components. Detectors must never re-decode input on
//! their own; they read this model, and additional inspection decoding
//! (HTML entities, deeper layers) is applied uniformly by the pipeline from
//! the canonical form.

use std::net::IpAddr;

pub mod canonicalizer;

pub use canonicalizer::{
    decode_layers, Canonicalizer, RequestParts, DEFAULT_DECODE_LAYERS,
    STRICT_DECODE_LAYERS,
};

/// One query-string parameter.
///
/// Produced by [`Canonicalizer`]: names and values are decoded (bounded
/// percent decoding, `+` as space) in wire order with duplicates preserved.
/// Hand-built requests via [`CanonicalRequest::with_query_param`] store the
/// values exactly as given.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct QueryParam {
    pub name: String,
    pub value: String,
    /// `true` when the decoded wire bytes were not valid UTF-8.
    pub invalid_utf8: bool,
}

/// Verified client identity.
///
/// Values here are produced by the data plane *after* trusted-proxy
/// validation; a client-supplied `X-Varman-JA4` or `X-Forwarded-For` never
/// lands here directly (mandate §28).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ClientIdentity {
    /// Socket peer address after trusted-proxy resolution.
    pub ip: Option<IpAddr>,
    /// JA4 TLS fingerprint, computed locally by the listener (Phase 8+).
    pub ja4: Option<String>,
}

/// The single representation every Varman subsystem consumes.
#[derive(Debug, Clone)]
pub struct CanonicalRequest {
    method: String,
    authority: String,
    raw_path: String,
    raw_query: String,
    path: String,
    query: Vec<QueryParam>,
    headers: Vec<(String, String)>,
    cookies: Vec<(String, String)>,
    body: Option<Vec<u8>>,
    client: ClientIdentity,
    /// HTTP version as reported by the data plane (`"HTTP/1.1"` when the
    /// caller did not provide one).
    http_version: String,
    /// `true` when the percent-decoded path bytes were not valid UTF-8.
    path_invalid_utf8: bool,
}

impl CanonicalRequest {
    /// Start a request with the transport-level essentials.
    ///
    /// Hand-built requests (tests, non-wire callers) use `path` for both the
    /// raw and the canonical path and start with an empty query. Wire input
    /// goes through [`Canonicalizer::canonicalize`].
    pub fn new(
        method: impl Into<String>,
        authority: impl Into<String>,
        path: impl Into<String>,
    ) -> Self {
        let path = path.into();
        Self {
            method: method.into(),
            authority: authority.into(),
            raw_path: path.clone(),
            raw_query: String::new(),
            path,
            query: Vec::new(),
            headers: Vec::new(),
            cookies: Vec::new(),
            body: None,
            client: ClientIdentity::default(),
            http_version: "HTTP/1.1".to_string(),
            path_invalid_utf8: false,
        }
    }

    /// Assemble a fully canonicalized request. Only the canonicalizer should
    /// call this: it is the one place allowed to set divergent raw/canonical
    /// forms.
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn from_canonical_parts(
        method: String,
        authority: String,
        raw_path: String,
        raw_query: String,
        path: String,
        query: Vec<QueryParam>,
        headers: Vec<(String, String)>,
        cookies: Vec<(String, String)>,
        body: Option<Vec<u8>>,
        client: ClientIdentity,
        http_version: String,
        path_invalid_utf8: bool,
    ) -> Self {
        Self {
            method,
            authority,
            raw_path,
            raw_query,
            path,
            query,
            headers,
            cookies,
            body,
            client,
            http_version,
            path_invalid_utf8,
        }
    }

    pub fn method(&self) -> &str {
        &self.method
    }

    pub fn authority(&self) -> &str {
        &self.authority
    }

    pub fn path(&self) -> &str {
        &self.path
    }

    /// Path exactly as received (before decoding and dot-segment
    /// resolution); kept for logging and forwarding decisions.
    pub fn raw_path(&self) -> &str {
        &self.raw_path
    }

    /// Query exactly as received.
    pub fn raw_query(&self) -> &str {
        &self.raw_query
    }

    pub fn query(&self) -> &[QueryParam] {
        &self.query
    }

    /// Headers in wire order; duplicate names are preserved (smuggling
    /// detection depends on seeing every occurrence).
    pub fn headers(&self) -> &[(String, String)] {
        &self.headers
    }

    pub fn cookies(&self) -> &[(String, String)] {
        &self.cookies
    }

    pub fn body(&self) -> Option<&[u8]> {
        self.body.as_deref()
    }

    pub fn client(&self) -> &ClientIdentity {
        &self.client
    }

    /// HTTP version as reported by the data plane (`"HTTP/1.1"` when the
    /// caller did not provide one).
    pub fn http_version(&self) -> &str {
        &self.http_version
    }

    /// `true` when the percent-decoded path bytes were not valid UTF-8.
    pub fn path_invalid_utf8(&self) -> bool {
        self.path_invalid_utf8
    }

    /// First header value for `name` (case-insensitive; names are stored
    /// lowercased).
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(key, _)| key.eq_ignore_ascii_case(name))
            .map(|(_, value)| value.as_str())
    }

    /// Every value for `name`, in wire order.
    pub fn headers_all<'a>(
        &'a self,
        name: &'a str,
    ) -> impl Iterator<Item = &'a str> + 'a {
        self.headers
            .iter()
            .filter(move |(key, _)| key.eq_ignore_ascii_case(name))
            .map(|(_, value)| value.as_str())
    }

    /// First cookie value for `name`.
    pub fn cookie(&self, name: &str) -> Option<&str> {
        self.cookies
            .iter()
            .find(|(key, _)| key == name)
            .map(|(_, value)| value.as_str())
    }

    /// Append a header; the name is stored lowercased.
    pub fn with_header(
        mut self,
        name: impl Into<String>,
        value: impl Into<String>,
    ) -> Self {
        let mut name = name.into();
        name.make_ascii_lowercase();
        self.headers.push((name, value.into()));
        self
    }

    pub fn with_cookie(
        mut self,
        name: impl Into<String>,
        value: impl Into<String>,
    ) -> Self {
        self.cookies.push((name.into(), value.into()));
        self
    }

    pub fn with_query_param(
        mut self,
        name: impl Into<String>,
        value: impl Into<String>,
    ) -> Self {
        self.query.push(QueryParam {
            name: name.into(),
            value: value.into(),
            invalid_utf8: false,
        });
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
}

#[cfg(test)]
mod tests {
    use super::{CanonicalRequest, ClientIdentity};
    use std::net::IpAddr;

    #[test]
    fn headers_lowercase_names_and_keep_duplicates_in_order() {
        let req = CanonicalRequest::new("GET", "example.com", "/")
            .with_header("X-Forwarded-For", "1.2.3.4")
            .with_header("x-forwarded-for", "5.6.7.8");
        assert_eq!(req.header("X-Forwarded-For"), Some("1.2.3.4"));
        let all: Vec<&str> = req.headers_all("x-forwarded-for").collect();
        assert_eq!(all, vec!["1.2.3.4", "5.6.7.8"]);
    }

    #[test]
    fn client_identity_carries_verified_values() {
        let ip: IpAddr = "203.0.113.9".parse().expect("valid test ip");
        let req = CanonicalRequest::new("POST", "api.example.com", "/v1/items")
            .with_client(ClientIdentity {
                ip: Some(ip),
                ja4: Some("t13d1516h2_8daaf6152771_b186095e22b6".to_string()),
            });
        assert_eq!(req.client().ip, Some(ip));
        assert!(req.client().ja4.is_some());
    }

    #[test]
    fn query_params_preserve_wire_values_in_order() {
        let req = CanonicalRequest::new("GET", "example.com", "/search")
            .with_query_param("q", "hello%20world")
            .with_query_param("q", "second");
        assert_eq!(req.query().len(), 2);
        assert_eq!(req.query()[0].value, "hello%20world");
    }
}
