//! The canonical request model.
//!
//! **Status: provisional (Phase 2 skeleton).** The *types* are stable; the
//! normalization algorithm that fills them lands in Phase 3. Until then the
//! constructor stores values exactly as received (except header-name casing)
//! so that no consumer can rely on an accidental normalization behaviour.
//!
//! Security invariant (mandate §10): normalization is a security boundary.
//! Every subsystem — router, WAF, cache, upstream forwarding — must consume
//! *one* canonical representation, so `/open/../admin` cannot mean different
//! paths to different components. Detectors must never re-decode input on
//! their own; they read this model.
//!
//! Phase 3 will extend this module with the decode/normalize pipeline
//! (percent decoding layers, HTML entities, path collapse, query/cookie
//! parsing) and its bypass corpus. Field semantics below note what is
//! *provisional copy* versus what is final.

use std::net::IpAddr;

/// One query-string parameter.
///
/// Provisional: names and values are stored exactly as they appear in the
/// request (still percent-encoded). Phase 3 defines the decoding layers and
/// guarantees each detector sees the same decoded views.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct QueryParam {
    pub name: String,
    pub value: String,
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
    path: String,
    query: Vec<QueryParam>,
    headers: Vec<(String, String)>,
    cookies: Vec<(String, String)>,
    body: Option<Vec<u8>>,
    client: ClientIdentity,
}

impl CanonicalRequest {
    /// Start a request with the transport-level essentials.
    ///
    /// `path` is stored as given for now (see module docs); `authority` is the
    /// validated host, no scheme or port handling yet.
    pub fn new(
        method: impl Into<String>,
        authority: impl Into<String>,
        path: impl Into<String>,
    ) -> Self {
        Self {
            method: method.into(),
            authority: authority.into(),
            path: path.into(),
            query: Vec::new(),
            headers: Vec::new(),
            cookies: Vec::new(),
            body: None,
            client: ClientIdentity::default(),
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
