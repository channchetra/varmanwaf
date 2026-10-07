//! JWT analysis detector (Phase 8).
//!
//! Inspects attacker-controlled JSON Web Tokens (Authorization headers,
//! cookies, query values, bodies) and flags headers that undermine the
//! application's verification:
//!
//! | Evidence | Tier |
//! | --- | --- |
//! | `alg: none` (the signature is never verified) | Block |
//! | Non-`none` `alg` with an empty signature segment | Block |
//! | `jku` / `x5u` header (external key URL) | Monitor |
//! | `jwk` header (embedded key) | Monitor |
//! | `kid` containing a path separator or traversal | Monitor |
//! | JWT-shaped token without a signature segment | Log |
//!
//! Missing `exp`, opaque bearer tokens and JWTs whose payload is not JSON
//! stay clean — the benign corpus carries real-world samples of all three,
//! and rejecting them would flag ordinary API traffic.

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;

use super::super::{
    Action, AttackCategory, Confidence, Detector, DetectorId, DetectorResult,
    EvidenceSource, Finding, Severity,
};

use crate::canonical::CanonicalRequest;

/// Default maximum value length considered by the structural analysis.
pub const DEFAULT_MAX_VALUE_LEN: usize = 8 * 1024;

/// JWT-shaped candidates inside a value: runs starting at `eyJ` (base64url of
/// `{"`) over the base64url alphabet and `.` separators.
fn jwt_candidates(value: &str) -> Vec<&str> {
    let bytes = value.as_bytes();
    let mut out = Vec::new();
    let mut i = 0usize;
    while i + 3 <= bytes.len() {
        if &bytes[i..i + 3] != b"eyJ" {
            i += 1;
            continue;
        }
        let start = i;
        let mut end = i + 3;
        while end < bytes.len() {
            let byte = bytes[end];
            let part_of_token = byte.is_ascii_alphanumeric()
                || byte == b'-'
                || byte == b'_'
                || byte == b'.';
            if !part_of_token {
                break;
            }
            end += 1;
        }
        if end > start + 3 {
            out.push(&value[start..end]);
        }
        i = end.max(i + 1);
    }
    out
}

struct Evidence {
    rule: &'static str,
    severity: Severity,
    action: Action,
    score: u32,
    detail: String,
}

fn block(rule: &'static str, score: u32, detail: &str) -> Evidence {
    Evidence {
        rule,
        severity: Severity::High,
        action: Action::Block,
        score,
        detail: detail.to_string(),
    }
}

fn monitor(rule: &'static str, detail: &str) -> Evidence {
    Evidence {
        rule,
        severity: Severity::Medium,
        action: Action::Monitor,
        score: 20,
        detail: detail.to_string(),
    }
}

/// Analyse one JWT-shaped token; `None` keeps it clean.
fn analyze_token(token: &str) -> Option<Evidence> {
    let mut parts = token.split('.');
    let header_b64 = parts.next()?;
    let payload_b64 = parts.next()?;
    let signature = parts.next();
    if parts.next().is_some() || payload_b64.is_empty() {
        return None;
    }
    let header_bytes = URL_SAFE_NO_PAD.decode(header_b64).ok()?;
    let header: serde_json::Value =
        serde_json::from_slice(&header_bytes).ok()?;
    let object = header.as_object().filter(|object| !object.is_empty())?;

    let alg = object.get("alg").and_then(|value| value.as_str());
    if alg.is_some_and(|alg| alg.eq_ignore_ascii_case("none")) {
        return Some(block(
            "sem.jwt.alg_none",
            40,
            "JWT header declares alg=none (the signature is never verified)",
        ));
    }
    if alg.is_some() && signature.is_some_and(str::is_empty) {
        return Some(block(
            "sem.jwt.unsigned",
            40,
            "JWT carries an empty signature segment",
        ));
    }
    if object.contains_key("jku") || object.contains_key("x5u") {
        return Some(monitor(
            "sem.jwt.external_key_url",
            "JWT header references an external key URL (jku/x5u)",
        ));
    }
    if object.contains_key("jwk") {
        return Some(monitor(
            "sem.jwt.embedded_key",
            "JWT header embeds a key (jwk)",
        ));
    }
    if let Some(kid) = object.get("kid").and_then(|value| value.as_str()) {
        if kid.contains('/') || kid.contains('\\') || kid.contains("..") {
            return Some(monitor(
                "sem.jwt.kid_traversal",
                "JWT kid contains a path separator or traversal",
            ));
        }
    }
    if signature.is_none() {
        return Some(Evidence {
            rule: "sem.jwt.malformed",
            severity: Severity::Low,
            action: Action::Log,
            score: 5,
            detail: "JWT-shaped token without a signature segment".to_string(),
        });
    }
    None
}

fn analyze(value: &str) -> Option<Evidence> {
    jwt_candidates(value).into_iter().find_map(analyze_token)
}

/// JWT header analysis detector.
#[derive(Debug, Clone, Copy)]
pub struct JwtDetector {
    max_value_len: usize,
}

impl JwtDetector {
    pub const fn new() -> Self {
        Self {
            max_value_len: DEFAULT_MAX_VALUE_LEN,
        }
    }

    pub const fn with_max_value_len(max_value_len: usize) -> Self {
        Self { max_value_len }
    }
}

impl Default for JwtDetector {
    fn default() -> Self {
        Self::new()
    }
}

impl Detector for JwtDetector {
    fn id(&self) -> DetectorId {
        DetectorId("semantic.jwt.structural")
    }

    fn inspect(
        &self,
        request: &CanonicalRequest,
        ctx: &mut super::super::DetectionContext,
    ) -> DetectorResult {
        let mut findings: Vec<Finding> = Vec::new();
        let mut degraded = None;

        let scan = |value: &str,
                    source: EvidenceSource,
                    field: Option<&str>,
                    findings: &mut Vec<Finding>,
                    degraded: &mut Option<&'static str>| {
            if value.len() > self.max_value_len {
                if degraded.is_none() {
                    *degraded = Some("value exceeds semantic budget");
                }
                return;
            }
            let Some(evidence) = analyze(value) else {
                return;
            };
            let mut finding = Finding::new(
                DetectorId("semantic.jwt.structural"),
                evidence.rule,
                AttackCategory::CredentialAbuse,
            )
            .confidence(match evidence.action {
                Action::Block => Confidence::High,
                Action::Monitor => Confidence::Medium,
                _ => Confidence::Low,
            })
            .severity(evidence.severity)
            .score(evidence.score)
            .action(evidence.action)
            .source(source)
            .detail(evidence.detail);
            if let Some(field) = field {
                finding = finding.field(field.to_string());
            }
            findings.push(finding);
        };

        for (name, value) in request.headers() {
            // Cookie values are scanned through the parsed cookie list below;
            // scanning the raw `Cookie` header too would double-score the
            // same token.
            if name.eq_ignore_ascii_case("cookie") {
                continue;
            }
            scan(
                value,
                EvidenceSource::Header,
                Some(name),
                &mut findings,
                &mut degraded,
            );
        }
        for param in request.query() {
            scan(
                &param.value,
                EvidenceSource::Query,
                Some(&param.name),
                &mut findings,
                &mut degraded,
            );
        }
        for (name, value) in request.cookies() {
            scan(
                value,
                EvidenceSource::Cookie,
                Some(name),
                &mut findings,
                &mut degraded,
            );
        }
        if let Some(body) = request.body() {
            let limit = ctx.budget().max_body_bytes.min(body.len());
            match std::str::from_utf8(&body[..limit]) {
                Ok(text) => {
                    scan(
                        text,
                        EvidenceSource::Body,
                        None,
                        &mut findings,
                        &mut degraded,
                    );
                    if body.len() > limit && degraded.is_none() {
                        degraded = Some("body scan truncated at budget");
                    }
                },
                Err(_) => {
                    if degraded.is_none() {
                        degraded = Some("body is not valid utf-8");
                    }
                },
            }
        }

        DetectorResult { findings, degraded }
    }
}

#[cfg(test)]
mod tests {
    use super::JwtDetector;
    use crate::canonical::{Canonicalizer, RequestParts};
    use crate::pipeline::{Action, AttackCategory, DetectionContext, Detector};

    fn b64(json: &str) -> String {
        use base64::Engine as _;
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(json)
    }

    fn token(header: &str, signature: &str) -> String {
        format!("{}.{}.{}", b64(header), b64("{\"sub\":\"123\"}"), signature)
    }

    fn inspect(request: RequestParts) -> crate::pipeline::DetectorResult {
        let request = Canonicalizer::default().canonicalize(request);
        let detector = JwtDetector::new();
        let mut ctx = DetectionContext::new();
        detector.inspect(&request, &mut ctx)
    }

    fn query(value: &str) -> crate::pipeline::DetectorResult {
        let encoded = value.replace('%', "%25");
        inspect(RequestParts::new(
            "GET",
            "example.com",
            format!("/?token={encoded}"),
        ))
    }

    fn tier(value: &str) -> Option<(String, Action)> {
        query(value)
            .findings
            .first()
            .map(|finding| (finding.rule_id.to_string(), finding.action_hint))
    }

    #[test]
    fn alg_none_blocks() {
        let alg_none = token("{\"alg\":\"none\",\"typ\":\"JWT\"}", "");
        assert_eq!(
            tier(&alg_none),
            Some(("sem.jwt.alg_none".to_string(), Action::Block))
        );
        // Case variants of the algorithm name are the same attack.
        let mixed = token("{\"alg\":\"NoNe\"}", "");
        assert_eq!(
            tier(&mixed),
            Some(("sem.jwt.alg_none".to_string(), Action::Block))
        );
    }

    #[test]
    fn empty_signature_blocks() {
        let unsigned = token("{\"alg\":\"HS256\"}", "");
        assert_eq!(
            tier(&unsigned),
            Some(("sem.jwt.unsigned".to_string(), Action::Block))
        );
    }

    #[test]
    fn header_injection_vectors_monitor() {
        let jku = token(
            "{\"alg\":\"RS256\",\"jku\":\"https://evil.example/keys\"}",
            "c2ln",
        );
        assert_eq!(
            tier(&jku),
            Some(("sem.jwt.external_key_url".to_string(), Action::Monitor))
        );
        let x5u = token("{\"alg\":\"RS256\",\"x5u\":\"https://x/k\"}", "c2ln");
        assert_eq!(
            tier(&x5u),
            Some(("sem.jwt.external_key_url".to_string(), Action::Monitor))
        );
        let jwk =
            token("{\"alg\":\"HS256\",\"jwk\":{\"kty\":\"oct\"}}", "c2ln");
        assert_eq!(
            tier(&jwk),
            Some(("sem.jwt.embedded_key".to_string(), Action::Monitor))
        );
        let kid =
            token("{\"alg\":\"HS256\",\"kid\":\"../../etc/passwd\"}", "c2ln");
        assert_eq!(
            tier(&kid),
            Some(("sem.jwt.kid_traversal".to_string(), Action::Monitor))
        );
    }

    #[test]
    fn malformed_shape_logs_only() {
        let two_segments =
            format!("{}.{}", b64("{\"alg\":\"RS256\"}"), b64("{}"));
        assert_eq!(
            tier(&two_segments),
            Some(("sem.jwt.malformed".to_string(), Action::Log))
        );
    }

    #[test]
    fn clean_tokens_stay_clean() {
        // Real-world HS256 token with `iat` but no `exp`.
        let valid = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw";
        assert_eq!(tier(valid), None);
        // RS256 token whose payload is not JSON (opaque test fixture).
        let opaque = "eyJhbGciOiJSUzI1NiJ9.cGF5bG9hZA.c2ln";
        assert_eq!(tier(opaque), None);
        // `kid` without separators is ordinary key selection.
        let kid = token("{\"alg\":\"RS256\",\"kid\":\"key-2024\"}", "c2ln");
        assert_eq!(tier(&kid), None);
        // Opaque bearer tokens are not JWTs.
        assert_eq!(tier("opaque-session-token-12345"), None);
        // JWT-shaped prose that is not a JSON header stays clean.
        assert_eq!(tier("eyJhbGciOiJIUzI1NiJ9x"), None);
    }

    #[test]
    fn authorization_header_and_cookie_are_scanned() {
        let alg_none = token("{\"alg\":\"none\"}", "");
        let header = inspect(
            RequestParts::new("GET", "example.com", "/")
                .with_header("Authorization", format!("Bearer {alg_none}")),
        );
        assert_eq!(header.findings.len(), 1);
        assert_eq!(header.findings[0].action_hint, Action::Block);
        assert_eq!(header.findings[0].source.as_str(), "header");

        let cookie = inspect(
            RequestParts::new("GET", "example.com", "/")
                .with_header("Cookie", format!("session={alg_none}")),
        );
        assert_eq!(cookie.findings.len(), 1);
        assert_eq!(cookie.findings[0].source.as_str(), "cookie");
    }

    #[test]
    fn findings_carry_the_credential_abuse_category() {
        let alg_none = token("{\"alg\":\"none\"}", "");
        let result = query(&alg_none);
        assert_eq!(
            result.findings[0].category,
            AttackCategory::CredentialAbuse
        );
    }
}
