//! Stage implementations for [`WafEngine::inspect`].
//!
//! The parent module keeps the pipeline order and the verdict assembly; each
//! detector stage lives here so a single check stays readable on its own.
//! Ordering, thresholds and messages are part of the engine's contract and are
//! unchanged by this split.

use std::net::IpAddr;
use std::str::FromStr;

use crate::normalize::{DecodedValue, NormalizedRequest, ValueSource};
use crate::rules::expression::{evaluate, EvalContext};
use crate::rules::signatures::{
    ci_backtick_interleaved, ci_chr_chain, crlf_header_injection_shaped,
    detect_deser_shape, detect_expr_injection, detect_js_call, detect_sqli,
    detect_xss, path_tautology_segment, pt_double_exec_extension,
    pt_remote_backslash_include, sqli_into_file_statement_shaped,
    sqli_union_statement_shaped, ssrf_protocol_smuggling, xss_markup_shaped,
    xss_script_tag_shaped, xss_script_uri_html_shaped, LegacyAttackCategory,
    SignatureHit,
};
use crate::rules::{CompiledRule, RuleAction};
use crate::score::{ScoreBreakdown, ScoreClass};
use crate::{StackSet, WafAction, WafVerdict};

use super::{
    FilteredCtx, HitRec, InspectionState, RequestData, RuleRec, ScanScratch,
    WafEngine, FIELD_STRONG_MAX_LEN,
};

/// Immutable per-value inputs shared by the Stage-1 detectors: the decoded
/// value itself, its needle text and the demotion flags the families consult.
struct ValueCtx<'a> {
    value: &'a DecodedValue,
    /// Decoded text every detector scans.
    needle: &'a str,
    /// Referer / User-Agent display metadata without markup structure.
    is_meta_header: bool,
    /// Strict level only: an injection-family companion hit on the same
    /// value, which restores the CRLF critical call.
    injection_company: bool,
}

impl<'a> ValueCtx<'a> {
    fn new(
        value: &'a DecodedValue,
        strict: bool,
        hits: &[SignatureHit],
    ) -> Self {
        let needle = value.decoded.as_str();
        // Reflected display metadata (Referer / User-Agent) is not an
        // execution surface the way query/body/cookie values are: real SQLi
        // lands in fields the backend feeds to an interpreter, while a
        // Referer quoting "union select" is overwhelmingly search-result
        // noise. Demote those two headers to weak signals for the reflected
        // families — structural backend-parsing families (Log4Shell, XXE,
        // deserialization) keep full severity because a JVM parses *every*
        // header it receives.
        let is_meta_header = value.source == ValueSource::Header
            && (value.name.eq_ignore_ascii_case("referer")
                || value.name.eq_ignore_ascii_case("user-agent"))
            && !xss_markup_shaped(needle);
        // A CRLF hit is only response-splitting material on its own surface
        // shape; on strict it also escalates when the same value carries an
        // injection-family companion — that combination is real CRLF-
        // injection traffic (command / traversal / SSRF payload smuggled past
        // the line break), while multi-line log or telemetry text has none.
        let injection_company = strict
            && hits.iter().any(|h| {
                matches!(
                    h.category,
                    LegacyAttackCategory::CommandInjection
                        | LegacyAttackCategory::PathTraversal
                        | LegacyAttackCategory::Deserialization
                        | LegacyAttackCategory::Ssrf
                )
            });
        Self {
            value,
            needle,
            is_meta_header,
            injection_company,
        }
    }

    /// Blob weighting: a body value that is not a discrete field, or is past
    /// the strong-signal cap at Normal level, is collected content rather
    /// than a typed input.
    fn blob_weak(&self, strict: bool) -> bool {
        self.value.source == ValueSource::Body
            && (!self.value.field
                || (self.value.decoded.len() > FIELD_STRONG_MAX_LEN && !strict))
    }
}

impl WafEngine {
    /// Stage 1 over every decoded value, in normalization order: Aho-Corasick
    /// signatures, the path-only shape detectors, libinjection SQLi / XSS and
    /// the structural shape detectors. Hits feed the scorer inline; the
    /// human-readable strings are deferred to [`HitRec`].
    pub(super) fn run_stage1_signatures<'n>(
        &self,
        normalized: &'n NormalizedRequest<'_>,
        scratch: &mut ScanScratch,
        state: &mut InspectionState<'n>,
    ) {
        for value in &normalized.decoded_values {
            if value.decoded.is_empty() {
                continue;
            }
            self.signatures.scan_into(
                &value.decoded,
                &mut scratch.hits,
                &mut scratch.seen,
            );
            let vctx =
                ValueCtx::new(value, self.level.is_strict(), &scratch.hits);
            self.score_signature_hits(&vctx, &scratch.hits, state);
            self.score_path_shapes(&vctx, state);
            // Path/method/header-name are not attacker-typed strings the same
            // way query / body / cookie values are.
            if !matches!(
                value.source,
                ValueSource::QueryParam
                    | ValueSource::Cookie
                    | ValueSource::Body
                    | ValueSource::Header
            ) {
                continue;
            }
            self.score_sqli(&vctx, state);
            self.score_xss(&vctx, state);
            self.score_deser_shape(&vctx, state);
            self.score_exploit_shapes(&vctx, state);
            self.score_expression_injection(&vctx, state);
        }
    }

    /// Splits the Aho-Corasick hits of one decoded value into the aggregate
    /// score, the blocking flag and the deferred hit records.
    fn score_signature_hits<'n>(
        &self,
        vctx: &ValueCtx<'n>,
        hits: &[SignatureHit],
        state: &mut InspectionState<'n>,
    ) {
        let strict = self.level.is_strict();
        for hit in hits {
            let mut severity = hit.severity;
            let mut critical = severity >= 5;
            // Per-site monitor downgrade: hits in monitored categories /
            // stacks keep scoring into the aggregate but never into the
            // blocking subset, and never trip the critical fast path.
            let monitored = self.hit_monitored(
                hit.category,
                self.signatures.pattern(hit.pattern).stack,
            );
            let reflected_family = matches!(
                hit.category,
                LegacyAttackCategory::SqlInjection
                    | LegacyAttackCategory::Xss
                    | LegacyAttackCategory::CommandInjection
            );
            let pid = self.signatures.pattern_id(hit.pattern);
            // A script-URI inside a body value without tag structure is
            // collected markup — beacons re-serialize DOM attributes
            // ("javascript: void(0)") verbatim as JSON, and the JSON unpacking
            // surfaces them as plain `href` members. It is skipped entirely
            // (zero score, like the SQL search-phrase rule): mirrors across
            // blob and unpacked members must not pile weak features onto the
            // XSS family gate. On URL-facing surfaces (query / cookie /
            // headers) a bare script URI stays critical: `?url=javascript:…`
            // is a real reflected-XSS shape. Same gate on every level. An
            // unclosed `<script` (search prose quoting the word) is likewise
            // zero value on every surface.
            let collected_js_uri = (pid == "XSS-007"
                && vctx.value.source == ValueSource::Body
                && !xss_script_uri_html_shaped(vctx.needle))
                || (pid == "XSS-001"
                    && !xss_script_tag_shaped(
                        vctx.needle,
                        vctx.value.source != ValueSource::Body,
                    ));
            // Weak signals still feed the family sub-scores (three distinct
            // weak features crossing a gate is the blocking path for payloads
            // reflected into Referer/UA), but at demoted severity so a single
            // value cannot one-shot.
            let weak = (vctx.is_meta_header && reflected_family)
                || (vctx.blob_weak(strict) && reflected_family);
            // A bare "union select" without statement structure is a search
            // phrase: the needle and its libinjection twin describe the same
            // string, so neither scores — zero value, mirrored across
            // query/Referer/body or not. Level-independent: `?bq=union
            // select …` search phrases exist on every tier and are not
            // injections on any of them.
            let search_phrase = (matches!(pid, "SQL-001" | "SQL-002")
                && !sqli_union_statement_shaped(vctx.needle))
                || (matches!(pid, "SQL-008" | "SQL-009")
                    && !sqli_into_file_statement_shaped(vctx.needle))
                || collected_js_uri;
            if weak {
                severity = severity.min(2);
                critical = false;
            } else if hit.category == LegacyAttackCategory::CrlfInjection
                && ((vctx.value.source != ValueSource::Body
                    && crlf_header_injection_shaped(vctx.needle))
                    || vctx.injection_company)
            {
                // `…\r\nX-Foo:` is response-splitting material on any
                // surface except a body blob; bare multi-line text (a
                // multi-line form input echoed into a query, prose) is
                // not — CRLF-003/004 carry their own header shape at
                // sev5 and stay critical via `severity >= 5` above.
                // On strict, a same-value injection-family companion
                // (command / traversal / SSRF / deser payload smuggled
                // past the line break) restores the critical call that
                // the blanket-body demotion gave up.
                critical = true;
            } else if strict
                && vctx.value.source != ValueSource::Path
                && matches!(
                    hit.category,
                    LegacyAttackCategory::CommandInjection
                        | LegacyAttackCategory::Deserialization
                )
            {
                // High-confidence injection families block outright at the
                // Strict level instead of waiting for the scorer — but only
                // off the path surface. Bare multi-line text in a body
                // (`…\r\n` in log payloads) is far too common for a blanket
                // CRLF escalation, and path matrix parameters (`/foo;cat=…`)
                // are storage URL grammar, not a shell; the path-source hits
                // also stay out of the RCE sub-score below.
                critical = true;
            }
            if critical && !search_phrase && !monitored {
                state.critical_hit = true;
            }
            if search_phrase {
                continue;
            }
            if vctx.value.source == ValueSource::Path
                && matches!(
                    hit.category,
                    LegacyAttackCategory::CommandInjection
                        | LegacyAttackCategory::Deserialization
                )
            {
                // A command shape inside the path itself never reaches a
                // shell (`;cat` is matrix-parameter grammar on storage URLs).
                // The hit keeps its aggregate score but stays out of the RCE
                // sub-score, or VARMAN-1061 blocks benign storage-style
                // paths at Strict.
                self.scorer.add_severity_hit_ex(
                    &mut state.breakdown,
                    severity,
                    monitored,
                );
            } else {
                self.scorer.add_category_hit_ex(
                    &mut state.breakdown,
                    hit.category,
                    severity,
                    monitored,
                );
            }
            state.recs.push(HitRec::Sig {
                pattern: hit.pattern,
                severity,
                source: vctx.value.source.as_str(),
                name: &vctx.value.name,
                monitored,
            });
        }
    }

    /// Path-only shape detectors: a tautology segment, a raw backtick pair
    /// and a double executable extension.
    fn score_path_shapes<'n>(
        &self,
        vctx: &ValueCtx<'n>,
        state: &mut InspectionState<'n>,
    ) {
        if vctx.value.source != ValueSource::Path {
            return;
        }
        if path_tautology_segment(vctx.needle) {
            self.record_critical_shape(
                state,
                LegacyAttackCategory::SqlInjection,
                "libinjection-sqli",
                "path-segment-tautology",
                vctx.value,
            );
        }
        // Raw backticks inside the path (`/ax--exec=`id`--remote`): URL
        // content never carries them unescaped, so a pair of them frames a
        // command substitution written by an attack tool.
        if vctx.needle.matches('`').count() >= 2 {
            self.record_critical_shape(
                state,
                LegacyAttackCategory::CommandInjection,
                "ci-shape",
                "path-backticks",
                vctx.value,
            );
        }
        // Double executable extension at the path tail
        // (`/uploadfiles/apache.php.jpeg`): multi-extension parser abuse
        // prepping a webshell — the image suffix is camouflage.
        if pt_double_exec_extension(&vctx.value.decoded) {
            self.record_critical_shape(
                state,
                LegacyAttackCategory::PathTraversal,
                "pt-shape",
                "double-exec-extension",
                vctx.value,
            );
        }
    }

    /// libinjection-style SQLi detector over one attacker-typed value.
    fn score_sqli<'n>(
        &self,
        vctx: &ValueCtx<'n>,
        state: &mut InspectionState<'n>,
    ) {
        let (is_sqli, sqli_fp) = detect_sqli(vctx.needle);
        if !is_sqli {
            return;
        }
        let weak =
            vctx.is_meta_header || vctx.blob_weak(self.level.is_strict());
        // Same zero-score rule as the needle gate: a union-select or
        // into-file fingerprint without statement structure is a search
        // phrase, and the needle hit for it is skipped as well. Tautology /
        // quote-keyword fingerprints over long values are prose that quotes
        // the tokens ("1 and 1=1 is a basic operation", keyword-list
        // documents) — real tautology probes are tiny, and long quote-keyword
        // attacks carry a UNION clause that has its own gate.
        let search_phrase = (sqli_fp.contains("union-select")
            && !sqli_union_statement_shaped(vctx.needle))
            || (sqli_fp.contains("into-file")
                && !sqli_into_file_statement_shaped(vctx.needle))
            || (sqli_fp.contains("tautology")
                && vctx.needle.len() > 32
                && !sqli_fp.contains("comment-terminator"))
            || (sqli_fp.contains("quote-keyword") && vctx.needle.len() > 256);
        let (severity, critical) = if weak { (2, false) } else { (5, true) };
        let monitored = self.hit_monitored(
            LegacyAttackCategory::SqlInjection,
            StackSet::GENERIC,
        );
        if critical && !search_phrase && !monitored {
            state.critical_hit = true;
        }
        if search_phrase {
            return;
        }
        self.scorer.add_category_hit_ex(
            &mut state.breakdown,
            LegacyAttackCategory::SqlInjection,
            severity,
            monitored,
        );
        state.recs.push(HitRec::Lib {
            kind: "libinjection-sqli",
            fingerprint: sqli_fp,
            source: vctx.value.source.as_str(),
            name: &vctx.value.name,
            monitored,
        });
    }

    /// libinjection-style XSS detector over one attacker-typed value.
    fn score_xss<'n>(
        &self,
        vctx: &ValueCtx<'n>,
        state: &mut InspectionState<'n>,
    ) {
        let (is_xss, xss_fp) = detect_xss(vctx.needle);
        if !is_xss {
            return;
        }
        // Mirrors the needle gate: a js-uri fingerprint on body markup
        // without tag structure is collected data — skipped entirely, and the
        // needle hit for it is skipped as well. A script-tag fingerprint over
        // an unclosed `<script` is prose quoting the word.
        let collected_js_uri = (xss_fp.contains("js-uri")
            && vctx.value.source == ValueSource::Body
            && !xss_script_uri_html_shaped(vctx.needle))
            || (xss_fp.contains("script-tag")
                && !xss_script_tag_shaped(
                    vctx.needle,
                    vctx.value.source != ValueSource::Body,
                ));
        let weak =
            vctx.is_meta_header || vctx.blob_weak(self.level.is_strict());
        let (severity, critical) = if weak { (2, false) } else { (5, true) };
        let monitored =
            self.hit_monitored(LegacyAttackCategory::Xss, StackSet::GENERIC);
        if critical && !collected_js_uri && !monitored {
            state.critical_hit = true;
        }
        if collected_js_uri {
            return;
        }
        self.scorer.add_category_hit_ex(
            &mut state.breakdown,
            LegacyAttackCategory::Xss,
            severity,
            monitored,
        );
        state.recs.push(HitRec::Lib {
            kind: "libinjection-xss",
            fingerprint: xss_fp,
            source: vctx.value.source.as_str(),
            name: &vctx.value.name,
            monitored,
        });
    }

    /// Structural PHP-serialization / OGNL shapes: no single literal, so they
    /// live beside the libinjection detectors. Weak signals (meta headers,
    /// body blobs, oversized values) score instead of blocking; Strict treats
    /// any such shape as a critical hit — these shapes are only produced by
    /// serializers and expression interpreters, which are exactly the
    /// surfaces being attacked.
    fn score_deser_shape<'n>(
        &self,
        vctx: &ValueCtx<'n>,
        state: &mut InspectionState<'n>,
    ) {
        let Some(shape) = detect_deser_shape(vctx.needle) else {
            return;
        };
        let strict = self.level.is_strict();
        let weak = vctx.is_meta_header
            || (vctx.value.source == ValueSource::Body
                && (!vctx.value.field
                    || vctx.value.decoded.len() > FIELD_STRONG_MAX_LEN)
                && !strict);
        let (severity, critical) = if weak {
            (2, false)
        } else if strict {
            (5, true)
        } else {
            (4, false)
        };
        let monitored = self.hit_monitored(
            LegacyAttackCategory::Deserialization,
            StackSet::GENERIC,
        );
        if critical && !monitored {
            state.critical_hit = true;
        }
        self.scorer.add_category_hit_ex(
            &mut state.breakdown,
            LegacyAttackCategory::Deserialization,
            severity,
            monitored,
        );
        state.recs.push(HitRec::Lib {
            kind: "deser-shape",
            fingerprint: shape.to_string(),
            source: vctx.value.source.as_str(),
            name: &vctx.value.name,
            monitored,
        });
    }

    /// Exploit-only shape compositions, each a critical with no honest
    /// counterpart: a shell command interleaved with an empty backtick pair
    /// (`;wh``oami`), a scheme prefix glued to backslash traversal
    /// (`dir=http\..\admin\…`), a codepoint chain, and an SSRF-exploit scheme
    /// carrying a framed newline (`ldap://…%0astats`).
    fn score_exploit_shapes<'n>(
        &self,
        vctx: &ValueCtx<'n>,
        state: &mut InspectionState<'n>,
    ) {
        if ci_backtick_interleaved(vctx.needle) {
            self.record_critical_shape(
                state,
                LegacyAttackCategory::CommandInjection,
                "ci-shape",
                "backtick-interleaved",
                vctx.value,
            );
        }
        if ci_chr_chain(vctx.needle) {
            self.record_critical_shape(
                state,
                LegacyAttackCategory::CommandInjection,
                "ci-shape",
                "chr-codepoint-chain",
                vctx.value,
            );
        }
        if ssrf_protocol_smuggling(vctx.needle) {
            self.record_critical_shape(
                state,
                LegacyAttackCategory::Ssrf,
                "ssrf-shape",
                "protocol-smuggling",
                vctx.value,
            );
        }
        if pt_remote_backslash_include(vctx.needle) {
            self.record_critical_shape(
                state,
                LegacyAttackCategory::PathTraversal,
                "pt-shape",
                "remote-backslash-include",
                vctx.value,
            );
        }
    }

    /// Strict level: structural EL / SSTI detection over the decoded value. A
    /// container with interpreter-facing shape is treated as a critical hit;
    /// a bracket-call in a real member field or on a URL-facing surface scores
    /// into the RCE gate.
    fn score_expression_injection<'n>(
        &self,
        vctx: &ValueCtx<'n>,
        state: &mut InspectionState<'n>,
    ) {
        if !self.level.is_strict() {
            return;
        }
        let monitored = self.hit_monitored(
            LegacyAttackCategory::TemplateInjection,
            StackSet::GENERIC,
        );
        if let Some(container) = detect_expr_injection(vctx.needle) {
            self.record_expr_hit(state, container, monitored, vctx.value);
        } else if detect_js_call(vctx.needle)
            && (vctx.value.field || vctx.value.source != ValueSource::Body)
        {
            // A bracket-call inside an unstructured body blob (collected page
            // text, log dumps) is prose — skipped entirely, or the RCE
            // sub-score alone would re-block what the critical gate let
            // through.
            self.record_expr_hit(state, "js-call", monitored, vctx.value);
        }
    }

    /// Records a severity-5 structural shape hit in `category`: it feeds the
    /// aggregate score and sets the critical flag unless the category is
    /// downgraded to monitor-only.
    fn record_critical_shape<'n>(
        &self,
        state: &mut InspectionState<'n>,
        category: LegacyAttackCategory,
        kind: &'static str,
        fingerprint: &'static str,
        value: &'n DecodedValue,
    ) {
        let monitored = self.hit_monitored(category, StackSet::GENERIC);
        if !monitored {
            state.critical_hit = true;
        }
        self.scorer.add_category_hit_ex(
            &mut state.breakdown,
            category,
            5,
            monitored,
        );
        state.recs.push(HitRec::Lib {
            kind,
            fingerprint: fingerprint.to_string(),
            source: value.source.as_str(),
            name: &value.name,
            monitored,
        });
    }

    /// Records a structural expression-injection hit and its critical call.
    fn record_expr_hit<'n>(
        &self,
        state: &mut InspectionState<'n>,
        container: &'static str,
        monitored: bool,
        value: &'n DecodedValue,
    ) {
        self.scorer.add_expr_hit_ex(&mut state.breakdown, monitored);
        if !monitored {
            state.critical_hit = true;
        }
        state.recs.push(HitRec::Expr {
            container,
            source: value.source.as_str(),
            name: &value.name,
            monitored,
        });
    }

    /// Also scan the normalized path itself — traversal patterns commonly
    /// appear after `..` resolution rather than in raw query params.
    pub(super) fn scan_normalized_path<'n>(
        &self,
        normalized: &'n NormalizedRequest<'_>,
        scratch: &mut ScanScratch,
        state: &mut InspectionState<'n>,
    ) {
        self.signatures.scan_into(
            &normalized.path,
            &mut scratch.hits,
            &mut scratch.seen,
        );
        for hit in &scratch.hits {
            // Mirror of the decoded-value search-phrase gate: a compact or
            // attribute `<script>` tag on the path is real attack material,
            // while prose quoting the word (`…binary<script is incorrect` as
            // a URL slug) must not one-shot through the sev-5 fast path. The
            // gate also skips the score.
            let pid = self.signatures.pattern_id(hit.pattern);
            let search_phrase = pid == "XSS-001"
                && !xss_script_tag_shaped(&normalized.path, true);
            if search_phrase {
                continue;
            }
            let critical = (hit.severity >= 5)
                || (self.level.is_strict()
                    && hit.category == LegacyAttackCategory::CrlfInjection);
            let monitored = self.hit_monitored(
                hit.category,
                self.signatures.pattern(hit.pattern).stack,
            );
            if critical && !monitored {
                state.critical_hit = true;
            }
            // Mirror of the decoded-value gate: CI/Deser shapes found on the
            // resolved path keep their aggregate score but stay out of the
            // RCE sub-score.
            if matches!(
                hit.category,
                LegacyAttackCategory::CommandInjection
                    | LegacyAttackCategory::Deserialization
            ) {
                self.scorer.add_severity_hit_ex(
                    &mut state.breakdown,
                    hit.severity,
                    monitored,
                );
            } else {
                self.scorer.add_category_hit_ex(
                    &mut state.breakdown,
                    hit.category,
                    hit.severity,
                    monitored,
                );
            }
            state.recs.push(HitRec::Sig {
                pattern: hit.pattern,
                severity: hit.severity,
                source: "path",
                name: "",
                monitored,
            });
        }
    }

    /// Expression-evaluation context holding the full Stage-1 score snapshot.
    pub(super) fn eval_context<'a>(
        &self,
        request: &'a RequestData,
        normalized: &'a NormalizedRequest<'_>,
        breakdown: &ScoreBreakdown,
    ) -> EvalContext<'a> {
        let parsed_ip = IpAddr::from_str(&request.client_ip).ok();
        let ssl = request.scheme.eq_ignore_ascii_case("https");
        EvalContext {
            method: &normalized.method,
            path: &normalized.path,
            full_uri: &normalized.full_uri,
            host: normalized.host(),
            user_agent: normalized.user_agent(),
            body: normalized.body_str(),
            headers: normalized.headers,
            cookies: &normalized.cookies,
            client_ip: &request.client_ip,
            parsed_ip,
            country_code: request.country_code.as_deref(),
            ssl,
            waf_score: breakdown.total,
            waf_score_sqli: breakdown.sqli_score,
            waf_score_xss: breakdown.xss_score,
            waf_score_rce: breakdown.rce_score,
        }
    }

    /// Allow rules are allowlist entries: they must win over both the Stage-1
    /// fast path and every other rule, otherwise an operator could not exempt
    /// a health-check endpoint or an internal network.
    pub(super) fn apply_allow_prepass(
        &self,
        ctx: &EvalContext<'_>,
        paranoia: u8,
        state: &InspectionState<'_>,
    ) -> Option<WafVerdict> {
        for rule in &self.rules {
            if !rule.enabled || rule.action != RuleAction::Allow {
                continue;
            }
            if self.rule_disabled(rule) {
                continue;
            }
            if rule.paranoia_level > paranoia
                || !self.stacks.contains(rule.stacks)
            {
                continue;
            }
            if !evaluate(&rule.expression, ctx) {
                continue;
            }
            let mut matched = self.matched_from(&state.recs, &[]);
            matched.push(rule.id.clone());
            return Some(WafVerdict {
                action: WafAction::Pass,
                score: state.breakdown.total_u8(),
                matched_rules: matched,
                details: format!(
                    "allow-rule matched: {} [{}]",
                    rule.id, rule.name
                ),
                breakdown: state.breakdown,
            });
        }
        None
    }

    /// Stage 2: non-Allow rules in declaration order (an Allow rule already
    /// won in the pre-pass). Managed rules see the blocking-only score
    /// snapshot; custom rules see the full aggregate.
    pub(super) fn evaluate_managed_rules<'a>(
        &'a self,
        request: &RequestData,
        ctx: &EvalContext<'_>,
        block_ctx: &EvalContext<'_>,
        paranoia: u8,
        state: &mut InspectionState<'a>,
    ) {
        for rule in &self.rules {
            if !rule.enabled || rule.action == RuleAction::Allow {
                continue;
            }
            if self.rule_disabled(rule) {
                continue;
            }
            if rule.paranoia_level > paranoia
                || !self.stacks.contains(rule.stacks)
            {
                continue;
            }
            let rule_ctx = if rule.id.starts_with("VARMAN-") {
                block_ctx
            } else {
                ctx
            };
            if !self.rule_matches(request, rule, rule_ctx) {
                continue;
            }
            self.apply_rule_hit(rule, state);
        }
    }

    /// Evaluates one rule, honouring target exclusions: a match is suppressed
    /// only when the rule no longer matches with those targets removed, so a
    /// finding independent of the excluded source stays.
    fn rule_matches(
        &self,
        request: &RequestData,
        rule: &CompiledRule,
        rule_ctx: &EvalContext<'_>,
    ) -> bool {
        if !evaluate(&rule.expression, rule_ctx) {
            return false;
        }
        let targets = self.excluded_targets(request, rule);
        if targets.is_empty() {
            return true;
        }
        let filtered = FilteredCtx::new(*rule_ctx, &targets);
        evaluate(&rule.expression, &filtered.as_ctx(*rule_ctx))
    }

    /// Site-wide exclusions for `rule`, merged with the path-scoped exclusion
    /// packages whose prefix the request path matches.
    fn excluded_targets(
        &self,
        request: &RequestData,
        rule: &CompiledRule,
    ) -> Vec<String> {
        let mut targets: Vec<String> = self
            .rule_target_exclusions
            .get(rule.id.as_str())
            .cloned()
            .unwrap_or_default();
        for exclusion in &self.path_target_exclusions {
            if exclusion.rule_id == rule.id
                && !exclusion.path_prefix.is_empty()
                && request.path.starts_with(&exclusion.path_prefix)
            {
                targets.extend(exclusion.targets.iter().cloned());
            }
        }
        targets
    }

    /// Records one matched rule and applies its action: the rule's score
    /// contribution (severity-derived or the control-plane override) and its
    /// enforcement. `Block` outranks `Challenge`; a monitor-only rule never
    /// enforces.
    fn apply_rule_hit<'a>(
        &'a self,
        rule: &'a CompiledRule,
        state: &mut InspectionState<'a>,
    ) {
        let monitored = self.rule_monitored(rule);
        // Control-plane score override: replaces the severity-derived
        // contribution of this rule; the rule's action still applies.
        let override_points = self.rule_scores.get(rule.id.as_str()).copied();
        state.rule_recs.push(RuleRec {
            id: &rule.id,
            name: &rule.name,
            action: rule.action,
            severity: rule.severity,
            monitored,
        });
        match rule.action {
            RuleAction::Allow => {
                unreachable!("allow rules handled in pre-pass")
            },
            RuleAction::Log => {
                // OWASP CRS anomaly-scoring semantics, kept deliberately: a
                // log-action hit feeds the same aggregate (including the
                // blocking subset), so several low-severity log hits — or log
                // hits stacked on signature hits — can cross the threshold
                // and block. Operators who want a rule to never contribute to
                // blocking use the per-rule monitor switch instead, which
                // routes through `add_severity_hit_ex(monitored=true)`.
                match override_points {
                    Some(points) => {
                        self.scorer.add_points_hit(&mut state.breakdown, points)
                    },
                    None => self
                        .scorer
                        .add_severity_hit(&mut state.breakdown, rule.severity),
                }
            },
            RuleAction::Block => {
                self.score_enforcing_rule(
                    rule,
                    override_points,
                    monitored,
                    state,
                );
                if !monitored {
                    state.forced_action = Some(WafAction::Block);
                }
            },
            RuleAction::Challenge | RuleAction::JsChallenge => {
                self.score_enforcing_rule(
                    rule,
                    override_points,
                    monitored,
                    state,
                );
                if !monitored && state.forced_action != Some(WafAction::Block) {
                    state.forced_action = Some(WafAction::Challenge);
                }
            },
        }
    }

    /// Scores an enforcing (`Block` / `Challenge`) rule hit, honouring the
    /// per-rule score override and the monitor downgrade.
    fn score_enforcing_rule(
        &self,
        rule: &CompiledRule,
        override_points: Option<u32>,
        monitored: bool,
        state: &mut InspectionState<'_>,
    ) {
        match override_points {
            Some(points) => self.scorer.add_points_hit_ex(
                &mut state.breakdown,
                points,
                monitored,
            ),
            None => self.scorer.add_severity_hit_ex(
                &mut state.breakdown,
                rule.severity,
                monitored,
            ),
        }
    }

    /// Final scoring: a forced rule action wins, then the aggregate threshold,
    /// then a Monitor verdict for any sub-threshold hit. A clean pass never
    /// materializes hit strings.
    pub(super) fn assemble_verdict(
        &self,
        state: &mut InspectionState<'_>,
    ) -> WafVerdict {
        let InspectionState {
            breakdown,
            recs,
            rule_recs,
            forced_action,
            ..
        } = state;
        breakdown.overall_class = self.scorer.classify(breakdown.block_total);
        let action = if let Some(forced) = *forced_action {
            forced
        } else if self.scorer.should_block(breakdown.block_total) {
            WafAction::Block
        } else if breakdown.total > 0 {
            // Below threshold but something fired — surface it as Monitor so
            // the caller still logs the event. Monitor-only hits keep their
            // aggregate score, so a downgrade surfaces here exactly as an
            // ordinary sub-threshold detection does.
            WafAction::Monitor
        } else {
            WafAction::Pass
        };
        // `Pass` can only be reached when nothing fired anywhere (any hit or
        // Log rule would have raised the score).
        if action == WafAction::Pass {
            debug_assert!(recs.is_empty() && rule_recs.is_empty());
            return WafVerdict::pass();
        }
        let reason = match breakdown.overall_class {
            ScoreClass::Clean => "clean",
            ScoreClass::LikelyClean => "likely-clean",
            ScoreClass::LikelyAttack => "likely-attack",
            ScoreClass::Attack => "attack",
        };
        self.finalize_verdict(
            breakdown,
            self.matched_from(recs, rule_recs),
            self.details_from(recs, rule_recs),
            Some(action),
            reason,
        )
    }
}

/// Blocking-only snapshot handed to managed rules: hits downgraded to
/// monitor-only can never push a family or aggregate gate. The full snapshot
/// stays available to custom rules and the Allow pre-pass.
pub(super) fn blocking_context<'a>(
    ctx: EvalContext<'a>,
    breakdown: &ScoreBreakdown,
) -> EvalContext<'a> {
    EvalContext {
        waf_score: breakdown.block_total,
        waf_score_sqli: breakdown.block_sqli_score,
        waf_score_xss: breakdown.block_xss_score,
        waf_score_rce: breakdown.block_rce_score,
        ..ctx
    }
}
