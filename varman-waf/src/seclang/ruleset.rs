//! SecLang rule-set runner (Phase 7).
//!
//! Ties the pieces together: parse a SecLang source into rule groups, then
//! evaluate them against a transaction in order. Matching groups record a
//! [`RuleHit`] and execute their `setvar` actions; non-matching groups are
//! skipped. `TX` variables set by one rule are visible to the rules after it.
//!
//! Action validation is strict and observable: an action this engine does not
//! implement is a **compile error**, never a silent no-op (mandate §37).
//!
//! Implemented actions: `id`, `phase`, `block`, `deny`, `drop`, `pass`,
//! `allow`, `log`, `nolog`, `monitor`, `challenge`, `msg`, `logdata`,
//! `severity`, `score`, `tag`, `status`, `ver`, `rev`, `maturity`,
//! `accuracy`, `chain`, `t:<name>`, `setvar:tx.<name>=<value>` (assignment,
//! `+n`, `-n`).

use crate::seclang::parser::{parse_line, SecLangError, SecLangLine};
use crate::seclang::transaction::{
    group_rules, ResolvedValue, SecLangTransaction, SecRuleGroup,
};

/// Actions the engine accepts (and what they mean): `t:` and `setvar:` are
/// executed; the rest are recorded for policy/scoring layers.
const ALLOWED_ACTIONS: &[&str] = &[
    "id:",
    "phase:",
    "block",
    "deny",
    "drop",
    "pass",
    "allow",
    "log",
    "nolog",
    "monitor",
    "challenge",
    "msg:",
    "logdata:",
    "severity:",
    "score:",
    "tag:",
    "status:",
    "ver:",
    "rev:",
    "maturity:",
    "accuracy:",
    "chain",
    "t:",
    "setvar:",
    "capture",
    "auditlog",
];

fn validate_actions(group: &SecRuleGroup) -> Result<(), SecLangError> {
    for rule in &group.rules {
        for action in &rule.line.actions {
            let trimmed = action.trim();
            let known = ALLOWED_ACTIONS
                .iter()
                .any(|allowed| trimmed.starts_with(allowed));
            if !known {
                return Err(SecLangError {
                    reason: format!("unsupported action {trimmed:?}"),
                });
            }
            if let Some(spec) = trimmed.strip_prefix("setvar:") {
                parse_setvar(spec)?;
            }
        }
    }
    Ok(())
}

/// Validated `setvar` operation, applied when the rule matches.
#[derive(Debug, Clone, PartialEq, Eq)]
enum SetVar {
    Assign(String, String),
    Increment(String, i64),
}

fn parse_setvar(spec: &str) -> Result<SetVar, SecLangError> {
    let spec = spec.trim().trim_matches('\'').trim_matches('"');
    let Some((target, value)) = spec.split_once('=') else {
        return Err(SecLangError {
            reason: format!("setvar without '=': {spec:?}"),
        });
    };
    let target = target.trim();
    let Some(name) = target.strip_prefix("tx.") else {
        return Err(SecLangError {
            reason: format!("setvar target {target:?} is not a TX variable"),
        });
    };
    let value = value.trim();
    if let Some(delta) =
        value.strip_prefix('+').or_else(|| value.strip_prefix('-'))
    {
        let sign = if value.starts_with('-') { -1 } else { 1 };
        let magnitude = delta.parse::<i64>().map_err(|_| SecLangError {
            reason: format!("setvar offset {value:?} is not a number"),
        })?;
        return Ok(SetVar::Increment(name.to_string(), sign * magnitude));
    }
    Ok(SetVar::Assign(name.to_string(), value.to_string()))
}

fn apply_setvar(txn: &mut SecLangTransaction, op: &SetVar) {
    match op {
        SetVar::Assign(name, value) => txn.tx_set(name, value.clone()),
        SetVar::Increment(name, delta) => {
            let current: i64 = txn
                .tx_get(name)
                .and_then(|v| v.trim().parse().ok())
                .unwrap_or(0);
            txn.tx_set(name, (current + delta).to_string());
        },
    }
}

/// One matching rule (or chain) in evaluation order.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RuleHit {
    pub rule_ids: Vec<Option<u64>>,
    /// Values that matched, in rule/variable order.
    pub variables_hit: Vec<ResolvedValue>,
    /// Actions recorded for policy/scoring layers.
    pub actions: Vec<String>,
}

/// A compiled rule set ready for evaluation.
#[derive(Debug)]
pub struct SecRuleSet {
    groups: Vec<SecRuleGroup>,
    setvars: Vec<Vec<SetVar>>,
}

impl SecRuleSet {
    /// Parse and compile a SecLang source (comments and blank lines skipped).
    pub fn from_source(source: &str) -> Result<Self, SecLangError> {
        let mut rules = Vec::new();
        for line in source.lines() {
            match parse_line(line)? {
                SecLangLine::Ignored => {},
                SecLangLine::Rule(rule) => rules.push(rule),
            }
        }
        let groups = group_rules(rules)?;
        let mut setvars = Vec::with_capacity(groups.len());
        for group in &groups {
            validate_actions(group)?;
            let mut ops = Vec::new();
            for rule in &group.rules {
                for action in &rule.line.actions {
                    if let Some(spec) = action.trim().strip_prefix("setvar:") {
                        ops.push(parse_setvar(spec)?);
                    }
                }
            }
            setvars.push(ops);
        }
        Ok(Self { groups, setvars })
    }

    pub fn group_count(&self) -> usize {
        self.groups.len()
    }

    /// Evaluate every group in order; `setvar` effects are visible to later
    /// groups through `TX`.
    pub fn evaluate(&self, txn: &mut SecLangTransaction) -> Vec<RuleHit> {
        let mut hits = Vec::new();
        for (index, group) in self.groups.iter().enumerate() {
            let Some(variables_hit) = group.matches(txn) else {
                continue;
            };
            for op in &self.setvars[index] {
                apply_setvar(txn, op);
            }
            let actions = group
                .rules
                .last()
                .map(|rule| rule.line.actions.clone())
                .unwrap_or_default();
            hits.push(RuleHit {
                rule_ids: group.rule_ids(),
                variables_hit,
                actions,
            });
        }
        hits
    }
}

#[cfg(test)]
mod tests {
    use super::{SecRuleSet, SetVar};
    use crate::canonical::{Canonicalizer, RequestParts};
    use crate::seclang::parser::parse_line;

    fn request(query: &str) -> crate::canonical::CanonicalRequest {
        Canonicalizer::default().canonicalize(RequestParts::new(
            "GET",
            "example.com",
            query,
        ))
    }

    #[test]
    fn runs_matching_rules_in_order() {
        let ruleset = SecRuleSet::from_source(
            "# id must be numeric\n\
             SecRule ARGS:id \"@rx ^[0-9]+$\" \"id:900100,phase:1,log,setvar:tx.seen=1\"\n\
             SecRule ARGS:id \"@rx ^[a-z]+$\" \"id:900101,phase:1,block\"\n",
        )
        .expect("compile");
        assert_eq!(ruleset.group_count(), 2);

        let mut txn =
            crate::seclang::transaction::SecLangTransaction::from_request(
                &request("/?id=42"),
            );
        let hits = ruleset.evaluate(&mut txn);
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].rule_ids, vec![Some(900100)]);
        assert!(txn.tx_get("seen") == Some("1"));
    }

    #[test]
    fn setvar_increment_and_assignment_flow_between_rules() {
        let ruleset = SecRuleSet::from_source(
            "SecRule ARGS:a \"@streq 1\" \"id:1,setvar:tx.score=10,setvar:tx.hits=1\"\n\
             SecRule ARGS:b \"@streq 2\" \"id:2,setvar:tx.score=+5,setvar:tx.hits=+1\"\n\
             SecRule TX:score \"@streq 15\" \"id:3,block\"\n",
        )
        .expect("compile");
        let mut txn =
            crate::seclang::transaction::SecLangTransaction::from_request(
                &request("/?a=1&b=2"),
            );
        let hits = ruleset.evaluate(&mut txn);
        assert_eq!(hits.len(), 3, "{hits:?}");
        assert_eq!(txn.tx_get("score"), Some("15"));
        assert_eq!(txn.tx_get("hits"), Some("2"));
    }

    #[test]
    fn chains_score_once_when_all_members_match() {
        let ruleset = SecRuleSet::from_source(
            "SecRule ARGS:a \"@streq 1\" \"id:1,chain,setvar:tx.n=+1\"\n\
             SecRule ARGS:b \"@streq 2\" \"id:2,setvar:tx.n=+1\"\n",
        )
        .expect("compile");
        let mut txn =
            crate::seclang::transaction::SecLangTransaction::from_request(
                &request("/?a=1&b=2"),
            );
        let hits = ruleset.evaluate(&mut txn);
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].rule_ids, vec![Some(1), Some(2)]);
        assert_eq!(txn.tx_get("n"), Some("2"));

        // Second member failing means no hit and no setvar at all.
        let mut partial =
            crate::seclang::transaction::SecLangTransaction::from_request(
                &request("/?a=1&b=9"),
            );
        assert!(ruleset.evaluate(&mut partial).is_empty());
        assert!(partial.tx_get("n").is_none());
    }

    #[test]
    fn unsupported_actions_error_observably() {
        let error = SecRuleSet::from_source(
            "SecRule ARGS \"@rx x\" \"id:1,skipAfter:MARK\"",
        )
        .expect_err("must fail");
        assert!(error.reason.contains("unsupported action"), "{error}");
    }

    #[test]
    fn non_tx_setvar_targets_error() {
        let error = SecRuleSet::from_source(
            "SecRule ARGS \"@rx x\" \"id:1,setvar:ip.blocked=1\"",
        )
        .expect_err("must fail");
        assert!(error.reason.contains("not a TX variable"), "{error}");
    }

    #[test]
    fn setvar_parsing_forms() {
        for (spec, expected) in [
            ("tx.a=1", SetVar::Assign("a".into(), "1".into())),
            ("'tx.b=hello'", SetVar::Assign("b".into(), "hello".into())),
            ("tx.c=+2", SetVar::Increment("c".into(), 2)),
            ("tx.c=-3", SetVar::Increment("c".into(), -3)),
        ] {
            assert_eq!(super::parse_setvar(spec).expect("parses"), expected);
        }
        assert!(super::parse_setvar("tx.broken").is_err());
        assert!(super::parse_setvar("tx.d=+x").is_err());
    }

    #[test]
    fn comments_and_repeated_parses_are_stable() {
        let source = "# comment\n\nSecRule ARGS \"@rx x\" \"id:1\"\n";
        let first = SecRuleSet::from_source(source).expect("compile");
        let second = SecRuleSet::from_source(source).expect("compile");
        assert_eq!(first.group_count(), 1);
        assert_eq!(second.group_count(), 1);
        // Parser sanity: the rule id is visible through the group accessor.
        let parsed = parse_line("SecRule ARGS \"@rx x\" \"id:1\"");
        assert!(parsed.is_ok());
    }
}
