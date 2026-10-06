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
    "skip:",
    "skipAfter:",
    "t:",
    "setvar:",
    "capture",
    "auditlog",
];

/// `true` when the line is a `SecRuleRemoveById` directive (the exact word,
/// or followed by whitespace — never a longer identifier).
fn parsed_removal_directive(trimmed: &str) -> bool {
    trimmed == "SecRuleRemoveById"
        || trimmed
            .strip_prefix("SecRuleRemoveById")
            .is_some_and(|rest| rest.starts_with(char::is_whitespace))
}

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
    /// `skip:N` per group: skip the next N groups after a match.
    skip_groups: Vec<Option<u64>>,
    /// `skipAfter:NAME` per group: resolved index to continue at.
    skip_after: Vec<Option<usize>>,
}

impl SecRuleSet {
    /// Parse and compile a SecLang source (comments and blank lines skipped).
    ///
    /// `SecRuleRemoveById <ids…>` lines remove the named rules from the set
    /// before compilation (the mechanism OWASP CRS uses to tune itself).
    pub fn from_source(source: &str) -> Result<Self, SecLangError> {
        let mut removals: Vec<u64> = Vec::new();
        let mut retargets: Vec<(u64, Vec<String>)> = Vec::new();
        // `SecMarker` positions in the rule stream: `(name, rules_seen)`.
        let mut markers: Vec<(String, usize)> = Vec::new();
        let mut rules = Vec::new();
        for line in source.lines() {
            let trimmed = line.trim();
            if trimmed == "SecMarker" || trimmed.starts_with("SecMarker ") {
                let name = trimmed
                    .trim_start_matches("SecMarker")
                    .trim()
                    .trim_matches('"');
                if name.is_empty() {
                    return Err(SecLangError {
                        reason: "SecMarker without a name".to_string(),
                    });
                }
                markers.push((name.to_string(), rules.len()));
                continue;
            }
            if parsed_removal_directive(trimmed) {
                let rest = trimmed.trim_start_matches("SecRuleRemoveById");
                let ids: Vec<u64> = rest
                    .split(|c: char| c == ',' || c.is_whitespace())
                    .filter(|token| !token.is_empty())
                    .map(|token| {
                        token.parse::<u64>().map_err(|_| SecLangError {
                            reason: format!("SecRuleRemoveById id {token:?} is not a number"),
                        })
                    })
                    .collect::<Result<_, _>>()?;
                if ids.is_empty() {
                    return Err(SecLangError {
                        reason: "SecRuleRemoveById without rule ids"
                            .to_string(),
                    });
                }
                removals.extend(ids);
                continue;
            }
            if let Some(rest) = trimmed.strip_prefix("SecRuleUpdateTargetById ")
            {
                let (id_raw, variables_raw) =
                    rest.split_once(' ').ok_or_else(|| SecLangError {
                        reason:
                            "SecRuleUpdateTargetById without target variables"
                                .to_string(),
                    })?;
                let id = id_raw.parse::<u64>().map_err(|_| SecLangError {
                    reason: format!(
                        "SecRuleUpdateTargetById id {id_raw:?} is not a number"
                    ),
                })?;
                let variables: Vec<String> = variables_raw
                    .split('|')
                    .map(str::trim)
                    .filter(|entry| !entry.is_empty())
                    .map(str::to_string)
                    .collect();
                if variables.is_empty() {
                    return Err(SecLangError {
                        reason:
                            "SecRuleUpdateTargetById without target variables"
                                .to_string(),
                    });
                }
                if variables.iter().any(|v| v.starts_with('!')) {
                    return Err(SecLangError {
                        reason:
                            "SecRuleUpdateTargetById exclusions (!VAR) are not supported"
                                .to_string(),
                    });
                }
                retargets.push((id, variables));
                continue;
            }
            match parse_line(line)? {
                SecLangLine::Ignored => {},
                SecLangLine::Rule(rule) => rules.push(rule),
            }
        }
        if !retargets.is_empty() {
            for rule in &mut rules {
                let rule_id = rule.actions.iter().find_map(|action| {
                    action
                        .strip_prefix("id:")
                        .and_then(|id| id.trim().parse::<u64>().ok())
                });
                if let Some(id) = rule_id {
                    if let Some((_, variables)) =
                        retargets.iter().find(|(target, _)| *target == id)
                    {
                        rule.variables = variables.clone();
                    }
                }
            }
        }
        let mut groups = group_rules(rules)?;
        if !removals.is_empty() {
            for group in &mut groups {
                group.rules.retain(|rule| {
                    !rule.rule_id().is_some_and(|id| removals.contains(&id))
                });
            }
            groups.retain(|group| !group.rules.is_empty());
        }
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
        // Group start positions in the rule stream, for marker resolution.
        let mut starts = Vec::with_capacity(groups.len());
        let mut cursor = 0usize;
        for group in &groups {
            starts.push(cursor);
            cursor += group.rules.len();
        }
        let mut skip_groups = Vec::with_capacity(groups.len());
        let mut skip_after = Vec::with_capacity(groups.len());
        for (index, group) in groups.iter().enumerate() {
            let actions = group
                .rules
                .last()
                .map(|rule| rule.line.actions.clone())
                .unwrap_or_default();
            let mut skip_count: Option<u64> = None;
            let mut after_name: Option<String> = None;
            for action in &actions {
                let action = action.trim();
                if let Some(rest) = action.strip_prefix("skip:") {
                    skip_count =
                        Some(rest.trim().parse::<u64>().map_err(|_| {
                            SecLangError {
                                reason: format!(
                                    "skip count {rest:?} is not a number"
                                ),
                            }
                        })?);
                } else if let Some(name) = action.strip_prefix("skipAfter:") {
                    after_name = Some(name.trim().to_string());
                }
            }
            skip_groups.push(skip_count);
            let resolved = match after_name {
                Some(name) => {
                    let Some((_, marker_pos)) =
                        markers.iter().find(|(n, _)| *n == name)
                    else {
                        return Err(SecLangError {
                            reason: format!(
                                "skipAfter target {name:?} not found"
                            ),
                        });
                    };
                    let position = starts
                        .iter()
                        .position(|start| start >= marker_pos)
                        .unwrap_or(groups.len());
                    if position <= index {
                        return Err(SecLangError {
                            reason: format!(
                                "skipAfter target {name:?} must follow the rule"
                            ),
                        });
                    }
                    Some(position)
                },
                None => None,
            };
            skip_after.push(resolved);
        }
        Ok(Self {
            groups,
            setvars,
            skip_groups,
            skip_after,
        })
    }

    pub fn group_count(&self) -> usize {
        self.groups.len()
    }

    /// Evaluate every group in order, honouring `skip:N` and
    /// `skipAfter:NAME` control flow; `setvar` effects are visible to later
    /// groups through `TX`.
    pub fn evaluate(&self, txn: &mut SecLangTransaction) -> Vec<RuleHit> {
        let mut hits = Vec::new();
        let mut index = 0usize;
        while index < self.groups.len() {
            let group = &self.groups[index];
            let Some(variables_hit) = group.matches(txn) else {
                index += 1;
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
            let next = if let Some(skip) = self.skip_groups[index] {
                index + 1 + skip as usize
            } else if let Some(target) = self.skip_after[index] {
                target
            } else {
                index + 1
            };
            hits.push(RuleHit {
                rule_ids: group.rule_ids(),
                variables_hit,
                actions,
            });
            index = next;
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
    fn remove_by_id_drops_matching_rules() {
        let ruleset = SecRuleSet::from_source(
            "SecRule ARGS:a \"@streq 1\" \"id:1001,block\"\n\
             SecRule ARGS:b \"@streq 2\" \"id:1002,block\"\n\
             SecRuleRemoveById 1002\n",
        )
        .expect("compile");
        assert_eq!(ruleset.group_count(), 1);
        let mut txn =
            crate::seclang::transaction::SecLangTransaction::from_request(
                &request("/?a=1&b=2"),
            );
        let hits = ruleset.evaluate(&mut txn);
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].rule_ids, vec![Some(1001)]);

        // Unknown ids are a no-op, not an error: CRS tuning removes rules
        // that may not exist at the current paranoia level.
        let noop = SecRuleSet::from_source(
            "SecRule ARGS:a \"@streq 1\" \"id:1001\"\nSecRuleRemoveById 9999\n",
        )
        .expect("compile");
        assert_eq!(noop.group_count(), 1);
    }

    #[test]
    fn remove_by_id_validates_its_arguments() {
        let error = SecRuleSet::from_source("SecRuleRemoveById\n")
            .expect_err("must fail");
        assert!(error.reason.contains("without rule ids"), "{error}");
        let error = SecRuleSet::from_source("SecRuleRemoveById abc\n")
            .expect_err("must fail");
        assert!(error.reason.contains("not a number"), "{error}");
    }

    #[test]
    fn remove_by_id_in_a_chain_drops_the_member() {
        let ruleset = SecRuleSet::from_source(
            "SecRule ARGS:a \"@streq 1\" \"id:1,chain\"\n\
             SecRule ARGS:b \"@streq 2\" \"id:2\"\n\
             SecRuleRemoveById 2\n",
        )
        .expect("compile");
        // The remaining head rule is a singleton now.
        assert_eq!(ruleset.group_count(), 1);
        let mut txn =
            crate::seclang::transaction::SecLangTransaction::from_request(
                &request("/?a=1"),
            );
        let hits = ruleset.evaluate(&mut txn);
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].rule_ids, vec![Some(1)]);
    }

    #[test]
    fn update_target_by_id_replaces_variables() {
        let source = "SecRule ARGS:a \"@streq secret\" \"id:2001,block\"\n\
                      SecRuleUpdateTargetById 2001 REQUEST_HEADERS:X-Api-Key\n";
        let ruleset = SecRuleSet::from_source(source).expect("compile");
        let request = Canonicalizer::default().canonicalize(
            RequestParts::new("GET", "example.com", "/")
                .with_header("X-Api-Key", "secret"),
        );
        let mut txn =
            crate::seclang::transaction::SecLangTransaction::from_request(
                &request,
            );
        let hits = ruleset.evaluate(&mut txn);
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].rule_ids, vec![Some(2001)]);
        assert_eq!(hits[0].variables_hit[0].name, "REQUEST_HEADERS:x-api-key");

        // Without the update the same request does not match.
        let plain = SecRuleSet::from_source(
            "SecRule ARGS:a \"@streq secret\" \"id:2001,block\"\n",
        )
        .expect("compile");
        let mut txn =
            crate::seclang::transaction::SecLangTransaction::from_request(
                &request,
            );
        assert!(plain.evaluate(&mut txn).is_empty());

        // Unknown ids are a no-op.
        let noop = SecRuleSet::from_source(
            "SecRule ARGS:a \"@streq 1\" \"id:1\"\n\
             SecRuleUpdateTargetById 9999 REQUEST_HEADERS:X\n",
        )
        .expect("compile");
        assert_eq!(noop.group_count(), 1);
    }

    #[test]
    fn update_target_by_id_validates_arguments() {
        let error = SecRuleSet::from_source("SecRuleUpdateTargetById 2001\n")
            .expect_err("must fail");
        assert!(error.reason.contains("without target variables"), "{error}");
        let error =
            SecRuleSet::from_source("SecRuleUpdateTargetById abc ARGS\n")
                .expect_err("must fail");
        assert!(error.reason.contains("not a number"), "{error}");
        let error =
            SecRuleSet::from_source("SecRuleUpdateTargetById 2001 !ARGS:id\n")
                .expect_err("must fail");
        assert!(error.reason.contains("not supported"), "{error}");
    }

    #[test]
    fn skip_jumps_over_rules() {
        let ruleset = SecRuleSet::from_source(
            "SecRule ARGS:a \"@streq 1\" \"id:1,skip:1\"\n\
             SecRule ARGS:a \"@streq 1\" \"id:2,block\"\n\
             SecRule ARGS:a \"@streq 1\" \"id:3,block\"\n",
        )
        .expect("compile");
        let mut txn =
            crate::seclang::transaction::SecLangTransaction::from_request(
                &request("/?a=1"),
            );
        let hits = ruleset.evaluate(&mut txn);
        assert_eq!(hits.len(), 2, "{hits:?}");
        assert_eq!(hits[0].rule_ids, vec![Some(1)]);
        assert_eq!(hits[1].rule_ids, vec![Some(3)]);
    }

    #[test]
    fn skip_after_jumps_to_the_marker() {
        let ruleset = SecRuleSet::from_source(
            "SecRule ARGS:a \"@streq 1\" \"id:1,skipAfter:END\"\n\
             SecRule ARGS:a \"@streq 1\" \"id:2,block\"\n\
             SecMarker END\n\
             SecRule ARGS:a \"@streq 1\" \"id:3,block\"\n",
        )
        .expect("compile");
        assert_eq!(ruleset.group_count(), 3);
        let mut txn =
            crate::seclang::transaction::SecLangTransaction::from_request(
                &request("/?a=1"),
            );
        let hits = ruleset.evaluate(&mut txn);
        assert_eq!(hits.len(), 2, "{hits:?}");
        assert_eq!(hits[0].rule_ids, vec![Some(1)]);
        assert_eq!(hits[1].rule_ids, vec![Some(3)]);
    }

    #[test]
    fn skip_errors_are_observable() {
        let error = SecRuleSet::from_source(
            "SecRule ARGS \"@rx x\" \"id:1,skipAfter:NOPE\"\n",
        )
        .expect_err("must fail");
        assert!(error.reason.contains("not found"), "{error}");

        let error =
            SecRuleSet::from_source("SecRule ARGS \"@rx x\" \"id:1,skip:x\"\n")
                .expect_err("must fail");
        assert!(error.reason.contains("not a number"), "{error}");

        let error =
            SecRuleSet::from_source("SecMarker\n").expect_err("must fail");
        assert!(error.reason.contains("without a name"), "{error}");

        // A skipAfter pointing at a marker *behind* the rule would loop.
        let error = SecRuleSet::from_source(
            "SecMarker TOP\n\
             SecRule ARGS \"@rx x\" \"id:1,skipAfter:TOP\"\n",
        )
        .expect_err("must fail");
        assert!(error.reason.contains("must follow the rule"), "{error}");
    }

    #[test]
    fn unsupported_actions_error_observably() {
        let error = SecRuleSet::from_source(
            "SecRule ARGS \"@rx x\" \"id:1,ctl:ruleEngine=Off\"",
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
