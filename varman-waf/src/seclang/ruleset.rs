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

use std::path::Path;

use crate::seclang::parser::{
    parse_line, parse_quoted, split_actions, validate_macros, SecLangError,
    SecLangLine, SecOperator, SecRuleLine,
};
use crate::seclang::transaction::{
    expand_macros, group_rules, ResolvedValue, SecLangTransaction, SecRuleGroup,
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
    "skipafter:",
    "t:",
    "setvar:",
    "capture",
    "auditlog",
    "ctl:",
    "noauditlog",
    "multimatch",
    "initcol:",
];

/// `true` when the line is a `SecRuleRemoveById` directive (the exact word,
/// or followed by whitespace — never a longer identifier).
fn parsed_removal_directive(trimmed: &str) -> bool {
    trimmed == "SecRuleRemoveById"
        || trimmed
            .strip_prefix("SecRuleRemoveById")
            .is_some_and(|rest| rest.starts_with(char::is_whitespace))
}

/// Join `\`-terminated continuations into logical lines. Comment lines are
/// never continuations; joined parts keep a single space between them (CRS
/// continues between tokens, never inside a quoted value).
fn join_continuations(source: &str) -> Vec<String> {
    let mut logical = Vec::new();
    let mut current: Option<String> = None;
    for raw in source.lines() {
        let trimmed_end = raw.trim_end();
        let comment = trimmed_end.trim_start().starts_with('#');
        let continues = !comment && trimmed_end.ends_with('\\');
        if let Some(mut joined) = current.take() {
            joined.push(' ');
            if continues {
                joined.push_str(&trimmed_end[..trimmed_end.len() - 1]);
                current = Some(joined);
            } else {
                joined.push_str(trimmed_end);
                logical.push(joined);
            }
            continue;
        }
        if continues {
            current = Some(trimmed_end[..trimmed_end.len() - 1].to_string());
        } else {
            logical.push(raw.to_string());
        }
    }
    if let Some(joined) = current {
        logical.push(joined);
    }
    logical
}

/// Parse a `SecAction "…"` line into an unconditional rule.
fn parse_sec_action(trimmed: &str) -> Result<SecRuleLine, SecLangError> {
    let rest = trimmed.trim_start_matches("SecAction").trim();
    let actions_raw = if rest.starts_with('"') {
        parse_quoted(rest, 0)?.0
    } else {
        rest.to_string()
    };
    let actions = split_actions(&actions_raw);
    if actions.is_empty() {
        return Err(SecLangError {
            reason: "SecAction without actions".to_string(),
        });
    }
    Ok(SecRuleLine {
        variables: Vec::new(),
        operator: SecOperator::AlwaysMatch,
        negated: false,
        actions,
    })
}

/// Apply `SecDefaultAction` entries to a rule, per category.
fn merge_default_actions(rule: &mut SecRuleLine, defaults: &[String]) {
    for default in defaults {
        let key = action_key(default);
        let present = rule.actions.iter().any(|a| action_key(a) == key);
        if !present {
            rule.actions.push(default.clone());
        }
    }
}

fn validate_actions(group: &SecRuleGroup) -> Result<(), SecLangError> {
    for rule in &group.rules {
        for action in &rule.line.actions {
            let trimmed = action.trim();
            let lowered = trimmed.to_ascii_lowercase();
            let known = ALLOWED_ACTIONS
                .iter()
                .any(|allowed| lowered.starts_with(allowed));
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
    /// Increment target; the raw value is expanded and parsed when applied.
    Increment(String, String),
}

/// Validated `initcol` operation: creates a collection instance whose key is
/// the expanded value.
#[derive(Debug, Clone, PartialEq, Eq)]
struct InitCol {
    collection: String,
    key: String,
}

/// Case-insensitive action prefix stripping; the action validator accepts
/// case-insensitive names, so execution must match every accepted spelling.
fn strip_action_prefix<'a>(action: &'a str, prefix: &str) -> Option<&'a str> {
    let head = action.get(..prefix.len())?;
    head.eq_ignore_ascii_case(prefix)
        .then(|| &action[prefix.len()..])
}

fn parse_initcol(spec: &str) -> Result<InitCol, SecLangError> {
    let spec = spec.trim().trim_matches('\'').trim_matches('"');
    let Some((collection, key)) = spec.split_once('=') else {
        return Err(SecLangError {
            reason: format!("initcol without '=': {spec:?}"),
        });
    };
    let collection = collection.trim().to_ascii_lowercase();
    const COLLECTIONS: &[&str] =
        &["global", "ip", "user", "session", "resource"];
    if !COLLECTIONS.contains(&collection.as_str()) {
        return Err(SecLangError {
            reason: format!(
                "initcol collection {collection:?} is not supported"
            ),
        });
    }
    let key = key.trim();
    validate_macros(key)?;
    Ok(InitCol {
        collection,
        key: key.to_string(),
    })
}

fn parse_setvar(spec: &str) -> Result<SetVar, SecLangError> {
    let spec = spec.trim().trim_matches('\'').trim_matches('"');
    let Some((target, value)) = spec.split_once('=') else {
        return Err(SecLangError {
            reason: format!("setvar without '=': {spec:?}"),
        });
    };
    let target = target.trim();
    validate_macros(target)?;
    let Some(name) = target
        .strip_prefix("tx.")
        .or_else(|| target.strip_prefix("TX."))
    else {
        return Err(SecLangError {
            reason: format!("setvar target {target:?} is not a TX variable"),
        });
    };
    let value = value.trim();
    validate_macros(value)?;
    if let Some(delta) =
        value.strip_prefix('+').or_else(|| value.strip_prefix('-'))
    {
        // The offset may reference macros; its final shape is checked when
        // applied. A literal must parse now to stay observable.
        if !delta.contains("%{") && delta.parse::<i64>().is_err() {
            return Err(SecLangError {
                reason: format!("setvar offset {value:?} is not a number"),
            });
        }
        let sign = if value.starts_with('-') { "-" } else { "" };
        return Ok(SetVar::Increment(
            name.to_string(),
            format!("{sign}{}", delta.trim()),
        ));
    }
    Ok(SetVar::Assign(name.to_string(), value.to_string()))
}

/// Expand macros in a `setvar` target and strip the `tx.` prefix
/// (case-insensitive).
fn target_name(raw: &str, txn: &SecLangTransaction) -> String {
    let expanded = expand_macros(raw, txn);
    let name = expanded
        .strip_prefix("tx.")
        .or_else(|| expanded.strip_prefix("TX."))
        .unwrap_or(&expanded);
    name.to_string()
}

fn apply_setvar(txn: &mut SecLangTransaction, op: &SetVar) {
    match op {
        SetVar::Assign(name, value) => {
            let name = target_name(name, txn);
            let value = expand_macros(value, txn);
            txn.tx_set(&name, value);
        },
        SetVar::Increment(name, delta) => {
            let name = target_name(name, txn);
            let current: i64 = txn
                .tx_get(&name)
                .and_then(|v| v.trim().parse().ok())
                .unwrap_or(0);
            // Unresolvable macros expand to empty and contribute zero,
            // mirroring ModSecurity's numeric coercion.
            let expanded = expand_macros(delta, txn);
            let delta: i64 = expanded.trim().parse().unwrap_or(0);
            txn.tx_set(&name, (current + delta).to_string());
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
    /// `setvar` operations per group, then per chain member: a member's
    /// actions run before the next member evaluates.
    setvars: Vec<Vec<Vec<SetVar>>>,
    /// `skip:N` per group: skip the next N groups after a match.
    skip_groups: Vec<Option<u64>>,
    /// `skipAfter:NAME` per group: resolved index to continue at.
    skip_after: Vec<Option<usize>>,
    /// `ctl:` operations per group.
    ctl_ops: Vec<Vec<CtlOp>>,
    /// `initcol` operations per group.
    initcols: Vec<Vec<InitCol>>,
}

/// `ctl:ruleEngine` values: `On` (default), `DetectionOnly` (matches are
/// recorded but disruptive actions are stripped), `Off` (evaluation stops).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CtlMode {
    On,
    DetectionOnly,
    Off,
}

/// A validated `ctl:` operation.
#[derive(Debug, Clone, PartialEq, Eq)]
enum CtlOp {
    RuleEngine(CtlMode),
    BodyProcessor(String),
    RemoveById(u64),
    RemoveByTag(String),
    RemoveTargetByTag(String, String),
    AuditEngine,
    ForceRequestBody,
}

fn parse_ctl(spec: &str) -> Result<CtlOp, SecLangError> {
    let spec = spec.trim().trim_matches('\'').trim_matches('"');
    let Some((name, value)) = spec.split_once('=') else {
        return Err(SecLangError {
            reason: format!("ctl without '=': {spec:?}"),
        });
    };
    let name = name.trim().to_ascii_lowercase();
    let value = value.trim();
    match name.as_str() {
        "ruleengine" => Ok(CtlOp::RuleEngine(
            match value.to_ascii_lowercase().as_str() {
                "on" => CtlMode::On,
                "detectiononly" => CtlMode::DetectionOnly,
                "off" => CtlMode::Off,
                other => {
                    return Err(SecLangError {
                        reason: format!(
                            "unsupported ctl:ruleEngine value {other:?}"
                        ),
                    });
                },
            },
        )),
        "requestbodyprocessor" => {
            let processor = value.to_ascii_uppercase();
            match processor.as_str() {
                "JSON" | "URLENCODED" => Ok(CtlOp::BodyProcessor(processor)),
                other => Err(SecLangError {
                    reason: format!(
                        "unsupported ctl:requestBodyProcessor {other:?}"
                    ),
                }),
            }
        },
        "ruleremovebyid" => value
            .parse::<u64>()
            .map(CtlOp::RemoveById)
            .map_err(|_| SecLangError {
                reason: format!(
                    "ctl:ruleRemoveById id {value:?} is not a number"
                ),
            }),
        "ruleremovebytag" => Ok(CtlOp::RemoveByTag(value.to_string())),
        "ruleremovetargetbytag" => {
            let Some((tag, target)) = value.split_once(';') else {
                return Err(SecLangError {
                    reason: format!(
                        "ctl:ruleRemoveTargetByTag needs 'tag;target': {value:?}"
                    ),
                });
            };
            Ok(CtlOp::RemoveTargetByTag(
                tag.trim().to_string(),
                target.trim().to_string(),
            ))
        },
        "auditengine" => Ok(CtlOp::AuditEngine),
        "forcerequestbodyvariable" => Ok(CtlOp::ForceRequestBody),
        other => Err(SecLangError {
            reason: format!("unsupported ctl option {other:?}"),
        }),
    }
}

impl SecRuleSet {
    /// Parse and compile a SecLang source (comments and blank lines skipped).
    ///
    /// `SecRuleRemoveById <ids…>` lines remove the named rules from the set
    /// before compilation (the mechanism OWASP CRS uses to tune itself).
    pub fn from_source(source: &str) -> Result<Self, SecLangError> {
        Self::from_source_with_base(source, None)
    }

    /// Like [`Self::from_source`], with a base directory used to resolve
    /// `@pmFromFile` data files.
    pub fn from_source_with_base(
        source: &str,
        base_dir: Option<&Path>,
    ) -> Result<Self, SecLangError> {
        let mut removals: Vec<u64> = Vec::new();
        let mut retargets: Vec<(u64, Vec<String>)> = Vec::new();
        // `SecMarker` positions in the rule stream: `(name, rules_seen)`.
        let mut markers: Vec<(String, usize)> = Vec::new();
        // `SecDefaultAction` applies to every rule that follows it.
        let mut defaults: Vec<String> = Vec::new();
        let mut rules = Vec::new();
        for line in join_continuations(source) {
            let trimmed = line.trim();
            if trimmed == "SecDefaultAction"
                || trimmed.starts_with("SecDefaultAction ")
            {
                let rest =
                    trimmed.trim_start_matches("SecDefaultAction").trim();
                let actions_raw = if rest.starts_with('"') {
                    parse_quoted(rest, 0)?.0
                } else {
                    rest.to_string()
                };
                let parsed_defaults = split_actions(&actions_raw);
                if parsed_defaults.is_empty() {
                    return Err(SecLangError {
                        reason: "SecDefaultAction without actions".to_string(),
                    });
                }
                defaults = parsed_defaults;
                continue;
            }
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
                let variables_raw = variables_raw.trim().trim_matches('"');
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
                retargets.push((id, variables));
                continue;
            }
            if trimmed == "SecComponentSignature"
                || trimmed.starts_with("SecComponentSignature ")
            {
                // Metadata ModSecurity records verbatim; accepted with an
                // argument, otherwise it has no runtime effect.
                let value = trimmed
                    .trim_start_matches("SecComponentSignature")
                    .trim()
                    .trim_matches('"');
                if value.is_empty() {
                    return Err(SecLangError {
                        reason: "SecComponentSignature without a value"
                            .to_string(),
                    });
                }
                continue;
            }
            if trimmed == "SecAction" || trimmed.starts_with("SecAction ") {
                let mut rule = parse_sec_action(trimmed)?;
                merge_default_actions(&mut rule, &defaults);
                rules.push(rule);
                continue;
            }
            match parse_line(&line)? {
                SecLangLine::Ignored => {},
                SecLangLine::Rule(mut rule) => {
                    merge_default_actions(&mut rule, &defaults);
                    rules.push(rule);
                },
            }
        }
        if !retargets.is_empty() {
            for rule in &mut rules {
                let rule_id = rule.actions.iter().find_map(|action| {
                    action
                        .strip_prefix("id:")
                        .and_then(|id| id.trim().parse::<u64>().ok())
                });
                let Some(id) = rule_id else { continue };
                for (target, entries) in &retargets {
                    if *target != id {
                        continue;
                    }
                    // A non-negated target list replaces the rule's targets;
                    // `!VAR` entries are exclusions appended to the list (the
                    // evaluator filters matching resolved values).
                    let positives: Vec<String> = entries
                        .iter()
                        .filter(|entry| !entry.starts_with('!'))
                        .cloned()
                        .collect();
                    if !positives.is_empty() {
                        rule.variables = positives;
                    }
                    for entry in
                        entries.iter().filter(|entry| entry.starts_with('!'))
                    {
                        if !rule.variables.iter().any(|v| v == entry) {
                            rule.variables.push(entry.clone());
                        }
                    }
                }
            }
        }
        // Resolve `@pmFromFile` data files before compilation.
        for rule in &mut rules {
            let path = match &rule.operator {
                SecOperator::PmFromFile(path) => path.clone(),
                _ => continue,
            };
            let Some(base) = base_dir else {
                return Err(SecLangError {
                    reason: format!(
                        "@pmFromFile {path:?} needs a base directory; use SecRuleSet::from_source_with_base"
                    ),
                });
            };
            let full = base.join(&path);
            // Data files are read as bytes: shared-folder mounts can return
            // `EINVAL` for `read_to_string`, and pattern files are ASCII in
            // practice.
            let bytes = std::fs::read(&full).map_err(|error| SecLangError {
                reason: format!(
                    "@pmFromFile {path:?} could not be read from {}: {error}",
                    full.display()
                ),
            })?;
            let content = String::from_utf8_lossy(&bytes);
            let patterns: Vec<String> = content
                .lines()
                .map(str::trim)
                .filter(|line| !line.is_empty() && !line.starts_with('#'))
                .map(str::to_string)
                .collect();
            if patterns.is_empty() {
                return Err(SecLangError {
                    reason: format!(
                        "@pmFromFile {path:?} contains no patterns"
                    ),
                });
            }
            rule.operator = SecOperator::Pm(patterns);
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
        let mut setvars: Vec<Vec<Vec<SetVar>>> =
            Vec::with_capacity(groups.len());
        let mut initcols: Vec<Vec<InitCol>> = Vec::with_capacity(groups.len());
        for group in &groups {
            validate_actions(group)?;
            let mut group_ops = Vec::with_capacity(group.rules.len());
            let mut cols = Vec::new();
            for rule in &group.rules {
                let mut rule_ops = Vec::new();
                for action in &rule.line.actions {
                    let action = action.trim();
                    if let Some(spec) = strip_action_prefix(action, "setvar:") {
                        rule_ops.push(parse_setvar(spec)?);
                    } else if let Some(spec) =
                        strip_action_prefix(action, "initcol:")
                    {
                        cols.push(parse_initcol(spec)?);
                    }
                }
                group_ops.push(rule_ops);
            }
            setvars.push(group_ops);
            initcols.push(cols);
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
        let mut ctl_ops: Vec<Vec<CtlOp>> = Vec::with_capacity(groups.len());
        for (index, group) in groups.iter().enumerate() {
            let actions = group
                .rules
                .last()
                .map(|rule| rule.line.actions.clone())
                .unwrap_or_default();
            let mut skip_count: Option<u64> = None;
            let mut after_name: Option<String> = None;
            let mut ctl_ops_for_group: Vec<CtlOp> = Vec::new();
            for action in &actions {
                let action = action.trim();
                if let Some(rest) = strip_action_prefix(action, "skip:") {
                    skip_count =
                        Some(rest.trim().parse::<u64>().map_err(|_| {
                            SecLangError {
                                reason: format!(
                                    "skip count {rest:?} is not a number"
                                ),
                            }
                        })?);
                } else if let Some(name) =
                    strip_action_prefix(action, "skipafter:")
                {
                    after_name = Some(name.trim().to_string());
                } else if let Some(spec) = strip_action_prefix(action, "ctl:") {
                    ctl_ops_for_group.push(parse_ctl(spec)?);
                }
            }
            skip_groups.push(skip_count);
            ctl_ops.push(ctl_ops_for_group);
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
            ctl_ops,
            initcols,
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
        let mut mode = CtlMode::On;
        while index < self.groups.len() {
            let group = &self.groups[index];
            // Dynamic removal (`ctl:ruleRemoveById` / `ctl:ruleRemoveByTag`).
            let removed = group.rules.iter().any(|rule| {
                rule.rule_id().is_some_and(|id| txn.is_rule_removed(id))
                    || rule.tags().iter().any(|tag| txn.is_tag_removed(tag))
            });
            if removed {
                index += 1;
                continue;
            }
            let Some(variables_hit) =
                evaluate_group(group, txn, &self.setvars[index])
            else {
                index += 1;
                continue;
            };
            for collection in &self.initcols[index] {
                let key = expand_macros(&collection.key, txn);
                txn.register_collection(&collection.collection, &key);
            }
            let mut actions = group
                .rules
                .last()
                .map(|rule| rule.line.actions.clone())
                .unwrap_or_default();
            for op in &self.ctl_ops[index] {
                match op {
                    CtlOp::RuleEngine(new_mode) => mode = *new_mode,
                    CtlOp::BodyProcessor(processor) => {
                        txn.set_body_processor(processor);
                        if processor == "JSON" {
                            txn.parse_json_body();
                        }
                    },
                    CtlOp::RemoveById(id) => txn.remove_rule_id(*id),
                    CtlOp::RemoveByTag(tag) => txn.remove_rule_tag(tag),
                    CtlOp::RemoveTargetByTag(tag, target) => {
                        txn.remove_rule_target(tag, target)
                    },
                    // Accepted and documented: there is no audit subsystem
                    // yet, and the raw body is always exposed as
                    // `REQUEST_BODY`.
                    CtlOp::ForceRequestBody => txn.set_force_request_body(true),
                    CtlOp::AuditEngine => {},
                }
            }
            if mode == CtlMode::DetectionOnly {
                actions
                    .retain(|a| !matches!(a.trim(), "block" | "deny" | "drop"));
            }
            let stop = mode == CtlMode::Off;
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
            if stop {
                break;
            }
            index = next;
        }
        hits
    }
}

/// Match a group, honouring `capture`: when a member carries the `capture`
/// action its regex groups are written to `TX:0…9` before the next member
/// resolves its variables.
fn evaluate_group(
    group: &SecRuleGroup,
    txn: &mut SecLangTransaction,
    setvars: &[Vec<SetVar>],
) -> Option<Vec<ResolvedValue>> {
    let mut all = Vec::new();
    let mut previous: Vec<ResolvedValue> = Vec::new();
    for (index, rule) in group.rules.iter().enumerate() {
        // Chain semantics: each member sees the previous member's matches
        // through `MATCHED_VARS`.
        txn.set_matched_vars(if index == 0 {
            Vec::new()
        } else {
            previous.clone()
        });
        let excluded = txn.removed_targets_for(&rule.tags());
        let hits = rule.matches_excluding(txn, &excluded);
        if hits.is_empty() {
            return None;
        }
        txn.set_matched(hits.first().cloned());
        if rule.has_capture() {
            if let Some(first) = hits.first() {
                // Captures run on the transformed value: the regex matched
                // it, not the original (ModSecurity captures post-transform).
                rule.captures_into(&rule.transformed(&first.value), txn);
            }
        }
        // Chain-member actions run immediately: the next member can read
        // TX variables this member sets (CRS 920420, 931130 rely on this).
        if let Some(ops) = setvars.get(index) {
            for op in ops {
                apply_setvar(txn, op);
            }
        }
        // The next chain member sees transformed values (ModSecurity binds
        // the post-transform match into `MATCHED_VARS`).
        previous = hits
            .iter()
            .map(|hit| ResolvedValue {
                name: hit.name.clone(),
                value: rule.transformed(&hit.value),
                invalid_utf8: hit.invalid_utf8,
            })
            .collect();
        all.extend(hits);
    }
    Some(all)
}

/// Merge key for action deduplication: a rule's explicit action wins over a
/// `SecDefaultAction` entry of the same category.
fn action_key(action: &str) -> String {
    let action = action.trim();
    if action.starts_with("phase:") {
        return "phase".to_string();
    }
    match action {
        "block" | "deny" | "drop" | "pass" | "allow" => {
            "disposition".to_string()
        },
        "log" | "nolog" | "auditlog" => "audit".to_string(),
        "capture" => "capture".to_string(),
        other => other.to_string(),
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

        // Second member failing means no hit; earlier members' `setvar`
        // effects remain (ModSecurity has no rollback; CRS 920420 relies
        // on member actions running before the next member evaluates).
        let mut partial =
            crate::seclang::transaction::SecLangTransaction::from_request(
                &request("/?a=1&b=9"),
            );
        assert!(ruleset.evaluate(&mut partial).is_empty());
        assert_eq!(partial.tx_get("n"), Some("1"));
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
    }

    #[test]
    fn update_target_exclusions_keep_other_targets() {
        // Mirrors CRS 999: quoted `!`-exclusions must not clobber the rule's
        // other targets (ARGS/ARGS_NAMES here).
        let ruleset = SecRuleSet::from_source(
            "SecRule ARGS|ARGS_NAMES|REQUEST_COOKIES \"@streq evil\" \"id:100,block\"\n\
             SecRuleUpdateTargetById 100 \"!REQUEST_COOKIES:/^_ga(?:_\\w+)?$/\"\n\
             SecRuleUpdateTargetById 100 \"!REQUEST_COOKIES:__gads\"\n",
        )
        .expect("compile");
        let mut txn =
            crate::seclang::transaction::SecLangTransaction::from_request(
                &request("/?a=evil"),
            );
        let hits = ruleset.evaluate(&mut txn);
        assert_eq!(hits.len(), 1, "{hits:?}");
        assert_eq!(hits[0].rule_ids, vec![Some(100)]);
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
    fn capture_writes_regex_groups_to_tx() {
        let ruleset = SecRuleSet::from_source(
            "SecRule ARGS:credential \"@rx ^(\\w+):(\\w+)$\" \"id:1,chain,capture\"\n\
             SecRule TX:2 \"@streq secret\" \"id:2,block\"\n\
             SecRule TX:1 \"@streq user\" \"id:3,block\"\n",
        )
        .expect("compile");
        let mut txn =
            crate::seclang::transaction::SecLangTransaction::from_request(
                &request("/?credential=user:secret"),
            );
        let hits = ruleset.evaluate(&mut txn);
        assert_eq!(hits.len(), 2, "{hits:?}");
        assert_eq!(hits[0].rule_ids, vec![Some(1), Some(2)]);
        assert_eq!(hits[1].rule_ids, vec![Some(3)]);
        assert_eq!(txn.tx_get("0"), Some("user:secret"));
        assert_eq!(txn.tx_get("1"), Some("user"));
        assert_eq!(txn.tx_get("2"), Some("secret"));
    }

    #[test]
    fn without_capture_the_chain_cannot_see_groups() {
        let ruleset = SecRuleSet::from_source(
            "SecRule ARGS:credential \"@rx ^(\\w+):(\\w+)$\" \"id:1,chain\"\n\
             SecRule TX:2 \"@streq secret\" \"id:2,block\"\n",
        )
        .expect("compile");
        let mut txn =
            crate::seclang::transaction::SecLangTransaction::from_request(
                &request("/?credential=user:secret"),
            );
        assert!(ruleset.evaluate(&mut txn).is_empty());
        assert!(txn.tx_get("2").is_none());
    }

    #[test]
    fn default_actions_fill_in_missing_categories() {
        let ruleset = SecRuleSet::from_source(
            "SecDefaultAction \"phase:1,log,pass\"\n\
             SecRule ARGS:a \"@streq 1\" \"id:1\"\n",
        )
        .expect("compile");
        let mut txn =
            crate::seclang::transaction::SecLangTransaction::from_request(
                &request("/?a=1"),
            );
        let hits = ruleset.evaluate(&mut txn);
        assert_eq!(hits.len(), 1);
        let actions = &hits[0].actions;
        assert!(actions.iter().any(|a| a == "phase:1"), "{actions:?}");
        assert!(actions.iter().any(|a| a == "log"), "{actions:?}");
        assert!(actions.iter().any(|a| a == "pass"), "{actions:?}");

        // A rule's explicit action wins within its category; other categories
        // still fill in.
        let explicit = SecRuleSet::from_source(
            "SecDefaultAction \"phase:1,log,pass\"\n\
             SecRule ARGS:a \"@streq 1\" \"id:2,phase:2,block\"\n",
        )
        .expect("compile");
        let mut txn =
            crate::seclang::transaction::SecLangTransaction::from_request(
                &request("/?a=1"),
            );
        let hits = explicit.evaluate(&mut txn);
        let actions = &hits[0].actions;
        assert!(actions.iter().any(|a| a == "phase:2"), "{actions:?}");
        assert!(!actions.iter().any(|a| a == "phase:1"), "{actions:?}");
        assert!(actions.iter().any(|a| a == "block"), "{actions:?}");
        assert!(
            !actions.iter().any(|a| a == "pass"),
            "explicit disposition wins: {actions:?}"
        );
        assert!(actions.iter().any(|a| a == "log"), "{actions:?}");
    }

    #[test]
    fn default_action_requires_actions() {
        let error = SecRuleSet::from_source("SecDefaultAction\n")
            .expect_err("must fail");
        assert!(error.reason.contains("without actions"), "{error}");
    }

    #[test]
    fn continuations_join_logical_lines() {
        let ruleset = SecRuleSet::from_source(
            "SecRule ARGS:a \"@streq 1\" \\\n    \"id:1,phase:2,block\"\n",
        )
        .expect("compile");
        let mut txn =
            crate::seclang::transaction::SecLangTransaction::from_request(
                &request("/?a=1"),
            );
        let hits = ruleset.evaluate(&mut txn);
        assert_eq!(hits.len(), 1, "{hits:?}");
        assert_eq!(hits[0].rule_ids, vec![Some(1)]);
    }

    #[test]
    fn sec_action_matches_unconditionally() {
        let ruleset = SecRuleSet::from_source(
            "SecAction \"phase:1,pass,setvar:tx.score=7\"\n\
             SecRule TX:score \"@eq 7\" \"id:1,block\"\n",
        )
        .expect("compile");
        let mut txn =
            crate::seclang::transaction::SecLangTransaction::from_request(
                &request("/"),
            );
        let hits = ruleset.evaluate(&mut txn);
        assert_eq!(hits.len(), 2, "SecAction fires too: {hits:?}");
        assert_eq!(hits[1].rule_ids, vec![Some(1)]);

        let error =
            SecRuleSet::from_source("SecAction\n").expect_err("must fail");
        assert!(error.reason.contains("without actions"), "{error}");
    }

    #[test]
    fn component_signature_is_metadata() {
        let ruleset = SecRuleSet::from_source(
            "SecComponentSignature \"coreruleset-4.31.0-dev\"\n\
             SecRule ARGS:a \"@streq 1\" \"id:1\"\n",
        )
        .expect("compile");
        let mut txn =
            crate::seclang::transaction::SecLangTransaction::from_request(
                &request("/?a=1"),
            );
        assert_eq!(ruleset.evaluate(&mut txn).len(), 1);
        let error = SecRuleSet::from_source("SecComponentSignature\n")
            .expect_err("must fail");
        assert!(error.reason.contains("without a value"), "{error}");
    }

    #[test]
    fn setvar_expands_macros() {
        let ruleset = SecRuleSet::from_source(
            "SecAction \"phase:1,pass,setvar:tx.base=5\"\n\
             SecAction \"phase:1,pass,setvar:tx.total=+%{tx.base}\"\n\
             SecRule TX:total \"@eq 5\" \"id:1,block\"\n",
        )
        .expect("compile");
        let mut txn =
            crate::seclang::transaction::SecLangTransaction::from_request(
                &request("/"),
            );
        let hits = ruleset.evaluate(&mut txn);
        assert_eq!(hits.len(), 3, "{hits:?}");
        assert_eq!(hits[2].rule_ids, vec![Some(1)]);
    }

    #[test]
    fn setvar_target_expands_matched_var_name() {
        let ruleset = SecRuleSet::from_source(
            "SecRule ARGS:a \"@streq 1\" \"id:1,setvar:tx.matched_%{MATCHED_VAR_NAME}=%{MATCHED_VAR}\"\n\
             SecRule TX:matched_ARGS:a \"@streq 1\" \"id:2,block\"\n",
        )
        .expect("compile");
        let mut txn =
            crate::seclang::transaction::SecLangTransaction::from_request(
                &request("/?a=1"),
            );
        let hits = ruleset.evaluate(&mut txn);
        assert_eq!(hits.len(), 2, "{hits:?}");
        assert_eq!(txn.tx_get("matched_args:a"), Some("1"));
        assert_eq!(hits[1].rule_ids, vec![Some(2)]);
    }

    #[test]
    fn pm_from_file_loads_against_a_base_directory() {
        let dir = std::env::temp_dir();
        let file = dir.join("varman-pmfromfile-test.data");
        std::fs::write(&file, "# comment\nfoo\nbar\n").expect("write");
        let ruleset = SecRuleSet::from_source_with_base(
            "SecRule ARGS:a \"@pmFromFile varman-pmfromfile-test.data\" \"id:1\"\n",
            Some(&dir),
        )
        .expect("compile");
        let mut txn =
            crate::seclang::transaction::SecLangTransaction::from_request(
                &request("/?a=foo"),
            );
        assert_eq!(ruleset.evaluate(&mut txn).len(), 1);
        let _ = std::fs::remove_file(&file);

        let error = SecRuleSet::from_source(
            "SecRule ARGS:a \"@pmFromFile missing.data\" \"id:1\"\n",
        )
        .expect_err("must fail");
        assert!(error.reason.contains("base directory"), "{error}");
    }

    #[test]
    fn multi_match_records_every_value() {
        let ruleset = SecRuleSet::from_source(
            "SecRule ARGS:a \"@rx ^[0-9]$\" \"id:1,multiMatch\"\n",
        )
        .expect("compile");
        let mut txn =
            crate::seclang::transaction::SecLangTransaction::from_request(
                &request("/?a=1&a=2"),
            );
        let hits = ruleset.evaluate(&mut txn);
        assert_eq!(hits.len(), 1);
        assert_eq!(
            hits[0].variables_hit.len(),
            2,
            "{:?}",
            hits[0].variables_hit
        );

        let single = SecRuleSet::from_source(
            "SecRule ARGS:a \"@rx ^[0-9]$\" \"id:2\"\n",
        )
        .expect("compile");
        let mut txn =
            crate::seclang::transaction::SecLangTransaction::from_request(
                &request("/?a=1&a=2"),
            );
        let hits = single.evaluate(&mut txn);
        assert_eq!(hits[0].variables_hit.len(), 1);
    }

    #[test]
    fn initcol_registers_an_expanded_collection() {
        let ruleset = SecRuleSet::from_source(
            "SecRule ARGS:a \"@streq 1\" \"id:1,initcol:ip=%{MATCHED_VAR}\"\n",
        )
        .expect("compile");
        let mut txn =
            crate::seclang::transaction::SecLangTransaction::from_request(
                &request("/?a=1"),
            );
        ruleset.evaluate(&mut txn);
        assert!(txn.has_collection("ip", "1"));

        let error = SecRuleSet::from_source(
            "SecRule ARGS:a \"@streq 1\" \"id:1,initcol:wat=x\"\n",
        )
        .expect_err("must fail");
        assert!(error.reason.contains("initcol"), "{error}");
    }

    #[test]
    fn chains_bind_matched_vars_between_members() {
        // Mirrors CRS 944120's shape: the first member matches the payload,
        // the second member matches the previous member's `MATCHED_VARS`.
        let ruleset = SecRuleSet::from_source(
            "SecRule ARGS \"@rx clonetransformer\" \"id:1,chain\"\n\
             SecRule MATCHED_VARS \"@rx processbuilder\" \"id:2,block\"\n",
        )
        .expect("compile");
        let mut txn =
            crate::seclang::transaction::SecLangTransaction::from_request(
                &request("/?a=evilprocessbuilder_clonetransformer"),
            );
        let hits = ruleset.evaluate(&mut txn);
        assert_eq!(hits.len(), 1, "{hits:?}");
        assert_eq!(hits[0].rule_ids, vec![Some(1), Some(2)]);

        // Without the second keyword in the matched value the chain fails.
        let mut txn =
            crate::seclang::transaction::SecLangTransaction::from_request(
                &request("/?a=justclonetransformer"),
            );
        assert!(ruleset.evaluate(&mut txn).is_empty());
    }

    #[test]
    fn ctl_json_body_processor_populates_args() {
        let ruleset = SecRuleSet::from_source(
            "SecRule REQUEST_HEADERS:Content-Type \"@contains json\" \"id:1,ctl:requestBodyProcessor=JSON\"\n\
             SecRule ARGS:json.var \"@contains OR 1=1\" \"id:2,block\"\n",
        )
        .expect("compile");
        let request = Canonicalizer::default().canonicalize(
            RequestParts::new("POST", "example.com", "/")
                .with_header("Content-Type", "application/json")
                .with_body(br#"{"var":"1234 OR 1=1"}"#.to_vec()),
        );
        let mut txn =
            crate::seclang::transaction::SecLangTransaction::from_request(
                &request,
            );
        let hits = ruleset.evaluate(&mut txn);
        assert!(
            hits.iter().any(|hit| hit.rule_ids == vec![Some(2)]),
            "{hits:?}"
        );
        assert_eq!(txn.resolve("REQBODY_PROCESSOR")[0].value, "JSON");
    }

    #[test]
    fn ctl_rule_removal_and_unknown_options() {
        let ruleset = SecRuleSet::from_source(
            "SecRule ARGS:a \"@streq 1\" \"id:1,ctl:ruleRemoveById=2\"\n\
             SecRule ARGS:a \"@streq 1\" \"id:2,block\"\n",
        )
        .expect("compile");
        let mut txn =
            crate::seclang::transaction::SecLangTransaction::from_request(
                &request("/?a=1"),
            );
        let hits = ruleset.evaluate(&mut txn);
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].rule_ids, vec![Some(1)]);

        let by_tag = SecRuleSet::from_source(
            "SecRule ARGS:a \"@streq 1\" \"id:1,ctl:ruleRemoveByTag=attack\"\n\
             SecRule ARGS:a \"@streq 1\" \"id:2,tag:'attack',block\"\n",
        )
        .expect("compile");
        let mut txn =
            crate::seclang::transaction::SecLangTransaction::from_request(
                &request("/?a=1"),
            );
        assert_eq!(by_tag.evaluate(&mut txn).len(), 1);

        let error = SecRuleSet::from_source(
            "SecRule ARGS:a \"@streq 1\" \"id:1,ctl:wat=1\"\n",
        )
        .expect_err("must fail");
        assert!(error.reason.contains("unsupported ctl option"), "{error}");
    }

    #[test]
    fn ctl_rule_remove_target_by_tag_filters_variables() {
        let ruleset = SecRuleSet::from_source(
            "SecRule ARGS:skip \"@streq evil\" \"id:1,ctl:ruleRemoveTargetByTag=xss-perf-disable;ARGS:skip\"\n\
             SecRule ARGS:skip \"@streq evil\" \"id:2,tag:'xss-perf-disable',block\"\n",
        )
        .expect("compile");
        let mut txn =
            crate::seclang::transaction::SecLangTransaction::from_request(
                &request("/?skip=evil"),
            );
        let hits = ruleset.evaluate(&mut txn);
        assert_eq!(hits.len(), 1, "{hits:?}");
        assert_eq!(hits[0].rule_ids, vec![Some(1)]);

        let error = SecRuleSet::from_source(
            "SecRule ARGS:a \"@streq 1\" \"id:1,ctl:ruleRemoveTargetByTag=notag\"\n",
        )
        .expect_err("must fail");
        assert!(error.reason.contains("tag;target"), "{error}");
    }

    #[test]
    fn captures_use_transformed_values() {
        let ruleset = SecRuleSet::from_source(
            "SecRule ARGS:a \"@rx ^prefix-(.*)$\" \"id:1,t:lowercase,capture,chain,setvar:tx.got=%{tx.1}\"\n\
             SecRule TX:got \"@streq value\" \"id:2,block\"\n",
        )
        .expect("compile");
        let mut txn =
            crate::seclang::transaction::SecLangTransaction::from_request(
                &request("/?a=PREFIX-VALUE"),
            );
        let hits = ruleset.evaluate(&mut txn);
        assert_eq!(hits.len(), 1, "{hits:?}");
        assert_eq!(txn.tx_get("got"), Some("value"));
    }

    #[test]
    fn ctl_rule_engine_detection_only_strips_disruptive_actions() {
        let ruleset = SecRuleSet::from_source(
            "SecRule ARGS:a \"@streq 1\" \"id:1,ctl:ruleEngine=DetectionOnly\"\n\
             SecRule ARGS:a \"@streq 1\" \"id:2,block\"\n\
             SecRule ARGS:a \"@streq 1\" \"id:3,ctl:ruleEngine=On\"\n\
             SecRule ARGS:a \"@streq 1\" \"id:4,block\"\n",
        )
        .expect("compile");
        let mut txn =
            crate::seclang::transaction::SecLangTransaction::from_request(
                &request("/?a=1"),
            );
        let hits = ruleset.evaluate(&mut txn);
        assert_eq!(hits.len(), 4, "{hits:?}");
        assert!(
            !hits[1].actions.iter().any(|a| a == "block"),
            "detection-only stays undetected as disruptive: {:?}",
            hits[1].actions
        );
        assert!(
            hits[3].actions.iter().any(|a| a == "block"),
            "back on, block is recorded again: {:?}",
            hits[3].actions
        );
    }

    #[test]
    fn ctl_rule_engine_off_stops_and_validates() {
        let ruleset = SecRuleSet::from_source(
            "SecRule ARGS:a \"@streq 1\" \"id:1,ctl:ruleEngine=Off\"\n\
             SecRule ARGS:a \"@streq 1\" \"id:2,block\"\n",
        )
        .expect("compile");
        let mut txn =
            crate::seclang::transaction::SecLangTransaction::from_request(
                &request("/?a=1"),
            );
        let hits = ruleset.evaluate(&mut txn);
        assert_eq!(hits.len(), 1, "{hits:?}");
        assert_eq!(hits[0].rule_ids, vec![Some(1)]);

        let error = SecRuleSet::from_source(
            "SecRule ARGS \"@rx x\" \"id:1,ctl:ruleEngine=Maybe\"\n",
        )
        .expect_err("must fail");
        assert!(
            error.reason.contains("unsupported ctl:ruleEngine"),
            "{error}"
        );
    }

    #[test]
    fn unsupported_actions_error_observably() {
        let error = SecRuleSet::from_source(
            "SecRule ARGS \"@rx x\" \"id:1,expirevar:tx.x=1\"",
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
            ("tx.c=+2", SetVar::Increment("c".into(), "2".into())),
            ("tx.c=-3", SetVar::Increment("c".into(), "-3".into())),
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
