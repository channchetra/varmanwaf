//! "Why was this blocked?" - resolves one security event's decision chain
//! from what the control plane actually stores.
//!
//! Every step names its source: the event row, an automatic IP block, the
//! rule id (managed catalogue / imported CRS catalogue / policy layer / site
//! rule / virtual patch), the site's current policy binding, and the rule
//! tuning that applied. What cannot be determined is reported as `unknown`
//! with a note - never guessed.

use chrono::Utc;
use sea_orm::{
    ColumnTrait, DatabaseConnection, DbErr, EntityTrait, QueryFilter,
};
use serde::Serialize;
use serde_json::{json, Value};
use uuid::Uuid;

use crate::models::{
    agent_blocked_ip, crs_rule, crs_ruleset, rule, security_event,
    site_waf_policy, waf_policy, waf_policy_layer,
};
use crate::policy;
use varman_waf::rules::signatures::builtin_signature_info;

/// One resolved stage of the decision chain.
#[derive(Debug, Serialize)]
pub struct Step {
    /// `event` / `auto_block` / `rate_limit` / `bot` / `waf_rule` /
    /// `policy` / `tuning`.
    pub stage: &'static str,
    /// `hit`, `miss` or `unknown`.
    pub status: &'static str,
    pub title: String,
    pub detail: String,
    /// Raw resolved data, so the console can show the details without
    /// re-parsing prose.
    pub data: Value,
}

/// One rule or signature that fired while evaluating the request.
///
/// `waf_details` carries every match, in engine order. The why-chain resolves
/// each one independently so the console can show *all* evidence, not only the
/// first id the agent happened to store on the event row.
#[derive(Debug, Serialize)]
pub struct MatchedRule {
    pub id: String,
    pub name: String,
    /// `managed` / `signature` / `crs_import` / `policy` / `site_rule` /
    /// `patch` / `detector` / `unknown`.
    pub source: String,
    /// `hit` or `unknown`.
    pub status: String,
    pub severity: Option<u8>,
    pub action: Option<String>,
    pub category: Option<String>,
    /// `true` when this rule's action produced the event verdict.
    pub deciding: bool,
    /// Where/how it matched, extracted from `waf_details`
    /// (e.g. `in header 'user-agent'`).
    pub evidence: Option<String>,
    /// Human-readable provenance, ready to render.
    pub detail: String,
    /// Raw resolved data, so the console can show structured details.
    pub data: Value,
}

/// The full explanation for one event.
#[derive(Debug, Serialize)]
pub struct Explanation {
    /// `blocked`, `monitored`, `challenged`, `allowed` or `unknown`.
    pub verdict: &'static str,
    /// The rule id whose stage produced the verdict, when one did.
    pub blocked_by: Option<String>,
    /// Every rule/signature that fired, with its source and the deciding flag.
    pub matched_rules: Vec<MatchedRule>,
    pub steps: Vec<Step>,
    /// What could not be determined, in plain words.
    pub notes: Vec<String>,
}

fn verdict_for(action: &str) -> &'static str {
    match action {
        "block" | "deny" | "drop" => "blocked",
        "monitor" => "monitored",
        "challenge" => "challenged",
        "allow" => "allowed",
        _ => "unknown",
    }
}

fn step(
    stage: &'static str,
    status: &'static str,
    title: impl Into<String>,
    detail: impl Into<String>,
    data: Value,
) -> Step {
    Step {
        stage,
        status,
        title: title.into(),
        detail: detail.into(),
        data,
    }
}

/// Maximum distinct rules resolved for one event. A hostile request can
/// produce hundreds of signature hits; the why-chain is an explanation, not a
/// dump.
const MAX_MATCHED_RULES: usize = 16;

/// One line of `waf_details`, before database/catalogue resolution.
#[derive(Debug, Clone, PartialEq, Eq)]
struct ParsedRule {
    id: String,
    name: Option<String>,
    action: Option<String>,
    severity: Option<u8>,
    category: Option<String>,
    evidence: Option<String>,
    monitored: bool,
}

impl ParsedRule {
    fn simple(id: &str) -> Self {
        Self {
            id: id.to_string(),
            name: None,
            action: None,
            severity: None,
            category: None,
            evidence: None,
            monitored: false,
        }
    }
}

/// `finalize_verdict` prefixes the detail list with the verdict reason
/// (`likely-clean: …`, `attack: …`). Strip it before parsing the rule lines.
fn strip_reason_prefix(details: &str) -> &str {
    for reason in [
        "clean",
        "likely-clean",
        "likely-attack",
        "attack",
        "stage1-critical",
    ] {
        if let Some(rest) = details
            .strip_prefix(reason)
            .and_then(|rest| rest.strip_prefix(": "))
        {
            return rest;
        }
    }
    details
}

/// Reads `key=value` from a details tail, ending at whitespace.
fn field_value<'a>(segment: &'a str, key: &str) -> Option<&'a str> {
    let start = segment.find(key)? + key.len();
    let rest = &segment[start..];
    let end = rest.find(|c: char| c.is_whitespace()).unwrap_or(rest.len());
    let value = rest[..end].trim_matches(['[', ']', ',']);
    (!value.is_empty()).then_some(value)
}

/// Signature ids are `<UPPER>-<digits>` (`SSRF-006`, `CI-101`); managed rules
/// are `VARMAN-…` and are resolved separately.
fn is_signature_id(id: &str) -> bool {
    if id.starts_with("VARMAN-") {
        return false;
    }
    let Some((prefix, number)) = id.split_once('-') else {
        return false;
    };
    !prefix.is_empty()
        && prefix.bytes().all(|b| b.is_ascii_uppercase())
        && !number.is_empty()
        && number.bytes().all(|b| b.is_ascii_digit())
}

fn is_attack_category(value: &str) -> bool {
    matches!(
        value,
        "sqli"
            | "xss"
            | "rce"
            | "lfi"
            | "ssrf"
            | "deser"
            | "crlf"
            | "xxe"
            | "ssti"
    )
}

fn detector_name(id: &str) -> Option<&'static str> {
    match id {
        "libinjection-sqli" => Some("SQL injection shape"),
        "xss-shape" => Some("XSS shape"),
        "ci-shape" => Some("Command injection shape"),
        "pt-shape" => Some("Path traversal shape"),
        "deser-shape" => Some("Deserialization shape"),
        "expr-injection" | "EXPR-INJ" => Some("Expression injection"),
        _ => None,
    }
}

fn detector_category(id: &str) -> Option<&'static str> {
    match id {
        "libinjection-sqli" => Some("sqli"),
        "xss-shape" => Some("xss"),
        "ci-shape" => Some("rce"),
        "pt-shape" => Some("lfi"),
        "deser-shape" => Some("deser"),
        "expr-injection" | "EXPR-INJ" => Some("ssti"),
        _ => None,
    }
}

/// Split `waf_details` into the rules that actually fired.
///
/// The engine joins details with `"; "`:
/// `likely-clean: SSRF-006 [ssrf sev=3] in header 'user-agent'; VARMAN-1020
/// [Block sensitive dotfile probes] action=block sev=5`.
fn parse_waf_details(details: &str) -> Vec<ParsedRule> {
    let details = strip_reason_prefix(details.trim());
    let mut parsed: Vec<ParsedRule> = Vec::new();
    for segment in details.split("; ") {
        let segment = segment.trim();
        if segment.is_empty() {
            continue;
        }
        let Some(open) = segment.find(" [") else {
            continue;
        };
        let id = segment[..open].trim();
        if id.is_empty() {
            continue;
        }
        let after = &segment[open + 2..];
        let Some(close) = after.find(']') else {
            continue;
        };
        let bracket = &after[..close];
        let tail = after[close + 1..].trim();
        // Signature/detector lines end with "in header 'x'"; rule lines end
        // with "action=block sev=5". Only the former is match evidence.
        let evidence = tail.starts_with("in ").then(|| tail.to_string());
        let monitored = segment.contains("[monitored]");
        let action = field_value(tail, "action=").map(str::to_string);
        let field_severity =
            field_value(tail, "sev=").and_then(|v| v.parse::<u8>().ok());
        let (bracket_category, bracket_severity) =
            match bracket.split_once(" sev=") {
                Some((category, severity)) if is_attack_category(category) => {
                    (Some(category.to_string()), severity.parse::<u8>().ok())
                },
                _ => (None, None),
            };
        let info = builtin_signature_info(id);
        let severity = field_severity
            .or(bracket_severity)
            .or(info.map(|entry| entry.severity));
        let category = bracket_category
            .or_else(|| info.map(|entry| entry.category.as_str().to_string()))
            .or_else(|| detector_category(id).map(str::to_string));
        let name = if let Some(info) = info {
            Some(info.description.to_string())
        } else if let Some(name) = detector_name(id) {
            Some(name.to_string())
        } else if bracket.contains(" sev=") {
            // Signature whose id is not in this binary's catalogue (engine
            // version drift): keep the category but do not invent a name.
            None
        } else {
            Some(bracket.to_string())
        };
        push_parsed(
            &mut parsed,
            ParsedRule {
                id: id.to_string(),
                name,
                action,
                severity,
                category,
                evidence,
                monitored,
            },
        );
    }
    parsed
}

/// Merge duplicate ids, keeping the first-seen order and filling metadata.
fn push_parsed(parsed: &mut Vec<ParsedRule>, rule: ParsedRule) {
    if let Some(existing) = parsed
        .iter_mut()
        .find(|entry| entry.id.eq_ignore_ascii_case(&rule.id))
    {
        if existing.name.is_none() {
            existing.name = rule.name;
        }
        if existing.action.is_none() {
            existing.action = rule.action;
        }
        if existing.severity.is_none() {
            existing.severity = rule.severity;
        }
        if existing.category.is_none() {
            existing.category = rule.category;
        }
        if existing.evidence.is_none() {
            existing.evidence = rule.evidence;
        }
        existing.monitored |= rule.monitored;
    } else {
        parsed.push(rule);
    }
}

/// The rule that forced the verdict.
///
/// An explicit `action=block`/`challenge` line wins: that is the rule whose
/// action produced the event. Score-threshold blocks have no such line, so the
/// highest-severity critical signature is the next best answer; the event's
/// recorded rule id is the final fallback.
fn deciding_rule(parsed: &[ParsedRule], fallback: &str) -> Option<String> {
    if let Some(rule) = parsed.iter().find(|rule| {
        matches!(
            rule.action.as_deref(),
            Some("block" | "challenge" | "js_challenge")
        )
    }) {
        return Some(rule.id.clone());
    }
    let mut best: Option<&ParsedRule> = None;
    for rule in parsed {
        let Some(severity) = rule.severity else {
            continue;
        };
        if severity < 5 {
            continue;
        }
        if best.is_none_or(|current| {
            severity > current.severity.unwrap_or_default()
        }) {
            best = Some(rule);
        }
    }
    if let Some(rule) = best {
        return Some(rule.id.clone());
    }
    (!fallback.is_empty()).then(|| fallback.to_string())
}

/// Resolve one parsed rule through the same catalogue/database path as the
/// single-rule chain step.
async fn matched_rule_from(
    db: &DatabaseConnection,
    parsed: &ParsedRule,
    deciding_id: &str,
) -> Result<MatchedRule, DbErr> {
    let resolved = resolve_rule(db, &parsed.id).await?;
    let source = resolved
        .data
        .get("source")
        .and_then(Value::as_str)
        .unwrap_or("unknown")
        .to_string();
    let rule = resolved.data.get("rule");
    let name = rule
        .and_then(|value| value.get("name"))
        .and_then(Value::as_str)
        .map(str::to_string)
        .or_else(|| parsed.name.clone())
        .unwrap_or_else(|| resolved.title.clone());
    let severity = rule
        .and_then(|value| value.get("severity"))
        .and_then(Value::as_u64)
        .map(|value| value as u8)
        .or(parsed.severity);
    let action = rule
        .and_then(|value| value.get("action"))
        .and_then(Value::as_str)
        .map(str::to_string)
        .or_else(|| parsed.action.clone());
    let category = rule
        .and_then(|value| value.get("category"))
        .and_then(Value::as_str)
        .map(str::to_string)
        .or_else(|| parsed.category.clone());
    let mut detail = resolved.detail;
    if let Some(evidence) = &parsed.evidence {
        detail.push_str("; ");
        detail.push_str(evidence);
    }
    if parsed.monitored {
        detail.push_str("; monitored by the site's policy");
    }
    Ok(MatchedRule {
        id: parsed.id.clone(),
        name,
        source,
        status: resolved.status.to_string(),
        severity,
        action,
        category,
        deciding: !deciding_id.is_empty()
            && parsed.id.eq_ignore_ascii_case(deciding_id),
        evidence: parsed.evidence.clone(),
        detail,
        data: resolved.data,
    })
}

/// Splits `policy:<uuid>:<n>`, `:rl:<n>` and `:ip:<n>` forms.
fn parse_policy_rule_id(rule_id: &str) -> Option<(Uuid, &'static str, usize)> {
    let rest = rule_id.strip_prefix("policy:")?;
    let (uuid_text, tail) = rest.split_once(':')?;
    let policy_id = Uuid::parse_str(uuid_text).ok()?;
    let (kind, index_text) = match tail.split_once(':') {
        Some(("rl", index)) => ("rate_limit", index),
        Some(("ip", index)) => ("ip_access", index),
        Some((other, _)) => {
            // `policy:<uuid>:<other>:...` is not a shape we emit.
            let _ = other;
            return None;
        },
        None => ("custom_rules", tail),
    };
    let index = index_text.parse::<usize>().ok()?;
    Some((policy_id, kind, index))
}

/// Resolves the event's rule id into a step.
async fn resolve_rule(
    db: &DatabaseConnection,
    rule_id: &str,
) -> Result<Step, DbErr> {
    if rule_id.starts_with("VARMAN-") {
        if let Some(entry) =
            policy::catalogue().iter().find(|entry| entry.id == rule_id)
        {
            return Ok(step(
                "waf_rule",
                "hit",
                format!("{} ({})", entry.name, entry.id),
                format!(
                    "built-in managed rule: action {}, severity {}, \
                     category {}",
                    entry.action,
                    entry.severity,
                    entry.category.as_deref().unwrap_or("—")
                ),
                json!({
                    "source": "managed",
                    "rule": {
                        "id": entry.id,
                        "name": entry.name,
                        "action": entry.action,
                        "severity": entry.severity,
                        "category": entry.category,
                        "tags": entry.tags,
                        "stacks": entry.stacks,
                        "strict_only": entry.strict_only,
                    }
                }),
            ));
        }
        return Ok(step(
            "waf_rule",
            "unknown",
            rule_id.to_string(),
            "the rule id looks like a built-in managed rule, but the \
             catalogue does not carry it (engine version drift?)",
            json!({ "source": "managed", "rule_id": rule_id }),
        ));
    }

    if let Some(patch_id) = rule_id.strip_prefix("virtual-patch:") {
        let rows = crs_rule::Entity::find()
            .filter(crs_rule::Column::RuleId.eq(patch_id))
            .all(db)
            .await?;
        if rows.is_empty() {
            return Ok(step(
                "waf_rule",
                "hit",
                format!("Virtual patch {patch_id}"),
                "compiled from a SecLang patch source (policy or site \
                 virtual patches); no imported CRS rule carries this id",
                json!({ "source": "patch", "rule_id": patch_id }),
            ));
        }
        let ruleset_ids: Vec<Uuid> =
            rows.iter().map(|row| row.ruleset_id).collect();
        let rulesets = crs_ruleset::Entity::find()
            .filter(crs_ruleset::Column::Id.is_in(ruleset_ids))
            .all(db)
            .await?;
        let first = &rows[0];
        let ruleset = rulesets.iter().find(|r| r.id == first.ruleset_id);
        let file_line = format!("{}:{}", first.file, first.line);
        return Ok(step(
            "waf_rule",
            "hit",
            format!("CRS rule {patch_id}"),
            format!(
                "imported from CRS ruleset '{}' - {} (paranoia {}, {})",
                ruleset.map(|r| r.name.as_str()).unwrap_or("(deleted)"),
                file_line,
                first
                    .paranoia_level
                    .map(|level| level.to_string())
                    .unwrap_or_else(|| "—".to_string()),
                if first.category.is_empty() {
                    "no category"
                } else {
                    first.category.as_str()
                }
            ),
            json!({
                "source": "crs_import",
                "rule_id": patch_id,
                "file": first.file,
                "line": first.line,
                "category": first.category,
                "paranoia_level": first.paranoia_level,
                "phase": first.phase,
                "message": first.message,
                "ruleset": ruleset.map(|r| json!({
                    "id": r.id,
                    "name": r.name,
                    "version": r.version,
                    "fingerprint": r.fingerprint,
                })),
                "compiled": first.supported,
            }),
        ));
    }

    if let Some((policy_id, layer_kind, index)) = parse_policy_rule_id(rule_id)
    {
        let policy_row =
            waf_policy::Entity::find_by_id(policy_id).one(db).await?;
        let layer = waf_policy_layer::Entity::find()
            .filter(waf_policy_layer::Column::PolicyId.eq(policy_id))
            .filter(waf_policy_layer::Column::Kind.eq(layer_kind))
            .one(db)
            .await?;
        let entry = layer
            .as_ref()
            .and_then(|row| row.config.get("rules"))
            .and_then(Value::as_array)
            .and_then(|rules| rules.get(index))
            .cloned();
        match (policy_row, entry) {
            (Some(policy_row), Some(entry)) => {
                let name = entry
                    .get("name")
                    .and_then(Value::as_str)
                    .unwrap_or("(unnamed)");
                return Ok(step(
                    "waf_rule",
                    "hit",
                    format!("{name} ({rule_id})"),
                    format!(
                        "{} rule #{} of policy '{}' (revision {})",
                        layer_kind.replace('_', " "),
                        index,
                        policy_row.name,
                        policy_row.revision
                    ),
                    json!({
                        "source": "policy",
                        "layer": layer_kind,
                        "index": index,
                        "policy": {
                            "id": policy_row.id,
                            "name": policy_row.name,
                            "revision": policy_row.revision,
                            "enabled": policy_row.enabled,
                        },
                        "rule": entry,
                    }),
                ));
            },
            (policy, entry) => {
                return Ok(step(
                    "waf_rule",
                    "unknown",
                    rule_id.to_string(),
                    "the rule was defined by a policy layer that no longer \
                     exists (policy or layer #index deleted since)",
                    json!({
                        "source": "policy",
                        "layer": layer_kind,
                        "index": index,
                        "policy": policy.map(|row| json!({
                            "id": row.id,
                            "name": row.name,
                            "revision": row.revision,
                        })),
                        "rule": entry,
                    }),
                ));
            },
        }
    }

    if let Ok(id) = Uuid::parse_str(rule_id) {
        if let Some(row) = rule::Entity::find_by_id(id).one(db).await? {
            return Ok(step(
                "waf_rule",
                "hit",
                format!("{} ({})", row.name, row.id),
                format!(
                    "site custom rule: action {}, mode {}, expression {}",
                    row.action, row.mode, row.expression
                ),
                json!({
                    "source": "site_rule",
                    "rule": {
                        "id": row.id,
                        "name": row.name,
                        "action": row.action,
                        "mode": row.mode,
                        "expression": row.expression,
                        "enabled": row.enabled,
                    }
                }),
            ));
        }
    }

    // Built-in signatures live in the edge binary, not in PostgreSQL. The
    // console must still explain them: a hit such as SSRF-006 is a real
    // detection, not an unknown rule.
    if let Some(info) = builtin_signature_info(rule_id) {
        return Ok(step(
            "waf_rule",
            "hit",
            format!("{} - {}", info.id, info.description),
            format!(
                "built-in detection signature: {} family, severity {}{}; \
                 contributes anomaly score, no database rule required",
                info.category.as_str(),
                info.severity,
                if info.strict_only {
                    ", Strict level only"
                } else {
                    ""
                }
            ),
            json!({
                "source": "signature",
                "rule": {
                    "id": info.id,
                    "name": info.description,
                    "category": info.category.as_str(),
                    "severity": info.severity,
                    "strict_only": info.strict_only,
                }
            }),
        ));
    }

    // Structural detectors are not signatures either: the engine names the
    // shape it recognised (`libinjection-sqli`, `ci-shape`, …). They have no
    // database row, but they are still real evidence.
    if let Some(name) = detector_name(rule_id) {
        return Ok(step(
            "waf_rule",
            "hit",
            format!("{rule_id} - {name}"),
            "built-in structural detector: the engine matched a request \
             shape, not a literal signature id",
            json!({
                "source": "detector",
                "rule": {
                    "id": rule_id,
                    "name": name,
                    "category": detector_category(rule_id),
                }
            }),
        ));
    }

    if is_signature_id(rule_id) {
        return Ok(step(
            "waf_rule",
            "unknown",
            rule_id.to_string(),
            "the id looks like a built-in signature, but this binary's \
             catalogue does not carry it (engine version drift?)",
            json!({ "source": "signature", "rule_id": rule_id }),
        ));
    }

    Ok(step(
        "waf_rule",
        "unknown",
        rule_id.to_string(),
        "the rule id does not match any stored catalogue entry (managed, \
         imported CRS, policy layer, site rule, built-in signature or \
         structural detector)",
        json!({ "source": "unknown", "rule_id": rule_id }),
    ))
}

/// Builds the full explanation for one event.
pub async fn explain(
    db: &DatabaseConnection,
    event: &security_event::Model,
) -> Result<Explanation, DbErr> {
    let mut steps = Vec::new();
    let mut notes = Vec::new();
    let verdict = verdict_for(&event.action);
    let rule_id = event.rule_id.clone().unwrap_or_default();

    steps.push(step(
        "event",
        "hit",
        format!(
            "{} {}{}",
            event.method,
            event.path.as_deref().unwrap_or(""),
            event
                .host
                .as_deref()
                .map(|host| format!(" (host {host})"))
                .unwrap_or_default()
        ),
        format!(
            "decision '{}' ({}), score {}",
            event.action,
            verdict,
            event
                .score
                .map(|score| score.to_string())
                .unwrap_or_else(|| "—".to_string())
        ),
        json!({
            "event_id": event.id,
            "timestamp": event.timestamp,
            "site_id": event.site_id,
            "agent_id": event.agent_id,
            "request_id": event.request_id,
            "client_ip": event.client_ip,
            "country_code": event.country_code,
            "action": event.action,
            "score": event.score,
            "event_type": event.event_type,
            "rule_id": event.rule_id,
            "rule_name": event.rule_name,
            "details": event.waf_details,
        }),
    ));

    // Automatic IP block (created by the WAF after a blocking decision).
    let blocked = agent_blocked_ip::Entity::find()
        .filter(agent_blocked_ip::Column::Ip.eq(&event.client_ip))
        .all(db)
        .await?;
    let active = blocked.iter().find(|row| {
        row.expires_at.is_none_or(|expires| expires > Utc::now())
            && event.site_id.is_none_or(|site| row.site_id == site)
    });
    steps.push(match active {
        Some(row) => step(
            "auto_block",
            "hit",
            "Client IP is under automatic block",
            format!(
                "blocked at {} ({})",
                row.blocked_at,
                row.expires_at
                    .map(|expires| format!("expires {expires}"))
                    .unwrap_or_else(|| "no expiry recorded".to_string())
            ),
            json!({
                "ip": row.ip,
                "reason": row.reason,
                "blocked_at": row.blocked_at,
                "expires_at": row.expires_at,
                "agent_id": row.agent_id,
            }),
        ),
        None => step(
            "auto_block",
            "miss",
            "No active automatic block for this IP",
            "the IP is not (or no longer) in the auto-block list for this \
             site; any entries may have expired",
            json!({ "ip": event.client_ip, "entries_seen": blocked.len() }),
        ),
    });

    // Rate limiting produced the event?
    let is_rate_limit = rule_id.contains(":rl:")
        || event.event_type.as_deref() == Some("rate_limit");
    steps.push(if is_rate_limit {
        step(
            "rate_limit",
            "hit",
            "Rate limit decision",
            "the event came from a rate limit rule, not from body/argument \
             inspection",
            json!({ "rule_id": rule_id }),
        )
    } else {
        step(
            "rate_limit",
            "miss",
            "No rate limit involvement",
            "the rule id carries no rate-limit marker",
            json!({}),
        )
    });

    // Bot / challenge?
    match event.event_type.as_deref() {
        Some("bot") => steps.push(step(
            "bot",
            "hit",
            "Bot protection decision",
            "the event was produced by bot detection",
            json!({}),
        )),
        Some("challenge") => steps.push(step(
            "bot",
            "hit",
            "Challenge decision",
            "the request was answered with a challenge",
            json!({}),
        )),
        Some(other) => steps.push(step(
            "bot",
            "miss",
            format!("Not a bot decision (event type '{other}')"),
            "bot protection and challenges did not produce this event",
            json!({ "event_type": other }),
        )),
        None => {
            steps.push(step(
                "bot",
                "unknown",
                "Event type not recorded",
                "this row predates event-type recording; bot involvement \
                 cannot be determined from it",
                json!({}),
            ));
            notes.push(
                "this event row predates event-type recording (rows written \
                 before v0.28 have no event type)"
                    .to_string(),
            );
        },
    }

    // Every rule/signature the engine recorded in `waf_details`, not just the
    // first id stored on the event row. The agent stores the first match in
    // `rule_id`; that is often a weak signature while a managed rule later in
    // the same details string forced the block.
    let parsed =
        parse_waf_details(event.waf_details.as_deref().unwrap_or_default());
    let deciding_id = deciding_rule(&parsed, &rule_id);
    let deciding_ref = deciding_id.as_deref().unwrap_or_default();
    let mut matched_rules: Vec<MatchedRule> = Vec::new();
    let mut matched_ids: Vec<String> = Vec::new();
    for entry in parsed.iter().take(MAX_MATCHED_RULES) {
        matched_rules.push(matched_rule_from(db, entry, deciding_ref).await?);
        matched_ids.push(entry.id.clone());
    }
    if !rule_id.is_empty()
        && !matched_ids
            .iter()
            .any(|id| id.eq_ignore_ascii_case(&rule_id))
    {
        matched_rules.push(
            matched_rule_from(db, &ParsedRule::simple(&rule_id), deciding_ref)
                .await?,
        );
    }
    if parsed.len() > MAX_MATCHED_RULES {
        notes.push(format!(
            "the WAF recorded {} matches; the chain shows the first \
             {MAX_MATCHED_RULES}",
            parsed.len()
        ));
    }

    // The chain step names the rule that decided the verdict. Every other
    // match is rendered by the console's matched-rules list, not duplicated
    // here.
    if let Some(deciding) = matched_rules.iter().find(|entry| entry.deciding) {
        steps.push(step(
            "waf_rule",
            "hit",
            deciding.name.clone(),
            deciding.detail.clone(),
            deciding.data.clone(),
        ));
    } else if rule_id.is_empty() {
        steps.push(step(
            "waf_rule",
            "unknown",
            "No rule id recorded",
            "the agent shipped this event without a rule id (e.g. a score \
             threshold or mode downgrade); the producing rule cannot be \
             named",
            json!({}),
        ));
        notes.push("the agent recorded no rule id for this event".to_string());
    } else {
        steps.push(resolve_rule(db, &rule_id).await?);
    }

    let blocked_by = deciding_id
        .clone()
        .or_else(|| (!rule_id.is_empty()).then(|| rule_id.clone()));

    // Current policy binding + the tuning that addresses this rule.
    let site_id = event.site_id;
    let resolved = match site_id {
        Some(site) => policy::resolve(db, site).await?,
        None => policy::Resolved::default(),
    };
    let binding = match site_id {
        Some(site) => site_waf_policy::Entity::find_by_id(site).one(db).await?,
        None => None,
    };
    steps.push(match (&resolved.policy_id, &resolved.policy_name) {
        (Some(id), Some(name)) => step(
            "policy",
            "hit",
            format!(
                "Site follows policy '{name}' (revision {})",
                resolved.revision
            ),
            "the site's policy layers were compiled into the bundle the \
             edge evaluated",
            json!({
                "policy_id": id,
                "policy_name": name,
                "revision": resolved.revision,
                "override_kinds": resolved.override_kinds,
                "layer_kinds": resolved.layers.keys().collect::<Vec<_>>(),
            }),
        ),
        _ => step(
            "policy",
            "miss",
            "Site does not follow a policy",
            "the site ran on its own settings (or the assigned policy is \
             disabled/deleted)",
            json!({ "site_id": site_id }),
        ),
    });
    if let Some(binding) = &binding {
        let changed_after = binding.updated_at > event.timestamp;
        if changed_after {
            notes.push(
                "the site's policy binding changed after this event; the \
                 policy shown is the current one, not necessarily the one \
                 that served the request"
                    .to_string(),
            );
        }
    }

    let tuning = if rule_id.is_empty() {
        None
    } else {
        resolved
            .overrides
            .iter()
            .find(|entry| entry.rule_id == rule_id)
            .cloned()
    };
    steps.push(match tuning {
        Some(entry) => step(
            "tuning",
            "hit",
            "Rule tuning applies",
            format!(
                "the resolved policy sets action '{}'{} for this rule",
                entry.action,
                entry
                    .score
                    .map(|score| format!(" (score {score})"))
                    .unwrap_or_default()
            ),
            serde_json::to_value(&entry).unwrap_or(Value::Null),
        ),
        None => step(
            "tuning",
            "miss",
            "No rule tuning",
            "no override in the resolved policy addresses this rule id",
            json!({}),
        ),
    });
    if resolved
        .overrides
        .iter()
        .any(|entry| entry.rule_id.is_empty())
    {
        notes.push(
            "the policy also carries selector-based overrides (tags/severity); \
             they are expanded when the bundle is built and are not reversed \
             here"
                .to_string(),
        );
    }

    Ok(Explanation {
        verdict,
        blocked_by,
        matched_rules,
        steps,
        notes,
    })
}

#[cfg(test)]
mod tests {
    use super::{deciding_rule, parse_waf_details};

    #[test]
    fn parses_signature_and_managed_rule_from_one_details_string() {
        let parsed = parse_waf_details(
            "likely-clean: SSRF-006 [ssrf sev=3] in header \
             'user-agent'; VARMAN-1020 [Block sensitive dotfile probes] \
             action=block sev=5",
        );
        assert_eq!(parsed.len(), 2);
        assert_eq!(parsed[0].id, "SSRF-006");
        assert_eq!(parsed[0].name.as_deref(), Some("wildcard IPv4"));
        assert_eq!(parsed[0].severity, Some(3));
        assert_eq!(parsed[0].category.as_deref(), Some("ssrf"));
        assert_eq!(
            parsed[0].evidence.as_deref(),
            Some("in header 'user-agent'")
        );
        assert_eq!(parsed[1].id, "VARMAN-1020");
        assert_eq!(parsed[1].action.as_deref(), Some("block"));
        assert_eq!(parsed[1].severity, Some(5));
        assert_eq!(
            deciding_rule(&parsed, "SSRF-006").as_deref(),
            Some("VARMAN-1020")
        );
    }

    #[test]
    fn critical_signature_is_the_fallback_decider() {
        let parsed =
            parse_waf_details("attack: SQL-001 [sqli sev=5] in query 'id'");
        assert_eq!(parsed.len(), 1);
        assert_eq!(
            deciding_rule(&parsed, "SQL-001").as_deref(),
            Some("SQL-001")
        );
    }

    #[test]
    fn a_block_line_wins_over_an_earlier_weak_signature() {
        let parsed = parse_waf_details(
            "likely-clean: CI-001 [rce sev=5] in query 'cmd'; \
             policy:00000000-0000-0000-0000-000000000000:0 \
             [Block upload path] action=block sev=4",
        );
        assert_eq!(parsed.len(), 2);
        assert_eq!(
            deciding_rule(&parsed, "CI-001").as_deref(),
            Some("policy:00000000-0000-0000-0000-000000000000:0")
        );
    }

    #[test]
    fn duplicate_ids_merge_metadata() {
        let parsed = parse_waf_details(
            "SSRF-006 [ssrf sev=3] in header 'x'; SSRF-006 [ssrf sev=3] \
             action=block in body 'y'",
        );
        assert_eq!(parsed.len(), 1);
        assert_eq!(parsed[0].action.as_deref(), Some("block"));
        assert_eq!(parsed[0].evidence.as_deref(), Some("in header 'x'"));
    }

    #[test]
    fn structural_detectors_get_a_readable_name() {
        let parsed =
            parse_waf_details("ci-shape [path-backticks] in path '/x'");
        assert_eq!(parsed.len(), 1);
        assert_eq!(parsed[0].id, "ci-shape");
        assert_eq!(parsed[0].name.as_deref(), Some("Command injection shape"));
        assert_eq!(parsed[0].category.as_deref(), Some("rce"));
        assert_eq!(parsed[0].evidence.as_deref(), Some("in path '/x'"));
    }

    #[test]
    fn empty_or_unparseable_details_are_empty_not_errors() {
        assert!(parse_waf_details("").is_empty());
        assert!(parse_waf_details("likely-clean").is_empty());
        assert_eq!(deciding_rule(&[], "SSRF-006").as_deref(), Some("SSRF-006"));
    }
}
