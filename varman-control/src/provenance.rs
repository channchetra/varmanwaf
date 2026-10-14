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

/// The full explanation for one event.
#[derive(Debug, Serialize)]
pub struct Explanation {
    /// `blocked`, `monitored`, `challenged`, `allowed` or `unknown`.
    pub verdict: &'static str,
    /// The rule id whose stage produced the verdict, when one did.
    pub blocked_by: Option<String>,
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

    if let Some((policy_id, layer_kind, index)) =
        parse_policy_rule_id(rule_id)
    {
        let policy_row = waf_policy::Entity::find_by_id(policy_id)
            .one(db)
            .await?;
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

    Ok(step(
        "waf_rule",
        "unknown",
        rule_id.to_string(),
        "the rule id does not match any stored catalogue entry (managed, \
         imported CRS, policy layer or site rule)",
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

    // The rule itself.
    if rule_id.is_empty() {
        steps.push(step(
            "waf_rule",
            "unknown",
            "No rule id recorded",
            "the agent shipped this event without a rule id (e.g. a score \
             threshold or mode downgrade); the producing rule cannot be \
             named",
            json!({}),
        ));
        notes.push(
            "the agent recorded no rule id for this event".to_string(),
        );
    } else {
        steps.push(resolve_rule(db, &rule_id).await?);
    }

    // Current policy binding + the tuning that addresses this rule.
    let site_id = event.site_id;
    let resolved = match site_id {
        Some(site) => policy::resolve(db, site).await?,
        None => policy::Resolved::default(),
    };
    let binding = match site_id {
        Some(site) => {
            site_waf_policy::Entity::find_by_id(site).one(db).await?
        },
        None => None,
    };
    steps.push(match (&resolved.policy_id, &resolved.policy_name) {
        (Some(id), Some(name)) => step(
            "policy",
            "hit",
            format!("Site follows policy '{name}' (revision {})", resolved.revision),
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
    if resolved.overrides.iter().any(|entry| entry.rule_id.is_empty()) {
        notes.push(
            "the policy also carries selector-based overrides (tags/severity); \
             they are expanded when the bundle is built and are not reversed \
             here"
                .to_string(),
        );
    }

    Ok(Explanation {
        verdict,
        blocked_by: if rule_id.is_empty() {
            None
        } else {
            Some(rule_id)
        },
        steps,
        notes,
    })
}
