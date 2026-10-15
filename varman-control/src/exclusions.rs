//! Exclusion packages: the curated catalogue and entry handling.
//!
//! A package is a named, versioned set of entries. An entry addresses rules
//! (one rule id, or a tag/severity selector expanded against the managed
//! catalogue) and excludes request sources (`path`, `query`, `body`,
//! `header`, `cookie`, `user_agent`, `host`, `method`) from their
//! evaluation. A binding attaches a package to a site at a path prefix, so
//! the exclusion only applies while the request path matches.
//!
//! The catalogue ships the well-known false-positive cases for popular
//! applications. Every entry carries a note stating what it excludes and
//! the trade-off; nothing is applied until an operator attaches it.

use chrono::Utc;
use sea_orm::{ActiveModelTrait, ColumnTrait, EntityTrait, QueryFilter, Set};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::models::exclusion_packages;

/// One package entry as stored in the `entries` JSON column.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Entry {
    /// Managed rule id (`VARMAN-.`); empty when a selector is used.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub rule_id: String,
    /// Selector: rules carrying any of these tags.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub tags: Vec<String>,
    /// Selector: rules with severity at or above this level.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub severity_min: Option<u8>,
    /// Request sources excluded from the addressed rules.
    pub targets: Vec<String>,
    /// What this entry does and why (shown verbatim in the console).
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub note: String,
}

/// Sources an exclusion entry may name (the engine's request targets).
pub const EXCLUSION_TARGETS: [&str; 8] = [
    "path",
    "query",
    "body",
    "header",
    "cookie",
    "user_agent",
    "host",
    "method",
];

/// A catalogue definition (compiled in; seeded into the database).
pub struct CataloguePackage {
    pub key: &'static str,
    pub name: &'static str,
    pub description: &'static str,
    pub source_url: &'static str,
    pub version: &'static str,
    pub entries: &'static [CatalogueEntry],
}

pub struct CatalogueEntry {
    pub rule_id: &'static str,
    pub tags: &'static [&'static str],
    pub targets: &'static [&'static str],
    pub note: &'static str,
}

/// The built-in catalogue. Each package states exactly what it excludes;
/// operators review before attaching.
pub const CATALOGUE: &[CataloguePackage] = &[
    CataloguePackage {
        key: "wordpress-admin",
        name: "WordPress admin & REST",
        description: "Keeps WordPress's own admin traffic from tripping the \
                      CMS-probe and rich-text rules. Attach at /wp-admin and \
                      /wp-json (two bindings) so the exclusions stay scoped \
                      to the CMS surfaces.",
        source_url: "",
        version: "1",
        entries: &[
            CatalogueEntry {
                rule_id: "VARMAN-1040",
                tags: &[],
                targets: &["path"],
                note: "The phpMyAdmin/wp-admin probe rule addresses sites \
                       whose stack is not PHP; on WordPress itself /wp-admin \
                       is legitimate traffic.",
            },
            CatalogueEntry {
                rule_id: "VARMAN-1003",
                tags: &[],
                targets: &["body"],
                note: "The XSS anomaly rule sees editor payloads: post and \
                       page content legitimately carries HTML through the \
                       admin. Scoped to the admin prefix, this is the classic \
                       rich-text exclusion.",
            },
        ],
    },
    CataloguePackage {
        key: "nextjs-static",
        name: "Next.js static assets",
        description: "Long, hashed asset URLs under the framework's static \
                      prefix can look like scan noise. Attach at /_next.",
        source_url: "",
        version: "1",
        entries: &[CatalogueEntry {
            rule_id: "VARMAN-1051",
            tags: &[],
            targets: &["path"],
            note: "The very-long-URI rule counts build-hashed asset URLs as \
                   scan attempts; the path source is excluded for it under \
                   the static prefix only.",
        }],
    },
    CataloguePackage {
        key: "nextcloud-webdav",
        name: "Nextcloud WebDAV",
        description: "WebDAV paths carry file names and quoting that trip \
                      the long-URI and dotfile heuristics. Attach at \
                      /remote.php.",
        source_url: "",
        version: "1",
        entries: &[
            CatalogueEntry {
                rule_id: "VARMAN-1051",
                tags: &[],
                targets: &["path"],
                note: "Deep WebDAV paths are long by design; the path source \
                       is excluded for the long-URI rule under the WebDAV \
                       prefix.",
            },
            CatalogueEntry {
                rule_id: "VARMAN-1020",
                tags: &[],
                targets: &["path"],
                note: "Users sync files named like dotfiles; the dotfile \
                       probe rule reads them as reconnaissance under the \
                       WebDAV prefix.",
            },
        ],
    },
    CataloguePackage {
        key: "richtext-editors",
        name: "Rich-text editors (generic)",
        description: "Generic admin/editor surface: HTML content in the \
                      body is expected. Attach at the editor's prefix (e.g. \
                      /admin or /editor).",
        source_url: "",
        version: "1",
        entries: &[CatalogueEntry {
            rule_id: "VARMAN-1003",
            tags: &[],
            targets: &["body"],
            note: "The XSS anomaly rule fires on editor payloads that carry \
                   HTML; the body source is excluded for it under the \
                   editor prefix only.",
        }],
    },
];

/// Seeds/updates the built-in catalogue. Idempotent: content and version
/// follow the compiled catalogue, operator edits to custom packages are
/// untouched.
pub async fn seed_catalogue(
    db: &sea_orm::DatabaseConnection,
) -> Result<(), sea_orm::DbErr> {
    for package in CATALOGUE {
        let entries = entries_json(package);
        let existing = exclusion_packages::Entity::find()
            .filter(exclusion_packages::Column::Key.eq(package.key))
            .one(db)
            .await?;
        match existing {
            Some(row) => {
                let changed = row.name != package.name
                    || row.description != package.description
                    || row.version != package.version
                    || row.entries != entries;
                if changed {
                    let mut active: exclusion_packages::ActiveModel =
                        row.into();
                    active.name = Set(package.name.to_string());
                    active.description = Set(package.description.to_string());
                    active.source_url = Set(package.source_url.to_string());
                    active.version = Set(package.version.to_string());
                    active.entries = Set(entries);
                    active.updated_at = Set(Utc::now());
                    active.update(db).await?;
                }
            },
            None => {
                exclusion_packages::ActiveModel {
                    id: Set(Uuid::new_v4()),
                    key: Set(package.key.to_string()),
                    name: Set(package.name.to_string()),
                    description: Set(package.description.to_string()),
                    source_url: Set(package.source_url.to_string()),
                    version: Set(package.version.to_string()),
                    entries: Set(entries),
                    builtin: Set(true),
                    created_at: Set(Utc::now()),
                    updated_at: Set(Utc::now()),
                }
                .insert(db)
                .await?;
            },
        }
    }
    Ok(())
}

fn entries_json(package: &CataloguePackage) -> serde_json::Value {
    serde_json::Value::Array(
        package
            .entries
            .iter()
            .map(|entry| {
                serde_json::json!({
                    "rule_id": entry.rule_id,
                    "tags": entry.tags,
                    "targets": entry.targets,
                    "note": entry.note,
                })
            })
            .collect(),
    )
}

/// Parses and validates the entries column of a package.
pub fn parse_entries(value: &serde_json::Value) -> Result<Vec<Entry>, String> {
    let entries: Vec<Entry> = serde_json::from_value(value.clone())
        .map_err(|err| format!("entries are malformed: {err}"))?;
    if entries.is_empty() {
        return Err("a package needs at least one entry".to_string());
    }
    for entry in &entries {
        validate_entry(entry)?;
    }
    Ok(entries)
}

fn validate_entry(entry: &Entry) -> Result<(), String> {
    if entry.rule_id.is_empty()
        && entry.tags.is_empty()
        && entry.severity_min.is_none()
    {
        return Err("every entry needs a rule id or a tag/severity selector"
            .to_string());
    }
    if !entry.rule_id.is_empty() && !entry.rule_id.starts_with("VARMAN-") {
        return Err(format!(
            "'{}' is not a managed rule id (VARMAN-...)",
            entry.rule_id
        ));
    }
    if entry.targets.is_empty() {
        return Err("every entry needs at least one target".to_string());
    }
    for target in &entry.targets {
        if !EXCLUSION_TARGETS.contains(&target.as_str()) {
            return Err(format!(
                "'{target}' is not a request target ({})",
                EXCLUSION_TARGETS.join(", ")
            ));
        }
    }
    Ok(())
}

/// Expands a package's entries against the managed catalogue into
/// `(rule_id, targets)` pairs.
pub fn expand(entries: &[Entry]) -> Vec<(String, Vec<String>)> {
    let catalogue =
        varman_waf::managed_rule_catalogue(varman_waf::WafLevel::Strict);
    let mut expanded: Vec<(String, Vec<String>)> = Vec::new();
    for entry in entries {
        if !entry.rule_id.is_empty() {
            expanded.push((entry.rule_id.clone(), entry.targets.clone()));
            continue;
        }
        for rule in &catalogue {
            let tag_match = !entry.tags.is_empty()
                && entry
                    .tags
                    .iter()
                    .any(|tag| rule.tags.iter().any(|value| value == tag));
            let severity_match =
                entry.severity_min.is_some_and(|min| rule.severity >= min);
            if tag_match || severity_match {
                expanded.push((rule.id.to_string(), entry.targets.clone()));
            }
        }
    }
    // Merge duplicate rule ids (a rule addressed by two entries keeps both
    // target sets).
    let mut merged: std::collections::BTreeMap<String, Vec<String>> =
        std::collections::BTreeMap::new();
    for (rule_id, targets) in expanded {
        let slot = merged.entry(rule_id).or_default();
        for target in targets {
            if !slot.contains(&target) {
                slot.push(target);
            }
        }
    }
    merged.into_iter().collect()
}

/// Validates a binding path prefix.
pub fn validate_path_prefix(prefix: &str) -> Result<String, String> {
    let trimmed = prefix.trim();
    if trimmed.is_empty() || !trimmed.starts_with('/') {
        return Err("the path prefix must start with '/'".to_string());
    }
    if trimmed.len() > 256 {
        return Err("the path prefix is too long (max 256)".to_string());
    }
    if trimmed.contains("..") {
        return Err("the path prefix must not contain '..'".to_string());
    }
    Ok(trimmed.trim_end_matches('/').to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_catalogue_is_valid_and_uses_real_rules() {
        let catalogue_ids: Vec<String> =
            varman_waf::managed_rule_catalogue(varman_waf::WafLevel::Strict)
                .into_iter()
                .map(|rule| rule.id)
                .collect();
        for package in CATALOGUE {
            let entries = parse_entries(&entries_json(package))
                .unwrap_or_else(|err| panic!("{}: {err}", package.key));
            for entry in &entries {
                if !entry.rule_id.is_empty() {
                    assert!(
                        catalogue_ids.contains(&entry.rule_id),
                        "{} addresses unknown rule {}",
                        package.key,
                        entry.rule_id
                    );
                }
                assert!(
                    !entry.note.is_empty(),
                    "{} has an entry without a note",
                    package.key
                );
            }
        }
    }

    #[test]
    fn expansion_merges_selectors_and_exact_ids() {
        let entries = vec![
            Entry {
                rule_id: "VARMAN-1020".to_string(),
                tags: Vec::new(),
                severity_min: None,
                targets: vec!["path".to_string()],
                note: String::new(),
            },
            Entry {
                rule_id: String::new(),
                tags: vec!["dotfile".to_string()],
                severity_min: None,
                targets: vec!["query".to_string()],
                note: String::new(),
            },
        ];
        let expanded = expand(&entries);
        let dotfile = expanded
            .iter()
            .find(|(id, _)| id == "VARMAN-1020")
            .expect("the rule is addressed by both entries");
        assert_eq!(dotfile.1, vec!["path", "query"]);
    }

    #[test]
    fn entries_and_prefixes_are_validated() {
        assert!(
            parse_entries(&serde_json::json!([])).is_err(),
            "empty package"
        );
        assert!(parse_entries(&serde_json::json!([{
            "rule_id": "VARMAN-9999",
            "targets": ["path"]
        }]))
        .is_ok());
        assert!(
            parse_entries(&serde_json::json!([{
                "rule_id": "XSS-001",
                "targets": ["path"]
            }]))
            .is_err(),
            "non-managed ids are rejected"
        );
        assert!(
            parse_entries(&serde_json::json!([{
                "rule_id": "VARMAN-1020",
                "targets": ["teapot"]
            }]))
            .is_err(),
            "unknown targets are rejected"
        );

        assert_eq!(validate_path_prefix("/wp-admin/").unwrap(), "/wp-admin");
        assert!(validate_path_prefix("wp-admin").is_err());
        assert!(validate_path_prefix("/a/../b").is_err());
    }
}
