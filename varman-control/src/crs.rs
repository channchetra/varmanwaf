//! OWASP CRS ruleset import: fetch → parse with the engine's SecLang parser
//! → catalogue with file/line provenance → compile the supported subset for
//! the edge.
//!
//! The importer never claims more than it delivered: every logical statement
//! in the imported `rules/*.conf` files becomes a catalogue row. Rules this
//! engine cannot compile are stored with their parser error (visible in the
//! console and countable), and directives are recorded as such instead of
//! being dropped. A policy binds a ruleset through the `crs_import` layer;
//! the edge then receives the supported rules as SecLang source — the same
//! path virtual patches already use.

use std::io::Read;

use flate2::read::GzDecoder;
use sea_orm::{
    ActiveModelTrait, ColumnTrait, ConnectionTrait, DatabaseConnection, DbErr,
    EntityTrait, QueryFilter, QueryOrder, Set, Statement,
};
use sha2::{Digest, Sha256};
use uuid::Uuid;

use crate::models::{crs_rule, crs_ruleset};

/// Where an import fetches from.
#[derive(Clone, Debug)]
pub enum ImportSource {
    /// A GitHub release tag of `coreruleset/coreruleset`.
    GitHubTag(String),
    /// A direct URL to a `.tar.gz` archive.
    Url(String),
    /// An uploaded archive, base64 encoded.
    ArchiveBase64(String),
}

/// One parsed logical statement from an imported file.
#[derive(Clone, Debug, PartialEq)]
pub struct ImportedStatement {
    pub rule_id: String,
    /// `rule` or `directive`.
    pub kind: &'static str,
    pub file: String,
    pub line: i32,
    pub phase: Option<i32>,
    pub severity: String,
    pub paranoia_level: Option<i32>,
    pub category: String,
    pub message: String,
    pub source: String,
    pub supported: bool,
    pub error: String,
}

/// Outcome of one import.
pub struct ImportOutcome {
    pub ruleset: crs_ruleset::Model,
    /// True when the fingerprint already existed (no new rows).
    pub deduplicated: bool,
}

fn sha256_hex(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    hasher
        .finalize()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

/// Fetches (or decodes) the archive. Returns `(bytes, source label,
/// version label)`.
pub async fn fetch_archive(
    source: &ImportSource,
) -> Result<(Vec<u8>, String, String), String> {
    match source {
        ImportSource::GitHubTag(tag) => {
            let tag = tag.trim();
            if tag.is_empty() {
                return Err("a GitHub release tag is required".to_string());
            }
            if tag.chars().any(|c| c.is_whitespace()) {
                return Err(
                    "the GitHub release tag must not contain whitespace"
                        .to_string(),
                );
            }
            let url = format!(
                "https://github.com/coreruleset/coreruleset/archive/refs/tags/{tag}.tar.gz"
            );
            let bytes = download(&url).await?;
            let version = tag.trim_start_matches('v').to_string();
            Ok((bytes, format!("github:{tag}"), version))
        },
        ImportSource::Url(url) => {
            let url = url.trim();
            if !url.starts_with("https://") && !url.starts_with("http://") {
                return Err("the URL must be http(s)".to_string());
            }
            let bytes = download(url).await?;
            let version = url
                .rsplit('/')
                .next()
                .unwrap_or_default()
                .trim_end_matches(".tar.gz")
                .trim_start_matches('v')
                .to_string();
            Ok((bytes, format!("url:{url}"), version))
        },
        ImportSource::ArchiveBase64(encoded) => {
            use base64::engine::general_purpose::STANDARD as BASE64;
            use base64::Engine;
            let bytes = BASE64
                .decode(encoded.trim())
                .map_err(|err| format!("archive is not valid base64: {err}"))?;
            if bytes.is_empty() {
                return Err("the archive is empty".to_string());
            }
            Ok((bytes, "archive".to_string(), String::new()))
        },
    }
}

async fn download(url: &str) -> Result<Vec<u8>, String> {
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(60))
        .build()
        .map_err(|err| format!("could not build the HTTP client: {err}"))?;
    let response = client
        .get(url)
        .header("User-Agent", "VarmanWAF")
        .send()
        .await
        .map_err(|err| format!("download failed: {err}"))?;
    if !response.status().is_success() {
        return Err(format!("download failed: HTTP {}", response.status()));
    }
    let bytes = response
        .bytes()
        .await
        .map_err(|err| format!("download failed: {err}"))?;
    Ok(bytes.to_vec())
}

/// Extracts every `rules/*.conf` file from the archive, sorted by path so
/// the catalogue order is deterministic.
pub fn parse_archive(bytes: &[u8]) -> Result<Vec<(String, String)>, String> {
    let decoder = GzDecoder::new(bytes);
    let mut archive = tar::Archive::new(decoder);
    let mut files: Vec<(String, String)> = Vec::new();
    let entries = archive
        .entries()
        .map_err(|err| format!("the archive is not readable: {err}"))?;
    for entry in entries {
        let mut entry = entry
            .map_err(|err| format!("the archive is not readable: {err}"))?;
        let path = entry
            .path()
            .map_err(|err| format!("invalid archive entry: {err}"))?
            .to_string_lossy()
            .to_string();
        if !path.ends_with(".conf") || !path.contains("/rules/") {
            continue;
        }
        let mut text = String::new();
        entry
            .read_to_string(&mut text)
            .map_err(|err| format!("{path}: {err}"))?;
        files.push((path, text));
    }
    if files.is_empty() {
        return Err(
            "the archive carries no rules/*.conf files (is this a CRS archive?)"
                .to_string(),
        );
    }
    files.sort_by(|a, b| a.0.cmp(&b.0));
    Ok(files)
}

/// Splits one rules file into logical statements with chain members merged
/// into their head rule. Returns `(line number, statement text)`.
pub fn logical_statements(text: &str) -> Vec<(usize, String)> {
    let mut out: Vec<(usize, String)> = Vec::new();
    let mut current = String::new();
    let mut start_line = 0usize;
    for (index, raw) in text.lines().enumerate() {
        let line = raw.trim_end();
        let trimmed = line.trim_start();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        if current.is_empty() {
            start_line = index + 1;
        }
        let continued = line.ends_with('\\');
        let piece = line.trim_end_matches('\\').trim();
        if !current.is_empty() {
            current.push(' ');
        }
        current.push_str(piece);
        if !continued {
            out.push((start_line, std::mem::take(&mut current)));
        }
    }
    if !current.is_empty() {
        out.push((start_line, current));
    }

    // Merge chain members into the head statement (only the head carries
    // `chain` in its action list).
    let mut merged: Vec<(usize, String)> = Vec::new();
    let mut index = 0usize;
    while index < out.len() {
        let (line, mut combined) = out[index].clone();
        let mut last_has_chain = combined.contains(",chain");
        let mut cursor = index;
        while last_has_chain && cursor + 1 < out.len() {
            cursor += 1;
            combined.push('\n');
            combined.push_str(&out[cursor].1);
            last_has_chain = out[cursor].1.contains(",chain");
        }
        merged.push((line, combined));
        index = cursor + 1;
    }
    merged
}

fn capture(pattern: &str, text: &str) -> String {
    regex::Regex::new(pattern)
        .ok()
        .and_then(|regex| regex.captures(text))
        .and_then(|captures| captures.get(1))
        .map(|value| value.as_str().to_string())
        .unwrap_or_default()
}

/// Parses one logical statement into a catalogue row.
pub fn classify(file: &str, line: usize, statement: &str) -> ImportedStatement {
    let kind = if statement.starts_with("SecRule ") {
        "rule"
    } else {
        "directive"
    };
    let rule_id = capture(r"id:(\d+)", statement);
    let message = {
        let single = capture(r"msg:'([^']*)'", statement);
        if single.is_empty() {
            capture(r#"msg:"([^"]*)""#, statement)
        } else {
            single
        }
    };
    let severity = capture(r"severity:'([^']*)'", statement);
    let phase = capture(r"phase:(\d)", statement).parse::<i32>().ok();
    let paranoia_level = capture(r"paranoia-level/(\d)", statement)
        .parse::<i32>()
        .ok();
    let category = capture(r"tag:'attack-([a-z0-9-]+)'", statement);
    let (supported, error) = if kind == "rule" {
        match varman_waf::seclang::SecRuleSet::from_source(statement) {
            Ok(_) => (true, String::new()),
            Err(err) => (false, err.to_string()),
        }
    } else {
        (false, String::new())
    };
    ImportedStatement {
        rule_id,
        kind,
        file: file.to_string(),
        line: line as i32,
        phase,
        severity,
        paranoia_level,
        category,
        message,
        source: statement.to_string(),
        supported,
        error,
    }
}

/// Parses every statement of the given files into catalogue rows.
pub fn parse_files(files: &[(String, String)]) -> Vec<ImportedStatement> {
    let mut out = Vec::new();
    for (path, text) in files {
        for (line, statement) in logical_statements(text) {
            out.push(classify(path, line, &statement));
        }
    }
    out
}

/// Imports an archive: fetch, catalog (idempotent by fingerprint) and store.
pub async fn import(
    db: &DatabaseConnection,
    name: &str,
    source: &ImportSource,
) -> Result<ImportOutcome, String> {
    let (bytes, source_label, version) = fetch_archive(source).await?;
    let fingerprint = sha256_hex(&bytes);
    if let Some(existing) = crs_ruleset::Entity::find()
        .filter(crs_ruleset::Column::Fingerprint.eq(fingerprint.clone()))
        .one(db)
        .await
        .map_err(|err| err.to_string())?
    {
        return Ok(ImportOutcome {
            ruleset: existing,
            deduplicated: true,
        });
    }

    let files = parse_archive(&bytes)?;
    let statements = parse_files(&files);

    let id = Uuid::new_v4();
    let rule_count = statements.iter().filter(|row| row.kind == "rule").count();
    let supported_count = statements.iter().filter(|row| row.supported).count();
    let directive_count = statements
        .iter()
        .filter(|row| row.kind == "directive")
        .count();
    let unsupported_count = rule_count - supported_count;

    let ruleset = crs_ruleset::ActiveModel {
        id: Set(id),
        name: Set(name.trim().to_string()),
        version: Set(version),
        source: Set(source_label),
        fingerprint: Set(fingerprint),
        rule_count: Set(rule_count as i32),
        supported_count: Set(supported_count as i32),
        unsupported_count: Set(unsupported_count as i32),
        directive_count: Set(directive_count as i32),
        imported_at: Set(chrono::Utc::now()),
    }
    .insert(db)
    .await
    .map_err(|err| err.to_string())?;

    for statement in statements {
        crs_rule::ActiveModel {
            id: Set(Uuid::new_v4()),
            ruleset_id: Set(id),
            rule_id: Set(statement.rule_id),
            kind: Set(statement.kind.to_string()),
            file: Set(statement.file),
            line: Set(statement.line),
            phase: Set(statement.phase),
            severity: Set(statement.severity),
            paranoia_level: Set(statement.paranoia_level),
            category: Set(statement.category),
            message: Set(statement.message),
            source: Set(statement.source),
            supported: Set(statement.supported),
            error: Set(statement.error),
        }
        .insert(db)
        .await
        .map_err(|err| err.to_string())?;
    }

    tracing::info!(
        ruleset_id = %id,
        name = %ruleset.name,
        version = %ruleset.version,
        rules = rule_count,
        supported = supported_count,
        unsupported = unsupported_count,
        directives = directive_count,
        "CRS ruleset imported"
    );
    Ok(ImportOutcome {
        ruleset,
        deduplicated: false,
    })
}

/// Compiles the supported rules of one ruleset into a SecLang source for
/// the edge, optionally filtered by paranoia level ceiling and categories.
///
/// Rules without a paranoia tag are included unless a ceiling is set (setup
/// rules carry none); rules without an attack category are excluded when a
/// category filter is set.
pub async fn compile_source(
    db: &DatabaseConnection,
    ruleset_id: Uuid,
    paranoia_max: Option<i32>,
    categories: &[String],
) -> Result<(String, usize), DbErr> {
    let mut query = crs_rule::Entity::find()
        .filter(crs_rule::Column::RulesetId.eq(ruleset_id))
        .filter(crs_rule::Column::Supported.eq(true))
        .filter(crs_rule::Column::Kind.eq("rule"))
        .order_by_asc(crs_rule::Column::File)
        .order_by_asc(crs_rule::Column::Line);
    if let Some(max) = paranoia_max {
        query = query.filter(
            sea_orm::Condition::any()
                .add(crs_rule::Column::ParanoiaLevel.is_null())
                .add(crs_rule::Column::ParanoiaLevel.lte(max)),
        );
    }
    if !categories.is_empty() {
        query =
            query.filter(crs_rule::Column::Category.is_in(categories.to_vec()));
    }
    let rows = query.all(db).await?;
    let count = rows.len();
    let source = rows
        .iter()
        .map(|row| row.source.trim())
        .collect::<Vec<_>>()
        .join("\n");
    Ok((source, count))
}

/// Ruleset usage count: how many policies reference it through the
/// `crs_import` layer.
pub async fn usage_count(
    db: &DatabaseConnection,
    ruleset_id: Uuid,
) -> Result<i64, DbErr> {
    let rows = db
        .query_all(Statement::from_sql_and_values(
            db.get_database_backend(),
            "SELECT COUNT(*) FROM waf_policy_layers WHERE kind = 'crs_import' \
             AND config->>'ruleset_id' = $1",
            [ruleset_id.to_string().into()],
        ))
        .await?;
    Ok(rows
        .first()
        .and_then(|row| row.try_get::<i64>("", "count").ok())
        .unwrap_or(0))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn logical_statements_join_continuations_and_chains() {
        let text = "\
# comment line
SecRule REQUEST_URI \"@contains /one\" \\
    \"id:1,phase:1,block\"

SecRule REQUEST_URI \"@contains /chain-head\" \"id:2,phase:1,block,chain\"
    SecRule REQUEST_METHOD \"@streq POST\" \"t:none\"
SecRule ARGS \"@rx evil\" \"id:3,phase:2,block\"
";
        let statements = logical_statements(text);
        assert_eq!(statements.len(), 3);
        assert_eq!(statements[0].0, 2);
        assert!(statements[0].1.contains("@contains /one"));
        assert!(statements[1].1.contains("chain-head"));
        assert!(statements[1].1.contains("@streq POST"));
        assert!(statements[2].1.contains("id:3"));
    }

    #[test]
    fn classify_extracts_metadata_and_flags_unsupported_rules() {
        let supported = classify(
            "rules/REQUEST-900-TEST.conf",
            10,
            "SecRule REQUEST_URI \"@contains /crs-block\" \
             \"id:990001,phase:1,block,msg:'CRS test block',\
             severity:'CRITICAL',tag:'paranoia-level/1',tag:'attack-generic'\"",
        );
        assert_eq!(supported.rule_id, "990001");
        assert_eq!(supported.kind, "rule");
        assert_eq!(supported.message, "CRS test block");
        assert_eq!(supported.severity, "CRITICAL");
        assert_eq!(supported.phase, Some(1));
        assert_eq!(supported.paranoia_level, Some(1));
        assert_eq!(supported.category, "generic");
        assert!(supported.supported);
        assert!(supported.error.is_empty());

        let unsupported = classify(
            "rules/REQUEST-901-TEST.conf",
            4,
            "SecRule REQUEST_URI \"@definitelyNotAnOperator x\" \
             \"id:990002,phase:1,block\"",
        );
        assert_eq!(unsupported.rule_id, "990002");
        assert!(!unsupported.supported);
        assert!(!unsupported.error.is_empty());

        let directive = classify(
            "rules/REQUEST-902-TEST.conf",
            2,
            "SecRuleUpdateTargetById 942100 \"!ARGS:foo\"",
        );
        assert_eq!(directive.kind, "directive");
        assert!(!directive.supported);
    }

    #[test]
    fn parse_archive_reads_rules_files() {
        // Build a tiny tar.gz in memory with one rules file and one
        // non-rules file.
        let mut builder = tar::Builder::new(Vec::new());
        let rule =
            b"SecRule REQUEST_URI \"@contains /x\" \"id:1,phase:1,block\"";
        let mut header = tar::Header::new_gnu();
        header.set_size(rule.len() as u64);
        header.set_mode(0o644);
        header.set_cksum();
        builder
            .append_data(
                &mut header,
                "coreruleset-1/rules/REQUEST-900.conf",
                &rule[..],
            )
            .expect("append rule");
        let readme = b"hello";
        let mut header = tar::Header::new_gnu();
        header.set_size(readme.len() as u64);
        header.set_mode(0o644);
        header.set_cksum();
        builder
            .append_data(&mut header, "coreruleset-1/README.md", &readme[..])
            .expect("append readme");
        let tar_bytes = builder.into_inner().expect("finish tar");
        let mut encoder = flate2::write::GzEncoder::new(
            Vec::new(),
            flate2::Compression::default(),
        );
        std::io::Write::write_all(&mut encoder, &tar_bytes).expect("gzip");
        let gz = encoder.finish().expect("finish gzip");

        let files = parse_archive(&gz).expect("archive parses");
        assert_eq!(files.len(), 1);
        assert!(files[0].0.ends_with("REQUEST-900.conf"));
        let statements = parse_files(&files);
        assert_eq!(statements.len(), 1);
        assert!(statements[0].supported);
    }

    #[test]
    fn fingerprint_is_stable() {
        assert_eq!(sha256_hex(b"abc"), sha256_hex(b"abc"));
        assert_ne!(sha256_hex(b"abc"), sha256_hex(b"abd"));
        assert_eq!(sha256_hex(b"").len(), 64);
    }
}
