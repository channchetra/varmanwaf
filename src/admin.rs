// Copyright 2024-2025 Tree xie.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//! Maintenance commands of the `pingwaf` binary.
//!
//! [`run`] serves the `user`, `mode` and `security` subcommands. They talk
//! straight to PostgreSQL instead of the REST API, so they keep working when
//! the control plane is down, not yet seeded, or its IP allowlist has locked
//! the operator out — which is exactly when they are needed.
//!
//! A *running* control plane notices these writes on its own: the
//! self-protection refresher and the observation-mode watcher poll their
//! settings rows every 15 seconds. Passwords are hashed exactly like the API
//! does (bcrypt), and a password that is not given on the command line is
//! generated and printed once.

use anyhow::{Context, bail};
use chrono::Utc;
use sea_orm::{
    ActiveModelTrait, ColumnTrait, ConnectOptions, Database,
    DatabaseConnection, EntityTrait, QueryFilter, QueryOrder, Set,
};
use uuid::Uuid;

use pingwaf_server::api::defense;
use pingwaf_server::api::self_protection::{self, effective_allowlist};
use pingwaf_server::auth::password::{
    MAX_PASSWORD_BYTES, hash_password, validate_password,
};
use pingwaf_server::models::{
    api_protection_setting, defense_settings, ip_groups, role, user,
};

use crate::cli::{
    AddAdminOpts, AllowlistOpts, DbOpts, ModeCommand, OnOff, PingWafCli,
    PingWafCommand, ResetPasswordOpts, SecurityCommand, UserSubcommand,
};

/// Runs a maintenance subcommand.
///
/// The caller checks `PingWafCommand` first; a run mode reaching this
/// function is a programming error, reported rather than panicked so the
/// message names the mistake.
pub async fn run(cli: PingWafCli) -> anyhow::Result<()> {
    match cli.command {
        PingWafCommand::User { command } => user_command(command).await,
        PingWafCommand::Mode { command } => mode_command(command).await,
        PingWafCommand::Security { command } => security_command(command).await,
        PingWafCommand::Server(_)
        | PingWafCommand::Agent(_)
        | PingWafCommand::AllInOne(_) => {
            bail!("this is not a maintenance command")
        },
    }
}

// ─────────────────────────────────────────────────────────────
// Shared helpers
// ─────────────────────────────────────────────────────────────

/// Connects for a maintenance command. One statement runs at a time, so a
/// couple of connections is plenty.
async fn connect(db_url: &str) -> anyhow::Result<DatabaseConnection> {
    let mut options = ConnectOptions::new(db_url.to_string());
    options
        .max_connections(2)
        .min_connections(1)
        .sqlx_logging(false);
    Database::connect(options).await.context(
        "cannot connect to PostgreSQL (check --db-url or PINGWAF_DB_URL)",
    )
}

/// Lower-cases and structurally validates an e-mail address, the same way
/// the API layer does, so a CLI-created account logs in under the address
/// the operator typed.
fn normalise_email(raw: &str) -> anyhow::Result<String> {
    let email = raw.trim().to_lowercase();
    let (local, domain) =
        email.split_once('@').context("invalid e-mail address")?;
    if local.is_empty()
        || domain.is_empty()
        || domain.len() > 253
        || !domain.contains('.')
        || domain.starts_with('.')
        || domain.ends_with('.')
    {
        bail!("invalid e-mail address");
    }
    Ok(email)
}

/// The password to store: the one given, or a generated one. `true` in the
/// second slot marks a generated password, which the caller must print —
/// nothing else will ever show it.
fn resolve_password(given: &Option<String>) -> anyhow::Result<(String, bool)> {
    let Some(password) = given else {
        return Ok((generate_password(), true));
    };
    validate_password(password).map_err(|err| anyhow::anyhow!("{err}"))?;
    if password.len() > MAX_PASSWORD_BYTES {
        eprintln!(
            "warning: bcrypt only uses the first {MAX_PASSWORD_BYTES} bytes of a password"
        );
    }
    Ok((password.clone(), false))
}

/// A random password: 128 bits from two UUIDv4 payloads, the same
/// construction the API key generator uses.
fn generate_password() -> String {
    format!("{}{}", Uuid::new_v4().simple(), Uuid::new_v4().simple())
}

/// Prints a generated password exactly once.
fn print_generated(password: &str) {
    println!();
    println!("password: {password}");
    println!("Store it now; it is not shown again.");
}

// ─────────────────────────────────────────────────────────────
// user
// ─────────────────────────────────────────────────────────────

async fn user_command(command: UserSubcommand) -> anyhow::Result<()> {
    match command {
        UserSubcommand::List(db) => list_users(db).await,
        UserSubcommand::AddAdmin(opts) => add_admin(opts).await,
        UserSubcommand::ResetPassword(opts) => reset_password(opts).await,
    }
}

async fn list_users(db: DbOpts) -> anyhow::Result<()> {
    let db = connect(&db.db_url).await?;
    let users = user::Entity::find()
        .order_by_asc(user::Column::CreatedAt)
        .all(&db)
        .await
        .context(
            "cannot list users; has the control plane booted against this database?",
        )?;

    if users.is_empty() {
        println!("no users");
        return Ok(());
    }
    println!("{:<40} {:<8} {:<24} CREATED", "EMAIL", "ROLE", "NAME");
    for row in &users {
        println!(
            "{:<40} {:<8} {:<24} {}",
            row.email,
            row.role,
            row.name.as_deref().unwrap_or("-"),
            row.created_at.format("%Y-%m-%d %H:%M:%S UTC")
        );
    }
    println!();
    println!("{} user(s)", users.len());
    Ok(())
}

async fn add_admin(opts: AddAdminOpts) -> anyhow::Result<()> {
    let db = connect(&opts.db.db_url).await?;
    let email = normalise_email(&opts.email)?;
    let (password, generated) = resolve_password(&opts.password)?;

    let existing = user::Entity::find()
        .filter(user::Column::Email.eq(&email))
        .one(&db)
        .await
        .context(
            "cannot read the users table; has the control plane booted against this database?",
        )?;
    if existing.is_some() {
        bail!(
            "a user with e-mail {email} already exists; run \
             `pingwaf user reset-password --email {email}` to set a new password"
        );
    }

    let password_hash = hash_password(&password)
        .map_err(|err| anyhow::anyhow!("cannot hash the password: {err}"))?;
    let now = Utc::now();
    let row = user::ActiveModel {
        id: Set(Uuid::new_v4()),
        email: Set(email),
        password_hash: Set(password_hash),
        name: Set(Some(
            opts.name
                .clone()
                .unwrap_or_else(|| "Administrator".to_string()),
        )),
        role: Set(role::ADMIN.to_string()),
        created_at: Set(now),
        updated_at: Set(now),
    }
    .insert(&db)
    .await
    .context("cannot create the administrator")?;

    println!("administrator {} created (id {})", row.email, row.id);
    if generated {
        print_generated(&password);
    }
    Ok(())
}

async fn reset_password(opts: ResetPasswordOpts) -> anyhow::Result<()> {
    let db = connect(&opts.db.db_url).await?;
    let email = normalise_email(&opts.email)?;
    let (password, generated) = resolve_password(&opts.password)?;

    let Some(row) = user::Entity::find()
        .filter(user::Column::Email.eq(&email))
        .one(&db)
        .await
        .context(
            "cannot read the users table; has the control plane booted against this database?",
        )?
    else {
        bail!("no user with e-mail {email}");
    };

    let password_hash = hash_password(&password)
        .map_err(|err| anyhow::anyhow!("cannot hash the password: {err}"))?;
    let mut active: user::ActiveModel = row.into();
    active.password_hash = Set(password_hash);
    active.updated_at = Set(Utc::now());
    let row = active
        .update(&db)
        .await
        .context("cannot update the password")?;

    println!("password updated for {} ({})", row.email, row.role);
    if generated {
        print_generated(&password);
    }
    Ok(())
}

// ─────────────────────────────────────────────────────────────
// mode
// ─────────────────────────────────────────────────────────────

async fn mode_command(command: ModeCommand) -> anyhow::Result<()> {
    match command {
        ModeCommand::Observe(db) => set_observation_mode(db, true).await,
        ModeCommand::Enforce(db) => set_observation_mode(db, false).await,
        ModeCommand::Status(db) => {
            let db = connect(&db.db_url).await?;
            let row = defense::load(&db).await?;
            print_observation_mode(row.observation_mode);
            Ok(())
        },
    }
}

async fn set_observation_mode(db: DbOpts, enabled: bool) -> anyhow::Result<()> {
    let db = connect(&db.db_url).await?;
    let row = defense::load(&db).await?;
    if row.observation_mode != enabled {
        let mut active: defense_settings::ActiveModel = row.into();
        active.observation_mode = Set(enabled);
        active.updated_at = Set(Utc::now());
        active
            .update(&db)
            .await
            .context("cannot update the defense settings")?;
        println!(
            "a running control plane pushes this to the agents within 15 seconds"
        );
    }
    print_observation_mode(enabled);
    Ok(())
}

fn print_observation_mode(enabled: bool) {
    println!("observation mode: {}", if enabled { "on" } else { "off" });
    if enabled {
        println!(
            "every detection (WAF, IP/geo rules, bot protection, rate \
             limiting) runs but only records; nothing is blocked"
        );
    }
}

// ─────────────────────────────────────────────────────────────
// security
// ─────────────────────────────────────────────────────────────

async fn security_command(command: SecurityCommand) -> anyhow::Result<()> {
    match command {
        SecurityCommand::Status(db) => {
            let db = connect(&db.db_url).await?;
            security_status(&db).await
        },
        SecurityCommand::Allowlist(opts) => set_allowlist(opts).await,
    }
}

async fn security_status(db: &DatabaseConnection) -> anyhow::Result<()> {
    let settings = self_protection::load_settings(db).await?;
    let allowlist = effective_allowlist(db, &settings).await?;

    println!("control plane (9080) protection");
    println!(
        "  access log:        {}",
        if settings.access_log_enabled {
            format!(
                "enabled, retention {} day(s)",
                settings.access_log_retention_days
            )
        } else {
            "disabled".to_string()
        }
    );
    println!(
        "  IP allowlist:      {}",
        if settings.ip_allowlist_enabled {
            "enabled"
        } else {
            "disabled"
        }
    );
    println!(
        "    inline ranges:   {}",
        settings.ip_allowlist_ranges.len()
    );
    match settings.ip_allowlist_group_id {
        Some(group_id) => {
            let group = ip_groups::Entity::find_by_id(group_id).one(db).await?;
            match group {
                Some(group) => println!(
                    "    group:           {} ({group_id}, {} range(s){})",
                    group.name,
                    group.ip_ranges.len(),
                    if group.enabled {
                        ""
                    } else {
                        ", disabled and contributing nothing"
                    }
                ),
                None => println!("    group:           {group_id} (missing)"),
            }
        },
        None => println!("    group:           none"),
    }
    println!("    effective entries: {}", allowlist.len());
    println!(
        "  WAF:               {}",
        if settings.waf_enabled {
            format!("enabled ({})", settings.waf_mode)
        } else {
            "disabled".to_string()
        }
    );
    println!(
        "  updated at:        {}",
        settings.updated_at.format("%Y-%m-%d %H:%M:%S UTC")
    );
    Ok(())
}

async fn set_allowlist(opts: AllowlistOpts) -> anyhow::Result<()> {
    let db = connect(&opts.db.db_url).await?;
    let enabled = opts.state == OnOff::On;

    let settings = self_protection::load_settings(&db).await?;
    let allowlist = effective_allowlist(&db, &settings).await?;
    if enabled && allowlist.is_empty() && !opts.force {
        bail!(
            "the allowlist is empty; enabling it would refuse every API \
             caller (health probes excepted). Add ranges in the console \
             first, or pass --force to enable it anyway"
        );
    }

    if settings.ip_allowlist_enabled != enabled {
        let mut active: api_protection_setting::ActiveModel = settings.into();
        active.ip_allowlist_enabled = Set(enabled);
        active.updated_at = Set(Utc::now());
        active
            .update(&db)
            .await
            .context("cannot update the API protection settings")?;
        println!("a running control plane applies this within 15 seconds");
    }
    println!(
        "IP allowlist: {} ({} effective entr{})",
        if enabled { "enabled" } else { "disabled" },
        allowlist.len(),
        if allowlist.len() == 1 { "y" } else { "ies" }
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn emails_are_lowercased_and_validated() {
        assert_eq!(
            normalise_email("  Ops@Example.COM ").unwrap(),
            "ops@example.com"
        );
        assert!(normalise_email("no-at-sign").is_err());
        assert!(normalise_email("user@nodot").is_err());
        assert!(normalise_email("@example.com").is_err());
        assert!(normalise_email("user@.example.com").is_err());
        assert!(normalise_email("user@example.com.").is_err());
    }

    #[test]
    fn passwords_are_taken_or_generated() {
        let (password, generated) =
            resolve_password(&Some("correct horse".to_string())).unwrap();
        assert_eq!(password, "correct horse");
        assert!(!generated);

        // Short secrets never make it into the database.
        assert!(resolve_password(&Some("short".to_string())).is_err());

        let (password, generated) = resolve_password(&None).unwrap();
        assert!(generated);
        // 128 bits of hex from two UUIDv4 payloads.
        assert_eq!(password.len(), 64);
        assert!(password.chars().all(|c| c.is_ascii_hexdigit()));
    }
}
