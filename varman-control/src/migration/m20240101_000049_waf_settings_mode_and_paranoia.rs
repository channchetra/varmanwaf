//! Add the explicit site-level enforcement `mode` and `paranoia_level` to
//! `waf_settings`.
//!
//! Historically the site's WAF mode was derived from the strongest mode of
//! the site's enabled custom rules (block > monitor > off), and the paranoia
//! level from the highest rule severity. Both derivations produced
//! counter-intuitive behavior: a site relying on managed rules alone ran with
//! the engine effectively off, and adding one high-severity rule silently
//! raised detection sensitivity. Both values are now explicit columns; the
//! backfill derives each site's mode from its enabled rules exactly once so
//! existing behavior is preserved, then the explicit value wins.

use sea_orm_migration::prelude::*;

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .alter_table(
                Table::alter()
                    .table(WafSettings::Table)
                    .add_column(
                        ColumnDef::new(WafSettings::Mode)
                            .text()
                            .not_null()
                            .default("off"),
                    )
                    .add_column(
                        ColumnDef::new(WafSettings::ParanoiaLevel)
                            .integer()
                            .not_null()
                            .default(2),
                    )
                    .to_owned(),
            )
            .await?;

        // Backfill every site: create the missing posture rows and seed the
        // mode of existing rows with the one-time rule derivation (block >
        // monitor > off) that the control plane used before this column
        // existed. From here on the stored value is authoritative.
        let conn = manager.get_connection();
        conn.execute_unprepared(
            "INSERT INTO waf_settings \
             (id, site_id, waf_enabled, advanced_mode, monitor_categories, \
             monitor_stacks, monitor_managed_rules, mode, paranoia_level, \
             created_at, updated_at) \
             SELECT gen_random_uuid(), s.id, true, false, '{}', '{}', '{}', \
             CASE \
                 WHEN EXISTS (SELECT 1 FROM rules r \
                     WHERE r.site_id = s.id AND r.enabled AND r.mode = 'block') \
                 THEN 'block' \
                 WHEN EXISTS (SELECT 1 FROM rules r \
                     WHERE r.site_id = s.id AND r.enabled AND r.mode = 'monitor') \
                 THEN 'monitor' \
                 ELSE 'off' \
             END, \
             2, now(), now() \
             FROM sites s \
             ON CONFLICT (site_id) \
             DO UPDATE SET mode = EXCLUDED.mode, updated_at = now()",
        )
        .await?;

        Ok(())
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .alter_table(
                Table::alter()
                    .table(WafSettings::Table)
                    .drop_column(WafSettings::ParanoiaLevel)
                    .drop_column(WafSettings::Mode)
                    .to_owned(),
            )
            .await
    }
}

#[derive(DeriveIden)]
enum WafSettings {
    Table,
    Mode,
    ParanoiaLevel,
}
