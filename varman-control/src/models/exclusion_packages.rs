//! `exclusion_packages` + `site_exclusion_bindings` - named, path-scoped
//! rule-exclusion sets.
//!
//! A package is a versioned set of entries: a rule id or a tag selector,
//! plus the request sources to exclude from that rule's evaluation. A
//! binding attaches one package to a site at a path prefix; only requests
//! whose path starts with the prefix are affected.

use sea_orm::entity::prelude::*;
use serde::{Deserialize, Serialize};

#[derive(
    Clone, Debug, PartialEq, DeriveEntityModel, Serialize, Deserialize,
)]
#[sea_orm(table_name = "exclusion_packages")]
pub struct Model {
    #[sea_orm(primary_key, auto_increment = false)]
    pub id: Uuid,
    /// Stable key (`wordpress`, `nextjs-static`, operator-defined slugs).
    pub key: String,
    pub name: String,
    #[sea_orm(column_type = "Text", default_value = "")]
    pub description: String,
    /// Where the content came from; empty for operator-defined packages.
    #[sea_orm(column_type = "Text", default_value = "")]
    pub source_url: String,
    pub version: String,
    /// `[{ rule_id | tags | severity_min, targets, note }]`.
    #[sea_orm(column_type = "JsonBinary")]
    pub entries: Json,
    /// Seeded catalogue package (editable, not deletable).
    pub builtin: bool,
    pub created_at: DateTimeUtc,
    pub updated_at: DateTimeUtc,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {}

impl ActiveModelBehavior for ActiveModel {}

/// `site_exclusion_bindings` - a package attached to a site at a prefix.
pub mod bindings {
    use super::*;

    #[derive(
        Clone, Debug, PartialEq, DeriveEntityModel, Serialize, Deserialize,
    )]
    #[sea_orm(table_name = "site_exclusion_bindings")]
    pub struct Model {
        #[sea_orm(primary_key, auto_increment = false)]
        pub id: Uuid,
        pub site_id: Uuid,
        pub package_id: Uuid,
        /// Requests whose path starts with this prefix are affected.
        pub path_prefix: String,
        pub enabled: bool,
        /// The package version at attach time (re-attach updates it).
        pub installed_version: String,
        pub created_at: DateTimeUtc,
        pub updated_at: DateTimeUtc,
    }

    #[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
    pub enum Relation {}

    impl ActiveModelBehavior for ActiveModel {}
}
