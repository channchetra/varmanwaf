//! Key-value state pinned for the life of the instance.
//!
//! The JWT signing secret lives here when the operator did not configure one:
//! it is generated once on first boot and reused forever after, so restarting
//! never silently rotates it and open-source deployments never run on the
//! built-in default (see `lib.rs`).

use sea_orm::entity::prelude::*;

/// `instance_settings` — one row per key.
pub mod instance_settings {
    use super::*;

    #[derive(Clone, Debug, PartialEq, DeriveEntityModel)]
    #[sea_orm(table_name = "instance_settings")]
    pub struct Model {
        #[sea_orm(primary_key, auto_increment = false)]
        pub key: String,
        pub value: String,
        pub updated_at: DateTimeUtc,
    }

    #[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
    pub enum Relation {}

    impl ActiveModelBehavior for ActiveModel {}
}
