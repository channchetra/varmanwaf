//! `port_forwards` — TCP forwards from an edge listener to a private service.
//!
//! A forward is per-site (so it follows the site's ownership) and is enforced
//! by the agent: the listener checks the accepted peer against
//! `allowed_cidrs`, then copies bytes to `target_host:target_port`.

use sea_orm::entity::prelude::*;
use serde::{Deserialize, Serialize};

pub mod port_forwards {
    use super::*;

    #[derive(
        Clone, Debug, PartialEq, DeriveEntityModel, Serialize, Deserialize,
    )]
    #[sea_orm(table_name = "port_forwards")]
    pub struct Model {
        #[sea_orm(primary_key, auto_increment = false)]
        pub id: Uuid,
        pub site_id: Uuid,
        pub name: String,
        pub listen_port: i32,
        pub target_host: String,
        pub target_port: i32,
        pub allowed_cidrs: Vec<String>,
        pub enabled: bool,
        pub created_at: DateTimeUtc,
        pub updated_at: DateTimeUtc,
    }

    #[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
    pub enum Relation {}

    impl ActiveModelBehavior for ActiveModel {}
}
