//! `ip_group_sites` — many-to-many association between IP groups and sites
//! (only used when the group is not global).

use sea_orm::entity::prelude::*;
use serde::{Deserialize, Serialize};

#[derive(
    Clone, Debug, PartialEq, DeriveEntityModel, Serialize, Deserialize,
)]
#[sea_orm(table_name = "ip_group_sites")]
pub struct Model {
    #[sea_orm(primary_key, auto_increment = false)]
    pub ip_group_id: Uuid,
    #[sea_orm(primary_key, auto_increment = false)]
    pub site_id: Uuid,
    pub created_at: DateTimeUtc,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {}

impl ActiveModelBehavior for ActiveModel {}
