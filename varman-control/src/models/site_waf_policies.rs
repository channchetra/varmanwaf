//! `site_waf_policies` - which policy a site follows.
//!
//! One row per site at most; deleting the row returns the site to its own
//! `waf_settings` / rules. Deleting a policy cascades its assignments away,
//! so a removed policy can never leave a dangling reference behind.

use sea_orm::entity::prelude::*;
use serde::{Deserialize, Serialize};

#[derive(
    Clone, Debug, PartialEq, DeriveEntityModel, Serialize, Deserialize,
)]
#[sea_orm(table_name = "site_waf_policies")]
pub struct Model {
    #[sea_orm(primary_key, auto_increment = false)]
    pub site_id: Uuid,
    pub policy_id: Uuid,
    pub updated_at: DateTimeUtc,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {}

impl ActiveModelBehavior for ActiveModel {}
