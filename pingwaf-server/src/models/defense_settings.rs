//! `defense_settings` — one global row holding the defense mode switches.
//!
//! Today that is the observation mode: with it on, the data plane still runs
//! every detection (WAF, IP/geo rules, bot protection, rate limiting) but
//! records what it would have blocked instead of blocking, challenging or
//! rate-limiting the request.

use sea_orm::entity::prelude::*;
use serde::{Deserialize, Serialize};

#[derive(
    Clone, Debug, PartialEq, DeriveEntityModel, Serialize, Deserialize,
)]
#[sea_orm(table_name = "defense_settings")]
pub struct Model {
    /// Always `1`: the settings are global, not per-site.
    #[sea_orm(primary_key, auto_increment = false)]
    pub id: i32,
    /// When true, every protective action becomes observe-only.
    pub observation_mode: bool,
    pub updated_at: DateTimeUtc,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {}

impl ActiveModelBehavior for ActiveModel {}
