//! `varman.CommandType` values.
//!
//! Spelled out so the control plane does not depend on prost's enum variant
//! naming. Shared by the gRPC service and the REST command endpoint.

pub const CONFIG_RELOAD: i32 = 2;
pub const BLOCK_IP: i32 = 3;
pub const UNBLOCK_IP: i32 = 4;
pub const PURGE_CACHE: i32 = 5;
pub const UPDATE_SITE: i32 = 6;
pub const RESTART_AGENT: i32 = 7;
