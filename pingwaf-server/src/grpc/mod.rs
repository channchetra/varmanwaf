//! gRPC control plane service, agent registry and configuration builder.
//!
//! This module exposes three submodules:
//! - [`config`] — builds protocol messages from database rows
//! - [`control_plane`] — implements the `ControlPlane` gRPC service
//! - [`registry`] — in-memory map of live agent heartbeat streams
//!
//! The key integration point for the REST API is [`notify_config_changed`], which
//! pushes a fresh `SiteConfig` to every agent that serves the changed site.

pub mod cache_status;
pub mod config;
pub mod control_plane;
pub mod registry;

pub use cache_status::{CacheStatusRegistry, SiteCacheStatus};
pub use control_plane::ControlPlaneService;
pub use registry::{AgentRegistry, ConnectedAgent, COMMAND_CHANNEL_CAPACITY};

use pingwaf_proto::control_plane::{
    server_command::Payload, ServerCommand, SiteConfig, UpdateSiteCommand,
};
use sea_orm::{ColumnTrait, EntityTrait, QueryFilter};
use uuid::Uuid;

use crate::api::agents::command_type;
use crate::api::state::AppState;
use crate::grpc::config::{build_site_config, now_timestamp};
use crate::models::agent;

/// Notifies every connected agent that the configuration for `site_id` changed.
///
/// This is a best-effort operation: it logs failures but never propagates them
/// to the caller. The REST API handler has already committed the change; a push
/// failure merely means the agent will pick it up on the next `sync_rules`.
pub async fn notify_config_changed(state: &AppState, site_id: Uuid) {
    // Build the new configuration. If the database is unhappy there is nothing
    // worth sending, so bail out with a warning.
    let site_config = match build_site_config(&state.db, Some(&[site_id])).await
    {
        Ok(config) => config,
        Err(err) => {
            tracing::warn!(%site_id, error = %err, "failed to build site config for push");
            return;
        },
    };

    // Find every agent whose site_id matches, then attempt delivery.
    let agents = match agent::Entity::find()
        .filter(agent::Column::SiteId.eq(site_id))
        .all(&state.db)
        .await
    {
        Ok(rows) => rows,
        Err(err) => {
            tracing::warn!(%site_id, error = %err, "failed to list agents for config push");
            return;
        },
    };

    if agents.is_empty() {
        tracing::debug!(%site_id, "no agents bound to this site, skipping push");
        return;
    }

    let mut delivered = 0usize;
    for row in &agents {
        let command = ServerCommand {
            command_id: Uuid::new_v4().to_string(),
            r#type: command_type::UPDATE_SITE,
            issued_at: now_timestamp(),
            payload: Some(Payload::UpdateSite(UpdateSiteCommand {
                site_config: Some(site_config.clone()),
            })),
        };
        if state.agents.send_command(&row.id, command).await {
            delivered += 1;
        }
    }

    tracing::info!(
        %site_id,
        total = agents.len(),
        delivered,
        "config change pushed to agents"
    );
}

/// Notifies every registered agent that a deployment-wide setting changed.
///
/// Meant for changes that land in *every* site's bundle (the global error
/// pages today): calling [`notify_config_changed`] per site would rebuild one
/// site at a time and fan a single edit out into as many database passes as
/// there are sites. Instead the affected site ids are collected from the agent
/// table and built in one pass; each agent then receives only its own site, the
/// same payload a normal push carries, so an agent's cache never grows beyond
/// the site it is bound to.
pub async fn notify_all_config_changed(state: &AppState) {
    let agents = match agent::Entity::find().all(&state.db).await {
        Ok(rows) => rows,
        Err(err) => {
            tracing::warn!(error = %err, "failed to list agents for config push");
            return;
        },
    };
    if agents.is_empty() {
        tracing::debug!("no agents registered, skipping config push");
        return;
    }

    let site_ids: Vec<Uuid> = agents
        .iter()
        .filter_map(|row| row.site_id)
        .collect::<std::collections::HashSet<_>>()
        .into_iter()
        .collect();
    let config = match build_site_config(&state.db, Some(&site_ids)).await {
        Ok(config) => config,
        Err(err) => {
            tracing::warn!(error = %err, "failed to build site config for push");
            return;
        },
    };

    let mut delivered = 0usize;
    for row in &agents {
        // An agent without a site has no bundle to receive.
        let Some(site_id) = row.site_id else {
            continue;
        };
        let Some(site) = config
            .sites
            .iter()
            .find(|site| site.id == site_id.to_string())
        else {
            tracing::warn!(
                agent_id = %row.id,
                site_id = %site_id,
                "site missing from the built config, skipping agent"
            );
            continue;
        };
        let site_config = SiteConfig {
            sites: vec![site.clone()],
            updated_at: config.updated_at,
            config_hash: config.config_hash.clone(),
        };
        let command = ServerCommand {
            command_id: Uuid::new_v4().to_string(),
            r#type: command_type::UPDATE_SITE,
            issued_at: now_timestamp(),
            payload: Some(Payload::UpdateSite(UpdateSiteCommand {
                site_config: Some(site_config),
            })),
        };
        if state.agents.send_command(&row.id, command).await {
            delivered += 1;
        }
    }

    tracing::info!(
        sites = site_ids.len(),
        total = agents.len(),
        delivered,
        "global config change pushed to agents"
    );
}
