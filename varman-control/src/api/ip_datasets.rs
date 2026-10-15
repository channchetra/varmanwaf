//! IP datasets: the ipverse-synced country and ASN ranges.
//!
//! Reads are for the console (which shows every referenced key and whether
//! its dataset exists); writes are administrator-only syncs. A sync pushes
//! fresh bundles to every site whose geo policy references a synced key, so
//! "synced" and "applied" never drift apart.

use axum::extract::State;
use axum::routing::{get, post};
use axum::{Json, Router};
use chrono::{DateTime, Utc};
use sea_orm::EntityTrait;
use serde::{Deserialize, Serialize};

use crate::api::error::ApiError;
use crate::api::state::AppState;
use crate::auth::AuthUser;
use crate::grpc::notify_config_changed;
use crate::ipverse::{self, KIND_ASN, KIND_COUNTRY};
use crate::models::{geo_rules, ip_datasets};

/// Routes contributed to `/api/v1`.
pub fn routes() -> Router<AppState> {
    Router::new()
        .route("/ip-datasets", get(list))
        .route("/ip-datasets/sync", post(sync))
        .route("/ip-datasets/sync-referenced", post(sync_referenced))
}

#[derive(Debug, Serialize)]
pub struct DatasetsView {
    items: Vec<DatasetView>,
    /// Every key the geo policies reference, with whether its dataset
    /// exists. A missing key is not enforced.
    referenced: Vec<ReferencedKey>,
}

#[derive(Debug, Serialize)]
pub struct DatasetView {
    kind: String,
    key: String,
    ipv4_ranges: usize,
    ipv6_ranges: usize,
    source_url: String,
    synced_at: Option<DateTime<Utc>>,
    last_error: Option<String>,
    refresh_interval_minutes: Option<i32>,
    /// Whether any geo policy lists this key.
    referenced: bool,
}

#[derive(Debug, Serialize)]
pub struct ReferencedKey {
    kind: String,
    key: String,
    synced: bool,
    synced_at: Option<DateTime<Utc>>,
}

#[derive(Debug, Deserialize)]
pub struct SyncRequest {
    /// `country` or `asn`.
    kind: String,
    keys: Vec<String>,
}

#[derive(Debug, Serialize)]
pub struct SyncResult {
    key: String,
    synced: bool,
    ipv4_ranges: usize,
    ipv6_ranges: usize,
    error: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct SyncResponse {
    results: Vec<SyncResult>,
    /// Sites whose geo policy referenced a synced key and were re-pushed.
    pushed_sites: usize,
}

/// `GET /api/v1/ip-datasets` - administrators only.
async fn list(
    State(state): State<AppState>,
    current: AuthUser,
) -> Result<Json<DatasetsView>, ApiError> {
    current.require_admin().map_err(ApiError::from)?;

    let rows = ip_datasets::Entity::find().all(&state.db).await?;
    let referenced = referenced_keys(&state).await?;
    let referenced_set: std::collections::HashSet<(String, String)> =
        referenced
            .iter()
            .map(|entry| (entry.kind.clone(), entry.key.clone()))
            .collect();

    let items = rows
        .into_iter()
        .map(|row| DatasetView {
            referenced: referenced_set
                .contains(&(row.kind.clone(), row.dataset_key.clone())),
            kind: row.kind,
            key: row.dataset_key,
            ipv4_ranges: row.ipv4_ranges.len(),
            ipv6_ranges: row.ipv6_ranges.len(),
            source_url: row.source_url,
            synced_at: row.last_synced_at,
            last_error: row.last_error,
            refresh_interval_minutes: row.refresh_interval_minutes,
        })
        .collect();

    Ok(Json(DatasetsView { items, referenced }))
}

/// `POST /api/v1/ip-datasets/sync` - administrators only.
async fn sync(
    State(state): State<AppState>,
    current: AuthUser,
    Json(payload): Json<SyncRequest>,
) -> Result<Json<SyncResponse>, ApiError> {
    current.require_admin().map_err(ApiError::from)?;
    if !matches!(payload.kind.as_str(), KIND_COUNTRY | KIND_ASN) {
        return Err(ApiError::BadRequest(format!(
            "unknown dataset kind '{}' (use 'country' or 'asn')",
            payload.kind
        )));
    }
    if payload.keys.is_empty() {
        return Err(ApiError::BadRequest(
            "at least one key is required".to_string(),
        ));
    }

    let results = sync_keys(&state, &payload.kind, &payload.keys).await;
    let synced_keys: Vec<String> = results
        .iter()
        .filter(|result| result.synced)
        .map(|result| result.key.clone())
        .collect();
    let pushed_sites =
        push_affected_sites(&state, &payload.kind, &synced_keys, &current)
            .await;

    Ok(Json(SyncResponse {
        results,
        pushed_sites,
    }))
}

/// `POST /api/v1/ip-datasets/sync-referenced` - administrators only: refresh
/// every dataset a geo policy references (the one-button action).
async fn sync_referenced(
    State(state): State<AppState>,
    current: AuthUser,
) -> Result<Json<SyncResponse>, ApiError> {
    current.require_admin().map_err(ApiError::from)?;

    let referenced = referenced_keys(&state).await?;
    let countries: Vec<String> = referenced
        .iter()
        .filter(|entry| entry.kind == KIND_COUNTRY)
        .map(|entry| entry.key.clone())
        .collect();
    let asns: Vec<String> = referenced
        .iter()
        .filter(|entry| entry.kind == KIND_ASN)
        .map(|entry| entry.key.clone())
        .collect();

    let mut results = Vec::new();
    let mut pushed_sites = 0;
    for (kind, keys) in [(KIND_COUNTRY, countries), (KIND_ASN, asns)] {
        if keys.is_empty() {
            continue;
        }
        let batch = sync_keys(&state, kind, &keys).await;
        let synced_keys: Vec<String> = batch
            .iter()
            .filter(|result| result.synced)
            .map(|result| result.key.clone())
            .collect();
        pushed_sites +=
            push_affected_sites(&state, kind, &synced_keys, &current).await;
        results.extend(batch);
    }

    Ok(Json(SyncResponse {
        results,
        pushed_sites,
    }))
}

async fn sync_keys(
    state: &AppState,
    kind: &str,
    keys: &[String],
) -> Vec<SyncResult> {
    let mut results = Vec::with_capacity(keys.len());
    for key in keys {
        let normalised = ipverse::normalise_key(kind, key);
        let result = match normalised {
            Ok(normalised) => {
                match ipverse::sync_dataset(&state.db, kind, &normalised).await
                {
                    Ok(row) => SyncResult {
                        key: normalised,
                        synced: true,
                        ipv4_ranges: row.ipv4_ranges.len(),
                        ipv6_ranges: row.ipv6_ranges.len(),
                        error: None,
                    },
                    Err(error) => SyncResult {
                        key: normalised,
                        synced: false,
                        ipv4_ranges: 0,
                        ipv6_ranges: 0,
                        error: Some(error),
                    },
                }
            },
            Err(error) => SyncResult {
                key: key.clone(),
                synced: false,
                ipv4_ranges: 0,
                ipv6_ranges: 0,
                error: Some(error),
            },
        };
        results.push(result);
    }
    results
}

/// Re-pushes every site whose geo policy lists one of the synced keys.
async fn push_affected_sites(
    state: &AppState,
    kind: &str,
    synced_keys: &[String],
    current: &AuthUser,
) -> usize {
    if synced_keys.is_empty() {
        return 0;
    }
    let normalised: std::collections::HashSet<String> = synced_keys
        .iter()
        .filter_map(|key| ipverse::normalise_key(kind, key).ok())
        .collect();

    let rows = match geo_rules::Entity::find().all(&state.db).await {
        Ok(rows) => rows,
        Err(error) => {
            tracing::warn!(error = %error, "failed to load geo rules for dataset push");
            return 0;
        },
    };

    let mut pushed = 0;
    for row in rows {
        let affected = match kind {
            KIND_COUNTRY => row.countries.iter().any(|key| {
                ipverse::normalise_key(KIND_COUNTRY, key)
                    .is_ok_and(|key| normalised.contains(&key))
            }),
            KIND_ASN => row.blocked_asns.iter().any(|key| {
                ipverse::normalise_key(KIND_ASN, key)
                    .is_ok_and(|key| normalised.contains(&key))
            }),
            _ => false,
        };
        if affected {
            notify_config_changed(state, row.site_id, Some(&current.email))
                .await;
            pushed += 1;
        }
    }
    pushed
}

/// Every key the geo policies reference, deduplicated.
async fn referenced_keys(
    state: &AppState,
) -> Result<Vec<ReferencedKey>, ApiError> {
    let rows = geo_rules::Entity::find().all(&state.db).await?;
    let datasets = ip_datasets::Entity::find().all(&state.db).await?;
    let synced: std::collections::HashMap<
        (String, String),
        Option<DateTime<Utc>>,
    > = datasets
        .into_iter()
        .map(|row| {
            (
                (row.kind.clone(), row.dataset_key.clone()),
                row.last_synced_at,
            )
        })
        .collect();

    let mut seen = std::collections::BTreeSet::new();
    let mut referenced = Vec::new();
    for row in rows {
        for (kind, key) in row
            .countries
            .iter()
            .map(|key| (KIND_COUNTRY, key))
            .chain(row.blocked_asns.iter().map(|key| (KIND_ASN, key)))
        {
            let Ok(normalised) = ipverse::normalise_key(kind, key) else {
                continue;
            };
            if !seen.insert((kind.to_string(), normalised.clone())) {
                continue;
            }
            let synced_at = synced
                .get(&(kind.to_string(), normalised.clone()))
                .copied()
                .flatten();
            referenced.push(ReferencedKey {
                kind: kind.to_string(),
                key: normalised,
                synced: synced_at.is_some(),
                synced_at,
            });
        }
    }
    Ok(referenced)
}
