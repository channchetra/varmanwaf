//! ipverse datasets: country and ASN IP ranges, the only source of geo and
//! ASN enforcement data.
//!
//! Country documents live in `ipverse/rir-ip`
//! (`country/<cc>/ipv{4,6}-aggregated.txt`); autonomous-system documents live
//! in `ipverse/as-ip-blocks` (`as/<n>/ipv{4,6}-aggregated.txt`). Both are
//! plain-text, aggregated CIDR lists that the subscription parser already
//! handles. Synced rows are stored in `ip_datasets`; the geo compiler and
//! the client-IP analysis read them back, and a listed key without a row is
//! surfaced as missing rather than silently unmatched.

use std::collections::HashMap;

use chrono::{DateTime, Utc};
use sea_orm::{
    ActiveModelTrait, ColumnTrait, DatabaseConnection, EntityTrait,
    QueryFilter, Set,
};
use uuid::Uuid;

use crate::models::ip_datasets;
use crate::subscription::{fetch_subscription_ranges, subscription_client};

/// Country documents (ipverse `rir-ip`).
pub const COUNTRY_BASE: &str =
    "https://raw.githubusercontent.com/ipverse/rir-ip/master/country";
/// Autonomous-system documents (ipverse `as-ip-blocks`).
pub const ASN_BASE: &str =
    "https://raw.githubusercontent.com/ipverse/as-ip-blocks/master/as";

/// Dataset kinds.
pub const KIND_COUNTRY: &str = "country";
pub const KIND_ASN: &str = "asn";

/// Default refresh cadence: daily.
pub const DEFAULT_REFRESH_MINUTES: i32 = 24 * 60;

/// Normalises a dataset key: two-letter country codes become upper-case
/// (the URL uses the lower-case form), ASNs become bare digits.
pub fn normalise_key(kind: &str, key: &str) -> Result<String, String> {
    let trimmed = key.trim();
    match kind {
        KIND_COUNTRY => {
            let code = trimmed.to_uppercase();
            let ok = code.len() == 2
                && code.chars().all(|c| c.is_ascii_alphabetic());
            if ok {
                Ok(code)
            } else {
                Err(format!("'{trimmed}' is not a two-letter country code"))
            }
        },
        KIND_ASN => {
            let digits = trimmed
                .strip_prefix("AS")
                .or_else(|| trimmed.strip_prefix("as"))
                .unwrap_or(trimmed);
            digits
                .parse::<u32>()
                .map(|asn| asn.to_string())
                .map_err(|_| format!("'{trimmed}' is not an ASN"))
        },
        other => Err(format!("unknown dataset kind '{other}'")),
    }
}

/// The ipverse URLs for a normalised key: IPv4 first, then IPv6.
pub fn source_urls(kind: &str, key: &str) -> Result<(String, String), String> {
    match kind {
        KIND_COUNTRY => {
            let lower = key.to_lowercase();
            Ok((
                format!("{COUNTRY_BASE}/{lower}/ipv4-aggregated.txt"),
                format!("{COUNTRY_BASE}/{lower}/ipv6-aggregated.txt"),
            ))
        },
        KIND_ASN => Ok((
            format!("{ASN_BASE}/{key}/ipv4-aggregated.txt"),
            format!("{ASN_BASE}/{key}/ipv6-aggregated.txt"),
        )),
        other => Err(format!("unknown dataset kind '{other}'")),
    }
}

/// One synced dataset, as the compiler and the analysis read it.
#[derive(Debug, Clone)]
pub struct DatasetRanges {
    pub ipv4: Vec<String>,
    pub ipv6: Vec<String>,
    pub synced_at: Option<DateTime<Utc>>,
}

impl DatasetRanges {
    /// Both families in one list (the range matcher accepts either).
    pub fn all(&self) -> Vec<String> {
        let mut ranges = self.ipv4.clone();
        ranges.extend(self.ipv6.iter().cloned());
        ranges
    }
}

/// Downloads both families for one key and upserts the row. A 404 on the
/// IPv6 document means "no IPv6 ranges" (some ASNs announce none); every
/// other failure is recorded in `last_error` and returned.
pub async fn sync_dataset(
    db: &DatabaseConnection,
    kind: &str,
    key: &str,
) -> Result<ip_datasets::Model, String> {
    let key = normalise_key(kind, key)?;
    let (ipv4_url, ipv6_url) = source_urls(kind, &key)?;
    let client = subscription_client();

    let ipv4 = match fetch_subscription_ranges(&client, &ipv4_url).await {
        Ok(ranges) => ranges,
        Err(error) => {
            record_error(db, kind, &key, &ipv4_url, &error).await;
            return Err(error);
        },
    };
    let ipv6 = match fetch_subscription_ranges(&client, &ipv6_url).await {
        Ok(ranges) => ranges,
        Err(error) if error.contains("HTTP 404") => Vec::new(),
        Err(error) => {
            record_error(db, kind, &key, &ipv4_url, &error).await;
            return Err(error);
        },
    };

    upsert(db, kind, &key, ipv4, ipv6, &ipv4_url).await
}

/// Loads the synced datasets for a set of keys, keyed by the normalised key.
pub async fn load_map(
    db: &DatabaseConnection,
    kind: &str,
    keys: &[String],
) -> Result<HashMap<String, DatasetRanges>, sea_orm::DbErr> {
    if keys.is_empty() {
        return Ok(HashMap::new());
    }
    let normalised: Vec<String> = keys
        .iter()
        .filter_map(|key| normalise_key(kind, key).ok())
        .collect();
    let rows = ip_datasets::Entity::find()
        .filter(ip_datasets::Column::Kind.eq(kind))
        .filter(ip_datasets::Column::DatasetKey.is_in(normalised))
        .all(db)
        .await?;
    Ok(rows
        .into_iter()
        .map(|row| {
            (
                row.dataset_key.clone(),
                DatasetRanges {
                    ipv4: row.ipv4_ranges,
                    ipv6: row.ipv6_ranges,
                    synced_at: row.last_synced_at,
                },
            )
        })
        .collect())
}

/// Syncs every dataset whose refresh interval has elapsed (the sweep the
/// subscription scheduler calls on each tick).
pub async fn sync_due_datasets(
    db: &DatabaseConnection,
) -> Result<usize, sea_orm::DbErr> {
    let rows = ip_datasets::Entity::find()
        .filter(ip_datasets::Column::RefreshIntervalMinutes.is_not_null())
        .all(db)
        .await?;
    let now = Utc::now();
    let mut synced = 0;
    for row in rows {
        let interval = row.refresh_interval_minutes.unwrap_or(0);
        if interval <= 0 {
            continue;
        }
        let due = match row.last_synced_at {
            None => true,
            Some(last) => {
                now >= last + chrono::Duration::minutes(i64::from(interval))
            },
        };
        if !due {
            continue;
        }
        match sync_dataset(db, &row.kind, &row.dataset_key).await {
            Ok(_) => synced += 1,
            Err(error) => tracing::warn!(
                kind = %row.kind,
                key = %row.dataset_key,
                error = %error,
                "ipverse dataset refresh failed"
            ),
        }
    }
    Ok(synced)
}

/// Records a failed sync without losing the previous ranges.
async fn record_error(
    db: &DatabaseConnection,
    kind: &str,
    key: &str,
    source_url: &str,
    error: &str,
) {
    let existing = find(db, kind, key).await.ok().flatten();
    match existing {
        Some(row) => {
            let mut active: ip_datasets::ActiveModel = row.into();
            active.last_error = Set(Some(error.to_string()));
            active.updated_at = Set(Utc::now());
            if let Err(err) = active.update(db).await {
                tracing::warn!(error = %err, "failed to record dataset sync error");
            }
        },
        None => {
            let insert = ip_datasets::ActiveModel {
                id: Set(Uuid::new_v4()),
                kind: Set(kind.to_string()),
                dataset_key: Set(key.to_string()),
                ipv4_ranges: Set(Vec::new()),
                ipv6_ranges: Set(Vec::new()),
                source_url: Set(source_url.to_string()),
                refresh_interval_minutes: Set(Some(DEFAULT_REFRESH_MINUTES)),
                last_synced_at: Set(None),
                last_error: Set(Some(error.to_string())),
                created_at: Set(Utc::now()),
                updated_at: Set(Utc::now()),
            };
            if let Err(err) = insert.insert(db).await {
                tracing::warn!(error = %err, "failed to record dataset sync error");
            }
        },
    }
}

/// Inserts or updates the dataset row with fresh ranges.
async fn upsert(
    db: &DatabaseConnection,
    kind: &str,
    key: &str,
    ipv4: Vec<String>,
    ipv6: Vec<String>,
    source_url: &str,
) -> Result<ip_datasets::Model, String> {
    let now = Utc::now();
    match find(db, kind, key).await.map_err(|err| err.to_string())? {
        Some(row) => {
            let mut active: ip_datasets::ActiveModel = row.into();
            active.ipv4_ranges = Set(ipv4);
            active.ipv6_ranges = Set(ipv6);
            active.source_url = Set(source_url.to_string());
            active.last_synced_at = Set(Some(now));
            active.last_error = Set(None);
            active.updated_at = Set(now);
            active.update(db).await.map_err(|err| err.to_string())
        },
        None => {
            let insert = ip_datasets::ActiveModel {
                id: Set(Uuid::new_v4()),
                kind: Set(kind.to_string()),
                dataset_key: Set(key.to_string()),
                ipv4_ranges: Set(ipv4),
                ipv6_ranges: Set(ipv6),
                source_url: Set(source_url.to_string()),
                refresh_interval_minutes: Set(Some(DEFAULT_REFRESH_MINUTES)),
                last_synced_at: Set(Some(now)),
                last_error: Set(None),
                created_at: Set(now),
                updated_at: Set(now),
            };
            insert.insert(db).await.map_err(|err| err.to_string())
        },
    }
}

async fn find(
    db: &DatabaseConnection,
    kind: &str,
    key: &str,
) -> Result<Option<ip_datasets::Model>, sea_orm::DbErr> {
    ip_datasets::Entity::find()
        .filter(ip_datasets::Column::Kind.eq(kind))
        .filter(ip_datasets::Column::DatasetKey.eq(key))
        .one(db)
        .await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn keys_normalise_per_kind() {
        assert_eq!(normalise_key(KIND_COUNTRY, "us").unwrap(), "US");
        assert_eq!(normalise_key(KIND_COUNTRY, " US ").unwrap(), "US");
        assert!(normalise_key(KIND_COUNTRY, "USA").is_err());
        assert!(normalise_key(KIND_COUNTRY, "1").is_err());
        assert_eq!(normalise_key(KIND_ASN, "AS13335").unwrap(), "13335");
        assert_eq!(normalise_key(KIND_ASN, "as13335").unwrap(), "13335");
        assert_eq!(normalise_key(KIND_ASN, "13335").unwrap(), "13335");
        assert!(normalise_key(KIND_ASN, "cloudflare").is_err());
        assert!(normalise_key("planet", "earth").is_err());
    }

    #[test]
    fn urls_point_at_ipverse_only() {
        let (v4, v6) = source_urls(KIND_COUNTRY, "US").unwrap();
        assert_eq!(
            v4,
            "https://raw.githubusercontent.com/ipverse/rir-ip/master/country/us/ipv4-aggregated.txt"
        );
        assert_eq!(
            v6,
            "https://raw.githubusercontent.com/ipverse/rir-ip/master/country/us/ipv6-aggregated.txt"
        );
        let (v4, v6) = source_urls(KIND_ASN, "13335").unwrap();
        assert_eq!(
            v4,
            "https://raw.githubusercontent.com/ipverse/as-ip-blocks/master/as/13335/ipv4-aggregated.txt"
        );
        assert_eq!(
            v6,
            "https://raw.githubusercontent.com/ipverse/as-ip-blocks/master/as/13335/ipv6-aggregated.txt"
        );
    }

    #[test]
    fn ranges_merge_both_families() {
        let ranges = DatasetRanges {
            ipv4: vec!["8.8.8.0/24".to_string()],
            ipv6: vec!["2001:4860::/32".to_string()],
            synced_at: None,
        };
        assert_eq!(ranges.all().len(), 2);
    }
}
