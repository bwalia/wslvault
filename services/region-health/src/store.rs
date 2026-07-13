//! Database operations for region status tracking.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use wslvault_storage::pool::DbPool;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegionInfo {
    pub id: String,
    pub display_name: String,
    pub endpoint: String,
    pub status: String,
    pub is_local: bool,
    pub replication_lag_ms: Option<i64>,
    pub last_seen: DateTime<Utc>,
    pub metadata: serde_json::Value,
}

pub async fn list_regions(pool: &DbPool) -> anyhow::Result<Vec<RegionInfo>> {
    let rows: Vec<(String, String, String, String, bool, Option<i64>, DateTime<Utc>, serde_json::Value)> =
        sqlx::query_as(
            r#"
            SELECT id, display_name, endpoint, status, is_local, replication_lag_ms, last_seen, metadata
            FROM system.regions
            ORDER BY id
            "#,
        )
        .fetch_all(pool.inner())
        .await?;

    Ok(rows
        .into_iter()
        .map(
            |(
                id,
                display_name,
                endpoint,
                status,
                is_local,
                replication_lag_ms,
                last_seen,
                metadata,
            )| {
                RegionInfo {
                    id,
                    display_name,
                    endpoint,
                    status,
                    is_local,
                    replication_lag_ms,
                    last_seen,
                    metadata,
                }
            },
        )
        .collect())
}

pub async fn get_region(pool: &DbPool, region_id: &str) -> anyhow::Result<Option<RegionInfo>> {
    let row: Option<(String, String, String, String, bool, Option<i64>, DateTime<Utc>, serde_json::Value)> =
        sqlx::query_as(
            r#"
            SELECT id, display_name, endpoint, status, is_local, replication_lag_ms, last_seen, metadata
            FROM system.regions
            WHERE id = $1
            "#,
        )
        .bind(region_id)
        .fetch_optional(pool.inner())
        .await?;

    Ok(row.map(
        |(
            id,
            display_name,
            endpoint,
            status,
            is_local,
            replication_lag_ms,
            last_seen,
            metadata,
        )| {
            RegionInfo {
                id,
                display_name,
                endpoint,
                status,
                is_local,
                replication_lag_ms,
                last_seen,
                metadata,
            }
        },
    ))
}

pub async fn update_region_status(
    pool: &DbPool,
    region_id: &str,
    status: &str,
    replication_lag_ms: Option<i64>,
) -> anyhow::Result<()> {
    sqlx::query(
        r#"
        UPDATE system.regions
        SET status = $1, replication_lag_ms = $2, last_seen = now()
        WHERE id = $3
        "#,
    )
    .bind(status)
    .bind(replication_lag_ms)
    .bind(region_id)
    .execute(pool.inner())
    .await?;

    Ok(())
}
