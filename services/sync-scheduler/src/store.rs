//! Database operations for sync job management.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;
use wslvault_storage::pool::DbPool;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SyncJob {
    pub id: Uuid,
    pub integration_id: String,
    pub connector_type: String,
    pub direction: String,
    pub prefix: String,
    pub schedule: Option<String>,
    pub last_run_at: Option<DateTime<Utc>>,
    pub last_run_status: Option<String>,
    pub last_run_result: Option<serde_json::Value>,
    pub consecutive_failures: i32,
    pub max_failures: i32,
    pub enabled: bool,
    pub tenant_id: Uuid,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

/// One `system.sync_jobs` row as selected by `list_sync_jobs`:
/// `(id, integration_id, connector_type, direction, prefix, schedule, last_run_at,
/// last_run_status, last_run_result, consecutive_failures, max_failures, enabled,
/// tenant_id, created_at, updated_at)`.
type SyncJobRow = (
    Uuid,
    String,
    String,
    String,
    String,
    Option<String>,
    Option<DateTime<Utc>>,
    Option<String>,
    Option<serde_json::Value>,
    i32,
    i32,
    bool,
    Uuid,
    DateTime<Utc>,
    DateTime<Utc>,
);

pub async fn list_sync_jobs(pool: &DbPool) -> anyhow::Result<Vec<SyncJob>> {
    let rows: Vec<SyncJobRow> = sqlx::query_as(
        r#"
            SELECT id, integration_id, connector_type, direction, prefix, schedule,
                   last_run_at, last_run_status, last_run_result,
                   consecutive_failures, max_failures, enabled, tenant_id,
                   created_at, updated_at
            FROM system.sync_jobs
            ORDER BY integration_id
            "#,
    )
    .fetch_all(pool.inner())
    .await?;

    Ok(rows
        .into_iter()
        .map(
            |(
                id,
                integration_id,
                connector_type,
                direction,
                prefix,
                schedule,
                last_run_at,
                last_run_status,
                last_run_result,
                consecutive_failures,
                max_failures,
                enabled,
                tenant_id,
                created_at,
                updated_at,
            )| {
                SyncJob {
                    id,
                    integration_id,
                    connector_type,
                    direction,
                    prefix,
                    schedule,
                    last_run_at,
                    last_run_status,
                    last_run_result,
                    consecutive_failures,
                    max_failures,
                    enabled,
                    tenant_id,
                    created_at,
                    updated_at,
                }
            },
        )
        .collect())
}

pub async fn get_enabled_scheduled_jobs(pool: &DbPool) -> anyhow::Result<Vec<SyncJob>> {
    let all = list_sync_jobs(pool).await?;
    Ok(all
        .into_iter()
        .filter(|j| j.enabled && j.schedule.is_some())
        .collect())
}

pub async fn update_job_result(
    pool: &DbPool,
    job_id: Uuid,
    status: &str,
    result: serde_json::Value,
    consecutive_failures: i32,
) -> anyhow::Result<()> {
    sqlx::query(
        r#"
        UPDATE system.sync_jobs
        SET last_run_at = now(),
            last_run_status = $1,
            last_run_result = $2,
            consecutive_failures = $3
        WHERE id = $4
        "#,
    )
    .bind(status)
    .bind(result)
    .bind(consecutive_failures)
    .bind(job_id)
    .execute(pool.inner())
    .await?;

    Ok(())
}
