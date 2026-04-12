//! Failover logic for promoting a region.

use tracing::info;
use wslvault_storage::pool::DbPool;

/// Trigger a manual failover to the specified target region.
///
/// Writes a `region_promote` replication event so all regions are notified.
pub async fn trigger_failover(
    pool: &DbPool,
    target_region: &str,
    local_region: &str,
) -> anyhow::Result<()> {
    info!(
        target = target_region,
        initiated_from = local_region,
        "triggering manual failover"
    );

    // Write a region_promote replication event.
    sqlx::query(
        r#"
        INSERT INTO system.replication_events (event_type, source_region, payload)
        VALUES ('region_promote', $1, $2)
        "#,
    )
    .bind(local_region)
    .bind(serde_json::json!({
        "target_region": target_region,
        "initiated_by": local_region,
    }))
    .execute(pool.inner())
    .await?;

    // Update the target region's status to active.
    sqlx::query("UPDATE system.regions SET status = 'active', last_seen = now() WHERE id = $1")
        .bind(target_region)
        .execute(pool.inner())
        .await?;

    Ok(())
}
