//! Applies remote replication events to the local database.

use std::collections::HashMap;

use tracing::{debug, info, warn};
use wslvault_storage::pool::DbPool;

use crate::conflict::{self, ConflictContext, Resolution};
use crate::consumer::ReplicationEvent;

/// Apply a single replication event to the local database.
///
/// Uses the configured conflict resolution strategy when the local database
/// already has a version of the affected secret.
pub async fn apply_event(
    pool: &DbPool,
    event: &ReplicationEvent,
    conflict_strategy: &str,
    local_region: &str,
) -> anyhow::Result<()> {
    match event.event_type.as_str() {
        "secret_upsert" => apply_secret_upsert(pool, event, conflict_strategy, local_region).await,
        "secret_delete" => apply_secret_delete(pool, event).await,
        "secret_destroy" => apply_secret_destroy(pool, event).await,
        "key_rotate" => apply_key_rotate(pool, event).await,
        "policy_update" => apply_policy_update(pool, event).await,
        "tenant_update" => apply_tenant_update(pool, event).await,
        "region_failover" | "region_promote" => {
            info!(
                event_type = %event.event_type,
                source = %event.source_region,
                "received region control event"
            );
            Ok(())
        }
        other => {
            warn!(event_type = other, "unknown replication event type, skipping");
            Ok(())
        }
    }
}

async fn apply_secret_upsert(
    pool: &DbPool,
    event: &ReplicationEvent,
    conflict_strategy: &str,
    local_region: &str,
) -> anyhow::Result<()> {
    let tenant_id = event.payload["tenant_id"]
        .as_str()
        .ok_or_else(|| anyhow::anyhow!("missing tenant_id in secret_upsert payload"))?;
    let path = event.payload["path"]
        .as_str()
        .ok_or_else(|| anyhow::anyhow!("missing path in secret_upsert payload"))?;
    let ciphertext = event.payload["ciphertext"]
        .as_str()
        .ok_or_else(|| anyhow::anyhow!("missing ciphertext in secret_upsert payload"))?;
    let dek_id = event.payload["dek_id"]
        .as_str()
        .ok_or_else(|| anyhow::anyhow!("missing dek_id in secret_upsert payload"))?;

    let remote_updated_at = event.created_at;
    let remote_vc: HashMap<String, i64> =
        serde_json::from_value(event.vector_clock.clone()).unwrap_or_default();

    // Check if the secret already exists locally.
    let local_meta: Option<(chrono::DateTime<chrono::Utc>, serde_json::Value)> = sqlx::query_as(
        r#"
        SELECT updated_at, vector_clock
        FROM shared.secrets
        WHERE tenant_id = $1::uuid AND path = $2
        "#,
    )
    .bind(tenant_id)
    .bind(path)
    .fetch_optional(pool.inner())
    .await?;

    if let Some((local_ts, local_vc_json)) = local_meta {
        let local_vc: HashMap<String, i64> =
            serde_json::from_value(local_vc_json).unwrap_or_default();

        let ctx = ConflictContext {
            local_updated_at: Some(local_ts),
            remote_updated_at,
            local_vector_clock: local_vc,
            remote_vector_clock: remote_vc,
            local_region: local_region.to_string(),
            remote_region: event.source_region.clone(),
        };

        match conflict::resolve(conflict_strategy, &ctx) {
            Resolution::KeepLocal => {
                debug!(path, "conflict resolved: keeping local version");
                return Ok(());
            }
            Resolution::ManualReview => {
                warn!(path, "conflict requires manual review, skipping");
                return Ok(());
            }
            Resolution::AcceptRemote => {
                debug!(path, "conflict resolved: accepting remote version");
            }
        }
    }

    // Apply the remote secret version using the vault_upsert_secret function.
    // We bypass CAS here since this is a replicated write.
    sqlx::query(
        r#"
        SELECT shared.vault_upsert_secret(
            $1::uuid, $2, 'kv_v2', $3, $4, NULL, 10, false, '{}'::jsonb
        )
        "#,
    )
    .bind(tenant_id)
    .bind(path)
    .bind(ciphertext)
    .bind(dek_id)
    .execute(pool.inner())
    .await?;

    // Update origin_region and vector_clock on the secret.
    sqlx::query(
        r#"
        UPDATE shared.secrets
        SET origin_region = $1, vector_clock = $2
        WHERE tenant_id = $3::uuid AND path = $4
        "#,
    )
    .bind(&event.source_region)
    .bind(&event.vector_clock)
    .bind(tenant_id)
    .bind(path)
    .execute(pool.inner())
    .await?;

    info!(
        path,
        source_region = %event.source_region,
        "replicated secret_upsert"
    );

    Ok(())
}

async fn apply_secret_delete(pool: &DbPool, event: &ReplicationEvent) -> anyhow::Result<()> {
    let tenant_id = event.payload["tenant_id"]
        .as_str()
        .ok_or_else(|| anyhow::anyhow!("missing tenant_id"))?;
    let path = event.payload["path"]
        .as_str()
        .ok_or_else(|| anyhow::anyhow!("missing path"))?;
    let versions: Vec<i32> =
        serde_json::from_value(event.payload["versions"].clone()).unwrap_or_default();

    if !versions.is_empty() {
        let secret_id: Option<(uuid::Uuid,)> = sqlx::query_as(
            "SELECT id FROM shared.secrets WHERE tenant_id = $1::uuid AND path = $2",
        )
        .bind(tenant_id)
        .bind(path)
        .fetch_optional(pool.inner())
        .await?;

        if let Some((sid,)) = secret_id {
            let version_array: Vec<i32> = versions;
            sqlx::query("SELECT shared.vault_soft_delete_versions($1, $2)")
                .bind(sid)
                .bind(&version_array)
                .execute(pool.inner())
                .await?;
        }
    }

    info!(
        path,
        source_region = %event.source_region,
        "replicated secret_delete"
    );
    Ok(())
}

async fn apply_secret_destroy(pool: &DbPool, event: &ReplicationEvent) -> anyhow::Result<()> {
    let tenant_id = event.payload["tenant_id"]
        .as_str()
        .ok_or_else(|| anyhow::anyhow!("missing tenant_id"))?;
    let path = event.payload["path"]
        .as_str()
        .ok_or_else(|| anyhow::anyhow!("missing path"))?;
    let versions: Vec<i32> =
        serde_json::from_value(event.payload["versions"].clone()).unwrap_or_default();

    if !versions.is_empty() {
        let secret_id: Option<(uuid::Uuid,)> = sqlx::query_as(
            "SELECT id FROM shared.secrets WHERE tenant_id = $1::uuid AND path = $2",
        )
        .bind(tenant_id)
        .bind(path)
        .fetch_optional(pool.inner())
        .await?;

        if let Some((sid,)) = secret_id {
            sqlx::query("SELECT shared.vault_destroy_versions($1, $2)")
                .bind(sid)
                .bind(&versions)
                .execute(pool.inner())
                .await?;
        }
    }

    info!(
        path,
        source_region = %event.source_region,
        "replicated secret_destroy"
    );
    Ok(())
}

async fn apply_key_rotate(_pool: &DbPool, event: &ReplicationEvent) -> anyhow::Result<()> {
    info!(
        source_region = %event.source_region,
        "received key_rotate event (handled by crypto-service sync)"
    );
    Ok(())
}

async fn apply_policy_update(_pool: &DbPool, event: &ReplicationEvent) -> anyhow::Result<()> {
    info!(
        source_region = %event.source_region,
        "received policy_update event (handled by policy-engine sync)"
    );
    Ok(())
}

async fn apply_tenant_update(_pool: &DbPool, event: &ReplicationEvent) -> anyhow::Result<()> {
    info!(
        source_region = %event.source_region,
        "received tenant_update event"
    );
    Ok(())
}
