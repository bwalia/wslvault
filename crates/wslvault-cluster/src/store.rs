//! Cluster node persistence in `system.cluster_nodes`.

use chrono::{DateTime, Utc};
use uuid::Uuid;
use wslvault_storage::pool::DbPool;

use crate::error::ClusterError;
use crate::node::{NodeId, NodeInfo};

/// Register a new node in the cluster_nodes table (upsert by node_id).
pub async fn register_node(
    pool: &DbPool,
    service_name: &str,
    node_id: &NodeId,
    region: &str,
) -> Result<(), ClusterError> {
    sqlx::query(
        r#"
        INSERT INTO system.cluster_nodes (service_name, node_id, region, started_at, last_heartbeat)
        VALUES ($1, $2, $3, now(), now())
        ON CONFLICT (node_id) DO UPDATE SET
            service_name = EXCLUDED.service_name,
            region = EXCLUDED.region,
            started_at = now(),
            last_heartbeat = now(),
            is_leader = false
        "#,
    )
    .bind(service_name)
    .bind(&node_id.0)
    .bind(region)
    .execute(pool.inner())
    .await?;

    Ok(())
}

/// Update the heartbeat timestamp and leader flag for a node.
pub async fn update_heartbeat(
    pool: &DbPool,
    node_id: &NodeId,
    is_leader: bool,
) -> Result<(), ClusterError> {
    sqlx::query(
        r#"
        UPDATE system.cluster_nodes
        SET last_heartbeat = now(), is_leader = $1
        WHERE node_id = $2
        "#,
    )
    .bind(is_leader)
    .bind(&node_id.0)
    .execute(pool.inner())
    .await?;

    Ok(())
}

/// Remove a node from the cluster registry (called on graceful shutdown).
pub async fn deregister_node(pool: &DbPool, node_id: &NodeId) -> Result<(), ClusterError> {
    sqlx::query("DELETE FROM system.cluster_nodes WHERE node_id = $1")
        .bind(&node_id.0)
        .execute(pool.inner())
        .await?;

    Ok(())
}

/// One `system.cluster_nodes` row as returned by the `list_nodes` queries:
/// `(id, service_name, node_id, region, is_leader, last_heartbeat, started_at, metadata)`.
type ClusterNodeRow = (
    Uuid,
    String,
    String,
    String,
    bool,
    DateTime<Utc>,
    DateTime<Utc>,
    serde_json::Value,
);

/// List all nodes for a given service, ordered by leader status then heartbeat.
pub async fn list_nodes(
    pool: &DbPool,
    service_name: Option<&str>,
) -> Result<Vec<NodeInfo>, ClusterError> {
    let rows: Vec<ClusterNodeRow> = if let Some(svc) = service_name {
        sqlx::query_as(
            r#"
            SELECT id, service_name, node_id, region, is_leader, last_heartbeat, started_at, metadata
            FROM system.cluster_nodes
            WHERE service_name = $1
            ORDER BY is_leader DESC, last_heartbeat DESC
            "#,
        )
        .bind(svc)
        .fetch_all(pool.inner())
        .await?
    } else {
        sqlx::query_as(
            r#"
            SELECT id, service_name, node_id, region, is_leader, last_heartbeat, started_at, metadata
            FROM system.cluster_nodes
            ORDER BY service_name, is_leader DESC, last_heartbeat DESC
            "#,
        )
        .fetch_all(pool.inner())
        .await?
    };

    Ok(rows
        .into_iter()
        .map(
            |(
                id,
                service_name,
                node_id,
                region,
                is_leader,
                last_heartbeat,
                started_at,
                metadata,
            )| {
                NodeInfo {
                    id,
                    service_name,
                    node_id: NodeId(node_id),
                    region,
                    is_leader,
                    last_heartbeat,
                    started_at,
                    metadata,
                }
            },
        )
        .collect())
}

/// Prune stale nodes that haven't sent a heartbeat within `timeout_secs`.
pub async fn prune_stale_nodes(pool: &DbPool, timeout_secs: i64) -> Result<u64, ClusterError> {
    let result = sqlx::query(
        r#"
        DELETE FROM system.cluster_nodes
        WHERE last_heartbeat < now() - make_interval(secs => $1::double precision)
        "#,
    )
    .bind(timeout_secs as f64)
    .execute(pool.inner())
    .await?;

    Ok(result.rows_affected())
}
