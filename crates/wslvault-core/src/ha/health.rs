//! HA-aware health checking that aggregates cluster and region health
//! into a single status report for dashboards and API consumers.

use serde::{Deserialize, Serialize};

use super::cluster::{ClusterSummary, SharedClusterState};
use super::failover::FailoverManager;

/// Overall HA health status.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HaStatus {
    /// All regions healthy, leader elected, replication in sync.
    Healthy,
    /// Operational but with degraded redundancy (e.g. one region down).
    Degraded,
    /// Failover in progress or recently completed.
    Failover,
    /// Critically unhealthy — manual intervention may be needed.
    Critical,
    /// HA is not enabled; running in standalone mode.
    Standalone,
}

/// Complete HA health report for the `/v1/sys/ha-status` endpoint.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HaHealthReport {
    pub status: HaStatus,
    pub ha_enabled: bool,
    pub cluster: Option<ClusterSummary>,
    pub regions: Vec<RegionStatusSummary>,
    pub is_leader: bool,
    pub leader_node: Option<String>,
    pub leader_region: Option<String>,
    pub replication_status: ReplicationStatus,
    pub last_failover: Option<chrono::DateTime<chrono::Utc>>,
    pub uptime_seconds: u64,
    pub timestamp: chrono::DateTime<chrono::Utc>,
}

/// Per-region status for the health report.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegionStatusSummary {
    pub region: String,
    pub is_primary: bool,
    pub total_nodes: usize,
    pub healthy_nodes: usize,
    pub health_score: f64,
    pub replication_lag_ms: u64,
}

/// Replication health across regions.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReplicationStatus {
    pub mode: String,
    pub is_synced: bool,
    pub max_lag_ms: u64,
    pub regions_in_sync: usize,
    pub total_regions: usize,
}

/// Build an HA health report from the cluster and failover manager state.
pub async fn build_ha_health_report(
    cluster_state: &SharedClusterState,
    failover_mgr: &FailoverManager,
) -> HaHealthReport {
    let cluster = cluster_state.read().await;
    let summary = cluster.cluster_summary();

    let region_health = failover_mgr.get_region_health().await;
    let failover_history = failover_mgr.get_failover_history().await;

    let regions: Vec<RegionStatusSummary> = region_health
        .iter()
        .map(|rh| RegionStatusSummary {
            region: rh.region.clone(),
            is_primary: rh.is_primary,
            total_nodes: rh.node_count,
            healthy_nodes: rh.healthy_nodes,
            health_score: rh.health_score,
            replication_lag_ms: rh.replication_lag_ms,
        })
        .collect();

    let max_lag = region_health
        .iter()
        .map(|r| r.replication_lag_ms)
        .max()
        .unwrap_or(0);

    let regions_in_sync = region_health
        .iter()
        .filter(|r| r.replication_lag_ms < cluster.config.replication.max_lag_ms)
        .count();

    // Determine the leader's region.
    let leader_region = cluster
        .current_leader
        .as_ref()
        .and_then(|id| cluster.nodes.get(id).map(|n| n.region.clone()));

    // Determine overall status.
    let status = if !cluster.config.enabled {
        HaStatus::Standalone
    } else if summary.active_nodes == summary.total_nodes
        && max_lag < cluster.config.replication.max_lag_ms
    {
        HaStatus::Healthy
    } else if summary.active_nodes > 0 && cluster.current_leader.is_some() {
        HaStatus::Degraded
    } else if cluster.current_leader.is_none() {
        HaStatus::Critical
    } else {
        HaStatus::Failover
    };

    let is_leader = cluster.current_leader.as_ref() == Some(&cluster.local_node_id);

    let last_failover = failover_history.last().map(|e| e.timestamp);

    let uptime = cluster
        .nodes
        .get(&cluster.local_node_id)
        .map(|n| n.uptime_seconds)
        .unwrap_or(0);

    HaHealthReport {
        status,
        ha_enabled: cluster.config.enabled,
        cluster: Some(summary),
        regions,
        is_leader,
        leader_node: cluster.current_leader.clone(),
        leader_region,
        replication_status: ReplicationStatus {
            mode: format!("{:?}", cluster.config.replication.mode),
            is_synced: regions_in_sync == region_health.len(),
            max_lag_ms: max_lag,
            regions_in_sync,
            total_regions: region_health.len(),
        },
        last_failover,
        uptime_seconds: uptime,
        timestamp: chrono::Utc::now(),
    }
}
