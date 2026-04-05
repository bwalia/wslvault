//! Multi-region failover coordination.
//!
//! Monitors region health and orchestrates failover when the primary region
//! becomes unavailable. Supports both automatic and manual failover modes.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Instant;

use serde::{Deserialize, Serialize};
use tokio::sync::RwLock;
use tracing::{error, info, warn};

use super::cluster::{NodeState, SharedClusterState};
use super::config::HaConfig;

/// Health status of a region.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegionHealth {
    pub region: String,
    pub is_primary: bool,
    pub node_count: usize,
    pub healthy_nodes: usize,
    pub avg_latency_ms: f64,
    pub replication_lag_ms: u64,
    /// Overall health: 0.0 (completely down) to 1.0 (fully healthy).
    pub health_score: f64,
    pub last_check: chrono::DateTime<chrono::Utc>,
}

/// Tracks a failover event for audit purposes.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FailoverEvent {
    pub id: uuid::Uuid,
    pub timestamp: chrono::DateTime<chrono::Utc>,
    pub from_region: String,
    pub to_region: String,
    pub reason: FailoverReason,
    pub automatic: bool,
    pub duration_ms: u64,
    pub status: FailoverStatus,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FailoverReason {
    PrimaryDown,
    HighLatency,
    ReplicationLagExceeded,
    ManualTrigger,
    ScheduledMaintenance,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FailoverStatus {
    InProgress,
    Completed,
    Failed { error: String },
    RolledBack,
}

/// The failover manager that coordinates region-level failover decisions.
pub struct FailoverManager {
    cluster_state: SharedClusterState,
    config: HaConfig,
    region_health: Arc<RwLock<HashMap<String, RegionHealth>>>,
    failover_history: Arc<RwLock<Vec<FailoverEvent>>>,
    last_failover: Arc<RwLock<Option<Instant>>>,
}

impl FailoverManager {
    pub fn new(cluster_state: SharedClusterState, config: HaConfig) -> Self {
        Self {
            cluster_state,
            config,
            region_health: Arc::new(RwLock::new(HashMap::new())),
            failover_history: Arc::new(RwLock::new(Vec::new())),
            last_failover: Arc::new(RwLock::new(None)),
        }
    }

    /// Update the health status for a given region based on cluster state.
    pub async fn update_region_health(&self) {
        let cluster = self.cluster_state.read().await;
        let mut health_map = self.region_health.write().await;

        // Group nodes by region.
        let mut by_region: HashMap<String, Vec<_>> = HashMap::new();
        for node in cluster.nodes.values() {
            by_region
                .entry(node.region.clone())
                .or_default()
                .push(node.clone());
        }

        let primary_region = self
            .config
            .failover
            .region_priority
            .first()
            .cloned()
            .unwrap_or_default();

        for (region, nodes) in by_region {
            let healthy = nodes
                .iter()
                .filter(|n| {
                    matches!(
                        n.state,
                        NodeState::Active | NodeState::Leader | NodeState::Standby
                    )
                })
                .count();

            let avg_health: f64 = if nodes.is_empty() {
                0.0
            } else {
                nodes.iter().map(|n| n.health_score).sum::<f64>() / nodes.len() as f64
            };

            let max_lag = nodes.iter().map(|n| n.replication_lag_ms).max().unwrap_or(0);

            health_map.insert(
                region.clone(),
                RegionHealth {
                    region: region.clone(),
                    is_primary: region == primary_region,
                    node_count: nodes.len(),
                    healthy_nodes: healthy,
                    avg_latency_ms: 0.0, // populated by probe layer
                    replication_lag_ms: max_lag,
                    health_score: avg_health,
                    last_check: chrono::Utc::now(),
                },
            );
        }
    }

    /// Evaluate whether a failover should be initiated.
    pub async fn evaluate_failover(&self) -> Option<FailoverEvent> {
        if !self.config.failover.auto_failover {
            return None;
        }

        // Respect cooldown.
        {
            let last = self.last_failover.read().await;
            if let Some(t) = *last {
                let cooldown =
                    std::time::Duration::from_millis(self.config.failover.failover_cooldown_ms);
                if t.elapsed() < cooldown {
                    return None;
                }
            }
        }

        let health_map = self.region_health.read().await;
        let priority = &self.config.failover.region_priority;

        // Find the current primary.
        let primary_region = priority.first()?;
        let primary_health = health_map.get(primary_region)?;

        // Check if primary is unhealthy.
        let should_failover = primary_health.health_score < 0.5
            || primary_health.healthy_nodes == 0
            || primary_health.replication_lag_ms > self.config.replication.max_lag_ms * 2;

        if !should_failover {
            return None;
        }

        // Find the best failover target.
        let target = priority.iter().skip(1).find(|r| {
            health_map
                .get(*r)
                .map(|h| h.health_score > 0.7 && h.healthy_nodes > 0)
                .unwrap_or(false)
        })?;

        let reason = if primary_health.healthy_nodes == 0 {
            FailoverReason::PrimaryDown
        } else if primary_health.replication_lag_ms > self.config.replication.max_lag_ms * 2 {
            FailoverReason::ReplicationLagExceeded
        } else {
            FailoverReason::HighLatency
        };

        warn!(
            from = %primary_region,
            to = %target,
            reason = ?reason,
            primary_health = primary_health.health_score,
            "initiating automatic failover"
        );

        Some(FailoverEvent {
            id: uuid::Uuid::now_v7(),
            timestamp: chrono::Utc::now(),
            from_region: primary_region.clone(),
            to_region: target.clone(),
            reason,
            automatic: true,
            duration_ms: 0,
            status: FailoverStatus::InProgress,
        })
    }

    /// Execute a failover event.
    pub async fn execute_failover(&self, mut event: FailoverEvent) -> FailoverEvent {
        let start = Instant::now();

        info!(
            from = %event.from_region,
            to = %event.to_region,
            "executing failover"
        );

        // Update cluster state: promote nodes in the target region.
        {
            let mut cluster = self.cluster_state.write().await;

            // Demote nodes in the old primary.
            for node in cluster.nodes.values_mut() {
                if node.region == event.from_region && node.state == NodeState::Leader {
                    node.state = NodeState::Standby;
                }
            }

            // Elect a new leader in the target region.
            let target_nodes: Vec<String> = cluster
                .nodes
                .iter()
                .filter(|(_, n)| {
                    n.region == event.to_region
                        && matches!(
                            n.state,
                            NodeState::Active | NodeState::Standby
                        )
                })
                .map(|(id, _)| id.clone())
                .collect();

            if let Some(new_leader) = target_nodes.first() {
                let leader_id = new_leader.clone();
                cluster.election_term += 1;
                cluster.current_leader = Some(leader_id.clone());

                if let Some(node) = cluster.nodes.get_mut(&leader_id) {
                    node.state = NodeState::Leader;
                }

                info!(new_leader = %leader_id, region = %event.to_region, "failover leader elected");
                event.status = FailoverStatus::Completed;
            } else {
                error!(region = %event.to_region, "no healthy nodes in target region for failover");
                event.status = FailoverStatus::Failed {
                    error: "no healthy nodes in target region".into(),
                };
            }
        }

        event.duration_ms = start.elapsed().as_millis() as u64;

        // Record the failover.
        {
            let mut history = self.failover_history.write().await;
            history.push(event.clone());
        }
        {
            let mut last = self.last_failover.write().await;
            *last = Some(Instant::now());
        }

        event
    }

    /// Trigger a manual failover to a specific region.
    pub async fn manual_failover(&self, target_region: &str) -> FailoverEvent {
        let current_leader_region = {
            let cluster = self.cluster_state.read().await;
            cluster
                .current_leader
                .as_ref()
                .and_then(|id| cluster.nodes.get(id))
                .map(|n| n.region.clone())
                .unwrap_or_else(|| "unknown".to_string())
        };

        let event = FailoverEvent {
            id: uuid::Uuid::now_v7(),
            timestamp: chrono::Utc::now(),
            from_region: current_leader_region,
            to_region: target_region.to_string(),
            reason: FailoverReason::ManualTrigger,
            automatic: false,
            duration_ms: 0,
            status: FailoverStatus::InProgress,
        };

        self.execute_failover(event).await
    }

    /// Get the current health of all regions.
    pub async fn get_region_health(&self) -> Vec<RegionHealth> {
        self.region_health.read().await.values().cloned().collect()
    }

    /// Get the failover event history.
    pub async fn get_failover_history(&self) -> Vec<FailoverEvent> {
        self.failover_history.read().await.clone()
    }
}

/// Run the failover monitor as a background loop.
pub async fn run_failover_monitor(manager: Arc<FailoverManager>) {
    let mut interval = tokio::time::interval(std::time::Duration::from_secs(5));

    loop {
        interval.tick().await;

        // Update region health from cluster state.
        manager.update_region_health().await;

        // Evaluate whether failover is needed.
        if let Some(event) = manager.evaluate_failover().await {
            let result = manager.execute_failover(event).await;
            match result.status {
                FailoverStatus::Completed => {
                    info!(
                        to = %result.to_region,
                        duration_ms = result.duration_ms,
                        "failover completed successfully"
                    );
                }
                FailoverStatus::Failed { ref error } => {
                    error!(error = %error, "failover failed");
                }
                _ => {}
            }
        }
    }
}
