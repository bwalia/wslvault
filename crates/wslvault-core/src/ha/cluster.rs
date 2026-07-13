//! Cluster membership tracking and leader election.
//!
//! Implements a heartbeat-based failure detector and a simple leader election
//! protocol suitable for coordinating the write path across multiple nodes.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};
use tokio::sync::RwLock;
use tracing::{debug, error, info, warn};

use super::config::HaConfig;

/// Possible states for a node in the cluster.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NodeState {
    /// Node is initialising and discovering peers.
    Joining,
    /// Node is active and receiving heartbeats.
    Active,
    /// Node is the current leader for write coordination.
    Leader,
    /// Node is a standby follower.
    Standby,
    /// Node has not been heard from within the failure threshold.
    Suspect,
    /// Node is confirmed unreachable; failover may be initiated.
    Dead,
}

/// Information about a single cluster node.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NodeInfo {
    pub node_id: String,
    pub region: String,
    pub availability_zone: String,
    pub address: String,
    pub state: NodeState,
    pub last_heartbeat: Option<chrono::DateTime<chrono::Utc>>,
    pub uptime_seconds: u64,
    pub version: String,
    /// Health score 0.0 (dead) to 1.0 (perfect).
    pub health_score: f64,
    /// Replication lag in milliseconds (0 for the leader).
    pub replication_lag_ms: u64,
}

/// The shared cluster state maintained by every node.
#[derive(Debug)]
pub struct ClusterState {
    pub config: HaConfig,
    pub local_node_id: String,
    pub local_state: NodeState,
    pub current_leader: Option<String>,
    pub nodes: HashMap<String, NodeInfo>,
    pub last_heartbeat_times: HashMap<String, Instant>,
    pub election_term: u64,
    start_time: Instant,
}

pub type SharedClusterState = Arc<RwLock<ClusterState>>;

impl ClusterState {
    pub fn new(config: HaConfig) -> Self {
        let node_id = if config.node_id.is_empty() {
            uuid::Uuid::now_v7().to_string()
        } else {
            config.node_id.clone()
        };

        let local_info = NodeInfo {
            node_id: node_id.clone(),
            region: config.region.clone(),
            availability_zone: config.availability_zone.clone(),
            address: String::new(),
            state: NodeState::Joining,
            last_heartbeat: Some(chrono::Utc::now()),
            uptime_seconds: 0,
            version: env!("CARGO_PKG_VERSION").to_string(),
            health_score: 1.0,
            replication_lag_ms: 0,
        };

        let mut nodes = HashMap::new();
        nodes.insert(node_id.clone(), local_info);

        Self {
            config,
            local_node_id: node_id,
            local_state: NodeState::Joining,
            current_leader: None,
            nodes,
            last_heartbeat_times: HashMap::new(),
            election_term: 0,
            start_time: Instant::now(),
        }
    }

    /// Record a heartbeat from a peer node.
    pub fn receive_heartbeat(&mut self, peer: NodeInfo) {
        let peer_id = peer.node_id.clone();
        self.last_heartbeat_times
            .insert(peer_id.clone(), Instant::now());

        // Update or insert the peer info.
        self.nodes.insert(peer_id, peer);
    }

    /// Check for nodes that have exceeded the failure threshold.
    pub fn detect_failures(&mut self) -> Vec<String> {
        let timeout = self.config.failure_timeout();
        let now = Instant::now();
        let mut failed = Vec::new();

        for (node_id, last_seen) in &self.last_heartbeat_times {
            if node_id == &self.local_node_id {
                continue;
            }
            if now.duration_since(*last_seen) > timeout {
                if let Some(node) = self.nodes.get_mut(node_id) {
                    if node.state != NodeState::Dead {
                        warn!(node_id = %node_id, "node exceeded failure threshold, marking suspect");
                        node.state = NodeState::Suspect;
                    }
                }
                failed.push(node_id.clone());
            }
        }

        failed
    }

    /// Promote this node to leader (called after winning an election).
    pub fn become_leader(&mut self) {
        info!(node_id = %self.local_node_id, term = self.election_term, "this node is now the leader");
        self.local_state = NodeState::Leader;
        self.current_leader = Some(self.local_node_id.clone());

        if let Some(node) = self.nodes.get_mut(&self.local_node_id) {
            node.state = NodeState::Leader;
        }
    }

    /// Step down to standby (called when a higher-priority node claims leadership).
    pub fn become_standby(&mut self, leader_id: &str) {
        info!(
            node_id = %self.local_node_id,
            leader = %leader_id,
            "stepping down to standby"
        );
        self.local_state = NodeState::Standby;
        self.current_leader = Some(leader_id.to_string());

        if let Some(node) = self.nodes.get_mut(&self.local_node_id) {
            node.state = NodeState::Standby;
        }
    }

    /// Transition from Joining to Active.
    pub fn activate(&mut self) {
        if self.local_state == NodeState::Joining {
            self.local_state = NodeState::Active;
            if let Some(node) = self.nodes.get_mut(&self.local_node_id) {
                node.state = NodeState::Active;
            }
            info!(node_id = %self.local_node_id, "node activated");
        }
    }

    /// Build a NodeInfo representing this node's current state.
    pub fn local_node_info(&self) -> NodeInfo {
        NodeInfo {
            node_id: self.local_node_id.clone(),
            region: self.config.region.clone(),
            availability_zone: self.config.availability_zone.clone(),
            address: String::new(),
            state: self.local_state,
            last_heartbeat: Some(chrono::Utc::now()),
            uptime_seconds: self.start_time.elapsed().as_secs(),
            version: env!("CARGO_PKG_VERSION").to_string(),
            health_score: 1.0,
            replication_lag_ms: 0,
        }
    }

    /// Returns a summary of all known nodes for API/dashboard consumption.
    pub fn cluster_summary(&self) -> ClusterSummary {
        let nodes: Vec<NodeInfo> = self.nodes.values().cloned().collect();
        let active_count = nodes
            .iter()
            .filter(|n| {
                matches!(
                    n.state,
                    NodeState::Active | NodeState::Leader | NodeState::Standby
                )
            })
            .count();
        let regions: Vec<String> = nodes
            .iter()
            .map(|n| n.region.clone())
            .collect::<std::collections::HashSet<_>>()
            .into_iter()
            .collect();

        ClusterSummary {
            total_nodes: nodes.len(),
            active_nodes: active_count,
            leader: self.current_leader.clone(),
            election_term: self.election_term,
            regions,
            nodes,
        }
    }
}

/// Summary of the cluster state, suitable for API responses and dashboards.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClusterSummary {
    pub total_nodes: usize,
    pub active_nodes: usize,
    pub leader: Option<String>,
    pub election_term: u64,
    pub regions: Vec<String>,
    pub nodes: Vec<NodeInfo>,
}

/// Run the heartbeat loop as a background task.
///
/// Periodically broadcasts this node's status to all known peers
/// and checks for failed nodes.
pub async fn run_heartbeat_loop(state: SharedClusterState) {
    let interval = {
        let s = state.read().await;
        s.config.heartbeat_interval()
    };

    let mut tick = tokio::time::interval(interval);

    loop {
        tick.tick().await;

        let mut s = state.write().await;

        // Update local node info.
        let local_info = s.local_node_info();
        let local_id = s.local_node_id.clone();
        s.nodes.insert(local_id.clone(), local_info);
        s.last_heartbeat_times.insert(local_id, Instant::now());

        // Detect failures.
        let failed = s.detect_failures();
        if !failed.is_empty() {
            debug!(failed_nodes = ?failed, "detected potentially failed nodes");

            // If the leader is among the failed nodes, trigger election.
            if let Some(ref leader) = s.current_leader {
                if failed.contains(leader) {
                    warn!(leader = %leader, "leader appears to have failed, initiating election");
                    s.election_term += 1;
                    // Simple election: node with lexicographically smallest active ID wins.
                    let active_ids: Vec<&String> = s
                        .nodes
                        .iter()
                        .filter(|(_, n)| {
                            matches!(
                                n.state,
                                NodeState::Active | NodeState::Leader | NodeState::Standby
                            )
                        })
                        .map(|(id, _)| id)
                        .collect();

                    if let Some(new_leader) = active_ids.into_iter().min() {
                        let new_leader = new_leader.clone();
                        if new_leader == s.local_node_id {
                            s.become_leader();
                        } else {
                            s.become_standby(&new_leader);
                        }
                    }
                }
            }
        }

        // If no leader is set and we're past the joining phase, elect one.
        if s.current_leader.is_none() && s.local_state != NodeState::Joining {
            s.election_term += 1;
            s.become_leader();
        }
    }
}

/// Create a new shared cluster state and return it.
pub fn new_cluster_state(config: HaConfig) -> SharedClusterState {
    Arc::new(RwLock::new(ClusterState::new(config)))
}
