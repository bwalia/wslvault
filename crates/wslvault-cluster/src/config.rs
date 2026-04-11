//! Cluster configuration.

use serde::{Deserialize, Serialize};

/// Configuration for HA clustering behaviour.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct ClusterConfig {
    /// Unique identifier for this node. Defaults to `hostname:pid` at runtime.
    pub node_id: Option<String>,
    /// Region this node belongs to (e.g. "us-east-1", "eu-west-2").
    pub region: String,
    /// How often the leader refreshes its heartbeat (seconds).
    pub heartbeat_interval_secs: u64,
    /// How long before a missing heartbeat is considered a leadership vacancy (seconds).
    pub leader_lock_timeout_secs: u64,
}

impl Default for ClusterConfig {
    fn default() -> Self {
        Self {
            node_id: None,
            region: "default".into(),
            heartbeat_interval_secs: 5,
            leader_lock_timeout_secs: 30,
        }
    }
}

impl ClusterConfig {
    /// Resolve the node_id, falling back to hostname:pid.
    pub fn resolved_node_id(&self) -> String {
        self.node_id.clone().unwrap_or_else(|| {
            let hostname = hostname::get()
                .map(|h| h.to_string_lossy().to_string())
                .unwrap_or_else(|_| "unknown".into());
            format!("{}:{}", hostname, std::process::id())
        })
    }
}
