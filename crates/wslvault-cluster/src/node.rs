//! Node identity and metadata for cluster membership.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// Unique node identifier within the cluster.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct NodeId(pub String);

impl std::fmt::Display for NodeId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// Information about a running cluster node, as stored in `system.cluster_nodes`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NodeInfo {
    pub id: Uuid,
    pub service_name: String,
    pub node_id: NodeId,
    pub region: String,
    pub is_leader: bool,
    pub last_heartbeat: DateTime<Utc>,
    pub started_at: DateTime<Utc>,
    pub metadata: serde_json::Value,
}
