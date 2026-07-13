//! Configuration for the replication-agent.

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct ReplicationAgentConfig {
    /// The region this agent belongs to.
    pub local_region: String,
    /// HTTP listen address for replication API and health probes.
    pub listen_addr: String,
    /// Peer region endpoints to pull replication events from.
    pub peer_endpoints: Vec<PeerEndpoint>,
    /// How often to poll peer regions for new events (milliseconds).
    pub poll_interval_ms: u64,
    /// Maximum events to fetch per poll batch.
    pub batch_size: usize,
    /// Conflict resolution strategy.
    pub conflict_strategy: String,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct PeerEndpoint {
    pub region_id: String,
    pub url: String,
}

impl ReplicationAgentConfig {
    pub fn from_env() -> Self {
        let local_region = std::env::var("REGION_ID").unwrap_or_else(|_| "default".to_string());
        let listen_addr =
            std::env::var("REPLICATION_LISTEN_ADDR").unwrap_or_else(|_| "0.0.0.0:8091".to_string());
        let poll_interval_ms: u64 = std::env::var("REPLICATION_POLL_INTERVAL_MS")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(500);
        let batch_size: usize = std::env::var("REPLICATION_BATCH_SIZE")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(100);
        let conflict_strategy = std::env::var("REPLICATION_CONFLICT_STRATEGY")
            .unwrap_or_else(|_| "last_write_wins".to_string());

        // Parse REPLICATION_PEERS as comma-separated "region_id=url" pairs.
        let peer_endpoints = std::env::var("REPLICATION_PEERS")
            .unwrap_or_default()
            .split(',')
            .filter(|s| !s.is_empty())
            .filter_map(|pair| {
                let parts: Vec<&str> = pair.splitn(2, '=').collect();
                if parts.len() == 2 {
                    Some(PeerEndpoint {
                        region_id: parts[0].trim().to_string(),
                        url: parts[1].trim().to_string(),
                    })
                } else {
                    None
                }
            })
            .collect();

        Self {
            local_region,
            listen_addr,
            peer_endpoints,
            poll_interval_ms,
            batch_size,
            conflict_strategy,
        }
    }
}
