//! HA and multi-region configuration types.

use std::time::Duration;

use serde::{Deserialize, Serialize};

/// Configuration for high-availability and multi-region failover.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct HaConfig {
    /// Whether HA mode is enabled.
    pub enabled: bool,
    /// Unique identifier for this node.
    pub node_id: String,
    /// Region this node belongs to (e.g. "us-east-1", "eu-west-1").
    pub region: String,
    /// Availability zone within the region.
    pub availability_zone: String,
    /// List of peer node addresses for cluster membership.
    pub peer_addresses: Vec<String>,
    /// Heartbeat interval in milliseconds.
    pub heartbeat_interval_ms: u64,
    /// How many missed heartbeats before a node is considered dead.
    pub failure_threshold: u32,
    /// Election timeout in milliseconds; randomised to avoid split votes.
    pub election_timeout_ms: u64,
    /// Multi-region replication settings.
    pub replication: ReplicationConfig,
    /// Failover configuration.
    pub failover: FailoverConfig,
}

impl Default for HaConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            node_id: String::new(),
            region: "us-east-1".into(),
            availability_zone: "us-east-1a".into(),
            peer_addresses: Vec::new(),
            heartbeat_interval_ms: 1000,
            failure_threshold: 3,
            election_timeout_ms: 5000,
            replication: ReplicationConfig::default(),
            failover: FailoverConfig::default(),
        }
    }
}

impl HaConfig {
    pub fn heartbeat_interval(&self) -> Duration {
        Duration::from_millis(self.heartbeat_interval_ms)
    }

    pub fn election_timeout(&self) -> Duration {
        Duration::from_millis(self.election_timeout_ms)
    }

    pub fn failure_timeout(&self) -> Duration {
        Duration::from_millis(self.heartbeat_interval_ms * self.failure_threshold as u64)
    }
}

/// Replication mode for cross-region data sync.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct ReplicationConfig {
    /// Replication mode: "sync", "async", or "semi-sync".
    pub mode: ReplicationMode,
    /// Maximum replication lag allowed (in milliseconds) before triggering alerts.
    pub max_lag_ms: u64,
    /// Number of regions that must acknowledge a write in sync/semi-sync mode.
    pub ack_quorum: u32,
    /// Batch size for async replication.
    pub batch_size: usize,
}

impl Default for ReplicationConfig {
    fn default() -> Self {
        Self {
            mode: ReplicationMode::Async,
            max_lag_ms: 5000,
            ack_quorum: 1,
            batch_size: 100,
        }
    }
}

/// Replication mode enum.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ReplicationMode {
    /// All regions must acknowledge before write returns.
    Sync,
    /// Write returns immediately; replication happens in background.
    Async,
    /// Primary region + N regions must acknowledge.
    SemiSync,
}

/// Failover-specific configuration.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct FailoverConfig {
    /// Whether automatic failover is enabled (vs. manual operator action).
    pub auto_failover: bool,
    /// Minimum time before initiating failover after detecting failure.
    pub failover_cooldown_ms: u64,
    /// Priority ordering of regions for failover (first = highest priority).
    pub region_priority: Vec<String>,
    /// Whether to attempt automatic failback when the primary recovers.
    pub auto_failback: bool,
    /// Percentage of traffic to route to standby during warm standby.
    pub standby_read_percentage: u8,
}

impl Default for FailoverConfig {
    fn default() -> Self {
        Self {
            auto_failover: true,
            failover_cooldown_ms: 30_000,
            region_priority: vec![
                "us-east-1".into(),
                "us-west-2".into(),
                "eu-west-1".into(),
            ],
            auto_failback: false,
            standby_read_percentage: 0,
        }
    }
}
