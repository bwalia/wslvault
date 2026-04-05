//! High Availability and Multi-Region Failover for WSLVault.
//!
//! Provides:
//! - Cluster membership tracking and heartbeat protocol
//! - Leader election via a simple bully algorithm over gRPC
//! - Region-aware routing with failover priority
//! - Health-weighted load distribution across regions
//!
//! Each WSLVault node runs an HA coordinator that:
//! 1. Periodically heartbeats to peers
//! 2. Participates in leader election for write-path coordination
//! 3. Reports its region and health status
//! 4. Detects peer failures and triggers failover

pub mod cluster;
pub mod config;
pub mod failover;
pub mod health;
