//! Prometheus metrics collection for WSLVault services.
//!
//! Provides pre-defined metric families for:
//! - HTTP/gRPC request latency and throughput
//! - Secret operations (reads, writes, deletes)
//! - Key management operations
//! - Lease lifecycle
//! - Audit event counts
//! - HA cluster health
//! - System resource usage (CPU, memory)
//! - Replication lag

pub mod collector;
pub mod middleware;
pub mod server;
