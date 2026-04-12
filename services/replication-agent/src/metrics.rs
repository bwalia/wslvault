//! Prometheus metrics for the replication-agent.

use axum::response::IntoResponse;
use prometheus::{Encoder, GaugeVec, IntCounterVec, Opts, Registry, TextEncoder};

lazy_static::lazy_static! {
    static ref REGISTRY: Registry = Registry::new();

    pub static ref REPLICATION_LAG_MS: GaugeVec = GaugeVec::new(
        Opts::new("vault_replication_lag_ms", "Replication lag in milliseconds"),
        &["source_region", "dest_region"]
    ).unwrap();

    pub static ref EVENTS_APPLIED: IntCounterVec = IntCounterVec::new(
        Opts::new("vault_replication_events_applied_total", "Total replication events applied"),
        &["region", "status"]
    ).unwrap();

    pub static ref CONFLICTS_TOTAL: IntCounterVec = IntCounterVec::new(
        Opts::new("vault_replication_conflicts_total", "Total replication conflicts"),
        &["region", "resolution"]
    ).unwrap();
}

/// Serve Prometheus metrics as text.
pub async fn metrics_handler() -> impl IntoResponse {
    let encoder = TextEncoder::new();
    let metric_families = prometheus::gather();
    let mut buffer = Vec::new();
    encoder.encode(&metric_families, &mut buffer).unwrap();
    String::from_utf8(buffer).unwrap()
}
