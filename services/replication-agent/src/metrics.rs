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

/// Registers all replication-agent metrics with the process registry.
///
/// Call once during startup. Errors (e.g. a duplicate registration if called
/// twice) are logged rather than panicking the service, so a metrics setup
/// mistake never brings down the data path.
pub fn register_metrics() {
    let collectors: [(&str, Box<dyn prometheus::core::Collector>); 3] = [
        (
            "vault_replication_lag_ms",
            Box::new(REPLICATION_LAG_MS.clone()),
        ),
        (
            "vault_replication_events_applied_total",
            Box::new(EVENTS_APPLIED.clone()),
        ),
        (
            "vault_replication_conflicts_total",
            Box::new(CONFLICTS_TOTAL.clone()),
        ),
    ];
    for (name, collector) in collectors {
        if let Err(e) = REGISTRY.register(collector) {
            tracing::warn!(metric = name, error = %e, "failed to register metric");
        }
    }
}

/// Serve Prometheus metrics as text.
///
/// Runs on every scrape, so encoding failures return an empty body instead of
/// panicking the request handler.
pub async fn metrics_handler() -> impl IntoResponse {
    let encoder = TextEncoder::new();
    let metric_families = REGISTRY.gather();
    let mut buffer = Vec::new();
    if let Err(e) = encoder.encode(&metric_families, &mut buffer) {
        tracing::error!(error = %e, "failed to encode prometheus metrics");
        return String::new();
    }
    String::from_utf8(buffer).unwrap_or_else(|e| {
        tracing::error!(error = %e, "prometheus metrics were not valid UTF-8");
        String::new()
    })
}
