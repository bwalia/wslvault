//! Central metrics registry for all WSLVault services.
//!
//! Uses the `prometheus` crate to define and expose metrics.  Each service
//! imports the relevant metric families and increments/observes them in its
//! request handlers.

use once_cell::sync::Lazy;
use prometheus::{
    Encoder, HistogramOpts, HistogramVec, IntCounterVec, IntGauge, IntGaugeVec, Opts, Registry,
    TextEncoder,
};

/// Global metrics registry shared by all components in the process.
pub static REGISTRY: Lazy<Registry> = Lazy::new(|| {
    let r = Registry::new_custom(Some("wslvault".into()), None)
        .expect("failed to create prometheus registry");

    // Register all metrics at startup.
    r.register(Box::new(HTTP_REQUEST_DURATION.clone())).unwrap();
    r.register(Box::new(HTTP_REQUESTS_TOTAL.clone())).unwrap();
    r.register(Box::new(GRPC_REQUEST_DURATION.clone())).unwrap();
    r.register(Box::new(GRPC_REQUESTS_TOTAL.clone())).unwrap();
    r.register(Box::new(SECRET_OPERATIONS_TOTAL.clone()))
        .unwrap();
    r.register(Box::new(SECRETS_MANAGED.clone())).unwrap();
    r.register(Box::new(SECRET_VERSIONS_TOTAL.clone())).unwrap();
    r.register(Box::new(KEY_OPERATIONS_TOTAL.clone())).unwrap();
    r.register(Box::new(ACTIVE_LEASES.clone())).unwrap();
    r.register(Box::new(LEASE_OPERATIONS_TOTAL.clone()))
        .unwrap();
    r.register(Box::new(AUDIT_EVENTS_TOTAL.clone())).unwrap();
    r.register(Box::new(AUDIT_EVENTS_BY_ACTION.clone()))
        .unwrap();
    r.register(Box::new(AUTH_ATTEMPTS_TOTAL.clone())).unwrap();
    r.register(Box::new(POLICY_EVALUATIONS_TOTAL.clone()))
        .unwrap();
    r.register(Box::new(HA_CLUSTER_NODES.clone())).unwrap();
    r.register(Box::new(HA_IS_LEADER.clone())).unwrap();
    r.register(Box::new(HA_REPLICATION_LAG_MS.clone())).unwrap();
    r.register(Box::new(HA_FAILOVER_TOTAL.clone())).unwrap();
    r.register(Box::new(HA_ELECTION_TERM.clone())).unwrap();
    r.register(Box::new(ENCRYPTION_OPERATIONS_TOTAL.clone()))
        .unwrap();
    r.register(Box::new(ENCRYPTION_DURATION.clone())).unwrap();

    r
});

// ── HTTP Metrics ────────────────────────────────────────────────────────────

/// Histogram of HTTP request durations in seconds, labelled by method, path, and status.
pub static HTTP_REQUEST_DURATION: Lazy<HistogramVec> = Lazy::new(|| {
    HistogramVec::new(
        HistogramOpts::new(
            "http_request_duration_seconds",
            "HTTP request latency in seconds",
        )
        .buckets(vec![
            0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0,
        ]),
        &["method", "path", "status", "service"],
    )
    .unwrap()
});

/// Counter of total HTTP requests, labelled by method, path, and status.
pub static HTTP_REQUESTS_TOTAL: Lazy<IntCounterVec> = Lazy::new(|| {
    IntCounterVec::new(
        Opts::new("http_requests_total", "Total number of HTTP requests"),
        &["method", "path", "status", "service"],
    )
    .unwrap()
});

// ── gRPC Metrics ────────────────────────────────────────────────────────────

/// Histogram of gRPC request durations.
pub static GRPC_REQUEST_DURATION: Lazy<HistogramVec> = Lazy::new(|| {
    HistogramVec::new(
        HistogramOpts::new(
            "grpc_request_duration_seconds",
            "gRPC request latency in seconds",
        )
        .buckets(vec![
            0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5,
        ]),
        &["method", "status", "service"],
    )
    .unwrap()
});

/// Counter of total gRPC requests.
pub static GRPC_REQUESTS_TOTAL: Lazy<IntCounterVec> = Lazy::new(|| {
    IntCounterVec::new(
        Opts::new("grpc_requests_total", "Total number of gRPC requests"),
        &["method", "status", "service"],
    )
    .unwrap()
});

// ── Secret Metrics ──────────────────────────────────────────────────────────

/// Counter of secret operations, labelled by operation type and tenant.
pub static SECRET_OPERATIONS_TOTAL: Lazy<IntCounterVec> = Lazy::new(|| {
    IntCounterVec::new(
        Opts::new("secret_operations_total", "Total secret operations"),
        &["operation", "tenant_id", "outcome"],
    )
    .unwrap()
});

/// Gauge of total secrets currently managed across all tenants.
pub static SECRETS_MANAGED: Lazy<IntGaugeVec> = Lazy::new(|| {
    IntGaugeVec::new(
        Opts::new("secrets_managed", "Number of secrets currently managed"),
        &["tenant_id", "engine"],
    )
    .unwrap()
});

/// Gauge of total secret versions.
pub static SECRET_VERSIONS_TOTAL: Lazy<IntGauge> = Lazy::new(|| {
    IntGauge::new(
        "secret_versions_total",
        "Total number of secret versions stored",
    )
    .unwrap()
});

// ── Key Management Metrics ──────────────────────────────────────────────────

/// Counter of key management operations (generate, rotate, wrap, unwrap).
pub static KEY_OPERATIONS_TOTAL: Lazy<IntCounterVec> = Lazy::new(|| {
    IntCounterVec::new(
        Opts::new("key_operations_total", "Total key management operations"),
        &["operation", "algorithm", "outcome"],
    )
    .unwrap()
});

// ── Lease Metrics ───────────────────────────────────────────────────────────

/// Gauge of currently active leases.
pub static ACTIVE_LEASES: Lazy<IntGaugeVec> = Lazy::new(|| {
    IntGaugeVec::new(
        Opts::new("active_leases", "Number of active leases"),
        &["tenant_id"],
    )
    .unwrap()
});

/// Counter of lease lifecycle operations.
pub static LEASE_OPERATIONS_TOTAL: Lazy<IntCounterVec> = Lazy::new(|| {
    IntCounterVec::new(
        Opts::new("lease_operations_total", "Total lease operations"),
        &["operation", "outcome"],
    )
    .unwrap()
});

// ── Audit Metrics ───────────────────────────────────────────────────────────

/// Counter of total audit events emitted.
pub static AUDIT_EVENTS_TOTAL: Lazy<IntCounterVec> = Lazy::new(|| {
    IntCounterVec::new(
        Opts::new("audit_events_total", "Total audit events emitted"),
        &["outcome"],
    )
    .unwrap()
});

/// Counter of audit events broken down by action type.
pub static AUDIT_EVENTS_BY_ACTION: Lazy<IntCounterVec> = Lazy::new(|| {
    IntCounterVec::new(
        Opts::new("audit_events_by_action", "Audit events by action category"),
        &["action", "outcome", "tenant_id"],
    )
    .unwrap()
});

// ── Auth & Policy Metrics ───────────────────────────────────────────────────

/// Counter of authentication attempts.
pub static AUTH_ATTEMPTS_TOTAL: Lazy<IntCounterVec> = Lazy::new(|| {
    IntCounterVec::new(
        Opts::new("auth_attempts_total", "Total authentication attempts"),
        &["method", "outcome"],
    )
    .unwrap()
});

/// Counter of policy evaluations.
pub static POLICY_EVALUATIONS_TOTAL: Lazy<IntCounterVec> = Lazy::new(|| {
    IntCounterVec::new(
        Opts::new("policy_evaluations_total", "Total policy evaluations"),
        &["action", "outcome"],
    )
    .unwrap()
});

// ── HA / Cluster Metrics ────────────────────────────────────────────────────

/// Gauge of cluster node count by state.
pub static HA_CLUSTER_NODES: Lazy<IntGaugeVec> = Lazy::new(|| {
    IntGaugeVec::new(
        Opts::new("ha_cluster_nodes", "Number of cluster nodes by state"),
        &["state", "region"],
    )
    .unwrap()
});

/// Gauge indicating if this node is the cluster leader (1) or not (0).
pub static HA_IS_LEADER: Lazy<IntGauge> = Lazy::new(|| {
    IntGauge::new(
        "ha_is_leader",
        "Whether this node is the HA leader (1=yes, 0=no)",
    )
    .unwrap()
});

/// Gauge of replication lag in milliseconds per region.
pub static HA_REPLICATION_LAG_MS: Lazy<IntGaugeVec> = Lazy::new(|| {
    IntGaugeVec::new(
        Opts::new("ha_replication_lag_ms", "Replication lag in milliseconds"),
        &["region"],
    )
    .unwrap()
});

/// Counter of failover events.
pub static HA_FAILOVER_TOTAL: Lazy<IntCounterVec> = Lazy::new(|| {
    IntCounterVec::new(
        Opts::new("ha_failover_total", "Total failover events"),
        &["from_region", "to_region", "reason", "outcome"],
    )
    .unwrap()
});

/// Gauge tracking the current election term.
pub static HA_ELECTION_TERM: Lazy<IntGauge> =
    Lazy::new(|| IntGauge::new("ha_election_term", "Current HA election term").unwrap());

// ── Encryption / Transit Metrics ────────────────────────────────────────────

/// Counter of encryption/decryption operations.
pub static ENCRYPTION_OPERATIONS_TOTAL: Lazy<IntCounterVec> = Lazy::new(|| {
    IntCounterVec::new(
        Opts::new("encryption_operations_total", "Total encryption operations"),
        &["operation", "algorithm", "outcome"],
    )
    .unwrap()
});

/// Histogram of encryption/decryption latency.
pub static ENCRYPTION_DURATION: Lazy<HistogramVec> = Lazy::new(|| {
    HistogramVec::new(
        HistogramOpts::new(
            "encryption_duration_seconds",
            "Encryption/decryption latency in seconds",
        )
        .buckets(vec![0.0001, 0.0005, 0.001, 0.005, 0.01, 0.05, 0.1]),
        &["operation", "algorithm"],
    )
    .unwrap()
});

/// Gather all registered metrics and encode them as a Prometheus text exposition.
///
/// Runs on every `/metrics` scrape, so it never panics: an encoding failure
/// yields an empty exposition rather than taking down the request handler.
pub fn gather_metrics() -> String {
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
