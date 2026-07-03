//! Dedicated Prometheus metrics HTTP server.
//!
//! Runs a lightweight axum server on the configured metrics port (default 9090)
//! that exposes the `/metrics` endpoint for Prometheus scraping.

use std::net::SocketAddr;

use axum::routing::get;
use axum::Router;
use tracing::{error, info};

use super::collector::gather_metrics;

/// Handler for GET /metrics — returns Prometheus text exposition format.
async fn metrics_handler() -> String {
    gather_metrics()
}

/// Health check on the metrics server itself.
async fn metrics_health() -> &'static str {
    "ok"
}

/// Resolve the metrics server bind address from the environment.
///
/// Reads `VAULT_METRICS_ADDR` (e.g. `0.0.0.0:9090`); falls back to
/// `0.0.0.0:9090` when unset or unparseable. Lets services running on the same
/// host avoid port clashes without code changes.
pub fn metrics_addr_from_env() -> SocketAddr {
    const DEFAULT: ([u8; 4], u16) = ([0, 0, 0, 0], 9090);
    match std::env::var("VAULT_METRICS_ADDR") {
        Ok(raw) => raw.parse().unwrap_or_else(|_| {
            error!(value = %raw, "invalid VAULT_METRICS_ADDR; using default 0.0.0.0:9090");
            DEFAULT.into()
        }),
        Err(_) => DEFAULT.into(),
    }
}

/// Spawn the metrics server as a background task using the env-configured
/// address. Convenience wrapper for services that have no other need to read
/// the address themselves.
pub fn spawn_from_env() {
    let addr = metrics_addr_from_env();
    tokio::spawn(run_metrics_server(addr));
}

/// Start the metrics HTTP server on the given address.
///
/// This should be spawned as a background task in each service's main function:
/// ```ignore
/// tokio::spawn(wslvault_core::metrics::server::run_metrics_server(
///     config.observability.metrics_addr,
/// ));
/// ```
pub async fn run_metrics_server(addr: SocketAddr) {
    let app = Router::new()
        .route("/metrics", get(metrics_handler))
        .route("/health", get(metrics_health));

    info!(addr = %addr, "starting Prometheus metrics server");

    match tokio::net::TcpListener::bind(addr).await {
        Ok(listener) => {
            if let Err(e) = axum::serve(listener, app).await {
                error!(error = %e, "metrics server error");
            }
        }
        Err(e) => {
            error!(error = %e, addr = %addr, "failed to bind metrics server");
        }
    }
}
