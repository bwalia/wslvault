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
