//! HTTP health and readiness endpoints for Kubernetes liveness/readiness probes
//! and load-balancer health checks.
//!
//! Two routes are exposed on the HTTP server:
//!   GET /healthz  — liveness probe: returns 200 if the process is alive.
//!   GET /readyz   — readiness probe: returns 200 once the service is fully
//!                   initialised and ready to serve gRPC traffic.

use axum::http::StatusCode;
use axum::response::IntoResponse;
use axum::Json;
use serde::Serialize;

/// Response body for health endpoints.
#[derive(Debug, Serialize)]
pub struct HealthResponse {
    pub status: &'static str,
    pub service: &'static str,
    pub version: &'static str,
}

/// Liveness probe handler.
///
/// Returns `200 OK` with a JSON body as long as the process is running.
/// Kubernetes restarts the pod if this endpoint stops responding.
pub async fn liveness() -> impl IntoResponse {
    (
        StatusCode::OK,
        Json(HealthResponse {
            status: "ok",
            service: "crypto-service",
            version: env!("CARGO_PKG_VERSION"),
        }),
    )
}

/// Readiness probe handler.
///
/// Returns `200 OK` once all startup tasks have completed.
/// Returns `503 Service Unavailable` while the service is still initialising.
/// Kubernetes only routes traffic to pods that pass this probe.
///
/// For the current in-memory implementation, the service is always ready once
/// the process starts. A future implementation would check database connectivity
/// and that the root KEK is loaded before returning 200.
pub async fn readiness() -> impl IntoResponse {
    (
        StatusCode::OK,
        Json(HealthResponse {
            status: "ready",
            service: "crypto-service",
            version: env!("CARGO_PKG_VERSION"),
        }),
    )
}
