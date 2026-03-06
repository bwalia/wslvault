//! Health and readiness endpoints for the secret-engine service.
//!
//! Exposes two lightweight HTTP handlers:
//! - GET /healthz  — liveness probe: always returns 200 while the process is alive.
//! - GET /readyz   — readiness probe: returns 200 once the service is fully
//!                   initialised and able to serve traffic.
//!
//! Both handlers are registered on the shared axum Router by `build_health_router`.

use axum::{http::StatusCode, response::IntoResponse, Json};
use serde::Serialize;

/// Response body for health endpoints.
#[derive(Debug, Serialize)]
pub struct HealthResponse {
    pub status: &'static str,
    pub service: &'static str,
    pub version: &'static str,
}

/// Liveness handler — responds as long as the process is running.
pub async fn liveness() -> impl IntoResponse {
    (
        StatusCode::OK,
        Json(HealthResponse {
            status: "ok",
            service: "secret-engine",
            version: env!("CARGO_PKG_VERSION"),
        }),
    )
}

/// Readiness handler — returns 200 once the service is ready to accept traffic.
///
/// In future iterations this could check the crypto-service connection and
/// return 503 if the upstream is unreachable.
pub async fn readiness() -> impl IntoResponse {
    (
        StatusCode::OK,
        Json(HealthResponse {
            status: "ready",
            service: "secret-engine",
            version: env!("CARGO_PKG_VERSION"),
        }),
    )
}
