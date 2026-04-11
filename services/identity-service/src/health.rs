//! HTTP health-check endpoints for the identity-service.
//!
//! Provides `/healthz` (liveness) and `/readyz` (readiness) routes suitable
//! for Kubernetes probes.  Both endpoints return a JSON body so that
//! operators can distinguish between "process is alive" and "service is ready
//! to accept traffic".

use axum::{http::StatusCode, response::IntoResponse, routing::get, Json, Router};
use serde::Serialize;

/// Payload returned by the health endpoints.
#[derive(Debug, Serialize, utoipa::ToSchema)]
pub struct HealthResponse {
    pub status: &'static str,
    pub service: &'static str,
}

/// GET /healthz — liveness probe.
///
/// Returns 200 OK as long as the process is alive and the event loop is
/// running.  Does not check downstream dependencies.
#[utoipa::path(
    get,
    path = "/healthz",
    responses(
        (status = 200, description = "Service is alive", body = HealthResponse),
    ),
    tag = "health"
)]
pub async fn liveness() -> impl IntoResponse {
    (
        StatusCode::OK,
        Json(HealthResponse {
            status: "ok",
            service: "identity-service",
        }),
    )
}

/// GET /readyz — readiness probe.
///
/// Returns 200 OK when the service is ready to accept gRPC traffic.
/// Extend this handler to check dependency health (e.g., database
/// connectivity) before returning 200 when those dependencies are added.
#[utoipa::path(
    get,
    path = "/readyz",
    responses(
        (status = 200, description = "Service is ready to accept traffic", body = HealthResponse),
    ),
    tag = "health"
)]
pub async fn readiness() -> impl IntoResponse {
    (
        StatusCode::OK,
        Json(HealthResponse {
            status: "ready",
            service: "identity-service",
        }),
    )
}

/// Builds an `axum::Router` containing the health-check routes.
///
/// Mount this router directly onto the main HTTP server:
/// ```no_run
/// let app = health::router().merge(other_routes);
/// ```
pub fn router() -> Router {
    Router::new()
        .route("/healthz", get(liveness))
        .route("/readyz", get(readiness))
}
