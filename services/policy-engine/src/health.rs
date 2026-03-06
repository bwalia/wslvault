//! Axum HTTP health endpoint for the policy-engine service.
//!
//! Exposes `GET /health` returning `200 OK` with a JSON body. This is used
//! by Kubernetes liveness and readiness probes, as well as load-balancer
//! health checks.

use axum::http::StatusCode;
use axum::response::IntoResponse;
use axum::routing::get;
use axum::{Json, Router};
use serde::Serialize;

/// JSON body returned by the health endpoint.
#[derive(Debug, Serialize)]
struct HealthResponse {
    status: &'static str,
    service: &'static str,
}

/// Handler for `GET /health`. Always returns `200 OK` as long as the process
/// is running and able to accept connections.
async fn health_handler() -> impl IntoResponse {
    (
        StatusCode::OK,
        Json(HealthResponse {
            status: "ok",
            service: "policy-engine",
        }),
    )
}

/// Build the Axum `Router` containing health-related routes.
///
/// Mount this router at the service's HTTP listener address:
///
/// ```ignore
/// let app = health_router();
/// axum::serve(listener, app).await?;
/// ```
pub fn health_router() -> Router {
    Router::new().route("/health", get(health_handler))
}
