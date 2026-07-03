//! Health check endpoint for the pki-engine service.

use axum::{http::StatusCode, response::IntoResponse, Json};
use serde::Serialize;

/// Response body for the health endpoint.
#[derive(Serialize)]
pub struct HealthResponse {
    pub status: &'static str,
    pub service: &'static str,
}

/// Handler for `GET /health`.
pub async fn health_handler() -> impl IntoResponse {
    (
        StatusCode::OK,
        Json(HealthResponse {
            status: "ok",
            service: "pki-engine",
        }),
    )
}
