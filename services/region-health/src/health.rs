//! Health and readiness probes.

use axum::http::StatusCode;

pub async fn health_handler() -> StatusCode {
    StatusCode::OK
}
