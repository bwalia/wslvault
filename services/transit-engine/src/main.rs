//! transit-engine service entry point.
//!
//! Starts an axum HTTP server on port 8086 that exposes the transit
//! encryption-as-a-service API.  A GET /health endpoint is also available
//! for liveness checks.

mod health;
mod http;
mod key_store;
mod operations;

use axum::{routing::get, routing::post, Router};
use tracing::info;
use tracing_subscriber::{fmt, prelude::*, EnvFilter};

use crate::http::{
    create_key_handler, decrypt_handler, encrypt_handler, rewrap_handler, rotate_key_handler,
    sign_handler, verify_handler, AppState,
};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Initialise structured tracing; RUST_LOG controls the filter level.
    tracing_subscriber::registry()
        .with(EnvFilter::from_default_env())
        .with(fmt::layer())
        .init();

    info!("starting transit-engine service");

    // Create the shared in-memory key store.
    let key_store = key_store::new_key_store();
    let state = AppState { key_store };

    let router = Router::new()
        // Health probe
        .route("/health", get(health::health_handler))
        // Transit encryption operations
        .route("/v1/transit/encrypt/:key_name", post(encrypt_handler))
        .route("/v1/transit/decrypt/:key_name", post(decrypt_handler))
        .route("/v1/transit/sign/:key_name", post(sign_handler))
        .route("/v1/transit/verify/:key_name", post(verify_handler))
        .route("/v1/transit/rewrap/:key_name", post(rewrap_handler))
        // Key management
        .route("/v1/transit/keys/:key_name", post(create_key_handler))
        .route(
            "/v1/transit/keys/:key_name/rotate",
            post(rotate_key_handler),
        )
        .with_state(state);

    let addr = "0.0.0.0:8086".parse::<std::net::SocketAddr>()?;
    info!("HTTP server listening on {}", addr);

    let listener = tokio::net::TcpListener::bind(addr).await?;
    axum::serve(listener, router).await?;

    Ok(())
}
