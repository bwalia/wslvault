//! pki-engine service entry point.
//!
//! Starts an axum HTTP server on port 8088 that exposes the PKI secrets engine
//! REST API.  A `GET /health` endpoint is available for liveness probes.
//!
//! # Backend selection
//!
//! - **`DATABASE_URL` is set**: `PgPkiStore` persists CA records, roles, and
//!   certificate metadata to `pki.pki_ca`, `pki.pki_roles`, and
//!   `pki.pki_certs` in PostgreSQL.
//! - **`DATABASE_URL` absent**: `InMemoryPkiStore` is used.  All state is lost
//!   on process exit.  Suitable for development and CI.
//!
//! # CA key protection
//!
//! CA private keys are encrypted at rest using AES-256-GCM via the
//! `key_protect::RootKek` loaded from `PKI_ROOT_KEY` (base64-encoded 32
//! bytes) at startup.  The service will not start if `PKI_ROOT_KEY` is absent
//! or malformed.
//!
//! # Gateway authentication
//!
//! All PKI routes are gated behind the shared `X-Gateway-Auth` middleware
//! (same as transit-engine).  The health probe is intentionally excluded so
//! orchestrators can check liveness without credentials.

mod ca;
mod error;
mod health;
mod http;
mod key_protect;
mod pg_store;
mod store;
mod types;

use std::sync::Arc;

use axum::{
    routing::{delete, get, post},
    Router,
};
use tracing::info;
use tracing_subscriber::{fmt, prelude::*, EnvFilter};
use utoipa::OpenApi as _;
use utoipa_swagger_ui::SwaggerUi;

use wslvault_core::config::DatabaseConfig;
use wslvault_storage::pool::DbPool;

use crate::http::{
    crl_handler, delete_role_handler, generate_ca_handler, get_ca_handler, get_role_handler,
    import_ca_handler, issue_handler, revoke_handler, sign_csr_handler, upsert_role_handler,
    ApiDoc, AppState,
};
use crate::key_protect::RootKek;
use crate::pg_store::PgPkiStore;
use crate::store::{InMemoryPkiStore, PkiStore};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Initialise structured tracing; RUST_LOG controls the filter level.
    tracing_subscriber::registry()
        .with(EnvFilter::from_default_env())
        .with(fmt::layer())
        .init();

    info!("starting pki-engine service");

    // Expose Prometheus metrics for scraping (address via VAULT_METRICS_ADDR).
    wslvault_core::metrics::server::spawn_from_env();

    // Load the service-level root KEK from `PKI_ROOT_KEY`.
    // Fail fast if the variable is absent or malformed; running without key
    // protection would expose CA private keys in the database.
    let kek = Arc::new(RootKek::from_env().map_err(|e| {
        format!("failed to load PKI_ROOT_KEY: {e}")
    })?);

    info!(key_version = kek.version, "PKI root KEK loaded");

    // Select the PKI store backend based on whether DATABASE_URL is present.
    let store: Arc<dyn PkiStore> = match std::env::var("DATABASE_URL") {
        Ok(database_url) if !database_url.is_empty() => {
            info!("DATABASE_URL detected — using PostgreSQL PKI backend");

            let db_config = DatabaseConfig {
                url: database_url,
                ..DatabaseConfig::default()
            };

            let pool = DbPool::connect(&db_config).await.map_err(|e| {
                format!("failed to connect to PostgreSQL: {e}")
            })?;

            Arc::new(PgPkiStore::new(pool))
        }
        _ => {
            info!("DATABASE_URL not set — using in-memory PKI backend");
            Arc::new(InMemoryPkiStore::new())
        }
    };

    let state = AppState { store, kek };

    // PKI routes are gated behind the shared gateway-auth middleware.
    let pki_routes = Router::new()
        // CA management
        .route("/v1/pki/ca/generate", post(generate_ca_handler))
        .route("/v1/pki/ca", get(get_ca_handler))
        .route("/v1/pki/ca/import", post(import_ca_handler))
        // Role management
        .route("/v1/pki/roles/:name", post(upsert_role_handler))
        .route("/v1/pki/roles/:name", get(get_role_handler))
        .route("/v1/pki/roles/:name", delete(delete_role_handler))
        // Certificate issuance
        .route("/v1/pki/issue/:role_name", post(issue_handler))
        .route("/v1/pki/sign/:role_name", post(sign_csr_handler))
        // Revocation
        .route("/v1/pki/revoke", post(revoke_handler))
        .route("/v1/pki/crl", get(crl_handler))
        .with_state(state)
        .layer(axum::middleware::from_fn_with_state(
            wslvault_core::middleware::GatewayAuth::from_env(),
            wslvault_core::middleware::require_gateway_auth,
        ));

    let router = Router::new()
        // Liveness probe (no auth required).
        .route("/health", get(health::health_handler))
        .merge(pki_routes)
        .merge(SwaggerUi::new("/swagger-ui").url("/api-docs/openapi.json", ApiDoc::openapi()));

    let addr = "0.0.0.0:8088".parse::<std::net::SocketAddr>()?;
    info!("HTTP server listening on {}", addr);

    let listener = tokio::net::TcpListener::bind(addr).await?;
    axum::serve(listener, router).await?;

    Ok(())
}
