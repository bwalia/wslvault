//! transit-engine service entry point.
//!
//! Starts an axum HTTP server on port 8086 that exposes the transit
//! encryption-as-a-service API.  A GET /health endpoint is also available
//! for liveness checks.
//!
//! # Backend selection
//!
//! The backend is chosen at startup based on the `DATABASE_URL` environment
//! variable:
//!
//! - **`DATABASE_URL` is set**: `PgTransitKeyBackend` is used.  Key metadata
//!   is persisted in `system.key_descriptors`; raw key material lives in an
//!   in-process cache that is populated from PG on startup.
//! - **`DATABASE_URL` is absent**: `InMemoryTransitKeyStore` is used.  All
//!   state is lost when the process exits.  Suitable for development and CI.
//!
//! # Policy enforcement
//!
//! Every route handler checks authorization against the policy-engine before
//! performing any key-store or cryptographic operation.  The policy-engine
//! endpoint defaults to `http://policy-engine:50053` and can be overridden
//! with the `POLICY_ENGINE_ENDPOINT` environment variable.  If the
//! policy-engine is unreachable the request is denied (fail-closed).
//!
//! # Audit logging
//!
//! Every route handler emits an audit event to the audit-service after
//! completing (success or failure). The audit-service endpoint defaults to
//! `http://audit-service:50056` and can be overridden with the
//! `AUDIT_SERVICE_ENDPOINT` environment variable. Audit failures are logged
//! but never block or fail the operation.

mod audit_client;
mod health;
mod http;
mod key_store;
mod operations;
mod pg_store;
mod policy_client;

use std::sync::Arc;

use axum::{routing::get, routing::post, Router};
use tracing::info;
use tracing_subscriber::{fmt, prelude::*, EnvFilter};
use utoipa::OpenApi as _;
use utoipa_swagger_ui::SwaggerUi;

use wslvault_core::config::DatabaseConfig;
use wslvault_storage::pool::DbPool;

use crate::audit_client::AuditClient;
use crate::http::{
    create_key_handler, decrypt_handler, encrypt_handler, rewrap_handler, rotate_key_handler,
    sign_handler, verify_handler, ApiDoc, AppState,
};
use crate::key_store::{InMemoryTransitKeyStore, TransitKeyStoreBackend};
use crate::pg_store::PgTransitKeyBackend;
use crate::policy_client::PolicyClient;

/// Default policy-engine gRPC endpoint used when `POLICY_ENGINE_ENDPOINT` is not set.
const DEFAULT_POLICY_ENDPOINT: &str = "http://policy-engine:50053";

/// Default audit-service gRPC endpoint used when `AUDIT_SERVICE_ENDPOINT` is not set.
const DEFAULT_AUDIT_ENDPOINT: &str = "http://audit-service:50056";

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Initialise structured tracing; RUST_LOG controls the filter level.
    tracing_subscriber::registry()
        .with(EnvFilter::from_default_env())
        .with(fmt::layer())
        .init();

    info!("starting transit-engine service");

    // Expose Prometheus metrics for scraping (address via VAULT_METRICS_ADDR).
    wslvault_core::metrics::server::spawn_from_env();

    // Select the key store backend based on whether DATABASE_URL is present.
    //
    // Using `Arc<dyn TransitKeyStoreBackend>` here keeps AppState a single
    // concrete type regardless of which backend is active, which is required
    // for axum's `State` extractor.
    let key_store: Arc<dyn TransitKeyStoreBackend> =
        match std::env::var("DATABASE_URL") {
            Ok(database_url) if !database_url.is_empty() => {
                info!("DATABASE_URL detected — using PostgreSQL transit key backend");

                let db_config = DatabaseConfig {
                    url: database_url,
                    ..DatabaseConfig::default()
                };

                let pool = DbPool::connect(&db_config).await.map_err(|e| {
                    // Propagate the error as a boxed error so main() can return it.
                    format!("failed to connect to PostgreSQL: {}", e)
                })?;

                let backend = PgTransitKeyBackend::new(pool).await.map_err(|e| {
                    format!("failed to initialise PG transit key backend: {}", e)
                })?;

                Arc::new(backend)
            }
            _ => {
                info!("DATABASE_URL not set — using in-memory transit key backend");
                Arc::new(InMemoryTransitKeyStore::new())
            }
        };

    // Resolve the policy-engine endpoint.
    // Precedence: POLICY_ENGINE_ENDPOINT env var > compiled default.
    let policy_endpoint = std::env::var("POLICY_ENGINE_ENDPOINT")
        .unwrap_or_else(|_| DEFAULT_POLICY_ENDPOINT.to_string());

    info!(policy_endpoint = %policy_endpoint, "using policy-engine endpoint");

    // Resolve the audit-service endpoint.
    // Precedence: AUDIT_SERVICE_ENDPOINT env var > compiled default.
    let audit_endpoint = std::env::var("AUDIT_SERVICE_ENDPOINT")
        .unwrap_or_else(|_| DEFAULT_AUDIT_ENDPOINT.to_string());

    info!(audit_endpoint = %audit_endpoint, "using audit-service endpoint");

    let policy_client = PolicyClient::new(policy_endpoint);
    let audit_client = AuditClient::new(audit_endpoint);

    let state = AppState {
        key_store,
        policy_client,
        audit_client,
    };

    // Transit operations trust tenant-identity headers, so they are gated on
    // gateway-origin authentication (shared X-Gateway-Auth secret). The health
    // probe is left open for orchestrators.
    let transit_routes = Router::new()
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
        .with_state(state)
        .layer(axum::middleware::from_fn_with_state(
            wslvault_core::middleware::GatewayAuth::from_env(),
            wslvault_core::middleware::require_gateway_auth,
        ));

    let router = Router::new()
        // Health probe
        .route("/health", get(health::health_handler))
        .merge(transit_routes)
        // Swagger UI is served at /swagger-ui; the OpenAPI JSON is at
        // /api-docs/openapi.json for programmatic consumption.
        .merge(SwaggerUi::new("/swagger-ui").url("/api-docs/openapi.json", ApiDoc::openapi()));

    let addr = "0.0.0.0:8086".parse::<std::net::SocketAddr>()?;
    info!("HTTP server listening on {}", addr);

    let listener = tokio::net::TcpListener::bind(addr).await?;
    axum::serve(listener, router).await?;

    Ok(())
}
