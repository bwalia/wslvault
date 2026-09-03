//! audit-service entry point.
//!
//! Starts two servers concurrently:
//! - gRPC server on port 50056 (AuditService)
//! - HTTP health server on port 8085 (GET /health)
//!
//! When the `DATABASE_URL` environment variable is set the service uses the
//! PostgreSQL-backed store; otherwise it falls back to the in-memory store so
//! the service can start in development without a database.

mod analytics;
mod grpc;
mod health;
mod http;
mod integrity;
mod pg_store;
mod store;

use std::sync::Arc;

use axum::{middleware, routing::get, Router};
use grpc::proto::audit_service_server::AuditServiceServer;
use grpc::AuditServiceImpl;
use tonic::transport::Server as GrpcServer;
use tracing::info;
use tracing_subscriber::{fmt, prelude::*, EnvFilter};
use wslvault_core::metrics::middleware::metrics_middleware;

use store::AuditStoreBackend;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Initialise structured tracing; RUST_LOG controls the filter level.
    tracing_subscriber::registry()
        // Default to `info` when RUST_LOG is unset. `from_default_env()` alone
        // yields an empty filter, which silences the service completely — no
        // startup line, no errors, nothing shipped to Loki — so a crash-looping
        // or misbehaving pod leaves no trace at all.
        .with(EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")))
        .with(fmt::layer())
        .init();

    info!("starting audit-service");

    // Per-tenant signing keys, derived from one master secret. The service
    // refuses to start without it: the previous hardcoded fallback produced a
    // log that looked signed and could be forged by anyone with the source.
    let signer = integrity::AuditSigner::from_env().map_err(|e| anyhow::anyhow!(e))?;

    // Select the storage backend based on whether DATABASE_URL is configured.
    let audit_store: Arc<dyn AuditStoreBackend> =
        if let Ok(database_url) = std::env::var("DATABASE_URL") {
            info!("DATABASE_URL found – connecting to PostgreSQL");

            let config = wslvault_core::config::DatabaseConfig {
                url: database_url,
                ..Default::default()
            };

            let pool = wslvault_storage::pool::DbPool::connect(&config).await?;
            info!("PostgreSQL connection pool established; using PgAuditBackend");
            Arc::new(pg_store::PgAuditBackend::new(pool, signer.clone()))
        } else {
            info!("DATABASE_URL not set – using in-memory audit store");
            Arc::new(store::InMemoryAuditStore::new())
        };

    // Both servers read through the same backend.
    let audit_store_for_http = Arc::clone(&audit_store);

    // Build the gRPC service.
    let audit_service = AuditServiceImpl::new(audit_store, signer);
    let grpc_addr = "0.0.0.0:50056".parse()?;

    // Start metrics server.
    let metrics_addr: std::net::SocketAddr = "0.0.0.0:9090".parse()?;
    tokio::spawn(wslvault_core::metrics::server::run_metrics_server(
        metrics_addr,
    ));

    // Build the health HTTP service with metrics middleware.
    // The query surface rides on the same port as /health. It is merged rather
    // than nested so the path stays /v1/audit/events, which is what the UI and
    // the gateway already call.
    let health_router = Router::new()
        .route("/health", get(health::health_handler))
        .merge(http::router(audit_store_for_http))
        .layer(middleware::from_fn(metrics_middleware));
    let health_addr = "0.0.0.0:8085".parse::<std::net::SocketAddr>()?;

    info!("gRPC server listening on {}", grpc_addr);
    info!("health server listening on {}", health_addr);
    info!("metrics server listening on {}", metrics_addr);

    tokio::try_join!(
        // gRPC server
        async {
            GrpcServer::builder()
                .add_service(AuditServiceServer::new(audit_service))
                .serve(grpc_addr)
                .await
                .map_err(|e| -> Box<dyn std::error::Error> { Box::new(e) })
        },
        // HTTP health server
        async {
            let listener = tokio::net::TcpListener::bind(health_addr).await?;
            axum::serve(listener, health_router)
                .await
                .map_err(|e| -> Box<dyn std::error::Error> { Box::new(e) })
        },
    )?;

    Ok(())
}
