//! Server wiring: starts the tonic gRPC server and the axum HTTP REST server
//! as two concurrent tokio tasks that share a single `SecretStoreBackend` instance.
//!
//! # Backend selection
//! The backend is chosen at startup based on the `DATABASE_URL` environment variable:
//! - When `DATABASE_URL` is set, a `PgSecretBackend` is created using the URL
//!   together with default `DatabaseConfig` pool settings.
//! - When `DATABASE_URL` is absent, the in-memory `KvStore` is used.  This is
//!   appropriate for development and integration tests that do not require a
//!   live PostgreSQL instance.
//!
//! # Policy enforcement
//! Every read/write/delete operation is gated behind a call to the
//! policy-engine.  The `policy_endpoint` parameter is forwarded to both the
//! gRPC and HTTP handlers so that each handler can issue an `Authorize` RPC
//! before touching the store.  If the policy-engine is unreachable the request
//! is denied (fail-closed).
//!
//! # Lease management
//! A `LeaseClient` is constructed once and shared (via cheap clone) between
//! both servers.  Lease creation on secret reads is best-effort — if the
//! lease-manager is unavailable the operation still succeeds (degraded mode).
//! Lease revocation is always fire-and-forget.
//!
//! # Lifecycle
//! Both servers are started with `tokio::spawn` and the main task calls
//! `tokio::try_join!` to await them. If either server exits (cleanly or with
//! an error) the other is left running until the process is signalled — suitable
//! for development and early production. Production-grade deployments should
//! attach a shutdown signal to both servers.

use std::net::SocketAddr;
use std::sync::Arc;

use axum::middleware;
use tonic::transport::Server as TonicServer;
use tracing::{error, info, warn};
use wslvault_core::config::DatabaseConfig;

use crate::audit_client::AuditClient;
use crate::grpc::secret_proto::secret_service_server::SecretServiceServer;
use crate::grpc::SecretServiceImpl;
use crate::health::{liveness, readiness};
use crate::http::build_router;
use crate::kv_store::{KvStore, SecretStoreBackend};
use crate::lease_client::LeaseClient;
use crate::pg_store::PgSecretBackend;
use crate::policy_client::PolicyClient;
use wslvault_core::metrics::middleware::metrics_middleware;
use wslvault_storage::pool::DbPool;

/// Run both servers concurrently.
///
/// # Arguments
/// * `grpc_addr`        — Socket address for the tonic gRPC server (e.g. `0.0.0.0:50052`)
/// * `http_addr`        — Socket address for the axum REST server (e.g. `0.0.0.0:8081`)
/// * `crypto_endpoint`  — gRPC endpoint URL of the crypto-service (e.g. `http://crypto-service:50051`)
/// * `audit_endpoint`   — gRPC endpoint URL of the audit-service (e.g. `http://audit-service:50056`)
/// * `policy_endpoint`  — gRPC endpoint URL of the policy-engine (e.g. `http://policy-engine:50053`)
/// * `lease_endpoint`   — gRPC endpoint URL of the lease-manager (e.g. `http://lease-manager:50055`)
pub async fn run(
    grpc_addr: SocketAddr,
    http_addr: SocketAddr,
    crypto_endpoint: String,
    audit_endpoint: String,
    policy_endpoint: String,
    lease_endpoint: String,
) -> anyhow::Result<()> {
    // Select the storage backend.  The PostgreSQL backend is used when
    // DATABASE_URL is present; the in-memory KvStore is the fallback.
    let store: Arc<dyn SecretStoreBackend> = match std::env::var("DATABASE_URL") {
        Ok(database_url) => {
            info!("DATABASE_URL detected — connecting to PostgreSQL backend");
            let db_config = DatabaseConfig {
                url: database_url,
                ..DatabaseConfig::default()
            };
            let pool = DbPool::connect(&db_config).await.map_err(|e| {
                error!(error = %e, "failed to connect to PostgreSQL");
                anyhow::anyhow!("PostgreSQL connection failed: {}", e)
            })?;
            info!("PostgreSQL connection pool established; using PgSecretBackend");
            Arc::new(PgSecretBackend::new(pool))
        }
        Err(_) => {
            warn!("DATABASE_URL not set — falling back to in-memory KvStore (not for production)");
            KvStore::new()
        }
    };

    // Construct the audit client once; it is cheaply clonable (`Clone` is
    // derived) and is shared by both the gRPC and HTTP servers.
    let audit_client = AuditClient::new(audit_endpoint);

    // Construct the policy client once; it is also cheaply clonable and is
    // shared by both the gRPC and HTTP servers.  Each handler will issue an
    // Authorize RPC before proceeding with any store or crypto operation.
    let policy_client = PolicyClient::new(policy_endpoint);

    // Construct the lease client once; it is cheaply clonable and shared by
    // both servers.  Lease creation is best-effort — the service continues in
    // degraded mode when the lease-manager is unreachable.
    let lease_client = LeaseClient::new(lease_endpoint);

    let grpc_task = tokio::spawn(run_grpc(
        grpc_addr,
        Arc::clone(&store),
        crypto_endpoint.clone(),
        audit_client.clone(),
        policy_client.clone(),
        lease_client.clone(),
    ));

    let http_task = tokio::spawn(run_http(
        http_addr,
        Arc::clone(&store),
        crypto_endpoint,
        audit_client,
        policy_client,
        lease_client,
    ));

    // Await both; propagate the first error encountered.
    tokio::try_join!(
        async {
            grpc_task
                .await
                .map_err(|e| anyhow::anyhow!("grpc task panicked: {}", e))?
        },
        async {
            http_task
                .await
                .map_err(|e| anyhow::anyhow!("http task panicked: {}", e))?
        },
    )?;

    Ok(())
}

/// Start the tonic gRPC server.
async fn run_grpc(
    addr: SocketAddr,
    store: Arc<dyn SecretStoreBackend>,
    crypto_endpoint: String,
    audit_client: AuditClient,
    policy_client: PolicyClient,
    lease_client: LeaseClient,
) -> anyhow::Result<()> {
    let service_impl = SecretServiceImpl::new(
        store,
        crypto_endpoint,
        audit_client,
        policy_client,
        lease_client,
    );
    let svc = SecretServiceServer::new(service_impl);

    info!(addr = %addr, "starting gRPC server");

    TonicServer::builder()
        .add_service(svc)
        .serve(addr)
        .await
        .map_err(|e| {
            error!(error = %e, "gRPC server error");
            anyhow::anyhow!("gRPC server failed: {}", e)
        })
}

/// Start the axum HTTP server.
async fn run_http(
    addr: SocketAddr,
    store: Arc<dyn SecretStoreBackend>,
    crypto_endpoint: String,
    audit_client: AuditClient,
    policy_client: PolicyClient,
    lease_client: LeaseClient,
) -> anyhow::Result<()> {
    // Build the secret API router, forwarding the policy and lease clients so
    // every handler can gate operations and optionally attach TTL-based leases.
    let secret_router = build_router(
        store,
        crypto_endpoint,
        audit_client,
        policy_client,
        lease_client,
    );

    // Mount health probes alongside the secret API routes, with metrics middleware.
    let app = secret_router
        .route("/healthz", axum::routing::get(liveness))
        .route("/readyz", axum::routing::get(readiness))
        .layer(middleware::from_fn(metrics_middleware));

    info!(addr = %addr, "starting HTTP server");

    let listener = tokio::net::TcpListener::bind(addr).await.map_err(|e| {
        error!(error = %e, addr = %addr, "failed to bind HTTP listener");
        anyhow::anyhow!("HTTP bind failed: {}", e)
    })?;

    axum::serve(listener, app).await.map_err(|e| {
        error!(error = %e, "HTTP server error");
        anyhow::anyhow!("HTTP server failed: {}", e)
    })
}
