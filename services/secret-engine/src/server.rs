//! Server wiring: starts the tonic gRPC server and the axum HTTP REST server
//! as two concurrent tokio tasks that share a single `KvStore` instance.
//!
//! # Lifecycle
//! Both servers are started with `tokio::spawn` and the main task calls
//! `tokio::try_join!` to await them. If either server exits (cleanly or with
//! an error) the other is left running until the process is signalled — suitable
//! for development and early production. Production-grade deployments should
//! attach a shutdown signal to both servers.

use std::net::SocketAddr;
use std::sync::Arc;

use tonic::transport::Server as TonicServer;
use tracing::{error, info};

use crate::grpc::secret_proto::secret_service_server::SecretServiceServer;
use crate::grpc::SecretServiceImpl;
use crate::health::{liveness, readiness};
use crate::http::build_router;
use crate::kv_store::KvStore;

/// Run both servers concurrently.
///
/// # Arguments
/// * `grpc_addr`       — Socket address for the tonic gRPC server (e.g. `0.0.0.0:50052`)
/// * `http_addr`       — Socket address for the axum REST server (e.g. `0.0.0.0:8081`)
/// * `crypto_endpoint` — gRPC endpoint URL of the crypto-service (e.g. `http://crypto-service:50051`)
pub async fn run(
    grpc_addr: SocketAddr,
    http_addr: SocketAddr,
    crypto_endpoint: String,
) -> anyhow::Result<()> {
    let store = KvStore::new();

    let grpc_task = tokio::spawn(run_grpc(
        grpc_addr,
        Arc::clone(&store),
        crypto_endpoint.clone(),
    ));

    let http_task = tokio::spawn(run_http(http_addr, Arc::clone(&store), crypto_endpoint));

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
    store: Arc<KvStore>,
    crypto_endpoint: String,
) -> anyhow::Result<()> {
    let service_impl = SecretServiceImpl::new(store, crypto_endpoint);
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
    store: Arc<KvStore>,
    crypto_endpoint: String,
) -> anyhow::Result<()> {
    // Build the secret API router.
    let secret_router = build_router(store, crypto_endpoint);

    // Mount health probes alongside the secret API routes.
    let app = secret_router
        .route("/healthz", axum::routing::get(liveness))
        .route("/readyz", axum::routing::get(readiness));

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
