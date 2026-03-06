//! Server wiring: sets up the tonic gRPC server and the axum HTTP server,
//! then runs both concurrently until a shutdown signal is received.
//!
//! The two servers share a single Tokio runtime but listen on separate ports:
//!   - gRPC on 0.0.0.0:50051
//!   - HTTP (health + metrics) on 0.0.0.0:8080

use std::net::SocketAddr;

use axum::routing::get;
use axum::Router;
use tokio::signal;
use tonic::transport::Server as TonicServer;
use tracing::{error, info};

use crate::grpc::proto::crypto_service_server::CryptoServiceServer;
use crate::grpc::CryptoServiceImpl;
use crate::health;
use crate::kek_store::KekStore;

/// Addresses used by each server component.
pub struct ServerConfig {
    pub grpc_addr: SocketAddr,
    pub http_addr: SocketAddr,
}

impl Default for ServerConfig {
    fn default() -> Self {
        Self {
            grpc_addr: ([0, 0, 0, 0], 50051).into(),
            http_addr: ([0, 0, 0, 0], 8080).into(),
        }
    }
}

/// Build the axum `Router` for HTTP health and metrics traffic.
pub fn build_http_router() -> Router {
    Router::new()
        .route("/healthz", get(health::liveness))
        .route("/readyz", get(health::readiness))
}

/// Run both the gRPC and HTTP servers concurrently, returning only when both
/// have shut down cleanly.
///
/// Graceful shutdown is triggered by:
/// - SIGTERM (Kubernetes pod termination)
/// - SIGINT  (Ctrl-C in development)
///
/// Both servers honour the same shutdown signal; once the signal fires each
/// server drains in-flight requests before exiting.
pub async fn run(kek_store: KekStore, config: ServerConfig) -> Result<(), anyhow::Error> {
    let grpc_service = CryptoServiceImpl::new(kek_store);

    // Build the tonic gRPC server.
    let grpc_addr = config.grpc_addr;
    let grpc_server = TonicServer::builder()
        .add_service(CryptoServiceServer::new(grpc_service))
        .serve_with_shutdown(grpc_addr, shutdown_signal());

    // Build the axum HTTP server.
    let http_addr = config.http_addr;
    let http_router = build_http_router();
    let http_listener = tokio::net::TcpListener::bind(http_addr).await?;
    let http_server =
        axum::serve(http_listener, http_router).with_graceful_shutdown(shutdown_signal());

    info!(
        grpc_addr = %grpc_addr,
        http_addr = %http_addr,
        "crypto-service starting"
    );

    // Run both servers concurrently. Either completing (or failing) causes
    // the whole `select!` to resolve, and we propagate any error.
    tokio::select! {
        result = grpc_server => {
            match result {
                Ok(()) => info!("gRPC server shut down cleanly"),
                Err(err) => {
                    error!(%err, "gRPC server exited with error");
                    return Err(err.into());
                }
            }
        }
        result = http_server => {
            match result {
                Ok(()) => info!("HTTP server shut down cleanly"),
                Err(err) => {
                    error!(%err, "HTTP server exited with error");
                    return Err(err.into());
                }
            }
        }
    }

    Ok(())
}

/// Returns a `Future` that resolves when the process receives SIGTERM or SIGINT.
///
/// Using a single future means both servers wait for the same signal, which
/// prevents one server from tearing down before the other has drained.
async fn shutdown_signal() {
    let ctrl_c = async {
        signal::ctrl_c()
            .await
            .expect("Failed to install Ctrl-C handler");
    };

    #[cfg(unix)]
    let sigterm = async {
        signal::unix::signal(signal::unix::SignalKind::terminate())
            .expect("Failed to install SIGTERM handler")
            .recv()
            .await;
    };

    // On non-Unix platforms (Windows) only Ctrl-C is supported.
    #[cfg(not(unix))]
    let sigterm = std::future::pending::<()>();

    tokio::select! {
        _ = ctrl_c => {
            info!("Received SIGINT (Ctrl-C), initiating graceful shutdown");
        }
        _ = sigterm => {
            info!("Received SIGTERM, initiating graceful shutdown");
        }
    }
}
