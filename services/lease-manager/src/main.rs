//! lease-manager service entry point.
//!
//! Starts two servers concurrently:
//! - gRPC server on port 50055 (LeaseService)
//! - HTTP health server on port 8084 (GET /health)
//!
//! A background Tokio task runs every 5 seconds to sweep expired leases.

mod expiration;
mod grpc;
mod health;
mod store;

use axum::{routing::get, Router};
use grpc::proto::lease_service_server::LeaseServiceServer;
use grpc::LeaseServiceImpl;
use tonic::transport::Server as GrpcServer;
use tracing::info;
use tracing_subscriber::{fmt, prelude::*, EnvFilter};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Initialise structured tracing; RUST_LOG controls the filter level.
    tracing_subscriber::registry()
        .with(EnvFilter::from_default_env())
        .with(fmt::layer())
        .init();

    info!("starting lease-manager service");

    // Create the shared in-memory lease store.
    let lease_store = store::new_store();

    // Spawn background expiration sweep.
    let _expiration_handle = expiration::spawn_expiration_task(lease_store.clone());

    // Build the gRPC service.
    let lease_service = LeaseServiceImpl::new(lease_store.clone());
    let grpc_addr = "0.0.0.0:50055".parse()?;

    // Build the health HTTP service.
    let health_router = Router::new().route("/health", get(health::health_handler));
    let health_addr = "0.0.0.0:8084".parse::<std::net::SocketAddr>()?;

    info!("gRPC server listening on {}", grpc_addr);
    info!("health server listening on {}", health_addr);

    // Run both servers concurrently; if either fails the process exits.
    tokio::try_join!(
        // gRPC server
        async {
            GrpcServer::builder()
                .add_service(LeaseServiceServer::new(lease_service))
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
