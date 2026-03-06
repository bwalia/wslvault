//! audit-service entry point.
//!
//! Starts two servers concurrently:
//! - gRPC server on port 50056 (AuditService)
//! - HTTP health server on port 8085 (GET /health)

mod grpc;
mod health;
mod integrity;
mod store;

use axum::{routing::get, Router};
use grpc::proto::audit_service_server::AuditServiceServer;
use grpc::AuditServiceImpl;
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

    info!("starting audit-service");

    // Create the shared in-memory audit store.
    let audit_store = store::new_store();

    // Build the gRPC service.
    let audit_service = AuditServiceImpl::new(audit_store);
    let grpc_addr = "0.0.0.0:50056".parse()?;

    // Build the health HTTP service.
    let health_router = Router::new().route("/health", get(health::health_handler));
    let health_addr = "0.0.0.0:8085".parse::<std::net::SocketAddr>()?;

    info!("gRPC server listening on {}", grpc_addr);
    info!("health server listening on {}", health_addr);

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
