//! lease-manager service entry point.
//!
//! Starts two servers concurrently:
//! - gRPC server on port 50055 (LeaseService)
//! - HTTP health server on port 8084 (GET /health)
//!
//! Background Tokio tasks:
//! - Expiration sweep (every 5 s): transitions stale leases to Expired.
//! - Rotation sweep (default every 60 s): fires webhooks or performs automated
//!   rotation for ROTATION_REQUIRED secrets whose `next_rotation_at` has passed.
//! - Deprecated version cleanup (default every 3600 s): calls
//!   `shared.vault_revoke_deprecated_versions()` to zero out ciphertext of
//!   old versions after their grace period expires.
//!
//! When `DATABASE_URL` is set the service uses the PostgreSQL-backed store;
//! otherwise it falls back to the in-memory store so the service can start
//! in development without a database.

mod expiration;
mod grpc;
mod health;
mod pg_store;
mod rotation;
mod rotation_metrics;
mod store;

use std::sync::Arc;

use axum::{routing::get, Router};
use grpc::proto::lease_service_server::LeaseServiceServer;
use grpc::LeaseServiceImpl;
use tonic::transport::Server as GrpcServer;
use tracing::info;
use tracing_subscriber::{fmt, prelude::*, EnvFilter};
use wslvault_cluster::config::ClusterConfig;
use wslvault_cluster::leader::LeaderElector;

use store::LeaseStoreBackend;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Initialise structured tracing; RUST_LOG controls the filter level.
    tracing_subscriber::registry()
        .with(EnvFilter::from_default_env())
        .with(fmt::layer())
        .init();

    info!("starting lease-manager service");

    // Expose Prometheus metrics for scraping (address via VAULT_METRICS_ADDR).
    wslvault_core::metrics::server::spawn_from_env();

    // Pre-register rotation metrics so the /metrics endpoint shows them even
    // before the first sweep cycle runs.
    rotation_metrics::init();

    // Select the storage backend based on whether DATABASE_URL is configured.
    // When a database is available, also initialise the leader elector so that
    // coordination tasks (expiration sweeps) run on exactly one node.
    //
    // We also retain the raw `PgPool` so that the rotation tasks — which need
    // direct SQL access — can share the same pool without an additional connect.
    let (lease_store, elector, pg_pool): (
        Arc<dyn LeaseStoreBackend>,
        Option<Arc<LeaderElector>>,
        Option<sqlx::PgPool>,
    ) = if let Ok(database_url) = std::env::var("DATABASE_URL") {
        info!("DATABASE_URL found – connecting to PostgreSQL");

        let config = wslvault_core::config::DatabaseConfig {
            url: database_url,
            ..Default::default()
        };

        let pool = wslvault_storage::pool::DbPool::connect(&config).await?;
        info!("PostgreSQL connection pool established; using PgLeaseBackend");

        // Initialise leader election for coordination tasks.
        let cluster_config = ClusterConfig::default();
        let leader = Arc::new(LeaderElector::new(
            pool.clone(),
            &cluster_config,
            "lease-manager",
        ));
        let _election_handle = leader.run();

        // Clone the inner PgPool before moving `pool` into PgLeaseBackend.
        let inner_pool = pool.inner().clone();

        (
            Arc::new(pg_store::PgLeaseBackend::new(pool)),
            Some(leader),
            Some(inner_pool),
        )
    } else {
        info!("DATABASE_URL not set – using in-memory lease store");
        (Arc::new(store::InMemoryLeaseStore::new()), None, None)
    };

    // Spawn background expiration sweep (works with any backend).
    // When an elector is available, only the leader node runs the sweep.
    let _expiration_handle =
        expiration::spawn_expiration_task(Arc::clone(&lease_store), elector.clone());

    // Spawn rotation sweep and deprecated-version cleanup tasks.
    // These require a PostgreSQL pool, so they are only started when DATABASE_URL
    // is configured (signalled by `pg_pool` being Some).
    if let Some(pool) = pg_pool {
        let rotation_config = rotation::RotationConfig::from_env();
        let (_rotation_sweep_handle, _version_cleanup_handle) =
            rotation::spawn_rotation_tasks(pool, elector, rotation_config);
    }

    // Build the gRPC service.
    let lease_service = LeaseServiceImpl::new(Arc::clone(&lease_store));
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
