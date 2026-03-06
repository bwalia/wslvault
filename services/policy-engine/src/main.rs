//! WSLVault policy-engine binary.
//!
//! Starts a tonic gRPC server that implements the `PolicyService` proto
//! alongside a lightweight Axum HTTP server for health probes.
//!
//! # Configuration (environment variables)
//!
//! | Variable                 | Default           | Description                            |
//! |--------------------------|-------------------|----------------------------------------|
//! | `VAULT_LISTEN_ADDR`      | `0.0.0.0:50053`   | gRPC listener address                  |
//! | `VAULT_HEALTH_ADDR`      | `0.0.0.0:8083`    | HTTP health listener address           |
//! | `VAULT_COMPILE_INTERVAL` | `5`               | Seconds between policy recompilations  |
//! | `RUST_LOG`               | `info`            | `tracing-subscriber` filter directive  |

use std::sync::Arc;
use std::time::Duration;

use tokio::sync::RwLock;
use tonic::transport::Server;
use tracing::{error, info};
use tracing_subscriber::EnvFilter;

mod evaluator;
mod grpc;
mod health;
mod model;
mod store;

/// Generated protobuf types and tonic service traits.
pub mod proto {
    tonic::include_proto!("wslvault.policy.v1");
}

use evaluator::CompiledPolicies;
use grpc::PolicyServiceImpl;
use proto::policy_service_server::PolicyServiceServer;
use store::PolicyStore;

// ---------------------------------------------------------------------------
// Configuration
// ---------------------------------------------------------------------------

/// Runtime configuration, loaded from environment variables with defaults.
#[derive(Debug)]
struct Config {
    /// Address on which the gRPC server listens.
    grpc_listen_addr: String,
    /// Address on which the HTTP health server listens.
    health_listen_addr: String,
    /// How often (in seconds) the background compilation task rebuilds the
    /// evaluated policy snapshot.
    compile_interval_secs: u64,
}

impl Config {
    fn from_env() -> Self {
        Self {
            grpc_listen_addr: std::env::var("VAULT_LISTEN_ADDR")
                .unwrap_or_else(|_| "0.0.0.0:50053".to_string()),
            health_listen_addr: std::env::var("VAULT_HEALTH_ADDR")
                .unwrap_or_else(|_| "0.0.0.0:8083".to_string()),
            compile_interval_secs: std::env::var("VAULT_COMPILE_INTERVAL")
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(5),
        }
    }
}

// ---------------------------------------------------------------------------
// Background policy compilation task
// ---------------------------------------------------------------------------

/// Periodically rebuilds the `CompiledPolicies` snapshot from the `PolicyStore`.
///
/// The evaluation path reads from the snapshot under a read lock; this task
/// holds a write lock only during the brief swap at the end of each iteration,
/// so it does not block concurrent authorization calls for long.
async fn run_compilation_task(
    store: PolicyStore,
    compiled: Arc<RwLock<CompiledPolicies>>,
    interval: Duration,
) {
    let mut ticker = tokio::time::interval(interval);
    // Skip the first tick so we don't wait a full interval before the first
    // compilation — the initial snapshot is populated synchronously in main.
    ticker.tick().await;

    loop {
        ticker.tick().await;

        let all_docs = store.get_all().await;
        let mut new_snapshot = CompiledPolicies::new();

        for (_tenant_id, doc) in all_docs {
            new_snapshot.upsert(doc.name.clone(), doc.rules);
        }

        {
            let mut guard = compiled.write().await;
            *guard = new_snapshot;
        }

        info!("policy compilation snapshot refreshed");
    }
}

// ---------------------------------------------------------------------------
// Entry point
// ---------------------------------------------------------------------------

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // --- Initialise structured JSON logging ---
    tracing_subscriber::fmt()
        .json()
        .with_env_filter(EnvFilter::from_default_env())
        .with_target(true)
        .with_thread_ids(true)
        .init();

    let config = Config::from_env();
    info!(
        grpc_addr  = %config.grpc_listen_addr,
        health_addr = %config.health_listen_addr,
        compile_interval_secs = config.compile_interval_secs,
        "policy-engine starting"
    );

    // --- Build shared state ---
    let store = PolicyStore::new();
    let compiled = Arc::new(RwLock::new(CompiledPolicies::new()));

    // Perform an initial synchronous compilation so the first request is not
    // served against an empty snapshot.
    {
        let all_docs = store.get_all().await;
        let mut snapshot = compiled.write().await;
        for (_tenant_id, doc) in all_docs {
            snapshot.upsert(doc.name.clone(), doc.rules);
        }
    }

    // --- Spawn background compilation task ---
    {
        let store_clone = store.clone();
        let compiled_clone = Arc::clone(&compiled);
        let interval = Duration::from_secs(config.compile_interval_secs);
        tokio::spawn(async move {
            run_compilation_task(store_clone, compiled_clone, interval).await;
        });
    }

    // --- Build gRPC service ---
    let grpc_addr = config.grpc_listen_addr.parse()?;
    let policy_service = PolicyServiceImpl::new(store.clone(), Arc::clone(&compiled));
    let grpc_server = Server::builder()
        .add_service(PolicyServiceServer::new(policy_service))
        .serve_with_shutdown(grpc_addr, shutdown_signal());

    // --- Build HTTP health server ---
    let health_addr: std::net::SocketAddr = config.health_listen_addr.parse()?;
    let health_listener = tokio::net::TcpListener::bind(health_addr).await?;
    let health_app = health::health_router();
    let health_server =
        axum::serve(health_listener, health_app).with_graceful_shutdown(shutdown_signal());

    info!(
        grpc_addr  = %grpc_addr,
        health_addr = %health_addr,
        "policy-engine ready"
    );

    // --- Run both servers concurrently; stop on first error or signal ---
    tokio::select! {
        result = grpc_server => {
            if let Err(e) = result {
                error!(error = %e, "gRPC server exited with error");
            }
        }
        result = health_server => {
            if let Err(e) = result {
                error!(error = %e, "health server exited with error");
            }
        }
    }

    info!("policy-engine shut down gracefully");
    Ok(())
}

/// Returns a future that resolves when SIGTERM or CTRL-C is received.
async fn shutdown_signal() {
    let ctrl_c = async {
        tokio::signal::ctrl_c()
            .await
            .expect("failed to install CTRL-C handler");
    };

    #[cfg(unix)]
    let terminate = async {
        tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
            .expect("failed to install SIGTERM handler")
            .recv()
            .await;
    };

    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        _ = ctrl_c    => info!("received CTRL-C, shutting down"),
        _ = terminate => info!("received SIGTERM, shutting down"),
    }
}
