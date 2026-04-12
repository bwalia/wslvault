//! WSLVault policy-engine binary.
//!
//! Starts a tonic gRPC server that implements the `PolicyService` proto
//! alongside a lightweight Axum HTTP server for health probes.
//!
//! # Configuration (environment variables)
//!
//! | Variable                 | Default           | Description                                         |
//! |--------------------------|-------------------|-----------------------------------------------------|
//! | `VAULT_LISTEN_ADDR`      | `0.0.0.0:50053`   | gRPC listener address                               |
//! | `VAULT_HEALTH_ADDR`      | `0.0.0.0:8083`    | HTTP health listener address                        |
//! | `VAULT_COMPILE_INTERVAL` | `5`               | Seconds between policy recompilations               |
//! | `DATABASE_URL`           | *(unset)*         | PostgreSQL connection URL; enables the PG backend   |
//! | `RUST_LOG`               | `info`            | `tracing-subscriber` filter directive               |

use std::sync::Arc;
use std::time::Duration;

use tokio::sync::RwLock;
use tonic::transport::Server;
use tracing::{debug, error, info, warn};
use tracing_subscriber::EnvFilter;
use wslvault_cluster::config::ClusterConfig;
use wslvault_cluster::leader::LeaderElector;

mod evaluator;
mod grpc;
mod health;
mod http;
mod model;
mod pg_store;
mod store;

/// Generated protobuf types and tonic service traits.
pub mod proto {
    tonic::include_proto!("wslvault.policy.v1");
}

use evaluator::CompiledPolicies;
use grpc::PolicyServiceImpl;
use pg_store::PgPolicyBackend;
use proto::policy_service_server::PolicyServiceServer;
use store::{PolicyStore, PolicyStoreBackend};
use wslvault_core::config::DatabaseConfig;
use wslvault_storage::pool::DbPool;

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

/// Periodically rebuilds the `CompiledPolicies` snapshot from the policy store.
///
/// The evaluation path reads from the snapshot under a read lock; this task
/// holds a write lock only during the brief swap at the end of each iteration,
/// so it does not block concurrent authorization calls for long.
///
/// When a `LeaderElector` is provided, only the leader node performs the
/// compilation to avoid redundant database reads across replicas. Follower
/// nodes still serve stale snapshots (safe because policy changes are
/// eventually consistent by design).
///
/// Accepts any `Arc<dyn PolicyStoreBackend>` so that both the in-memory store
/// and the Postgres backend can be used without changing this function.
async fn run_compilation_task(
    store: Arc<dyn PolicyStoreBackend>,
    compiled: Arc<RwLock<CompiledPolicies>>,
    interval: Duration,
    elector: Option<Arc<LeaderElector>>,
) {
    let mut ticker = tokio::time::interval(interval);
    // Skip the first tick so we don't wait a full interval before the first
    // compilation — the initial snapshot is populated synchronously in main.
    ticker.tick().await;

    loop {
        ticker.tick().await;

        // When leader election is active, only the leader compiles policies.
        if let Some(ref elector) = elector {
            if !elector.is_leader() {
                debug!("policy compilation skipped: not the leader");
                continue;
            }
        }

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
    //
    // If DATABASE_URL is set, connect to PostgreSQL and use PgPolicyBackend.
    // Otherwise fall back to the in-memory PolicyStore so the service can run
    // in development and test environments without a database.
    let (store, elector): (Arc<dyn PolicyStoreBackend>, Option<Arc<LeaderElector>>) =
        match std::env::var("DATABASE_URL") {
            Ok(database_url) => {
                info!("DATABASE_URL set — connecting to PostgreSQL");
                let db_config = DatabaseConfig {
                    url: database_url,
                    ..DatabaseConfig::default()
                };
                let pool = DbPool::connect(&db_config).await.map_err(|e| {
                    error!(error = %e, "failed to connect to PostgreSQL");
                    e
                })?;

                // Initialise leader election for the compilation background task.
                let cluster_config = ClusterConfig::default();
                let leader = Arc::new(LeaderElector::new(
                    pool.clone(),
                    &cluster_config,
                    "policy-engine",
                ));
                let _election_handle = leader.run();

                (Arc::new(PgPolicyBackend::new(pool)), Some(leader))
            }
            Err(_) => {
                warn!(
                    "DATABASE_URL not set — using in-memory policy store (data will not persist)"
                );
                (Arc::new(PolicyStore::new()), None)
            }
        };

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
        let store_clone = Arc::clone(&store);
        let compiled_clone = Arc::clone(&compiled);
        let interval = Duration::from_secs(config.compile_interval_secs);
        let elector_clone = elector.clone();
        tokio::spawn(async move {
            run_compilation_task(store_clone, compiled_clone, interval, elector_clone).await;
        });
    }

    // --- Build gRPC service ---
    let grpc_addr = config.grpc_listen_addr.parse()?;
    let policy_service = PolicyServiceImpl::new(Arc::clone(&store), Arc::clone(&compiled));
    let grpc_server = Server::builder()
        .add_service(PolicyServiceServer::new(policy_service))
        .serve_with_shutdown(grpc_addr, shutdown_signal());

    // --- Build HTTP API server (health + REST policy endpoints) ---
    let health_addr: std::net::SocketAddr = config.health_listen_addr.parse()?;
    let health_listener = tokio::net::TcpListener::bind(health_addr).await?;
    let http_state = http::AppState {
        store: Arc::clone(&store),
        compiled: Arc::clone(&compiled),
    };
    let health_app = http::api_router(http_state);
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
