//! sync-scheduler: scheduled and event-driven sync with external secret managers.
//!
//! Responsibilities:
//!   - Load sync job definitions from `system.sync_jobs`.
//!   - Run scheduled jobs at cron intervals.
//!   - Execute sync using the appropriate wslvault-connectors connector.
//!   - Record results and track consecutive failures.
//!   - Expose health and status endpoints.
//!
//! Uses leader election so only one replica runs jobs at a time.

mod runner;
mod scheduler;
mod store;

use std::sync::Arc;

use axum::extract::State;
use axum::response::Json;
use axum::routing::get;
use axum::Router;
use tracing::{info, warn};
use tracing_subscriber::EnvFilter;
use wslvault_cluster::config::ClusterConfig;
use wslvault_cluster::leader::LeaderElector;
use wslvault_core::config::DatabaseConfig;
use wslvault_storage::pool::DbPool;

#[derive(Clone)]
struct AppState {
    pool: DbPool,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt()
        .json()
        .with_env_filter(EnvFilter::from_default_env())
        .with_target(true)
        .init();

    info!("starting sync-scheduler");

    let database_url = std::env::var("DATABASE_URL")
        .map_err(|_| anyhow::anyhow!("DATABASE_URL is required for sync-scheduler"))?;

    let db_config = DatabaseConfig {
        url: database_url,
        ..DatabaseConfig::default()
    };

    let pool = DbPool::connect(&db_config).await?;

    let cluster_config = ClusterConfig {
        region: std::env::var("REGION_ID").unwrap_or_else(|_| "default".to_string()),
        ..ClusterConfig::default()
    };
    let elector = Arc::new(LeaderElector::new(
        pool.clone(),
        &cluster_config,
        "sync-scheduler",
    ));
    let _election_handle = elector.run();

    // Spawn the scheduler loop.
    let scheduler_pool = pool.clone();
    let scheduler_elector = Arc::clone(&elector);
    tokio::spawn(async move {
        scheduler::run_scheduler_loop(scheduler_pool, scheduler_elector).await;
    });

    let state = AppState { pool };

    let listen_addr = std::env::var("SYNC_SCHEDULER_LISTEN_ADDR")
        .unwrap_or_else(|_| "0.0.0.0:8093".to_string());
    let addr: std::net::SocketAddr = listen_addr.parse()?;

    let app = Router::new()
        .route("/health", get(health))
        .route("/v1/sys/sync/status", get(sync_status))
        .route("/v1/sys/integrations", get(list_integrations))
        .with_state(state);

    info!(addr = %addr, "sync-scheduler HTTP server starting");
    let listener = tokio::net::TcpListener::bind(addr).await?;
    axum::serve(listener, app).await?;

    Ok(())
}

async fn health() -> axum::http::StatusCode {
    axum::http::StatusCode::OK
}

async fn sync_status(State(state): State<AppState>) -> Json<Vec<store::SyncJob>> {
    let jobs = store::list_sync_jobs(&state.pool).await.unwrap_or_default();
    Json(jobs)
}

async fn list_integrations(State(state): State<AppState>) -> Json<Vec<store::SyncJob>> {
    let jobs = store::list_sync_jobs(&state.pool).await.unwrap_or_default();
    Json(jobs)
}
