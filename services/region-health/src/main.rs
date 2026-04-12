//! region-health: multi-region health monitoring and failover service.
//!
//! Responsibilities:
//!   - Poll each region's health endpoint every 10 seconds.
//!   - Update `system.regions` with current status and replication lag.
//!   - Expose `GET /v1/sys/regions` for CLI and dashboard consumption.
//!   - Handle forced failover via `POST /v1/sys/regions/:id/promote`.
//!   - Emit region health metrics for Prometheus.

mod failover;
mod health;
mod poller;
mod store;

use std::sync::Arc;

use axum::extract::{Path, State};
use axum::response::Json;
use axum::routing::{get, post};
use axum::Router;
use tracing::{info, warn};
use tracing_subscriber::EnvFilter;
use wslvault_cluster::config::ClusterConfig;
use wslvault_cluster::leader::LeaderElector;
use wslvault_core::config::DatabaseConfig;
use wslvault_storage::pool::DbPool;

use crate::store::RegionInfo;

/// Shared application state.
#[derive(Clone)]
struct AppState {
    pool: DbPool,
    elector: Arc<LeaderElector>,
    local_region: String,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt()
        .json()
        .with_env_filter(EnvFilter::from_default_env())
        .with_target(true)
        .init();

    info!("starting region-health service");

    let local_region =
        std::env::var("REGION_ID").unwrap_or_else(|_| "default".to_string());

    let database_url = std::env::var("DATABASE_URL")
        .map_err(|_| anyhow::anyhow!("DATABASE_URL is required for region-health"))?;

    let db_config = DatabaseConfig {
        url: database_url,
        ..DatabaseConfig::default()
    };

    let pool = DbPool::connect(&db_config).await?;

    let cluster_config = ClusterConfig {
        region: local_region.clone(),
        ..ClusterConfig::default()
    };
    let elector = Arc::new(LeaderElector::new(
        pool.clone(),
        &cluster_config,
        "region-health",
    ));
    let _election_handle = elector.run();

    // Spawn the background health polling loop (leader-only).
    let poller_pool = pool.clone();
    let poller_elector = Arc::clone(&elector);
    let poller_region = local_region.clone();
    tokio::spawn(async move {
        poller::run_health_poller(poller_pool, poller_elector, &poller_region).await;
    });

    let state = AppState {
        pool,
        elector,
        local_region,
    };

    let listen_addr = std::env::var("REGION_HEALTH_LISTEN_ADDR")
        .unwrap_or_else(|_| "0.0.0.0:8092".to_string());
    let addr: std::net::SocketAddr = listen_addr.parse()?;

    let app = Router::new()
        .route("/health", get(health::health_handler))
        .route("/v1/sys/regions", get(list_regions))
        .route("/v1/sys/regions/:region_id", get(get_region))
        .route("/v1/sys/regions/:region_id/promote", post(promote_region))
        .route("/v1/sys/cluster/status", get(cluster_status))
        .route("/v1/sys/cluster/nodes", get(cluster_nodes))
        .with_state(state);

    info!(addr = %addr, "region-health HTTP server starting");
    let listener = tokio::net::TcpListener::bind(addr).await?;
    axum::serve(listener, app).await?;

    Ok(())
}

async fn list_regions(State(state): State<AppState>) -> Json<Vec<RegionInfo>> {
    let regions = store::list_regions(&state.pool).await.unwrap_or_default();
    Json(regions)
}

async fn get_region(
    State(state): State<AppState>,
    Path(region_id): Path<String>,
) -> Json<Option<RegionInfo>> {
    let region = store::get_region(&state.pool, &region_id).await.ok().flatten();
    Json(region)
}

async fn promote_region(
    State(state): State<AppState>,
    Path(region_id): Path<String>,
) -> Json<serde_json::Value> {
    match failover::trigger_failover(&state.pool, &region_id, &state.local_region).await {
        Ok(()) => Json(serde_json::json!({
            "status": "ok",
            "message": format!("Failover to {} initiated", region_id),
        })),
        Err(e) => Json(serde_json::json!({
            "status": "error",
            "message": e.to_string(),
        })),
    }
}

async fn cluster_status(
    State(state): State<AppState>,
) -> Json<serde_json::Value> {
    let nodes = wslvault_cluster::store::list_nodes(&state.pool, None)
        .await
        .unwrap_or_default();
    Json(serde_json::json!({
        "local_region": state.local_region,
        "nodes": nodes,
    }))
}

async fn cluster_nodes(
    State(state): State<AppState>,
    axum::extract::Query(params): axum::extract::Query<std::collections::HashMap<String, String>>,
) -> Json<serde_json::Value> {
    let service = params.get("service").map(|s| s.as_str());
    let nodes = wslvault_cluster::store::list_nodes(&state.pool, service)
        .await
        .unwrap_or_default();
    Json(serde_json::json!({ "nodes": nodes }))
}
