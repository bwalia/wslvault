//! replication-agent: cross-region secret synchronisation service.
//!
//! Responsibilities:
//!   - Consume replication events from peer regions via their HTTP replication API.
//!   - Apply remote events to the local database with conflict resolution.
//!   - Serve a replication API endpoint so peer regions can pull events from us.
//!   - Track replication lag and emit Prometheus metrics.
//!
//! Uses leader election (via wslvault-cluster) so only one instance per region
//! actively consumes and applies events — preventing duplicate processing.

mod applier;
mod config;
mod conflict;
mod consumer;
mod health;
mod metrics;
mod producer;

use std::sync::Arc;

use axum::{routing::get, Router};
use tracing::{error, info, warn};
use tracing_subscriber::EnvFilter;
use wslvault_cluster::config::ClusterConfig;
use wslvault_cluster::leader::LeaderElector;
use wslvault_core::config::DatabaseConfig;
use wslvault_storage::pool::DbPool;

use crate::config::ReplicationAgentConfig;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt()
        .json()
        .with_env_filter(EnvFilter::from_default_env())
        .with_target(true)
        .init();

    info!("starting replication-agent");

    let agent_config = ReplicationAgentConfig::from_env();

    // Database connection is required for the replication-agent.
    let database_url = std::env::var("DATABASE_URL")
        .map_err(|_| anyhow::anyhow!("DATABASE_URL is required for replication-agent"))?;

    let db_config = DatabaseConfig {
        url: database_url,
        ..DatabaseConfig::default()
    };

    let pool = DbPool::connect(&db_config).await?;
    info!("database connection pool established");

    // Leader election ensures only one replica per region consumes events.
    let cluster_config = ClusterConfig {
        region: agent_config.local_region.clone(),
        ..ClusterConfig::default()
    };
    let elector = Arc::new(LeaderElector::new(
        pool.clone(),
        &cluster_config,
        "replication-agent",
    ));
    let _election_handle = elector.run();

    // Spawn the background consumer loop.
    let consumer_pool = pool.clone();
    let consumer_config = agent_config.clone();
    let consumer_elector = Arc::clone(&elector);
    tokio::spawn(async move {
        consumer::run_consumer_loop(consumer_pool, consumer_config, consumer_elector).await;
    });

    // Serve the HTTP replication API + health probes + metrics.
    let http_addr = agent_config
        .listen_addr
        .parse::<std::net::SocketAddr>()
        .unwrap_or_else(|_| ([0, 0, 0, 0], 8091).into());

    let app = Router::new()
        .route("/health", get(health::health_handler))
        .route("/ready", get(health::ready_handler))
        .route(
            "/v1/replication/events",
            get(producer::get_events_handler),
        )
        .route(
            "/v1/replication/ack",
            axum::routing::post(producer::ack_handler),
        )
        .route("/metrics", get(metrics::metrics_handler))
        .with_state(pool);

    info!(addr = %http_addr, "replication-agent HTTP server starting");
    let listener = tokio::net::TcpListener::bind(http_addr).await?;
    axum::serve(listener, app).await?;

    Ok(())
}
