//! region-health: multi-region health monitoring and failover service.
//!
//! Responsibilities:
//!   - Poll each region's health endpoint every 10 seconds.
//!   - Update `system.regions` with current status and replication lag.
//!   - Expose `GET /v1/sys/regions` for CLI and dashboard consumption.
//!   - Handle forced failover via `POST /v1/sys/regions/:id/promote`.
//!   - Emit region health metrics for Prometheus.
//!
//! Startup ordering matters for Kubernetes: the HTTP server binds and starts
//! serving `/health` (liveness) *immediately*, independent of the database.
//! Connecting to Postgres, leader election, and the poller all run in a
//! background task that retries with backoff. This keeps the liveness port open
//! (so the pod does not crash-loop) even when the database is briefly
//! unreachable; readiness (`/ready`) reflects actual DB connectivity separately.

mod failover;
mod health;
mod poller;
mod store;

use std::sync::Arc;
use std::time::Duration;

use axum::extract::{Path, State};
use axum::http::{Request, StatusCode};
use axum::middleware::Next;
use axum::response::{IntoResponse, Json, Response};
use axum::routing::{get, post};
use axum::Router;
use tokio::sync::OnceCell;
use tracing::{error, info, warn};
use tracing_subscriber::EnvFilter;
use wslvault_cluster::config::ClusterConfig;
use wslvault_cluster::leader::LeaderElector;
use wslvault_core::config::DatabaseConfig;
use wslvault_storage::pool::DbPool;

use crate::store::RegionInfo;

/// Shared application state.
///
/// `pool` is populated asynchronously by the background initializer once the
/// database connection succeeds; until then, data-plane handlers return 503.
#[derive(Clone)]
struct AppState {
    pool: Arc<OnceCell<DbPool>>,
    local_region: String,
}

impl AppState {
    /// The DB pool once the background initializer has connected it, or 503.
    fn pool(&self) -> Result<&DbPool, StatusCode> {
        self.pool.get().ok_or(StatusCode::SERVICE_UNAVAILABLE)
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt()
        .json()
        // Default to `info` when RUST_LOG is unset so startup and errors are
        // visible (previously `from_default_env()` silenced all output when no
        // RUST_LOG was set, which hid crash-loop causes entirely).
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .with_target(true)
        .init();

    info!("starting region-health service");

    // Expose Prometheus metrics for scraping (address via VAULT_METRICS_ADDR).
    wslvault_core::metrics::server::spawn_from_env();

    let local_region = std::env::var("REGION_ID").unwrap_or_else(|_| "default".to_string());

    // Shared, lazily-populated DB pool. The HTTP server (below) binds and serves
    // /health right away; the background task connects the database (with retry),
    // publishes the pool here, then starts leader election and the poller.
    let state = AppState {
        pool: Arc::new(OnceCell::new()),
        local_region: local_region.clone(),
    };

    spawn_background_init(state.pool.clone(), local_region);

    let listen_addr =
        std::env::var("REGION_HEALTH_LISTEN_ADDR").unwrap_or_else(|_| "0.0.0.0:8092".to_string());
    let addr: std::net::SocketAddr = listen_addr.parse()?;

    // Everything under /v1/sys is operator surface: the region topology, the
    // node inventory, and a promote that forces a failover. None of it was
    // gated on anything at all — any caller that could open a socket to this
    // service could read the estate's layout and trigger a region promotion.
    // The health and readiness probes stay open for orchestrators.
    let operator_routes = Router::new()
        .route("/v1/sys/regions", get(list_regions))
        .route("/v1/sys/regions/:region_id", get(get_region))
        .route("/v1/sys/regions/:region_id/promote", post(promote_region))
        .route("/v1/sys/cluster/status", get(cluster_status))
        .route("/v1/sys/cluster/nodes", get(cluster_nodes))
        .with_state(state.clone())
        .layer(axum::middleware::from_fn(require_platform_admin));

    let app = Router::new()
        .route("/health", get(health::health_handler))
        .route("/ready", get(readiness_handler))
        .with_state(state)
        .merge(operator_routes);

    info!(addr = %addr, "region-health HTTP server starting");
    let listener = tokio::net::TcpListener::bind(addr).await?;
    axum::serve(listener, app).await?;

    Ok(())
}

/// Connect the database (with retry/backoff), publish the pool, then run leader
/// election and the poller. Runs for the process lifetime so the liveness port
/// is never blocked on the database.
fn spawn_background_init(pool_cell: Arc<OnceCell<DbPool>>, local_region: String) {
    tokio::spawn(async move {
        let database_url = match std::env::var("DATABASE_URL") {
            Ok(url) => url,
            Err(_) => {
                error!(
                    "DATABASE_URL is not set; region API and readiness stay unavailable, but the \
                     liveness server remains up"
                );
                return;
            }
        };

        let db_config = DatabaseConfig {
            url: database_url,
            ..DatabaseConfig::default()
        };

        // Retry with exponential backoff so a briefly-unreachable database does
        // not take down the health server.
        let mut backoff = Duration::from_secs(1);
        let pool = loop {
            match DbPool::connect(&db_config).await {
                Ok(pool) => break pool,
                Err(e) => {
                    warn!(
                        error = %e,
                        retry_in_secs = backoff.as_secs(),
                        "region-health: database connect failed, retrying"
                    );
                    tokio::time::sleep(backoff).await;
                    backoff = (backoff * 2).min(Duration::from_secs(30));
                }
            }
        };
        info!("region-health: database connected");

        // Publish the pool so data-plane handlers and readiness can use it.
        if pool_cell.set(pool.clone()).is_err() {
            warn!("region-health: db pool was already initialized");
        }

        // Leader election runs in its own detached task; the poller runs here so
        // this task (and the elector it owns) live for the process lifetime.
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

        poller::run_health_poller(pool, elector, &local_region).await;
    });
}

/// Readiness: 200 only once the database pool is connected *and* reachable.
async fn readiness_handler(State(state): State<AppState>) -> StatusCode {
    match state.pool.get() {
        Some(pool) => match pool.health_check().await {
            Ok(()) => StatusCode::OK,
            Err(_) => StatusCode::SERVICE_UNAVAILABLE,
        },
        None => StatusCode::SERVICE_UNAVAILABLE,
    }
}

/// Reject anyone who is not a platform administrator.
///
/// Region topology is not tenant data — there is no per-tenant view of it to
/// serve — so the gate is the platform-admin policy rather than a policy-engine
/// lookup on some synthesised resource path. `wslvault_core::auth` owns the
/// name so this and identity-service cannot drift apart.
///
/// 403 rather than 401 for a valid token without the policy: the console reads
/// 401 as "session dead" and signs the user out, so answering 401 here would
/// eject any tenant member whose browser happened to prefetch this page.
async fn require_platform_admin(req: Request<axum::body::Body>, next: Next) -> Response {
    let identity = match wslvault_core::auth::resolve_identity(req.headers()).await {
        Ok(i) => i,
        Err(e) => {
            return (
                StatusCode::UNAUTHORIZED,
                Json(serde_json::json!({ "error": e.to_string() })),
            )
                .into_response()
        }
    };

    if !wslvault_core::auth::is_platform_admin(&identity) {
        warn!(
            principal_id = %identity.principal_id,
            "rejected a non-administrator on an operator endpoint"
        );
        return (
            StatusCode::FORBIDDEN,
            Json(serde_json::json!({
                "error": format!(
                    "platform administration required: this endpoint needs the '{}' policy",
                    wslvault_core::auth::admin_policy_name()
                ),
            })),
        )
            .into_response();
    }

    next.run(req).await
}

async fn list_regions(State(state): State<AppState>) -> Result<Json<Vec<RegionInfo>>, StatusCode> {
    let pool = state.pool()?;
    let regions = store::list_regions(pool).await.unwrap_or_default();
    Ok(Json(regions))
}

async fn get_region(
    State(state): State<AppState>,
    Path(region_id): Path<String>,
) -> Result<Json<Option<RegionInfo>>, StatusCode> {
    let pool = state.pool()?;
    let region = store::get_region(pool, &region_id).await.ok().flatten();
    Ok(Json(region))
}

async fn promote_region(
    State(state): State<AppState>,
    Path(region_id): Path<String>,
) -> Result<Json<serde_json::Value>, StatusCode> {
    let pool = state.pool()?;
    let body = match failover::trigger_failover(pool, &region_id, &state.local_region).await {
        Ok(()) => serde_json::json!({
            "status": "ok",
            "message": format!("Failover to {} initiated", region_id),
        }),
        Err(e) => serde_json::json!({
            "status": "error",
            "message": e.to_string(),
        }),
    };
    Ok(Json(body))
}

async fn cluster_status(
    State(state): State<AppState>,
) -> Result<Json<serde_json::Value>, StatusCode> {
    let pool = state.pool()?;
    let nodes = wslvault_cluster::store::list_nodes(pool, None)
        .await
        .unwrap_or_default();
    Ok(Json(serde_json::json!({
        "local_region": state.local_region,
        "nodes": nodes,
    })))
}

async fn cluster_nodes(
    State(state): State<AppState>,
    axum::extract::Query(params): axum::extract::Query<std::collections::HashMap<String, String>>,
) -> Result<Json<serde_json::Value>, StatusCode> {
    let pool = state.pool()?;
    let service = params.get("service").map(|s| s.as_str());
    let nodes = wslvault_cluster::store::list_nodes(pool, service)
        .await
        .unwrap_or_default();
    Ok(Json(serde_json::json!({ "nodes": nodes })))
}
