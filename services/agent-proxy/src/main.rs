//! wslvault agent-proxy — credential brokering for AI agents.
//!
//! An agent in a sandbox holds **no upstream credentials**. It holds a
//! short-lived wslvault session token, obtained by exchanging its Kubernetes
//! service-account token at identity-service (`/v1/auth/kubernetes/login`,
//! verified via TokenReview). It sends its API traffic through this proxy,
//! which:
//!
//! 1. verifies the session token (same verifier every wslvault service uses),
//! 2. checks the route's bindings — tenant, policy, principal, method, path,
//! 3. reads the real credential from secret-engine with **its own** identity,
//! 4. strips whatever the agent sent and injects the real credential,
//! 5. streams the exchange and writes an audit event.
//!
//! See `docs/agent-proxy.md` for the deployment model.
//!
//! | Variable | Purpose |
//! |---|---|
//! | `VAULT_LISTEN_ADDR` | default `0.0.0.0:8094` |
//! | `VAULT_AGENT_PROXY_ROUTES` / `_ROUTES_FILE` | route config (see `config.rs`) |
//! | `VAULT_AGENT_PROXY_K8S_ROLE` | proxy's own Kubernetes auth role (recommended) |
//! | `VAULT_AGENT_PROXY_TOKEN` | proxy's own static token (dev) |
//! | `VAULT_AGENT_PROXY_SECRET_TTL_SECS` | credential cache TTL, default 60 |
//! | `VAULT_AGENT_PROXY_ALLOW_HTTP_UPSTREAMS` | dev only: permit http:// upstreams |
//! | `VAULT_JWT_SECRET` / `VAULT_JWKS_URL` | session-token verification |
//! | `VAULT_SECRET_ENGINE_ADDR`, `VAULT_IDENTITY_SERVICE_ADDR`, `VAULT_AUDIT_SERVICE_ADDR` | backends |

mod audit;
mod broker;
mod config;
#[cfg(test)]
mod e2e_tests;
mod proxy;

use std::{net::SocketAddr, sync::Arc, time::Duration};

use axum::{routing::get, Json, Router};
use tracing::info;
use tracing_subscriber::{fmt, prelude::*, EnvFilter};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::registry()
        .with(EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")))
        .with(fmt::layer().json())
        .init();

    let routes = config::Routes::from_env()?;
    info!(routes = ?routes.names().collect::<Vec<_>>(), "loaded agent-proxy routes");

    let allow_http = config::allow_http_upstreams();

    // Never follow redirects with an injected credential attached: a 3xx to
    // another host would hand it the key. Redirects go back to the agent.
    let upstream = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .https_only(!allow_http)
        .connect_timeout(Duration::from_secs(10))
        .pool_idle_timeout(Duration::from_secs(90))
        .build()?;
    let internal = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .timeout(Duration::from_secs(10))
        .build()?;

    let broker = broker::Broker::from_env(internal)?;
    // Authenticate eagerly so a misconfigured role fails readiness, not the first agent.
    match broker.tenant_id().await {
        Ok(t) => info!(tenant_id = %t, "broker identity ready"),
        Err(e) => {
            tracing::warn!(error = %e, "broker identity not ready yet; will retry per request")
        }
    }

    let audit = audit::Audit::new(std::env::var("VAULT_AUDIT_SERVICE_ADDR").ok())?;
    let route_count = routes.len();
    let state = Arc::new(proxy::AppState {
        routes,
        broker,
        upstream,
        audit,
    });

    let app = Router::new()
        .route(
            "/health",
            get(move || async move {
                Json(serde_json::json!({ "status": "ok", "routes": route_count }))
            }),
        )
        .fallback(proxy::handle)
        .with_state(state);

    let addr: SocketAddr = std::env::var("VAULT_LISTEN_ADDR")
        .unwrap_or_else(|_| "0.0.0.0:8094".into())
        .parse()?;
    info!(%addr, "agent-proxy listening");
    let listener = tokio::net::TcpListener::bind(addr).await?;
    axum::serve(listener, app)
        .with_graceful_shutdown(async {
            let _ = tokio::signal::ctrl_c().await;
        })
        .await?;
    Ok(())
}
