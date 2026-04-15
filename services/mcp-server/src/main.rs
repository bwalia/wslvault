//! WSLVault MCP Server — Model Context Protocol integration for AI agents.
//!
//! Exposes WSLVault operations as MCP tools that AI agents (e.g. Claude)
//! can invoke to securely read/write secrets, encrypt/decrypt data, etc.
//!
//! Supports both HTTP/SSE transport (for remote agents) and stdio transport
//! (for local Claude Desktop integration).
//!
//! ## Authentication
//!
//! When `VAULT_MCP_AUTH_REQUIRED` is "true" (the default), all `/v1/mcp/*`
//! endpoints require an `Authorization: Bearer <token>` header. The token is
//! forwarded to backend services as `X-Vault-Token`, matching the pattern
//! used by the gateway Lua auth middleware. The `/health` endpoint is always
//! unauthenticated.

mod health;
mod tools;

use std::net::SocketAddr;

use axum::{
    extract::{Request, State},
    http::StatusCode,
    middleware::{self, Next},
    response::{IntoResponse, Json, Response},
    routing::{get, post},
    Router,
};
use serde::Serialize;
use tracing::info;
use tracing_subscriber::{fmt, prelude::*, EnvFilter};

/// Shared application state for all MCP tool handlers.
#[derive(Clone)]
pub struct AppState {
    /// Endpoint for the secret-engine HTTP API.
    pub secret_engine_url: String,
    /// Endpoint for the transit-engine HTTP API.
    pub transit_engine_url: String,
    /// Endpoint for the audit-service HTTP API.
    pub audit_engine_url: String,
    /// Whether Bearer token authentication is required on MCP endpoints.
    pub auth_required: bool,
}

/// Error body returned for authentication failures.
#[derive(Serialize)]
struct AuthError {
    error: String,
    message: String,
}

/// Axum middleware that validates the `Authorization: Bearer <token>` header.
///
/// When `state.auth_required` is true the middleware:
/// 1. Rejects requests without an `Authorization` header with HTTP 401.
/// 2. Rejects requests whose header is not in `Bearer <token>` form with HTTP 401.
/// 3. Injects the extracted token as `X-Vault-Token` so downstream handlers can
///    forward it to backend services — identical to the gateway Lua behaviour.
///
/// When `state.auth_required` is false the middleware is a no-op (dev/test mode).
async fn bearer_auth_middleware(
    State(state): State<AppState>,
    mut request: Request,
    next: Next,
) -> Response {
    if !state.auth_required {
        return next.run(request).await;
    }

    let auth_header = request
        .headers()
        .get(axum::http::header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok());

    let token = match auth_header {
        None => {
            return (
                StatusCode::UNAUTHORIZED,
                Json(AuthError {
                    error: "unauthenticated".into(),
                    message: "missing Authorization header".into(),
                }),
            )
                .into_response();
        }
        Some(value) => {
            // Expect exactly "Bearer <token>" — matches gateway regex `^Bearer\s+(.+)$`
            match value.strip_prefix("Bearer ") {
                Some(token) if !token.trim().is_empty() => token.trim().to_owned(),
                _ => {
                    return (
                        StatusCode::UNAUTHORIZED,
                        Json(AuthError {
                            error: "unauthenticated".into(),
                            message:
                                "invalid Authorization header format, expected: Bearer <token>"
                                    .into(),
                        }),
                    )
                        .into_response();
                }
            }
        }
    };

    // Inject the raw token as X-Vault-Token for upstream services to validate,
    // mirroring the gateway Lua auth middleware token-forward path.
    request
        .headers_mut()
        .insert("x-vault-token", token.parse().expect("token is valid header value"));

    next.run(request).await
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::registry()
        .with(fmt::layer().json())
        .with(EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")))
        .init();

    info!("mcp-server starting");

    let listen_addr: SocketAddr = std::env::var("VAULT_LISTEN_ADDR")
        .unwrap_or_else(|_| "0.0.0.0:8087".into())
        .parse()?;

    // Parse auth-required flag; defaults to true for production safety.
    let auth_required = std::env::var("VAULT_MCP_AUTH_REQUIRED")
        .unwrap_or_else(|_| "true".into())
        .to_lowercase()
        != "false";

    let state = AppState {
        secret_engine_url: std::env::var("VAULT_SECRET_ENGINE_ADDR")
            .unwrap_or_else(|_| "http://secret-engine:8081".into()),
        transit_engine_url: std::env::var("VAULT_TRANSIT_ENGINE_ADDR")
            .unwrap_or_else(|_| "http://transit-engine:8086".into()),
        audit_engine_url: std::env::var("VAULT_AUDIT_SERVICE_ADDR")
            .unwrap_or_else(|_| "http://audit-service:8085".into()),
        auth_required,
    };

    // MCP routes are protected by the bearer auth middleware.
    // /health is deliberately placed outside that layer so it stays unauthenticated.
    let mcp_routes = Router::new()
        .route("/v1/mcp/tools", get(tools::list_tools))
        .route("/v1/mcp/tools/call", post(tools::call_tool))
        .route("/v1/mcp/info", get(server_info))
        .route_layer(middleware::from_fn_with_state(
            state.clone(),
            bearer_auth_middleware,
        ));

    let app = Router::new()
        .route("/health", get(health::health_handler))
        .merge(mcp_routes)
        .with_state(state);

    info!(%auth_required, addr = %listen_addr, "MCP server listening");

    let listener = tokio::net::TcpListener::bind(listen_addr).await?;
    axum::serve(listener, app).await?;

    Ok(())
}

/// MCP server info response.
#[derive(Serialize)]
struct ServerInfo {
    name: String,
    version: String,
    protocol_version: String,
    capabilities: Vec<String>,
}

async fn server_info() -> Json<ServerInfo> {
    Json(ServerInfo {
        name: "wslvault-mcp-server".into(),
        version: env!("CARGO_PKG_VERSION").into(),
        protocol_version: "2024-11-05".into(),
        capabilities: vec!["tools".into()],
    })
}
