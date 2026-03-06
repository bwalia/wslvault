//! WSLVault MCP Server — Model Context Protocol integration for AI agents.
//!
//! Exposes WSLVault operations as MCP tools that AI agents (e.g. Claude)
//! can invoke to securely read/write secrets, encrypt/decrypt data, etc.
//!
//! Supports both HTTP/SSE transport (for remote agents) and stdio transport
//! (for local Claude Desktop integration).

mod health;
mod tools;

use std::net::SocketAddr;

use axum::{
    routing::{get, post},
    Json, Router,
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

    let state = AppState {
        secret_engine_url: std::env::var("VAULT_SECRET_ENGINE_ADDR")
            .unwrap_or_else(|_| "http://secret-engine:8081".into()),
        transit_engine_url: std::env::var("VAULT_TRANSIT_ENGINE_ADDR")
            .unwrap_or_else(|_| "http://transit-engine:8086".into()),
    };

    let app = Router::new()
        .route("/health", get(health::health_handler))
        // MCP protocol endpoints
        .route("/v1/mcp/tools", get(tools::list_tools))
        .route("/v1/mcp/tools/call", post(tools::call_tool))
        // MCP server info
        .route("/v1/mcp/info", get(server_info))
        .with_state(state);

    info!(addr = %listen_addr, "MCP server listening");

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
