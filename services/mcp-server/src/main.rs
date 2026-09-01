//! WSLVault MCP Server — Model Context Protocol integration for AI agents.
//!
//! Exposes WSLVault operations as MCP tools that AI agents (e.g. Claude)
//! can invoke to securely read/write secrets, encrypt/decrypt data, etc.
//!
//! ## Transports
//!
//! Two transports are available; select with `VAULT_MCP_TRANSPORT`:
//!
//! | Value  | Behaviour |
//! |--------|-----------|
//! | `http` | (default) Axum HTTP server on `VAULT_LISTEN_ADDR` (default `0.0.0.0:8087`). Exposes both the spec-compliant JSON-RPC endpoint (`POST /v1/mcp`) and the legacy REST endpoints (`GET /v1/mcp/tools`, `POST /v1/mcp/tools/call`, `GET /v1/mcp/info`). |
//! | `stdio`| Reads newline-delimited JSON-RPC from stdin and writes responses to stdout. All log output goes to stderr. Designed for local Claude Desktop / Claude Code integration. |
//!
//! ## Authentication
//!
//! **HTTP transport:** When `VAULT_MCP_AUTH_REQUIRED` is `"true"` (the
//! default), all `/v1/mcp/*` endpoints require an `Authorization: Bearer
//! <token>` header. The token is forwarded to backend services as
//! `X-Vault-Token`, matching the gateway Lua auth middleware. The `/health`
//! endpoint is always unauthenticated.
//!
//! **stdio transport:** Authentication is not enforced at the protocol level.
//! The vault token is read from `VAULT_TOKEN` (or `WSLVAULT_TOKEN` as a
//! fallback) and forwarded as `X-Vault-Token` on every outbound backend
//! request.

mod health;
mod jsonrpc;
mod tools;

use tools::{caller_context_from_headers, CallerContext};

use std::net::SocketAddr;

use axum::{
    body::Bytes,
    extract::{Request, State},
    http::StatusCode,
    middleware::{self, Next},
    response::{IntoResponse, Json, Response},
    routing::{get, post},
    Router,
};
use serde::Serialize;
use tracing::{debug, error, info};
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
    /// Endpoint for the lease-manager HTTP API.
    pub lease_manager_url: String,
    /// Whether Bearer token authentication is required on MCP endpoints.
    /// Only meaningful for the HTTP transport.
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
    request.headers_mut().insert(
        "x-vault-token",
        token.parse().expect("token is valid header value"),
    );

    next.run(request).await
}

// ---------------------------------------------------------------------------
// JSON-RPC HTTP handler
// ---------------------------------------------------------------------------

/// `POST /v1/mcp` — spec-compliant Streamable-HTTP-style JSON-RPC endpoint.
///
/// Accepts a JSON-RPC 2.0 request body and returns the corresponding response
/// object.  Notifications (requests without an `id`) receive an HTTP 204 No
/// Content because no JSON-RPC response is defined for them.
///
/// `X-Policies` and `X-Principal-Id` from the incoming request are extracted
/// and forwarded to backend services via [`CallerContext`] (pass-through from
/// gateway / UI middleware after JWT validation).
async fn jsonrpc_handler(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
    body: Bytes,
) -> Response {
    // Build caller context from gateway-injected headers.
    let ctx = caller_context_from_headers(&headers);

    // Step 1: parse the raw bytes as a JSON-RPC envelope.
    let req = match jsonrpc::parse_request(&body) {
        Ok(r) => r,
        Err(err_resp) => {
            let status = StatusCode::BAD_REQUEST;
            return (status, Json(err_resp)).into_response();
        }
    };

    // Step 2: validate structural constraints (jsonrpc == "2.0").
    if let Some(err_resp) = jsonrpc::validate_request(&req) {
        return (StatusCode::BAD_REQUEST, Json(err_resp)).into_response();
    }

    debug!(method = %req.method, id = ?req.id, "JSON-RPC request received");

    // Step 3: dispatch to the appropriate MCP method handler.
    match jsonrpc::dispatch(req, &state, ctx).await {
        Some(resp) => Json(resp).into_response(),
        // Notifications produce no response — return HTTP 204.
        None => StatusCode::NO_CONTENT.into_response(),
    }
}

// ---------------------------------------------------------------------------
// stdio transport
// ---------------------------------------------------------------------------

/// Run the MCP server in stdio transport mode.
///
/// Reads newline-delimited JSON-RPC messages from stdin and writes the
/// corresponding JSON-RPC responses to stdout — one response per line.  All
/// tracing output goes to stderr so it does not pollute the stdout stream.
///
/// The vault token is sourced from `VAULT_TOKEN` (or `WSLVAULT_TOKEN` as a
/// legacy fallback) and forwarded to backend services as `X-Vault-Token`
/// without any transport-level auth enforcement.
///
/// ## Caller context in stdio mode (dev/local use)
///
/// Because there is no gateway to inject `X-Policies` / `X-Principal-Id`
/// headers in stdio mode, the caller context is sourced from environment
/// variables:
///
/// | Env var                    | Forwarded as      |
/// |----------------------------|-------------------|
/// | `VAULT_MCP_POLICIES`       | `X-Policies`      |
/// | `VAULT_MCP_PRINCIPAL_ID`   | `X-Principal-Id`  |
///
/// In production the HTTP transport behind the gateway is authoritative and
/// these environment variables are not consulted.
async fn run_stdio(state: AppState) -> anyhow::Result<()> {
    use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};

    info!("MCP stdio transport started — reading JSON-RPC from stdin");

    // Build a single CallerContext for all requests in this stdio session from
    // environment variables (dev/local use; see doc comment above).
    let stdio_ctx = CallerContext {
        policies: std::env::var("VAULT_MCP_POLICIES")
            .ok()
            .filter(|s| !s.is_empty()),
        principal_id: std::env::var("VAULT_MCP_PRINCIPAL_ID")
            .ok()
            .filter(|s| !s.is_empty()),
        // stdio transport is a local/dev path with no HTTP request to carry a
        // bearer token. Backends therefore fall back to whatever the headers
        // above allow, which they only honour when explicitly configured to.
        token: std::env::var("VAULT_MCP_TOKEN")
            .ok()
            .filter(|s| !s.is_empty()),
    };

    let stdin = tokio::io::stdin();
    let stdout = tokio::io::stdout();
    let mut reader = BufReader::new(stdin);
    let mut writer = tokio::io::BufWriter::new(stdout);
    let mut line_buf = String::new();

    loop {
        line_buf.clear();
        let bytes_read = reader.read_line(&mut line_buf).await?;

        // EOF — the client closed the connection.
        if bytes_read == 0 {
            info!("stdin closed — mcp-server stdio transport exiting");
            break;
        }

        let trimmed = line_buf.trim();
        if trimmed.is_empty() {
            continue;
        }

        // Parse and dispatch, following the same pipeline as the HTTP handler.
        let req = match jsonrpc::parse_request(trimmed.as_bytes()) {
            Ok(r) => r,
            Err(err_resp) => {
                write_response(&mut writer, &err_resp).await?;
                continue;
            }
        };

        if let Some(err_resp) = jsonrpc::validate_request(&req) {
            write_response(&mut writer, &err_resp).await?;
            continue;
        }

        debug!(method = %req.method, id = ?req.id, "stdio JSON-RPC request");

        if let Some(resp) = jsonrpc::dispatch(req, &state, stdio_ctx.clone()).await {
            write_response(&mut writer, &resp).await?;
        }
        // Notifications produce no output — continue to next line.
    }

    writer.flush().await?;
    Ok(())
}

/// Serialise `resp` as a single JSON line followed by `\n` and flush.
async fn write_response<W, T>(writer: &mut W, resp: &T) -> anyhow::Result<()>
where
    W: tokio::io::AsyncWriteExt + Unpin,
    T: Serialize,
{
    let mut line = serde_json::to_string(resp)?;
    line.push('\n');
    writer.write_all(line.as_bytes()).await?;
    writer.flush().await?;
    Ok(())
}

// ---------------------------------------------------------------------------
// Entry point
// ---------------------------------------------------------------------------

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // In stdio mode, log to stderr only so stdout stays clean for JSON-RPC.
    let transport = std::env::var("VAULT_MCP_TRANSPORT")
        .unwrap_or_else(|_| "http".into())
        .to_lowercase();

    let log_target = if transport == "stdio" {
        // Force stderr output so the JSON-RPC stdout stream is never polluted.
        fmt::layer().json().with_writer(std::io::stderr)
    } else {
        fmt::layer().json().with_writer(std::io::stderr)
    };

    tracing_subscriber::registry()
        .with(log_target)
        .with(EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")))
        .init();

    info!(transport = %transport, "mcp-server starting");

    // Expose Prometheus metrics for scraping (address via VAULT_METRICS_ADDR).
    // Skip in stdio mode — metrics are irrelevant and it binds a TCP port.
    if transport != "stdio" {
        wslvault_core::metrics::server::spawn_from_env();
    }

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
        lease_manager_url: std::env::var("VAULT_LEASE_MANAGER_ADDR")
            .unwrap_or_else(|_| "http://lease-manager:8084".into()),
        auth_required,
    };

    match transport.as_str() {
        "stdio" => {
            // In stdio mode the vault token is read from the environment and
            // forwarded as X-Vault-Token by the existing tool handlers.  No
            // transport-level auth middleware is applied.
            let token = std::env::var("VAULT_TOKEN")
                .or_else(|_| std::env::var("WSLVAULT_TOKEN"))
                .unwrap_or_default();
            if token.is_empty() {
                error!(
                    "VAULT_TOKEN / WSLVAULT_TOKEN not set — backend calls will lack credentials"
                );
            } else {
                info!("stdio transport: vault token loaded from environment");
            }
            run_stdio(state).await?;
        }

        _ => {
            // Default: HTTP transport.
            if transport != "http" {
                error!(
                    transport = %transport,
                    "unrecognised VAULT_MCP_TRANSPORT value; falling back to http"
                );
            }

            let listen_addr: SocketAddr = std::env::var("VAULT_LISTEN_ADDR")
                .unwrap_or_else(|_| "0.0.0.0:8087".into())
                .parse()?;

            // MCP routes are protected by the bearer auth middleware.
            // /health is deliberately outside that layer so it stays unauthenticated.
            let mcp_routes = Router::new()
                // Spec-compliant JSON-RPC endpoint (MCP 2024-11-05 §3 Streamable HTTP)
                .route("/v1/mcp", post(jsonrpc_handler))
                // Legacy REST endpoints — preserved for backward compatibility.
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

            info!(%auth_required, addr = %listen_addr, "MCP HTTP server listening");

            let listener = tokio::net::TcpListener::bind(listen_addr).await?;
            axum::serve(listener, app).await?;
        }
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// Legacy REST info handler
// ---------------------------------------------------------------------------

/// MCP server info response (legacy REST endpoint).
#[derive(Serialize)]
struct ServerInfo {
    name: String,
    version: String,
    /// MCP spec revision implemented by this server.
    protocol_version: String,
    capabilities: Vec<String>,
}

/// `GET /v1/mcp/info` — legacy server info endpoint.
///
/// New clients should use the JSON-RPC `initialize` method instead.
async fn server_info() -> Json<ServerInfo> {
    Json(ServerInfo {
        name: "wslvault-mcp-server".into(),
        version: env!("CARGO_PKG_VERSION").into(),
        // Consistent with the protocolVersion returned by `initialize`.
        protocol_version: "2024-11-05".into(),
        capabilities: vec!["tools".into()],
    })
}
