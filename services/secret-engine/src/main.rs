//! secret-engine: KV secret storage service for the WSLVault platform.
//!
//! Provides two protocol surfaces:
//! - gRPC on port 50052 (tonic, generated from wslvault.secret.v1 proto)
//! - HTTP REST on port 8081 (axum, Vault-compatible paths)
//!
//! Configuration is loaded via `VaultConfig::load()` which merges:
//! 1. Compiled defaults
//! 2. `config/base.toml`
//! 3. `config/{VAULT_ENV}.toml`
//! 4. `VAULT__*` environment variables (highest precedence)
//!
//! The crypto-service endpoint defaults to `http://crypto-service:50051` and can
//! be overridden with `VAULT__CRYPTO_SERVICE__ENDPOINT`.

mod grpc;
mod health;
mod http;
mod kv_store;
mod path;
mod server;

use std::net::SocketAddr;

use tracing::info;
use tracing_subscriber::{fmt, prelude::*, EnvFilter};
use wslvault_core::config::VaultConfig;

/// Default gRPC listen address when none is provided in the configuration.
const DEFAULT_GRPC_ADDR: &str = "0.0.0.0:50052";

/// Default HTTP REST listen address when none is provided in the configuration.
const DEFAULT_HTTP_ADDR: &str = "0.0.0.0:8081";

/// Default crypto-service gRPC endpoint.
const DEFAULT_CRYPTO_ENDPOINT: &str = "http://crypto-service:50051";

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // ── 1. Load configuration ────────────────────────────────────────────────
    // Fall back to defaults when no config files are present (e.g. in CI).
    let config = VaultConfig::load().unwrap_or_else(|err| {
        eprintln!(
            "warning: could not load config ({}); using compiled defaults",
            err
        );
        VaultConfig::default()
    });

    // ── 2. Initialise structured tracing ────────────────────────────────────
    // Respects the RUST_LOG environment variable; falls back to the config value.
    let log_level = std::env::var("RUST_LOG")
        .unwrap_or_else(|_| config.observability.log_level.clone());

    tracing_subscriber::registry()
        .with(fmt::layer().json())
        .with(EnvFilter::new(log_level))
        .init();

    info!(
        service = %config.service_name,
        environment = %config.environment,
        "secret-engine starting"
    );

    // ── 3. Resolve listen addresses ─────────────────────────────────────────
    // The gRPC address is derived from the shared `listen_addr` in VaultConfig,
    // replacing the port with 50052 to avoid colliding with the HTTP port.
    let grpc_addr: SocketAddr = std::env::var("GRPC_ADDR")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or_else(|| {
            DEFAULT_GRPC_ADDR
                .parse()
                .expect("DEFAULT_GRPC_ADDR is a valid socket address")
        });

    // The HTTP REST address uses port 8081 by default.
    let http_addr: SocketAddr = std::env::var("HTTP_ADDR")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or_else(|| {
            DEFAULT_HTTP_ADDR
                .parse()
                .expect("DEFAULT_HTTP_ADDR is a valid socket address")
        });

    // ── 4. Resolve crypto-service endpoint ──────────────────────────────────
    // Precedence: CRYPTO_SERVICE_ENDPOINT env var > VaultConfig > compiled default.
    let crypto_endpoint = std::env::var("CRYPTO_SERVICE_ENDPOINT")
        .unwrap_or_else(|_| {
            let ep = config.crypto_service.endpoint.clone();
            if ep.is_empty() {
                DEFAULT_CRYPTO_ENDPOINT.to_string()
            } else {
                ep
            }
        });

    info!(
        grpc_addr = %grpc_addr,
        http_addr = %http_addr,
        crypto_endpoint = %crypto_endpoint,
        "resolved service configuration"
    );

    // ── 5. Start servers ─────────────────────────────────────────────────────
    server::run(grpc_addr, http_addr, crypto_endpoint).await?;

    Ok(())
}
