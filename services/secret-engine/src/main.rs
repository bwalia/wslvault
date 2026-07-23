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
//!
//! The audit-service endpoint defaults to `http://audit-service:50056` and can
//! be overridden with `AUDIT_SERVICE_ENDPOINT`.
//!
//! The policy-engine endpoint defaults to `http://policy-engine:50053` and can
//! be overridden with `POLICY_ENGINE_ENDPOINT`.  Every operation is checked
//! against the policy-engine before proceeding (fail-closed).
//!
//! The lease-manager endpoint defaults to `http://lease-manager:50055` and can
//! be overridden with `LEASE_MANAGER_ENDPOINT`.  Lease creation is optional —
//! if the lease-manager is unavailable, operations succeed in degraded mode.

mod audit_client;
mod grpc;
mod ha_status;
mod health;
mod http;
mod kv2;
mod kv_store;
mod lease_client;
mod path;
mod pg_store;
mod policy_client;
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

/// Default audit-service gRPC endpoint.
const DEFAULT_AUDIT_ENDPOINT: &str = "http://audit-service:50056";

/// Default policy-engine gRPC endpoint.
const DEFAULT_POLICY_ENDPOINT: &str = "http://policy-engine:50053";

/// Default lease-manager gRPC endpoint.
const DEFAULT_LEASE_ENDPOINT: &str = "http://lease-manager:50055";

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
    let log_level =
        std::env::var("RUST_LOG").unwrap_or_else(|_| config.observability.log_level.clone());

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
    let crypto_endpoint = std::env::var("CRYPTO_SERVICE_ENDPOINT").unwrap_or_else(|_| {
        let ep = config.crypto_service.endpoint.clone();
        if ep.is_empty() {
            DEFAULT_CRYPTO_ENDPOINT.to_string()
        } else {
            ep
        }
    });

    // ── 5. Resolve audit-service endpoint ───────────────────────────────────
    // Precedence: AUDIT_SERVICE_ENDPOINT env var > compiled default.
    let audit_endpoint = std::env::var("AUDIT_SERVICE_ENDPOINT")
        .unwrap_or_else(|_| DEFAULT_AUDIT_ENDPOINT.to_string());

    // ── 6. Resolve policy-engine endpoint ───────────────────────────────────
    // Precedence: POLICY_ENGINE_ENDPOINT env var > compiled default.
    let policy_endpoint = std::env::var("POLICY_ENGINE_ENDPOINT")
        .unwrap_or_else(|_| DEFAULT_POLICY_ENDPOINT.to_string());

    // ── 7. Resolve lease-manager endpoint ───────────────────────────────────
    // Precedence: LEASE_MANAGER_ENDPOINT env var > compiled default.
    // Lease creation is optional — the secret-engine operates in degraded mode
    // when this endpoint is unreachable.
    let lease_endpoint = std::env::var("LEASE_MANAGER_ENDPOINT")
        .unwrap_or_else(|_| DEFAULT_LEASE_ENDPOINT.to_string());

    info!(
        grpc_addr = %grpc_addr,
        http_addr = %http_addr,
        crypto_endpoint = %crypto_endpoint,
        audit_endpoint = %audit_endpoint,
        policy_endpoint = %policy_endpoint,
        lease_endpoint = %lease_endpoint,
        "resolved service configuration"
    );

    // ── 8. Start metrics server ──────────────────────────────
    let metrics_addr = config.observability.metrics_addr;
    tokio::spawn(wslvault_core::metrics::server::run_metrics_server(
        metrics_addr,
    ));

    // ── 9. Start HA heartbeat if enabled ─────────────────────
    if config.ha.enabled {
        let cluster_state = wslvault_core::ha::cluster::new_cluster_state(config.ha.clone());
        tokio::spawn(wslvault_core::ha::cluster::run_heartbeat_loop(
            cluster_state,
        ));
        info!("HA mode enabled, heartbeat loop started");
    }

    // ── 10. Start servers ────────────────────────────────────
    server::run(
        grpc_addr,
        http_addr,
        crypto_endpoint,
        audit_endpoint,
        policy_endpoint,
        lease_endpoint,
    )
    .await?;

    Ok(())
}
