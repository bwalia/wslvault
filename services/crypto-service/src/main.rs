//! crypto-service: cryptographic operations and key management for WSLVault.
//!
//! Responsibilities:
//!   - Manage the three-level key hierarchy (RootKEK -> TenantKEK -> DEK).
//!   - Expose a gRPC API (port 50051) for Encrypt / Decrypt / GenerateDek /
//!     RotateKey / GetKeyDescriptor operations.
//!   - Expose an HTTP server (port 8080) for liveness and readiness probes.
//!
//! # Configuration
//!
//! Configuration is loaded by `VaultConfig::load()`, which merges (in order of
//! increasing precedence):
//!   1. `config/base.toml`
//!   2. `config/<VAULT_ENV>.toml`
//!   3. `VAULT__*` environment variables
//!
//! The root KEK is loaded separately from the `VAULT_ROOT_KEY` environment
//! variable (a standard base64-encoded 32-byte key) because it is sensitive
//! key material that must never appear in config files.

mod grpc;
mod health;
mod kek_store;
mod server;

use tracing::{error, info};
use tracing_subscriber::EnvFilter;

use wslvault_core::config::VaultConfig;

use crate::kek_store::KekStore;
use crate::server::{ServerConfig, run};

#[tokio::main]
async fn main() {
    // Initialise structured JSON logging as early as possible so that any
    // startup errors are captured in the log stream.
    init_tracing();

    info!(
        service = "crypto-service",
        version = env!("CARGO_PKG_VERSION"),
        "Starting crypto-service"
    );

    if let Err(err) = run_service().await {
        error!(%err, "crypto-service exited with a fatal error");
        std::process::exit(1);
    }
}

/// Load configuration, initialise the key store, then start both servers.
///
/// Separating this from `main` keeps the error-handling path clean and avoids
/// unwrap chains in the entry point.
async fn run_service() -> Result<(), anyhow::Error> {
    // Load VaultConfig from files and environment.
    // Fall back to defaults if no config files are present (useful in dev/CI).
    let vault_config = VaultConfig::load().unwrap_or_else(|err| {
        info!(
            error = %err,
            "No config files found, using compiled defaults"
        );
        VaultConfig::default()
    });

    info!(
        service_name = %vault_config.service_name,
        environment = %vault_config.environment,
        listen_addr = %vault_config.listen_addr,
        "Configuration loaded"
    );

    // Load the root KEK from the VAULT_ROOT_KEY environment variable.
    // This is a hard requirement: the service cannot operate without a root KEK.
    let kek_store = KekStore::from_env().map_err(|err| {
        anyhow::anyhow!("Failed to initialise KekStore: {}", err)
    })?;

    // Bind gRPC on port 50051 and HTTP on port 8080.
    // These ports are intentionally independent of VaultConfig.listen_addr
    // so that the HTTP config address does not conflict with the gRPC listener.
    let server_config = ServerConfig {
        grpc_addr: ([0, 0, 0, 0], 50051).into(),
        http_addr: ([0, 0, 0, 0], 8080).into(),
    };

    run(kek_store, server_config).await
}

/// Initialise a tracing subscriber that emits structured JSON logs.
///
/// Log level is controlled by the `RUST_LOG` environment variable, defaulting
/// to `info` if not set.  Using JSON output ensures logs are machine-readable
/// in Kubernetes environments with a log aggregation pipeline.
fn init_tracing() {
    let filter = EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| EnvFilter::new("info"));

    tracing_subscriber::fmt()
        .json()
        .with_env_filter(filter)
        .with_target(true)
        .with_thread_ids(false)
        .with_file(false)
        .init();
}
