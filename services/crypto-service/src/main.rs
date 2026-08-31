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
//! The root KEK is loaded via a pluggable `RootKeyProvider` selected by the
//! `VAULT_ROOT_KEY_PROVIDER` environment variable (default: `env`).  The `env`
//! provider reads `VAULT_ROOT_KEY` (base64, 32 bytes) for backward compatibility.
//! Set `VAULT_ROOT_KEY_PROVIDER=aws-kms` (and rebuild with `--features aws-kms`)
//! to decrypt the root key from AWS KMS instead.
//!
//! # Database persistence (optional)
//!
//! When `DATABASE_URL` is set, the service creates a PostgreSQL connection pool
//! and uses `KekStore::with_db` so that wrapped key descriptors are persisted
//! across pod restarts.  `load_from_db` is then called immediately after
//! construction to restore any previously generated tenant KEKs and DEKs into
//! the in-memory caches.
//!
//! When `DATABASE_URL` is absent, the service operates in ephemeral mode using
//! `KekStore::from_env` — identical to the previous behaviour.

mod grpc;
mod health;
mod kek_store;
mod root_key;
mod server;

use tracing::{error, info, warn};
use tracing_subscriber::EnvFilter;

use wslvault_core::config::{DatabaseConfig, VaultConfig};
use wslvault_storage::pool::DbPool;

use crate::kek_store::KekStore;
use crate::root_key::select_provider;
use crate::server::{run, ServerConfig};

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

    // Select the root key provider based on VAULT_ROOT_KEY_PROVIDER (default: "env").
    // The provider abstracts where the 32-byte root KEK comes from, enabling a
    // drop-in swap between the env-var path and AWS KMS without changing downstream code.
    let root_key_provider = select_provider()
        .map_err(|err| anyhow::anyhow!("Failed to select root key provider: {}", err))?;

    info!(
        provider = std::env::var("VAULT_ROOT_KEY_PROVIDER")
            .unwrap_or_else(|_| "env".to_string())
            .as_str(),
        "Root key provider selected"
    );

    // Load the root KEK via the selected provider.  This may involve a network
    // call (e.g. AWS KMS Decrypt) so it must complete before the service opens
    // any ports to traffic.
    let root_kek = root_key_provider
        .load_root_key()
        .await
        .map_err(|err| anyhow::anyhow!("Failed to load root KEK: {}", err))?;

    // Attempt to wire up optional PostgreSQL persistence.
    //
    // `DATABASE_URL` is checked directly from the environment rather than from
    // VaultConfig because (a) it may be injected by Kubernetes secrets and
    // (b) it must never appear in config files tracked by version control.
    let kek_store = match std::env::var("DATABASE_URL") {
        Ok(database_url) if !database_url.trim().is_empty() => {
            info!("DATABASE_URL is set — initialising KekStore with database persistence");

            // Build a DatabaseConfig from the DATABASE_URL env var, inheriting
            // pool sizing from VaultConfig so operators can tune via VAULT__* vars.
            let db_config = DatabaseConfig {
                url: database_url,
                ..vault_config.database.clone()
            };

            let pool = DbPool::connect(&db_config)
                .await
                .map_err(|err| anyhow::anyhow!("Failed to connect to database: {}", err))?;

            let store = KekStore::with_root_kek(root_kek, pool)
                .map_err(|err| anyhow::anyhow!("Failed to initialise KekStore: {}", err))?;

            // Restore previously persisted tenant KEKs and DEKs from the database
            // into the in-memory caches before the service begins accepting traffic.
            store
                .load_from_db()
                .await
                .map_err(|err| anyhow::anyhow!("Failed to load keys from database: {}", err))?;

            store
        }
        _ => {
            // DATABASE_URL is absent or empty — fall back to ephemeral mode.
            // This branch preserves full backward compatibility.
            warn!("DATABASE_URL is not set — KekStore running in ephemeral mode (keys lost on restart)");

            KekStore::with_root_kek_ephemeral(root_kek)
        }
    };

    // Start metrics server on the configured address.
    let metrics_addr = vault_config.observability.metrics_addr;
    tokio::spawn(wslvault_core::metrics::server::run_metrics_server(
        metrics_addr,
    ));

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
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));

    tracing_subscriber::fmt()
        .json()
        .with_env_filter(filter)
        .with_target(true)
        .with_thread_ids(false)
        .with_file(false)
        .init();
}
