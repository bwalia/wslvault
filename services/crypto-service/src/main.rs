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
mod sys;

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

    // ── Key custody ─────────────────────────────────────────────────────────
    //
    // Two paths, and the difference between them is the whole point of the seal.
    //
    // SEALED (preferred): `system.seal_config` holds the root key encrypted
    // under an unseal key that exists nowhere — only as Shamir shares held by
    // separate people. The service starts sealed and refuses every crypto
    // operation until `POST /v1/sys/unseal` receives a threshold of them.
    //
    // LEGACY: `VAULT_ROOT_KEY` (or a KMS provider) hands over the key directly,
    // and the process boots unsealed. This was the only path that existed, and
    // it means whoever can read a Kubernetes Secret or a process environment
    // owns every secret in the vault. Kept so existing deployments survive the
    // upgrade; warned about loudly, because it is the posture the seal exists
    // to replace.
    let seal = wslvault_core::seal::Seal::new();

    // Database first: the seal material lives there, and whether it exists
    // decides which path we are on.
    let db_pool = match std::env::var("DATABASE_URL") {
        Ok(url) if !url.trim().is_empty() => {
            let db_config = DatabaseConfig {
                url,
                ..vault_config.database.clone()
            };
            Some(
                DbPool::connect(&db_config)
                    .await
                    .map_err(|err| anyhow::anyhow!("Failed to connect to database: {}", err))?,
            )
        }
        _ => None,
    };

    let mut sealed_start = false;
    if let Some(pool) = &db_pool {
        if let Some(material) = wslvault_storage::seal_store::load(pool)
            .await
            .map_err(|err| anyhow::anyhow!("Failed to read seal configuration: {}", err))?
        {
            info!(
                shares = material.shares,
                threshold = material.threshold,
                "vault is initialized and SEALED — POST /v1/sys/unseal to open it"
            );
            seal.load(material).await;
            sealed_start = true;
        }
    }

    if !sealed_start {
        match select_provider() {
            Ok(provider) => match provider.load_root_key().await {
                Ok(root_kek) => {
                    warn!(
                        "starting UNSEALED from VAULT_ROOT_KEY. The root key is in this \
                         process's environment, so anyone who can read it owns every secret \
                         in the vault. Run POST /v1/sys/init to adopt Shamir-split custody."
                    );
                    seal.unseal_with_root_key(root_kek).await;
                }
                Err(err) => {
                    if db_pool.is_some() {
                        info!(
                            reason = %err,
                            "no root key in the environment and the vault is not initialized \
                             — starting SEALED. POST /v1/sys/init to initialize it."
                        );
                    } else {
                        return Err(anyhow::anyhow!(
                            "no root key available and no DATABASE_URL to initialize a seal \
                             against: {err}"
                        ));
                    }
                }
            },
            Err(err) => return Err(anyhow::anyhow!("Failed to select root key provider: {err}")),
        }
    }

    let kek_store = match db_pool.clone() {
        Some(pool) => {
            let store = KekStore::with_seal(seal.clone(), pool)
                .map_err(|err| anyhow::anyhow!("Failed to initialise KekStore: {}", err))?;

            // Only meaningful while unsealed; a sealed vault has nothing it can
            // decrypt yet and warm-loads when it is opened instead.
            if seal.is_unsealed().await {
                store
                    .load_from_db()
                    .await
                    .map_err(|err| anyhow::anyhow!("Failed to load keys from database: {}", err))?;
            }

            store
        }
        None => {
            warn!("DATABASE_URL is not set — KekStore running in ephemeral mode (keys lost on restart)");
            KekStore::with_seal_ephemeral(seal.clone())
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

    let sys_state = std::sync::Arc::new(sys::SysState {
        seal: seal.clone(),
        pool: db_pool.clone(),
        kek_store: kek_store.clone(),
    });

    run(kek_store, sys_state, server_config).await
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
