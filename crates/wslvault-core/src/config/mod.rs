//! Configuration loading and validation for all WSLVault services.
//!
//! Each service embeds `VaultConfig` and can supplement it with service-specific fields.
//! Configuration is loaded by merging (in order of precedence):
//! 1. Compiled defaults
//! 2. `config/base.toml`
//! 3. `config/{environment}.toml` (environment from `VAULT_ENV`)
//! 4. `VAULT_` prefixed environment variables (highest precedence)

use std::net::SocketAddr;
use std::time::Duration;

use config::{Config, ConfigError, Environment, File};
use serde::{Deserialize, Serialize};

/// Database connection pool settings.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct DatabaseConfig {
    /// PostgreSQL connection URL (loaded from env, never hardcoded).
    pub url: String,
    pub max_connections: u32,
    pub min_connections: u32,
    pub acquire_timeout_secs: u64,
    pub idle_timeout_secs: u64,
    pub max_lifetime_secs: u64,
}

impl Default for DatabaseConfig {
    fn default() -> Self {
        Self {
            url: String::new(),
            max_connections: 20,
            min_connections: 2,
            acquire_timeout_secs: 5,
            idle_timeout_secs: 600,
            max_lifetime_secs: 1800,
        }
    }
}

/// TLS configuration for intra-cluster mTLS.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct TlsConfig {
    pub cert_path: String,
    pub key_path: String,
    pub ca_cert_path: String,
    pub require_client_cert: bool,
}

/// Crypto-service client settings; all services communicate with crypto-service.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct CryptoServiceConfig {
    /// gRPC endpoint, e.g. "https://crypto-service:50051".
    pub endpoint: String,
    pub timeout_ms: u64,
    pub pool_size: usize,
    pub tls: Option<TlsConfig>,
}

impl Default for CryptoServiceConfig {
    fn default() -> Self {
        Self {
            endpoint: "https://crypto-service:50051".into(),
            timeout_ms: 500,
            pool_size: 10,
            tls: None,
        }
    }
}

/// Observability config — tracing, metrics, structured logging.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct ObservabilityConfig {
    pub log_level: String,
    pub otlp_endpoint: Option<String>,
    pub service_name: String,
    pub metrics_addr: SocketAddr,
}

impl Default for ObservabilityConfig {
    fn default() -> Self {
        Self {
            log_level: "info".into(),
            otlp_endpoint: None,
            service_name: "wslvault".into(),
            metrics_addr: ([0, 0, 0, 0], 9090).into(),
        }
    }
}

/// Configuration for HA clustering behaviour.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct ClusterConfig {
    /// Unique identifier for this node. Defaults to `hostname:pid` at runtime.
    pub node_id: Option<String>,
    /// Region this node belongs to (e.g. "us-east-1", "eu-west-2").
    pub region: String,
    /// How often the leader refreshes its heartbeat (seconds).
    pub heartbeat_interval_secs: u64,
    /// How long before a missing heartbeat is considered a leadership vacancy (seconds).
    pub leader_lock_timeout_secs: u64,
}

impl Default for ClusterConfig {
    fn default() -> Self {
        Self {
            node_id: None,
            region: "default".into(),
            heartbeat_interval_secs: 5,
            leader_lock_timeout_secs: 30,
        }
    }
}

/// Configuration for cross-region replication.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct ReplicationConfig {
    /// The region identifier for this deployment.
    pub local_region: String,
    /// Peer regions to replicate with.
    pub peer_regions: Vec<RegionPeerConfig>,
    /// Replication mode: "async" or "sync".
    pub mode: String,
    /// Conflict resolution strategy: "last_write_wins", "vector_clock", or "manual".
    pub conflict_strategy: String,
    /// How often to poll for new replication events (milliseconds).
    pub poll_interval_ms: u64,
    /// Maximum number of events to process per batch.
    pub batch_size: usize,
}

impl Default for ReplicationConfig {
    fn default() -> Self {
        Self {
            local_region: "default".into(),
            peer_regions: Vec::new(),
            mode: "async".into(),
            conflict_strategy: "last_write_wins".into(),
            poll_interval_ms: 500,
            batch_size: 100,
        }
    }
}

/// Configuration for a single peer region.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct RegionPeerConfig {
    /// Region identifier (e.g. "eu-west-2").
    pub id: String,
    /// Replication API endpoint for this peer.
    pub replication_endpoint: String,
    /// Optional TLS configuration for the peer connection.
    pub tls: Option<TlsConfig>,
}

/// Top-level configuration shared by all services.
/// Individual services embed this and add their own fields.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct VaultConfig {
    pub listen_addr: SocketAddr,
    pub database: DatabaseConfig,
    pub crypto_service: CryptoServiceConfig,
    pub observability: ObservabilityConfig,
    /// Name of the service instance; used in log context and metrics labels.
    pub service_name: String,
    /// "dev" | "staging" | "production"
    pub environment: String,
    /// HA clustering configuration.
    pub cluster: ClusterConfig,
    /// Cross-region replication configuration.
    pub replication: ReplicationConfig,
}

impl Default for VaultConfig {
    fn default() -> Self {
        Self {
            listen_addr: ([0, 0, 0, 0], 8080).into(),
            database: DatabaseConfig::default(),
            crypto_service: CryptoServiceConfig::default(),
            observability: ObservabilityConfig::default(),
            service_name: "wslvault".into(),
            environment: "dev".into(),
            cluster: ClusterConfig::default(),
            replication: ReplicationConfig::default(),
        }
    }
}

impl VaultConfig {
    /// Load configuration by merging sources in order of precedence.
    pub fn load() -> Result<Self, ConfigError> {
        let env = std::env::var("VAULT_ENV").unwrap_or_else(|_| "dev".into());

        let config = Config::builder()
            .add_source(File::with_name("config/base").required(false))
            .add_source(File::with_name(&format!("config/{}", env)).required(false))
            .add_source(Environment::with_prefix("VAULT").separator("__"))
            .build()?;

        config.try_deserialize()
    }

    /// Return the acquire timeout as a `Duration`.
    pub fn acquire_timeout(&self) -> Duration {
        Duration::from_secs(self.database.acquire_timeout_secs)
    }
}
