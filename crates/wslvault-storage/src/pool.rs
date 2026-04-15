//! Database connection pool management.

use sqlx::postgres::{PgPool, PgPoolOptions};
use wslvault_core::config::DatabaseConfig;
use wslvault_core::VaultError;

/// Wrapper around the sqlx PgPool with WSLVault-specific initialization.
#[derive(Clone)]
pub struct DbPool {
    inner: PgPool,
}

// Manual Debug implementation to avoid leaking connection string details
// (host, credentials) that may be embedded in the PgPool's internal state.
impl std::fmt::Debug for DbPool {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DbPool")
            .field("size", &self.inner.size())
            .finish()
    }
}

impl DbPool {
    /// Create a new connection pool from the given database configuration.
    pub async fn connect(config: &DatabaseConfig) -> Result<Self, VaultError> {
        if config.url.is_empty() {
            return Err(VaultError::ValidationError {
                field: "database.url".into(),
                reason: "database URL must not be empty".into(),
            });
        }

        let pool = PgPoolOptions::new()
            .max_connections(config.max_connections)
            .min_connections(config.min_connections)
            .acquire_timeout(std::time::Duration::from_secs(config.acquire_timeout_secs))
            .idle_timeout(std::time::Duration::from_secs(config.idle_timeout_secs))
            .max_lifetime(std::time::Duration::from_secs(config.max_lifetime_secs))
            .connect(&config.url)
            .await
            .map_err(|e| VaultError::Database {
                reason: e.to_string(),
            })?;

        tracing::info!(
            max_connections = config.max_connections,
            "database connection pool established"
        );

        Ok(Self { inner: pool })
    }

    /// Wrap an existing sqlx `PgPool` in a `DbPool`.
    ///
    /// Useful when the caller already has a pool (e.g. created via
    /// `PgPoolOptions::new().connect(...)` directly) and needs the `DbPool`
    /// newtype for compatibility with the storage layer.
    pub fn from_pool(pool: PgPool) -> Self {
        Self { inner: pool }
    }

    /// Access the underlying sqlx pool for direct queries.
    pub fn inner(&self) -> &PgPool {
        &self.inner
    }

    /// Check that the database is reachable.
    pub async fn health_check(&self) -> Result<(), VaultError> {
        sqlx::query("SELECT 1")
            .execute(&self.inner)
            .await
            .map_err(|e| VaultError::Database {
                reason: e.to_string(),
            })?;
        Ok(())
    }
}
