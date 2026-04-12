//! PostgreSQL-backed secret store using the `wslvault-storage` crate.
//!
//! `PgSecretBackend` implements `SecretStoreBackend` by delegating every
//! operation to the free-standing async functions in
//! `wslvault_storage::secret_store`.  It is selected at startup when the
//! `DATABASE_URL` environment variable is present; the in-memory `KvStore`
//! is used as a fallback for development and testing environments where no
//! database is available.

use std::collections::HashMap;

use async_trait::async_trait;
use tracing::warn;
use wslvault_core::types::secret::SecretEngine;
use wslvault_core::types::tenant::TenantId;
use wslvault_core::VaultError;
use wslvault_storage::pool::DbPool;
use wslvault_storage::secret_store;

use crate::kv_store::{SecretEntry, SecretStoreBackend, VersionEntry};

/// PostgreSQL-backed secret store.
///
/// Each method parses the caller-supplied `tenant_id` string into the
/// strongly-typed `TenantId` newtype and then delegates to the corresponding
/// `wslvault_storage::secret_store` function.  The `DbPool` is `Clone` so
/// `PgSecretBackend` can be cheaply wrapped in an `Arc` and shared across
/// the gRPC and HTTP servers.
#[derive(Debug, Clone)]
pub struct PgSecretBackend {
    pool: DbPool,
    /// Region identifier for tagging replication events. Loaded from `REGION_ID` env.
    region_id: String,
}

impl PgSecretBackend {
    /// Create a new backend from an existing connection pool.
    pub fn new(pool: DbPool) -> Self {
        let region_id =
            std::env::var("REGION_ID").unwrap_or_else(|_| "default".to_string());
        Self { pool, region_id }
    }

    /// Write a replication event to the outbox table for cross-region sync.
    async fn emit_replication_event(
        &self,
        tenant_id: &str,
        path: &str,
        ciphertext: &str,
        dek_id: &str,
    ) -> Result<(), VaultError> {
        let payload = serde_json::json!({
            "tenant_id": tenant_id,
            "path": path,
            "ciphertext": ciphertext,
            "dek_id": dek_id,
        });

        sqlx::query(
            r#"
            INSERT INTO system.replication_events (event_type, source_region, payload)
            VALUES ('secret_upsert', $1, $2)
            "#,
        )
        .bind(&self.region_id)
        .bind(payload)
        .execute(self.pool.inner())
        .await
        .map_err(|e| VaultError::Database {
            reason: format!("replication event write failed: {}", e),
        })?;

        Ok(())
    }

    /// Parse a raw tenant-id string into the `TenantId` newtype, returning a
    /// structured validation error on failure instead of a generic string error.
    fn parse_tenant_id(tenant_id: &str) -> Result<TenantId, VaultError> {
        tenant_id.parse().map_err(|_| VaultError::ValidationError {
            field: "tenant_id".into(),
            reason: format!("'{}' is not a valid UUID", tenant_id),
        })
    }
}

#[async_trait]
impl SecretStoreBackend for PgSecretBackend {
    /// Read a secret version from PostgreSQL.
    ///
    /// When `version` is `None`, the current (latest live) version is used as
    /// reported by the `current_version` column on the `secrets` table.
    async fn get(
        &self,
        tenant_id: &str,
        path: &str,
        version: Option<u32>,
    ) -> Result<VersionEntry, VaultError> {
        let tid = Self::parse_tenant_id(tenant_id)?;
        let meta = secret_store::get_secret_metadata(&self.pool, &tid, path).await?;

        let target_version = version.unwrap_or(meta.current_version);
        if target_version == 0 {
            // No live version exists for this path.
            return Err(VaultError::SecretNotFound {
                path: path.to_string(),
                version: None,
            });
        }

        let sv = secret_store::get_secret_version(&self.pool, &meta.id, target_version).await?;

        Ok(VersionEntry {
            version: sv.version,
            ciphertext: sv.ciphertext,
            dek_id: sv.dek_id,
            created_at: sv.created_at,
            deleted_at: sv.deleted_at,
            destroyed: sv.destroyed,
            custom_metadata: sv.custom_metadata,
        })
    }

    /// Write a new secret version to PostgreSQL via the atomic upsert function.
    ///
    /// The `max_versions` argument defaults to 10 when not provided.  The
    /// `cas_required` flag on the secret row is set to `true` whenever a
    /// check-and-set version is supplied by the caller.
    async fn put(
        &self,
        tenant_id: &str,
        path: &str,
        ciphertext: String,
        dek_id: String,
        cas: Option<u32>,
        _custom_metadata: HashMap<String, String>,
        max_versions: Option<u32>,
    ) -> Result<(String, u32), VaultError> {
        let tid = Self::parse_tenant_id(tenant_id)?;
        let (secret_id, version) = secret_store::upsert_secret_version(
            &self.pool,
            &tid,
            path,
            &SecretEngine::KvV2,
            &ciphertext,
            &dek_id,
            cas,
            max_versions.unwrap_or(10),
            // Treat the presence of a CAS version as requiring CAS on the row.
            cas.is_some(),
        )
        .await?;

        // Emit a replication event so cross-region agents can propagate this write.
        // This is best-effort: failure to write the event does not fail the write.
        if let Err(e) = self
            .emit_replication_event(tenant_id, path, &ciphertext, &dek_id)
            .await
        {
            warn!(
                error = %e,
                path,
                "failed to emit replication event for secret upsert"
            );
        }

        Ok((secret_id.to_string(), version))
    }

    /// Soft-delete specific versions in PostgreSQL.
    ///
    /// Requires fetching the stable `secret_id` first because the storage
    /// layer operates on `SecretId`, not on `(tenant_id, path)` pairs.
    async fn soft_delete(
        &self,
        tenant_id: &str,
        path: &str,
        versions: &[u32],
    ) -> Result<u32, VaultError> {
        let tid = Self::parse_tenant_id(tenant_id)?;
        let meta = secret_store::get_secret_metadata(&self.pool, &tid, path).await?;
        secret_store::soft_delete_versions(&self.pool, &meta.id, versions).await
    }

    /// Permanently destroy specific versions in PostgreSQL.
    ///
    /// This operation is irreversible: the storage layer zeroes the ciphertext
    /// column and sets `destroyed = true`.
    async fn destroy(
        &self,
        tenant_id: &str,
        path: &str,
        versions: &[u32],
    ) -> Result<u32, VaultError> {
        let tid = Self::parse_tenant_id(tenant_id)?;
        let meta = secret_store::get_secret_metadata(&self.pool, &tid, path).await?;
        secret_store::destroy_versions(&self.pool, &meta.id, versions).await
    }

    /// List secret paths matching a prefix for the given tenant.
    ///
    /// On failure (e.g. invalid tenant UUID, database error) an empty list is
    /// returned rather than propagating the error, consistent with the
    /// `KvStore` fallback behaviour for listing.
    async fn list(&self, tenant_id: &str, prefix: &str) -> Vec<String> {
        let tid = match Self::parse_tenant_id(tenant_id) {
            Ok(t) => t,
            Err(_) => return Vec::new(),
        };

        secret_store::list_secret_paths(&self.pool, &tid, prefix)
            .await
            .unwrap_or_default()
    }

    /// Retrieve metadata for a secret path without loading any version data.
    ///
    /// The returned `SecretEntry` has an empty `versions` vec because the
    /// PostgreSQL backend does not eagerly load all versions — callers that
    /// need version data should call `get` with a specific version number.
    async fn get_metadata(
        &self,
        tenant_id: &str,
        path: &str,
    ) -> Result<SecretEntry, VaultError> {
        let tid = Self::parse_tenant_id(tenant_id)?;
        let meta = secret_store::get_secret_metadata(&self.pool, &tid, path).await?;

        Ok(SecretEntry {
            secret_id: meta.id.to_string(),
            tenant_id: meta.tenant_id.to_string(),
            path: meta.path,
            max_versions: meta.max_versions,
            cas_required: meta.cas_required,
            created_at: meta.created_at,
            updated_at: meta.updated_at,
            // Version list is not eagerly loaded for the PG backend;
            // callers use get() to retrieve individual versions.
            versions: Vec::new(),
        })
    }
}
