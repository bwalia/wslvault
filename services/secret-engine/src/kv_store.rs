//! In-memory KV store backend for the secret engine.
//!
//! All secret data is stored encrypted (ciphertext only). Plaintext values
//! are never persisted in this struct. The store supports:
//! - Multi-version storage per (tenant_id, path) key
//! - CAS (check-and-set) writes to prevent concurrent overwrites
//! - Configurable max_versions pruning of old versions
//! - Soft delete (marks version deleted without erasing ciphertext)
//! - Hard destroy (zeroes ciphertext and marks version permanently destroyed)

use std::collections::HashMap;
use std::sync::Arc;

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use tokio::sync::RwLock;
use uuid::Uuid;
use wslvault_core::VaultError;

/// Abstraction over secret storage so the engine can run against
/// in-memory (tests/dev) or PostgreSQL (production) backends.
///
/// Both `KvStore` (in-memory) and `PgSecretBackend` (PostgreSQL) implement
/// this trait, allowing `server.rs` to select the backend at startup based
/// on whether a `DATABASE_URL` environment variable is present.
#[async_trait]
pub trait SecretStoreBackend: Send + Sync + std::fmt::Debug {
    /// Read a secret version. If `version` is `None`, returns the current live version.
    async fn get(
        &self,
        tenant_id: &str,
        path: &str,
        version: Option<u32>,
    ) -> Result<VersionEntry, VaultError>;

    /// Write a new secret version, optionally enforcing CAS optimistic locking.
    async fn put(
        &self,
        tenant_id: &str,
        path: &str,
        ciphertext: String,
        dek_id: String,
        cas: Option<u32>,
        custom_metadata: HashMap<String, String>,
        max_versions: Option<u32>,
    ) -> Result<(String, u32), VaultError>;

    /// Mark specific secret versions as deleted without erasing their ciphertext.
    async fn soft_delete(
        &self,
        tenant_id: &str,
        path: &str,
        versions: &[u32],
    ) -> Result<u32, VaultError>;

    /// Permanently destroy specific secret versions, zeroing their ciphertext.
    async fn destroy(
        &self,
        tenant_id: &str,
        path: &str,
        versions: &[u32],
    ) -> Result<u32, VaultError>;

    /// List all secret paths under a given prefix within a tenant.
    async fn list(&self, tenant_id: &str, prefix: &str) -> Vec<String>;

    /// Retrieve metadata for a secret path without reading any version data.
    async fn get_metadata(
        &self,
        tenant_id: &str,
        path: &str,
    ) -> Result<SecretEntry, VaultError>;
}

/// Default maximum number of versions retained per secret when not specified by the caller.
const DEFAULT_MAX_VERSIONS: u32 = 10;

/// Composite key that scopes every secret to a specific tenant.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct SecretKey {
    pub tenant_id: String,
    pub path: String,
}

/// A single stored version of a secret.
///
/// The `ciphertext` field contains the encrypted secret data. When a version is
/// destroyed the ciphertext is replaced with an empty string so key material
/// cannot be recovered.
#[derive(Debug, Clone)]
pub struct VersionEntry {
    /// Monotonically increasing version number starting at 1.
    pub version: u32,
    /// base64-encoded ciphertext produced by the crypto-service.
    pub ciphertext: String,
    /// DEK ID returned by the crypto-service at write time, for key rotation tracking.
    pub dek_id: String,
    pub created_at: DateTime<Utc>,
    /// Set when the version is soft-deleted; ciphertext is retained.
    pub deleted_at: Option<DateTime<Utc>>,
    /// Set when the version is permanently destroyed; ciphertext is zeroed.
    pub destroyed: bool,
    pub custom_metadata: HashMap<String, String>,
}

/// All state associated with a single secret path.
#[derive(Debug, Clone)]
pub struct SecretEntry {
    /// Stable UUID for this path; does not change across versions.
    pub secret_id: String,
    pub tenant_id: String,
    pub path: String,
    /// Maximum number of non-destroyed versions to retain.
    pub max_versions: u32,
    /// If true, every write must supply a matching CAS version.
    pub cas_required: bool,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    /// All versions in ascending order; oldest first.
    pub versions: Vec<VersionEntry>,
}

impl SecretEntry {
    /// Return the latest non-destroyed, non-deleted version if one exists.
    pub fn current_version_number(&self) -> u32 {
        self.versions
            .iter()
            .rev()
            .find(|v| !v.destroyed && v.deleted_at.is_none())
            .map(|v| v.version)
            .unwrap_or(0)
    }

    /// Look up a version by number, returning None if it does not exist.
    pub fn get_version(&self, version: u32) -> Option<&VersionEntry> {
        self.versions.iter().find(|v| v.version == version)
    }
}

/// Thread-safe in-memory KV store.
///
/// An `Arc<KvStore>` is shared between the gRPC server, the HTTP server, and any
/// background tasks. All mutation goes through the `RwLock`.
#[derive(Debug, Default)]
pub struct KvStore {
    inner: RwLock<HashMap<SecretKey, SecretEntry>>,
}

impl KvStore {
    pub fn new() -> Arc<Self> {
        Arc::new(Self {
            inner: RwLock::new(HashMap::new()),
        })
    }

    /// Read a secret version.
    ///
    /// If `version` is `None`, returns the current (latest live) version.
    /// Returns `VaultError::SecretNotFound` if the path does not exist.
    /// Returns `VaultError::VersionDestroyed` if the requested version was destroyed.
    pub async fn get(
        &self,
        tenant_id: &str,
        path: &str,
        version: Option<u32>,
    ) -> Result<VersionEntry, VaultError> {
        let store = self.inner.read().await;
        let key = SecretKey {
            tenant_id: tenant_id.to_string(),
            path: path.to_string(),
        };

        let entry = store.get(&key).ok_or_else(|| VaultError::SecretNotFound {
            path: path.to_string(),
            version,
        })?;

        let target_version = match version {
            Some(v) => v,
            None => entry.current_version_number(),
        };

        if target_version == 0 {
            return Err(VaultError::SecretNotFound {
                path: path.to_string(),
                version: None,
            });
        }

        let ver_entry =
            entry
                .get_version(target_version)
                .ok_or_else(|| VaultError::SecretNotFound {
                    path: path.to_string(),
                    version: Some(target_version),
                })?;

        if ver_entry.destroyed {
            return Err(VaultError::VersionDestroyed {
                version: target_version,
            });
        }

        Ok(ver_entry.clone())
    }

    /// Write a new version of a secret.
    ///
    /// When `cas` is `Some(n)` the write succeeds only if the current version
    /// number equals `n`, preventing concurrent overwrites (optimistic locking).
    /// When the path is new and `cas` is `Some(0)`, the write is allowed as the
    /// "create-only" semantic.
    ///
    /// After inserting, versions older than `max_versions` are pruned.
    pub async fn put(
        &self,
        tenant_id: &str,
        path: &str,
        ciphertext: String,
        dek_id: String,
        cas: Option<u32>,
        custom_metadata: HashMap<String, String>,
        max_versions: Option<u32>,
    ) -> Result<(String, u32), VaultError> {
        let mut store = self.inner.write().await;
        let key = SecretKey {
            tenant_id: tenant_id.to_string(),
            path: path.to_string(),
        };
        let now = Utc::now();

        let entry = store.entry(key).or_insert_with(|| SecretEntry {
            secret_id: Uuid::now_v7().to_string(),
            tenant_id: tenant_id.to_string(),
            path: path.to_string(),
            max_versions: max_versions.unwrap_or(DEFAULT_MAX_VERSIONS),
            cas_required: cas.is_some(),
            created_at: now,
            updated_at: now,
            versions: Vec::new(),
        });

        // Apply max_versions override if provided on this write.
        if let Some(mv) = max_versions {
            entry.max_versions = mv;
        }

        let current = entry.current_version_number();

        // Enforce CAS constraint.
        if let Some(expected) = cas {
            if current != expected {
                return Err(VaultError::CasConflict {
                    expected,
                    actual: current,
                });
            }
        }

        let new_version = current + 1;
        entry.versions.push(VersionEntry {
            version: new_version,
            ciphertext,
            dek_id,
            created_at: now,
            deleted_at: None,
            destroyed: false,
            custom_metadata,
        });
        entry.updated_at = now;

        // Prune oldest live versions when we exceed max_versions.
        let effective_max = entry.max_versions;
        let secret_id = entry.secret_id.clone();

        // Count live (non-destroyed) versions and remove the oldest ones.
        let live_versions: Vec<u32> = entry
            .versions
            .iter()
            .filter(|v| !v.destroyed)
            .map(|v| v.version)
            .collect();

        if live_versions.len() as u32 > effective_max {
            let excess = live_versions.len() as u32 - effective_max;
            let to_remove: std::collections::HashSet<u32> = live_versions
                .iter()
                .take(excess as usize)
                .copied()
                .collect();

            // Remove pruned versions entirely from the list.
            entry.versions.retain(|v| !to_remove.contains(&v.version));
        }

        Ok((secret_id, new_version))
    }

    /// Soft-delete specific versions of a secret.
    ///
    /// Deleted versions are marked with a `deleted_at` timestamp. Their ciphertext
    /// is retained and they can be undeleted (not implemented here but reserved for
    /// future use). Already-deleted or destroyed versions are silently skipped.
    pub async fn soft_delete(
        &self,
        tenant_id: &str,
        path: &str,
        versions: &[u32],
    ) -> Result<u32, VaultError> {
        let mut store = self.inner.write().await;
        let key = SecretKey {
            tenant_id: tenant_id.to_string(),
            path: path.to_string(),
        };

        let entry = store
            .get_mut(&key)
            .ok_or_else(|| VaultError::SecretNotFound {
                path: path.to_string(),
                version: None,
            })?;

        let now = Utc::now();
        let mut deleted_count: u32 = 0;

        let target_versions: std::collections::HashSet<u32> = if versions.is_empty() {
            // Delete the current live version when no specific versions are given.
            let current = entry.current_version_number();
            if current > 0 {
                std::iter::once(current).collect()
            } else {
                std::collections::HashSet::new()
            }
        } else {
            versions.iter().copied().collect()
        };

        for ver in entry.versions.iter_mut() {
            if target_versions.contains(&ver.version) && !ver.destroyed && ver.deleted_at.is_none()
            {
                ver.deleted_at = Some(now);
                deleted_count += 1;
            }
        }

        Ok(deleted_count)
    }

    /// Permanently destroy specific versions of a secret.
    ///
    /// Destroyed versions have their ciphertext replaced with an empty string.
    /// This operation is irreversible. Already-destroyed versions are silently skipped.
    pub async fn destroy(
        &self,
        tenant_id: &str,
        path: &str,
        versions: &[u32],
    ) -> Result<u32, VaultError> {
        let mut store = self.inner.write().await;
        let key = SecretKey {
            tenant_id: tenant_id.to_string(),
            path: path.to_string(),
        };

        let entry = store
            .get_mut(&key)
            .ok_or_else(|| VaultError::SecretNotFound {
                path: path.to_string(),
                version: None,
            })?;

        let now = Utc::now();
        let mut destroyed_count: u32 = 0;

        let target_versions: std::collections::HashSet<u32> = if versions.is_empty() {
            // Destroy all non-destroyed versions when no specific versions are given.
            entry
                .versions
                .iter()
                .filter(|v| !v.destroyed)
                .map(|v| v.version)
                .collect()
        } else {
            versions.iter().copied().collect()
        };

        for ver in entry.versions.iter_mut() {
            if target_versions.contains(&ver.version) && !ver.destroyed {
                // Zero out the ciphertext so key material cannot be recovered.
                ver.ciphertext = String::new();
                ver.dek_id = String::new();
                ver.destroyed = true;
                // Mark deleted_at if not already set.
                ver.deleted_at.get_or_insert(now);
                destroyed_count += 1;
            }
        }

        Ok(destroyed_count)
    }

    /// List all secret paths under a given prefix within a tenant.
    ///
    /// Returns only paths that have at least one live (non-destroyed) version.
    /// The prefix should be a normalized path segment, e.g. "prod/database".
    pub async fn list(&self, tenant_id: &str, prefix: &str) -> Vec<String> {
        let store = self.inner.read().await;

        store
            .iter()
            .filter(|(k, entry)| {
                k.tenant_id == tenant_id
                    && (prefix.is_empty() || k.path.starts_with(prefix))
                    && entry.versions.iter().any(|v| !v.destroyed)
            })
            .map(|(k, _)| k.path.clone())
            .collect()
    }

    /// Retrieve the metadata for a secret path without reading any version data.
    pub async fn get_metadata(
        &self,
        tenant_id: &str,
        path: &str,
    ) -> Result<SecretEntry, VaultError> {
        let store = self.inner.read().await;
        let key = SecretKey {
            tenant_id: tenant_id.to_string(),
            path: path.to_string(),
        };

        store
            .get(&key)
            .cloned()
            .ok_or_else(|| VaultError::SecretNotFound {
                path: path.to_string(),
                version: None,
            })
    }
}

/// Implement `SecretStoreBackend` for the in-memory `KvStore` by delegating
/// each method to the existing inherent impl.
#[async_trait]
impl SecretStoreBackend for KvStore {
    async fn get(
        &self,
        tenant_id: &str,
        path: &str,
        version: Option<u32>,
    ) -> Result<VersionEntry, VaultError> {
        self.get(tenant_id, path, version).await
    }

    async fn put(
        &self,
        tenant_id: &str,
        path: &str,
        ciphertext: String,
        dek_id: String,
        cas: Option<u32>,
        custom_metadata: HashMap<String, String>,
        max_versions: Option<u32>,
    ) -> Result<(String, u32), VaultError> {
        self.put(tenant_id, path, ciphertext, dek_id, cas, custom_metadata, max_versions)
            .await
    }

    async fn soft_delete(
        &self,
        tenant_id: &str,
        path: &str,
        versions: &[u32],
    ) -> Result<u32, VaultError> {
        self.soft_delete(tenant_id, path, versions).await
    }

    async fn destroy(
        &self,
        tenant_id: &str,
        path: &str,
        versions: &[u32],
    ) -> Result<u32, VaultError> {
        self.destroy(tenant_id, path, versions).await
    }

    async fn list(&self, tenant_id: &str, prefix: &str) -> Vec<String> {
        self.list(tenant_id, prefix).await
    }

    async fn get_metadata(
        &self,
        tenant_id: &str,
        path: &str,
    ) -> Result<SecretEntry, VaultError> {
        self.get_metadata(tenant_id, path).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    async fn make_store() -> Arc<KvStore> {
        KvStore::new()
    }

    #[tokio::test]
    async fn put_and_get_basic() {
        let store = make_store().await;
        let (_, version) = store
            .put(
                "t1",
                "prod/db/pass",
                "cipher1".into(),
                "dek1".into(),
                None,
                HashMap::new(),
                None,
            )
            .await
            .unwrap();
        assert_eq!(version, 1);

        let ver = store.get("t1", "prod/db/pass", None).await.unwrap();
        assert_eq!(ver.version, 1);
        assert_eq!(ver.ciphertext, "cipher1");
    }

    #[tokio::test]
    async fn cas_conflict_is_detected() {
        let store = make_store().await;
        store
            .put(
                "t1",
                "p",
                "c1".into(),
                "d1".into(),
                None,
                HashMap::new(),
                None,
            )
            .await
            .unwrap();

        // CAS expects version 0 (not found or create-only), but current is 1.
        let result = store
            .put(
                "t1",
                "p",
                "c2".into(),
                "d2".into(),
                Some(0),
                HashMap::new(),
                None,
            )
            .await;
        assert!(matches!(result, Err(VaultError::CasConflict { .. })));
    }

    #[tokio::test]
    async fn soft_delete_marks_version() {
        let store = make_store().await;
        store
            .put(
                "t1",
                "p",
                "c".into(),
                "d".into(),
                None,
                HashMap::new(),
                None,
            )
            .await
            .unwrap();

        let deleted = store.soft_delete("t1", "p", &[1]).await.unwrap();
        assert_eq!(deleted, 1);

        // The version is now deleted; latest live version should be 0.
        let meta = store.get_metadata("t1", "p").await.unwrap();
        assert_eq!(meta.current_version_number(), 0);
    }

    #[tokio::test]
    async fn destroy_zeroes_ciphertext() {
        let store = make_store().await;
        store
            .put(
                "t1",
                "p",
                "secret".into(),
                "dek".into(),
                None,
                HashMap::new(),
                None,
            )
            .await
            .unwrap();

        store.destroy("t1", "p", &[1]).await.unwrap();

        let result = store.get("t1", "p", Some(1)).await;
        assert!(matches!(result, Err(VaultError::VersionDestroyed { .. })));
    }
}
