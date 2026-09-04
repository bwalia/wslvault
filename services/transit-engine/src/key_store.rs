//! In-memory transit key store and backend abstraction.
//!
//! Keys are identified by `(tenant_id, key_name)` and may have multiple
//! versions. Only the current version is used for new encryptions; all
//! previous versions remain available for decryption to allow gradual
//! re-encryption (rewrap) of existing ciphertexts.
//!
//! # Backend Architecture
//!
//! The `TransitKeyStoreBackend` trait decouples the HTTP handlers from the
//! concrete storage implementation.  Two implementations are provided:
//!
//! - `InMemoryTransitKeyStore`: pure in-memory map, used when `DATABASE_URL`
//!   is not set (development / testing).
//! - `PgTransitKeyBackend` (in `pg_store`): hybrid PostgreSQL + in-memory
//!   cache; metadata is persisted in PG while key material lives in the cache.

use std::collections::HashMap;
use std::sync::Arc;

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use tokio::sync::RwLock;
use zeroize::ZeroizeOnDrop;

use wslvault_core::VaultError;

/// Type alias for the raw, shared in-memory key map.
///
/// Used internally by `InMemoryTransitKeyStore` and the `PgTransitKeyBackend`
/// cache layer.  Consumers outside this module should program to the
/// `TransitKeyStoreBackend` trait instead.
pub type SharedKeyStore = Arc<RwLock<HashMap<(String, String), TransitKey>>>;

#[allow(dead_code)] // wire/DTO type: fields exist for serde and validation, not direct reads
/// A single 32-byte key version.  The `ZeroizeOnDrop` derive ensures the raw
/// bytes are wiped when the struct is dropped, preventing key material from
/// lingering in heap memory.
#[derive(Clone, ZeroizeOnDrop)]
pub struct KeyVersion {
    /// 1-based version index, monotonically increasing.
    pub version: u32,
    /// Raw 32-byte AES-256 key material.
    pub material: [u8; 32],
}

impl std::fmt::Debug for KeyVersion {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Never print raw key bytes in debug output.
        f.debug_struct("KeyVersion")
            .field("version", &self.version)
            .field("material", &"<redacted>")
            .finish()
    }
}

/// The supported key algorithm for transit operations.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum KeyAlgorithm {
    /// AES-256-GCM authenticated encryption.
    Aes256Gcm,
}

impl KeyAlgorithm {
    #[allow(dead_code)]
    pub fn as_str(&self) -> &'static str {
        match self {
            KeyAlgorithm::Aes256Gcm => "aes256-gcm",
        }
    }
}

#[allow(dead_code)] // metadata carried for API responses, not read internally
/// A named transit key with multiple versions.
#[derive(Debug, Clone)]
pub struct TransitKey {
    pub name: String,
    /// All key versions, index 0 corresponds to version 1.
    pub versions: Vec<KeyVersion>,
    /// The current (latest) version number. Encryptions always use this version.
    pub current_version: u32,
    pub algorithm: KeyAlgorithm,
    pub created_at: DateTime<Utc>,
}

impl TransitKey {
    /// Returns the raw key material for the current version.
    pub fn current_material(&self) -> &[u8; 32] {
        // current_version is 1-based; versions vec is 0-based.
        let idx = (self.current_version as usize).saturating_sub(1);
        &self.versions[idx].material
    }

    /// Returns the raw key material for a specific version, or None if the
    /// version does not exist.
    pub fn material_for_version(&self, version: u32) -> Option<&[u8; 32]> {
        let idx = (version as usize).saturating_sub(1);
        self.versions.get(idx).map(|kv| &kv.material)
    }
}

/// What a listing returns: everything about a key except the one thing that
/// must never leave this process. `TransitKey` carries raw material, so it is
/// not a type that can be handed to a serialiser by mistake; this is.
#[derive(Debug, Clone)]
pub struct TransitKeySummary {
    pub name: String,
    pub current_version: u32,
    pub algorithm: KeyAlgorithm,
    pub created_at: DateTime<Utc>,
}

impl From<&TransitKey> for TransitKeySummary {
    fn from(key: &TransitKey) -> Self {
        Self {
            name: key.name.clone(),
            current_version: key.current_version,
            algorithm: key.algorithm.clone(),
            created_at: key.created_at,
        }
    }
}

// ---------------------------------------------------------------------------
// Backend trait
// ---------------------------------------------------------------------------

/// Abstraction over transit key storage backends.
///
/// Implementing this trait allows the HTTP handlers to remain agnostic of
/// whether keys are kept purely in memory or persisted to PostgreSQL.
/// All methods mirror the original free-standing functions so that handler
/// code requires only a one-line change.
#[async_trait]
pub trait TransitKeyStoreBackend: Send + Sync {
    /// Create a new named key for the given tenant.
    ///
    /// Returns `VaultError::ValidationError` if the key already exists.
    async fn create_key(&self, tenant_id: &str, key_name: &str) -> Result<(), VaultError>;

    /// Retrieve a transit key by tenant and name.
    ///
    /// Returns a clone so callers hold no references into any internal lock.
    async fn get_key(&self, tenant_id: &str, key_name: &str) -> Result<TransitKey, VaultError>;

    /// Rotate a key by appending a new version and returning the new version number.
    ///
    /// Old versions are retained so that existing ciphertexts can still be
    /// decrypted until a rewrap pass has been completed.
    async fn rotate_key(&self, tenant_id: &str, key_name: &str) -> Result<u32, VaultError>;

    /// Every key belonging to `tenant_id`, name-ordered.
    ///
    /// Scoped to one tenant at the store layer rather than filtered by the
    /// caller: a listing that returned every tenant's key names and left the
    /// handler to trim it is one forgotten filter away from being a
    /// cross-tenant disclosure.
    async fn list_keys(&self, tenant_id: &str) -> Result<Vec<TransitKeySummary>, VaultError>;
}

// ---------------------------------------------------------------------------
// In-memory implementation
// ---------------------------------------------------------------------------

/// Pure in-memory implementation of `TransitKeyStoreBackend`.
///
/// State is not persisted; all keys are lost when the process exits.  This
/// backend is suitable for development, CI, and integration tests where a
/// running PostgreSQL instance is not available.
pub struct InMemoryTransitKeyStore {
    store: SharedKeyStore,
}

impl InMemoryTransitKeyStore {
    /// Create a new, empty in-memory key store.
    pub fn new() -> Self {
        Self {
            store: Arc::new(RwLock::new(HashMap::new())),
        }
    }
}

impl Default for InMemoryTransitKeyStore {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl TransitKeyStoreBackend for InMemoryTransitKeyStore {
    async fn create_key(&self, tenant_id: &str, key_name: &str) -> Result<(), VaultError> {
        create_key(&self.store, tenant_id, key_name).await
    }

    async fn get_key(&self, tenant_id: &str, key_name: &str) -> Result<TransitKey, VaultError> {
        get_key(&self.store, tenant_id, key_name).await
    }

    async fn rotate_key(&self, tenant_id: &str, key_name: &str) -> Result<u32, VaultError> {
        rotate_key(&self.store, tenant_id, key_name).await
    }

    async fn list_keys(&self, tenant_id: &str) -> Result<Vec<TransitKeySummary>, VaultError> {
        list_keys(&self.store, tenant_id).await
    }
}

// ---------------------------------------------------------------------------
// Convenience constructor (kept for backward-compat with main.rs during
// migration; prefer InMemoryTransitKeyStore::new() directly)
// ---------------------------------------------------------------------------

/// Create a new empty raw key store map.
///
/// Prefer constructing an `InMemoryTransitKeyStore` or `PgTransitKeyBackend`
/// through their respective `new()` functions.  This remains public so that
/// the `pg_store` module can initialise its internal cache.
#[allow(dead_code)]
pub fn new_key_store() -> SharedKeyStore {
    Arc::new(RwLock::new(HashMap::new()))
}

// ---------------------------------------------------------------------------
// Private helper implementations used by InMemoryTransitKeyStore
// ---------------------------------------------------------------------------

/// Create a new named key for the given tenant inside a `SharedKeyStore`.
///
/// Returns `VaultError::ValidationError` if a key with that name already exists
/// for the tenant.
async fn create_key(
    store: &SharedKeyStore,
    tenant_id: &str,
    key_name: &str,
) -> Result<(), VaultError> {
    let mut guard = store.write().await;
    let map_key = (tenant_id.to_string(), key_name.to_string());

    if guard.contains_key(&map_key) {
        return Err(VaultError::ValidationError {
            field: "key_name".into(),
            reason: format!(
                "key '{}' already exists for tenant '{}'",
                key_name, tenant_id
            ),
        });
    }

    let initial_version = KeyVersion {
        version: 1,
        material: generate_key_material(),
    };

    let transit_key = TransitKey {
        name: key_name.to_string(),
        versions: vec![initial_version],
        current_version: 1,
        algorithm: KeyAlgorithm::Aes256Gcm,
        created_at: Utc::now(),
    };

    guard.insert(map_key, transit_key);
    Ok(())
}

/// Every key held for `tenant_id`, ordered by name.
///
/// Both backends keep the full key set in this map — the PG backend warm-loads
/// it on startup and writes through on create and rotate — so a listing needs
/// no query of its own.
async fn list_keys(
    store: &SharedKeyStore,
    tenant_id: &str,
) -> Result<Vec<TransitKeySummary>, VaultError> {
    let guard = store.read().await;
    let mut keys: Vec<TransitKeySummary> = guard
        .iter()
        .filter(|((owner, _), _)| owner == tenant_id)
        .map(|(_, key)| TransitKeySummary::from(key))
        .collect();
    keys.sort_by(|a, b| a.name.cmp(&b.name));
    Ok(keys)
}

/// Look up an existing transit key by tenant + name.
///
/// Returns a clone of the key so callers hold no references into the lock.
async fn get_key(
    store: &SharedKeyStore,
    tenant_id: &str,
    key_name: &str,
) -> Result<TransitKey, VaultError> {
    let guard = store.read().await;
    guard
        .get(&(tenant_id.to_string(), key_name.to_string()))
        .cloned()
        .ok_or_else(|| VaultError::KeyNotFound {
            key_id: format!("{}/{}", tenant_id, key_name),
        })
}

/// Rotate a transit key by appending a new version and updating `current_version`.
///
/// Old versions are retained so that existing ciphertexts can still be decrypted.
async fn rotate_key(
    store: &SharedKeyStore,
    tenant_id: &str,
    key_name: &str,
) -> Result<u32, VaultError> {
    let mut guard = store.write().await;
    let map_key = (tenant_id.to_string(), key_name.to_string());

    let key = guard
        .get_mut(&map_key)
        .ok_or_else(|| VaultError::KeyNotFound {
            key_id: format!("{}/{}", tenant_id, key_name),
        })?;

    let new_version = key.current_version + 1;
    key.versions.push(KeyVersion {
        version: new_version,
        material: generate_key_material(),
    });
    key.current_version = new_version;

    Ok(new_version)
}

/// Generate a fresh 32-byte random key using the OS CSPRNG via `ring`.
pub(crate) fn generate_key_material() -> [u8; 32] {
    use ring::rand::{SecureRandom, SystemRandom};
    let rng = SystemRandom::new();
    let mut key = [0u8; 32];
    // ring's SystemRandom only fails if the OS RNG is broken; panic is appropriate.
    rng.fill(&mut key).expect("OS RNG must be available");
    key
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A listing must never reach past the tenant it was asked for.
    ///
    /// The filter is one line, which is exactly why it is worth pinning: drop
    /// it and every tenant learns every other tenant's key names, with nothing
    /// in the type system to notice.
    #[tokio::test]
    async fn list_keys_is_scoped_to_one_tenant() {
        let store = InMemoryTransitKeyStore::new();
        store.create_key("tenant-a", "billing").await.unwrap();
        store.create_key("tenant-a", "apollo").await.unwrap();
        store
            .create_key("tenant-b", "secret-project")
            .await
            .unwrap();

        let names: Vec<String> = store
            .list_keys("tenant-a")
            .await
            .unwrap()
            .into_iter()
            .map(|k| k.name)
            .collect();

        // Sorted, and tenant-b's key is absent.
        assert_eq!(names, vec!["apollo".to_string(), "billing".to_string()]);

        assert_eq!(store.list_keys("tenant-c").await.unwrap().len(), 0);
    }

    /// Rotation must be visible in the listing — a stale `latest_version` sends
    /// an operator rewrapping against a version that is no longer current.
    #[tokio::test]
    async fn list_keys_reports_the_current_version() {
        let store = InMemoryTransitKeyStore::new();
        store.create_key("tenant-a", "billing").await.unwrap();
        store.rotate_key("tenant-a", "billing").await.unwrap();

        let keys = store.list_keys("tenant-a").await.unwrap();
        assert_eq!(keys[0].current_version, 2);
    }
}
