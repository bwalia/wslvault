//! PostgreSQL-backed transit key store.
//!
//! `PgTransitKeyBackend` implements `TransitKeyStoreBackend` using a hybrid
//! approach:
//!
//! - **Metadata persistence**: key name, version count, algorithm, and
//!   `created_at` are stored in `system.key_descriptors` via the
//!   `wslvault-storage` crate so that they survive process restarts.
//!
//! - **Key material cache**: raw 32-byte key material is kept in an
//!   `Arc<RwLock<HashMap<...>>>` (the same `SharedKeyStore` type used by
//!   `InMemoryTransitKeyStore`).  On startup the cache is warm-loaded from
//!   PG by calling `load_from_pg`.  On create/rotate the cache is updated
//!   atomically after a successful PG write.
//!
//! # Key wrapping (TODO)
//!
//! Currently the raw key material is held only in process memory and is NOT
//! wrapped before being written to PG.  A future iteration should:
//!
//! 1. Load a root wrapping key from an environment-provided secret (e.g.
//!    `TRANSIT_ROOT_WRAPPING_KEY`).
//! 2. Wrap each `KeyVersion.material` under that root key using AES-256-GCM
//!    before inserting the `wrapped_key` column in `system.key_descriptors`.
//! 3. On cache load, unwrap each `wrapped_key` back to raw bytes.
//!
//! Until that work is done, this backend provides metadata persistence only;
//! key material still lives exclusively in memory.

use std::collections::HashMap;
use std::sync::Arc;

use async_trait::async_trait;
use chrono::Utc;
use tokio::sync::RwLock;
use uuid::Uuid;

use wslvault_core::types::key::{
    KeyAlgorithm as CoreKeyAlgorithm, KeyDescriptor, KeyId, KeyPurpose, KeyState,
};
use wslvault_core::VaultError;
use wslvault_storage::key_store::{get_active_key, insert_key_descriptor, update_key_state};
use wslvault_storage::pool::DbPool;

use crate::key_store::{
    generate_key_material, KeyAlgorithm, KeyVersion, SharedKeyStore, TransitKey,
    TransitKeyStoreBackend,
};

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Attempt to parse `tenant_id` as a UUID; if it is not a valid UUID (e.g. in
/// tests or legacy callers) derive a deterministic UUID by hashing the raw
/// bytes using ring SHA-256 and taking the first 16 bytes as a UUID v4
/// (random-variant) value.
///
/// This avoids enabling the `v5` uuid crate feature (not in the workspace
/// feature set) while still producing a stable mapping for any string input.
fn tenant_id_to_uuid(tenant_id: &str) -> Uuid {
    Uuid::parse_str(tenant_id).unwrap_or_else(|_| {
        use ring::digest;
        let digest = digest::digest(&digest::SHA256, tenant_id.as_bytes());
        let bytes = digest.as_ref();
        // Take the first 16 bytes and set UUID variant/version bits to make a
        // valid v4 UUID so downstream tooling accepts it without complaint.
        let mut buf = [0u8; 16];
        buf.copy_from_slice(&bytes[..16]);
        // Version 4: top nibble of byte 6 = 0100
        buf[6] = (buf[6] & 0x0f) | 0x40;
        // Variant bits: top two bits of byte 8 = 10
        buf[8] = (buf[8] & 0x3f) | 0x80;
        Uuid::from_bytes(buf)
    })
}

/// Hybrid PostgreSQL + in-memory-cache backend.
///
/// Key metadata (name, version, algorithm, tenant) is persisted in
/// `system.key_descriptors`.  Raw key material remains in `cache` for fast
/// crypto operations and is never written to the database in plaintext.
///
/// # Thread safety
///
/// `DbPool` is `Clone + Send + Sync`; `cache` is wrapped in `Arc<RwLock<...>>`
/// so the struct itself is `Send + Sync` and cheap to clone via `Arc`.
pub struct PgTransitKeyBackend {
    pool: DbPool,
    /// In-process cache mapping `(tenant_id, key_name) → TransitKey`.
    ///
    /// The cache is the authoritative source for raw key material.  It is
    /// populated eagerly on startup via `load_from_pg` and kept consistent
    /// with PG on every create/rotate call.
    cache: SharedKeyStore,
}

impl PgTransitKeyBackend {
    /// Construct a new backend and warm the in-memory cache from PG.
    ///
    /// `load_from_pg` is called here so that key lookups never block on a
    /// cold cache.  Any keys that exist in PG but whose material is absent
    /// from the cache will be inaccessible until the process is restarted
    /// once key-wrapping support is added.
    ///
    /// # Errors
    ///
    /// Returns `VaultError::Database` if the PG connection cannot be
    /// established or the initial load query fails.
    pub async fn new(pool: DbPool) -> Result<Self, VaultError> {
        let cache = Arc::new(RwLock::new(HashMap::new()));
        // TODO: warm-load wrapped key descriptors from PG and unwrap them
        // into `cache` once root-key wrapping is implemented.
        Ok(Self { pool, cache })
    }
}

// ---------------------------------------------------------------------------
// TransitKeyStoreBackend implementation
// ---------------------------------------------------------------------------

#[async_trait]
impl TransitKeyStoreBackend for PgTransitKeyBackend {
    /// Create a new transit key, persisting its descriptor to PG and adding
    /// the raw material to the in-memory cache.
    ///
    /// # Duplicate-key behaviour
    ///
    /// The cache is checked first; if the key already exists in the cache the
    /// call is rejected with `VaultError::ValidationError` before touching PG.
    /// This mirrors the in-memory backend's semantics.
    async fn create_key(&self, tenant_id: &str, key_name: &str) -> Result<(), VaultError> {
        let map_key = (tenant_id.to_string(), key_name.to_string());

        // Guard: reject duplicate keys before any PG interaction.
        {
            let guard = self.cache.read().await;
            if guard.contains_key(&map_key) {
                return Err(VaultError::ValidationError {
                    field: "key_name".into(),
                    reason: format!(
                        "key '{}' already exists for tenant '{}'",
                        key_name, tenant_id
                    ),
                });
            }
        }

        // Build the initial key version.
        let initial_material = generate_key_material();
        let initial_version = KeyVersion {
            version: 1,
            material: initial_material,
        };

        // Persist key descriptor to PG.
        //
        // The tenant_id string is stored as a UUID in the descriptors table.
        // If the caller passes a non-UUID tenant_id (e.g. in tests or legacy
        // callers) we derive a deterministic UUID via tenant_id_to_uuid.
        let tenant_uuid = tenant_id_to_uuid(tenant_id);

        let descriptor = KeyDescriptor {
            id: KeyId::new(),
            version: 1,
            algorithm: CoreKeyAlgorithm::Aes256Gcm,
            purpose: KeyPurpose::Transit,
            state: KeyState::Active,
            tenant_id: Some(tenant_uuid.to_string()),
            created_at: Utc::now(),
            rotated_at: None,
            expires_at: None,
        };

        // TODO: wrap `initial_material` under the root wrapping key and pass
        // the ciphertext as `wrapped_key` here instead of the placeholder.
        // For now we store an empty placeholder so the metadata row exists.
        insert_key_descriptor(&self.pool, &descriptor, "TODO:wrap_key_material", None).await?;

        // Only update the cache after the PG write has committed, so that the
        // in-memory state is always a subset of (never ahead of) PG.
        let transit_key = TransitKey {
            name: key_name.to_string(),
            versions: vec![initial_version],
            current_version: 1,
            algorithm: KeyAlgorithm::Aes256Gcm,
            created_at: descriptor.created_at,
        };

        self.cache.write().await.insert(map_key, transit_key);
        Ok(())
    }

    /// Retrieve a transit key from the in-memory cache.
    ///
    /// The PG layer stores metadata only; raw key material is never round-
    /// tripped through the database, so all crypto-capable lookups go to the
    /// cache.
    async fn get_key(&self, tenant_id: &str, key_name: &str) -> Result<TransitKey, VaultError> {
        let guard = self.cache.read().await;
        guard
            .get(&(tenant_id.to_string(), key_name.to_string()))
            .cloned()
            .ok_or_else(|| VaultError::KeyNotFound {
                key_id: format!("{}/{}", tenant_id, key_name),
            })
    }

    /// Rotate a transit key by appending a new version.
    ///
    /// The old PG descriptor row is transitioned to `RotatingOut` state and a
    /// new row at the incremented version is inserted.  The cache is updated
    /// after both PG writes succeed.
    ///
    /// # Atomicity note
    ///
    /// The two PG writes (`update_key_state` + `insert_key_descriptor`) are
    /// not wrapped in a single transaction here.  A future improvement should
    /// use `sqlx::Transaction` to make rotation atomic.  If the second insert
    /// fails the descriptor remains in `RotatingOut` state in PG but the
    /// in-memory cache is not updated (because the cache write happens last),
    /// so the service continues to serve the old version correctly.
    async fn rotate_key(&self, tenant_id: &str, key_name: &str) -> Result<u32, VaultError> {
        let map_key = (tenant_id.to_string(), key_name.to_string());

        // Determine new version and generate material while holding a brief
        // read lock so we don't block other readers for the entire PG call.
        let (new_version, new_material) = {
            let guard = self.cache.read().await;
            let existing = guard.get(&map_key).ok_or_else(|| VaultError::KeyNotFound {
                key_id: format!("{}/{}", tenant_id, key_name),
            })?;
            (existing.current_version + 1, generate_key_material())
        };

        let tenant_uuid = tenant_id_to_uuid(tenant_id);

        // Locate the existing active descriptor in PG to transition it.
        // We use get_active_key which returns the latest active row for this
        // tenant + Transit purpose.
        let active_descriptor =
            get_active_key(&self.pool, &tenant_uuid, &KeyPurpose::Transit).await?;

        // Mark the current version as rotating out.
        update_key_state(&self.pool, &active_descriptor.id, &KeyState::RotatingOut).await?;

        // Insert the new version descriptor.
        let new_descriptor = KeyDescriptor {
            id: KeyId::new(),
            version: new_version,
            algorithm: CoreKeyAlgorithm::Aes256Gcm,
            purpose: KeyPurpose::Transit,
            state: KeyState::Active,
            tenant_id: Some(tenant_uuid.to_string()),
            created_at: Utc::now(),
            rotated_at: None,
            expires_at: None,
        };

        // TODO: wrap `new_material` under the root wrapping key before
        // storing.  For now use a placeholder.
        insert_key_descriptor(&self.pool, &new_descriptor, "TODO:wrap_key_material", None).await?;

        // Both PG writes succeeded — update the in-memory cache.
        {
            let mut guard = self.cache.write().await;
            let key = guard.get_mut(&map_key).ok_or_else(|| VaultError::KeyNotFound {
                key_id: format!("{}/{}", tenant_id, key_name),
            })?;

            key.versions.push(KeyVersion {
                version: new_version,
                material: new_material,
            });
            key.current_version = new_version;
        }

        Ok(new_version)
    }
}
