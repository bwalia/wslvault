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
//! # Key wrapping
//!
//! Key material is wrapped under the root KEK (`VAULT_ROOT_KEY`, the same key
//! crypto-service uses — deliberately not a fourth independent root secret)
//! with AES-256-GCM before it reaches the database, and unwrapped on warm-load.
//!
//! The AAD binds each blob to `tenant:name:version`, so a wrapped key cannot be
//! transplanted onto a different key, a different version, or another tenant's
//! row even by someone with write access to the table.
//!
//! This used to write the literal string `"TODO:wrap_key_material"` into the
//! `wrapped_key` column and keep the real material in process memory only.
//! Every ciphertext a transit key had ever produced became undecryptable the
//! first time its pod restarted, and with more than one replica encrypt and
//! decrypt routed to different pods did not agree in the first place.

use std::collections::HashMap;
use std::sync::Arc;

use async_trait::async_trait;
use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine as _;
use chrono::Utc;
use sqlx::Row;
use tokio::sync::RwLock;
use tracing::{info, warn};
use uuid::Uuid;
use zeroize::Zeroizing;

use wslvault_core::crypto::envelope::{decrypt_with_dek, encrypt_with_dek};
use wslvault_core::types::key::{
    KeyAlgorithm as CoreKeyAlgorithm, KeyDescriptor, KeyId, KeyPurpose, KeyState,
};
use wslvault_core::VaultError;
use wslvault_storage::key_store::{
    insert_named_key_descriptor, list_loadable_keys_with_wrapped_key, update_key_state,
    PersistedKeyEntry,
};
use wslvault_storage::pool::DbPool;

use crate::key_store::{
    generate_key_material, KeyAlgorithm, KeyVersion, SharedKeyStore, TransitKey,
    TransitKeyStoreBackend, TransitKeySummary,
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

/// Environment variable holding the base64 32-byte root KEK.
///
/// Shared with crypto-service on purpose. Custody of key material is already
/// split across `VAULT_ROOT_KEY`, `PKI_ROOT_KEY` and `VAULT_JWT_SECRET`; adding
/// a fourth would make the eventual seal harder, not safer.
const ROOT_KEY_ENV: &str = "VAULT_ROOT_KEY";

/// Load the 32-byte root KEK used to wrap transit key material.
fn load_root_key() -> Result<Zeroizing<[u8; 32]>, VaultError> {
    let encoded = std::env::var(ROOT_KEY_ENV).map_err(|_| VaultError::Internal {
        reason: format!(
            "{ROOT_KEY_ENV} is required by the PostgreSQL transit backend: \
             key material cannot be persisted without a key to wrap it under"
        ),
    })?;
    let raw = BASE64
        .decode(encoded.trim())
        .map_err(|e| VaultError::Internal {
            reason: format!("{ROOT_KEY_ENV} is not valid base64: {e}"),
        })?;
    if raw.len() != 32 {
        return Err(VaultError::Internal {
            reason: format!("{ROOT_KEY_ENV} must decode to 32 bytes, got {}", raw.len()),
        });
    }
    let mut key = Zeroizing::new([0u8; 32]);
    key.copy_from_slice(&raw);
    Ok(key)
}

/// AAD binding a wrapped blob to exactly one key version of one tenant's key.
fn wrap_aad(tenant_id: &str, key_name: &str, version: u32) -> Vec<u8> {
    format!("transit:{tenant_id}:{key_name}:v{version}").into_bytes()
}

/// Wrap 32 bytes of key material for storage.
fn wrap_material(
    root: &[u8; 32],
    tenant_id: &str,
    key_name: &str,
    version: u32,
    material: &[u8; 32],
) -> Result<String, VaultError> {
    let aad = wrap_aad(tenant_id, key_name, version);
    Ok(encrypt_with_dek(root, material, &aad)?.ciphertext_b64)
}

/// Reverse of [`wrap_material`].
fn unwrap_material(
    root: &[u8; 32],
    tenant_id: &str,
    key_name: &str,
    version: u32,
    wrapped: &str,
) -> Result<[u8; 32], VaultError> {
    let aad = wrap_aad(tenant_id, key_name, version);
    let plaintext = decrypt_with_dek(root, wrapped, &aad)?;
    if plaintext.len() != 32 {
        return Err(VaultError::Internal {
            reason: format!(
                "unwrapped transit key is {} bytes, expected 32",
                plaintext.len()
            ),
        });
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(&plaintext);
    Ok(out)
}

/// The id of the currently-active descriptor for one named transit key.
///
/// Scoped to (tenant, name) so rotation cannot retire a different key's row.
async fn active_descriptor_id_for(
    pool: &DbPool,
    tenant_uuid: &Uuid,
    key_name: &str,
) -> Result<KeyId, VaultError> {
    let row = sqlx::query(
        "SELECT id FROM system.key_descriptors
         WHERE tenant_id = $1 AND key_name = $2
           AND purpose = 'transit' AND state = 'active'
         ORDER BY version DESC
         LIMIT 1",
    )
    .bind(tenant_uuid)
    .bind(key_name)
    .fetch_optional(pool.inner())
    .await
    .map_err(|e| VaultError::Database {
        reason: format!("failed to locate active transit descriptor: {e}"),
    })?
    .ok_or_else(|| VaultError::KeyNotFound {
        key_id: format!("{tenant_uuid}/{key_name}"),
    })?;

    Ok(KeyId(row.get::<Uuid, _>("id")))
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
    /// Root KEK that wraps every persisted key version.
    root_key: Zeroizing<[u8; 32]>,
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
        let root_key = load_root_key()?;
        let cache = Arc::new(RwLock::new(HashMap::new()));
        let backend = Self {
            pool,
            root_key,
            cache,
        };
        backend.load_from_pg().await?;
        Ok(backend)
    }

    /// Rehydrate every persisted transit key into the in-memory cache.
    ///
    /// Rows arrive version-ASC, so versions accumulate in order and
    /// `current_version` ends up on the highest. `rotating_out` rows are
    /// included: a rotated key still has to decrypt everything written under
    /// its earlier versions.
    ///
    /// A row that fails to unwrap is skipped with a WARN rather than aborting
    /// the load, so one damaged descriptor cannot stop the service from
    /// starting — but it is loud, because that is a corruption or a wrong root
    /// key and an operator needs to know.
    async fn load_from_pg(&self) -> Result<(), VaultError> {
        let rows: Vec<PersistedKeyEntry> =
            list_loadable_keys_with_wrapped_key(&self.pool, &KeyPurpose::Transit).await?;

        let mut cache = self.cache.write().await;
        let mut loaded = 0usize;
        let mut skipped = 0usize;

        for row in rows {
            let (Some(tenant_id), Some(key_name)) = (row.tenant_id.clone(), row.key_name.clone())
            else {
                // Pre-021 rows carry no name and cannot be addressed. They are
                // the "TODO:wrap_key_material" generation and hold nothing.
                skipped += 1;
                continue;
            };

            let material = match unwrap_material(
                &self.root_key,
                &tenant_id,
                &key_name,
                row.version,
                &row.wrapped_key,
            ) {
                Ok(m) => m,
                Err(e) => {
                    warn!(
                        key_id = %row.key_id,
                        key_name = %key_name,
                        version = row.version,
                        error = %e,
                        "failed to unwrap transit key — skipping (investigate immediately)"
                    );
                    skipped += 1;
                    continue;
                }
            };

            let entry = cache
                .entry((tenant_id, key_name.clone()))
                .or_insert_with(|| TransitKey {
                    name: key_name,
                    versions: Vec::new(),
                    current_version: 0,
                    algorithm: KeyAlgorithm::Aes256Gcm,
                    created_at: Utc::now(),
                });
            entry.versions.push(KeyVersion {
                version: row.version,
                material,
            });
            entry.current_version = entry.current_version.max(row.version);
            loaded += 1;
        }

        info!(
            keys = cache.len(),
            versions = loaded,
            skipped,
            "transit keys rehydrated from PostgreSQL"
        );
        Ok(())
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

        let wrapped = wrap_material(&self.root_key, tenant_id, key_name, 1, &initial_material)?;
        insert_named_key_descriptor(&self.pool, &descriptor, &wrapped, None, Some(key_name))
            .await?;

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

    /// Served from the same warm cache as `get_key`.
    ///
    /// Not a `SELECT`: a descriptor row whose material failed to unwrap is
    /// skipped by `load_from_pg`, so querying PG directly would advertise keys
    /// this process cannot actually use.
    async fn list_keys(&self, tenant_id: &str) -> Result<Vec<TransitKeySummary>, VaultError> {
        let guard = self.cache.read().await;
        let mut keys: Vec<TransitKeySummary> = guard
            .iter()
            .filter(|((owner, _), _)| owner == tenant_id)
            .map(|(_, key)| TransitKeySummary::from(key))
            .collect();
        keys.sort_by(|a, b| a.name.cmp(&b.name));
        Ok(keys)
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

        // Retire the outgoing version of THIS key.
        //
        // This used to call `get_active_key(pool, tenant, Transit)`, which
        // returns the tenant's latest active transit descriptor regardless of
        // which key it belongs to — so with two transit keys, rotating B
        // transitioned A's descriptor. The lookup is now by (tenant, name).
        let outgoing_id = active_descriptor_id_for(&self.pool, &tenant_uuid, key_name).await?;
        update_key_state(&self.pool, &outgoing_id, &KeyState::RotatingOut).await?;

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

        let wrapped = wrap_material(
            &self.root_key,
            tenant_id,
            key_name,
            new_version,
            &new_material,
        )?;
        insert_named_key_descriptor(&self.pool, &new_descriptor, &wrapped, None, Some(key_name))
            .await?;

        // Both PG writes succeeded — update the in-memory cache.
        {
            let mut guard = self.cache.write().await;
            let key = guard
                .get_mut(&map_key)
                .ok_or_else(|| VaultError::KeyNotFound {
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

#[cfg(test)]
mod tests {
    //! Wrapping round-trip and AAD binding. The PostgreSQL paths need a live
    //! database and are covered by the migration/integration checks instead;
    //! what is pinned here is the part that made restarts destroy data — that
    //! key material is genuinely wrapped, and that a wrapped blob is bound to
    //! exactly one tenant, key and version.

    use super::*;

    fn root() -> [u8; 32] {
        std::array::from_fn(|i| (i as u8).wrapping_mul(7))
    }

    fn material() -> [u8; 32] {
        std::array::from_fn(|i| (i as u8).wrapping_add(3))
    }

    #[test]
    fn wrap_unwrap_round_trips() {
        let wrapped = wrap_material(&root(), "tenant-a", "billing", 1, &material()).unwrap();
        let got = unwrap_material(&root(), "tenant-a", "billing", 1, &wrapped).unwrap();
        assert_eq!(got, material());
    }

    #[test]
    fn wrapped_material_is_not_the_plaintext() {
        let wrapped = wrap_material(&root(), "t", "k", 1, &material()).unwrap();
        let raw = BASE64.decode(&wrapped).unwrap();
        assert!(
            !raw.windows(32).any(|w| w == material()),
            "key material must not appear in the stored blob"
        );
        assert_ne!(wrapped, "TODO:wrap_key_material");
    }

    #[test]
    fn a_wrapped_key_cannot_be_transplanted() {
        let wrapped = wrap_material(&root(), "tenant-a", "billing", 1, &material()).unwrap();

        // Another tenant's row, another key's row, another version's row.
        for (tenant, name, version) in [
            ("tenant-b", "billing", 1),
            ("tenant-a", "payroll", 1),
            ("tenant-a", "billing", 2),
        ] {
            assert!(
                unwrap_material(&root(), tenant, name, version, &wrapped).is_err(),
                "AAD must bind the blob to {tenant}/{name}/v{version}"
            );
        }
    }

    #[test]
    fn a_different_root_key_cannot_unwrap() {
        let wrapped = wrap_material(&root(), "t", "k", 1, &material()).unwrap();
        assert!(unwrap_material(&[0xFF; 32], "t", "k", 1, &wrapped).is_err());
    }

    #[test]
    fn root_key_must_be_present_and_well_formed() {
        // The backend refuses to start rather than silently persisting
        // placeholders, which is what the old code did.
        std::env::remove_var(ROOT_KEY_ENV);
        assert!(load_root_key().is_err(), "missing root key must fail");

        std::env::set_var(ROOT_KEY_ENV, "not!base64!");
        assert!(load_root_key().is_err(), "malformed root key must fail");

        std::env::set_var(ROOT_KEY_ENV, BASE64.encode([0u8; 16]));
        assert!(load_root_key().is_err(), "short root key must fail");

        std::env::set_var(ROOT_KEY_ENV, BASE64.encode(root()));
        assert_eq!(*load_root_key().unwrap(), root());
        std::env::remove_var(ROOT_KEY_ENV);
    }
}
