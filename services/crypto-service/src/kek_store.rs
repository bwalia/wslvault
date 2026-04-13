//! KEK hierarchy management for the crypto-service.
//!
//! The key hierarchy is:
//!   RootKEK (loaded from VAULT_ROOT_KEY env var at startup)
//!     -> TenantKEK (generated on first request per tenant, wrapped under RootKEK)
//!       -> DEK (generated per-encrypt, wrapped under TenantKEK)
//!
//! All key material in memory is held in `Zeroizing` wrappers so it is wiped on drop.
//!
//! ## Persistence strategy
//!
//! Raw key material is **never** written to the database.  Only the wrapped (AES-256-GCM
//! encrypted) forms are persisted, using the same envelope format as the in-memory
//! representations.  On startup, when a `DbPool` is present, `load_from_db` fetches
//! all active wrapped keys and unwraps them into the in-memory caches so that the
//! service survives pod restarts without losing tenant state.
//!
//! When no `DATABASE_URL` is set the store operates in ephemeral (in-memory only) mode,
//! which remains fully supported for development and testing.

use std::collections::HashMap;
use std::sync::Arc;

use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine as _;
use rand::RngCore;
use tokio::sync::RwLock;
use tracing::{debug, info, warn};
use uuid::Uuid;
use zeroize::Zeroizing;

use wslvault_core::crypto::envelope::{decrypt_with_dek, encrypt_with_dek};
use wslvault_core::error::VaultError;
use wslvault_core::types::key::{
    KeyAlgorithm, KeyDescriptor, KeyId, KeyPurpose, KeyState,
};

use wslvault_storage::key_store::{
    insert_key_descriptor, list_active_keys_with_wrapped_key, update_key_state,
};
use wslvault_storage::pool::DbPool;

/// A tenant's Key Encryption Key entry kept in memory.
#[derive(Debug)]
struct TenantKekEntry {
    /// The 32-byte tenant KEK in plaintext form (only held for active use).
    raw_kek: Zeroizing<[u8; 32]>,
    /// The tenant KEK wrapped (encrypted) under the root KEK, for persistence/re-hydration.
    /// Format: base64(nonce || AES-256-GCM ciphertext).
    /// Retained so the in-memory state mirrors what is stored in the database.
    #[allow(dead_code)]
    wrapped_kek_b64: String,
    /// Monotonically increasing version incremented on rotation.
    /// Retained for future rotation support and diagnostic logging.
    #[allow(dead_code)]
    version: u32,
}

/// A DEK entry registered in the in-memory store.
#[derive(Debug)]
struct DekEntry {
    /// The raw 32-byte DEK, kept only for decryption use during its lifetime.
    raw_dek: Zeroizing<[u8; 32]>,
    /// The DEK wrapped under the owning tenant's active KEK.
    /// Format: base64(nonce || AES-256-GCM ciphertext).
    wrapped_dek_b64: String,
    /// Owning tenant.
    tenant_id: String,
    /// Monotonically increasing version (starts at 1).
    version: u32,
    /// String identifier for the DEK.
    #[allow(dead_code)]
    key_id: String,
}

/// Shared, thread-safe key store covering both tenant KEKs and DEKs.
#[derive(Clone, Debug)]
pub struct KekStore {
    inner: Arc<KekStoreInner>,
}

#[derive(Debug)]
struct KekStoreInner {
    /// Root KEK loaded from `VAULT_ROOT_KEY` at startup.
    root_kek: Zeroizing<[u8; 32]>,
    /// Tenant KEK map: tenant_id -> TenantKekEntry.
    tenant_keks: RwLock<HashMap<String, TenantKekEntry>>,
    /// DEK map: key_id -> DekEntry.
    deks: RwLock<HashMap<String, DekEntry>>,
    /// Optional database connection pool.  When `Some`, all key creation and
    /// rotation events are also persisted to PostgreSQL (wrapped keys only).
    /// When `None`, the store operates in ephemeral in-memory mode.
    db_pool: Option<DbPool>,
}

// Zeroizing<[u8; N]> requires explicit deref (&*) to coerce to &[u8];
// auto-deref does not bridge Deref<Target=[u8; N]> to the unsized slice.
#[allow(clippy::explicit_auto_deref)]
impl KekStore {
    /// Initialise the store by loading the root KEK from the `VAULT_ROOT_KEY` env var.
    ///
    /// `VAULT_ROOT_KEY` must be a standard base64-encoded 32-byte key.
    /// Returns a `VaultError::Internal` if the variable is missing or malformed.
    ///
    /// This constructor creates an ephemeral (in-memory only) store with no database
    /// connection.  Use [`KekStore::with_db`] when `DATABASE_URL` is available so that
    /// key state survives pod restarts.
    pub fn from_env() -> Result<Self, VaultError> {
        let root_kek = Self::load_root_kek_from_env()?;

        info!("Root KEK loaded from environment variable (ephemeral mode — no DB persistence)");

        Ok(Self {
            inner: Arc::new(KekStoreInner {
                root_kek,
                tenant_keks: RwLock::new(HashMap::new()),
                deks: RwLock::new(HashMap::new()),
                db_pool: None,
            }),
        })
    }

    /// Initialise the store with a database connection pool.
    ///
    /// Persists all newly generated and rotated keys (wrapped form only) to PostgreSQL
    /// so that the in-memory caches can be restored across restarts via [`load_from_db`].
    ///
    /// `root_kek_b64` is the standard base64-encoded 32-byte root KEK (identical to
    /// the value expected in `VAULT_ROOT_KEY`).
    pub fn with_db(root_kek_b64: &str, pool: DbPool) -> Result<Self, VaultError> {
        let raw_bytes = BASE64
            .decode(root_kek_b64.trim())
            .map_err(|e| VaultError::Internal {
                reason: format!("VAULT_ROOT_KEY is not valid base64: {e}"),
            })?;

        if raw_bytes.len() != 32 {
            return Err(VaultError::Internal {
                reason: format!(
                    "VAULT_ROOT_KEY must decode to exactly 32 bytes, got {}",
                    raw_bytes.len()
                ),
            });
        }

        let mut root_kek = Zeroizing::new([0u8; 32]);
        root_kek.copy_from_slice(&raw_bytes);

        info!("Root KEK loaded; KekStore initialised with database persistence");

        Ok(Self {
            inner: Arc::new(KekStoreInner {
                root_kek,
                tenant_keks: RwLock::new(HashMap::new()),
                deks: RwLock::new(HashMap::new()),
                db_pool: Some(pool),
            }),
        })
    }

    /// Restore in-memory key caches from the database.
    ///
    /// Loads all active tenant KEKs and DEKs persisted in PostgreSQL, unwraps their
    /// key material using the root KEK (for tenant KEKs) or the appropriate tenant KEK
    /// (for DEKs), and populates the in-memory caches.
    ///
    /// This method is a no-op when the store is running in ephemeral mode (no DB pool).
    ///
    /// # Security contract
    ///
    /// - Only wrapped key material is read from the database; raw key bytes never leave
    ///   this function's stack and are immediately placed in `Zeroizing` wrappers.
    /// - If a wrapped key cannot be unwrapped (e.g. corrupt or tampered envelope), that
    ///   entry is skipped with a warning rather than aborting the entire load.  This
    ///   allows the service to start even if a small number of persisted keys are
    ///   damaged, though operators should investigate any warnings.
    pub async fn load_from_db(&self) -> Result<(), VaultError> {
        let pool = match &self.inner.db_pool {
            Some(p) => p,
            None => {
                debug!("No DB pool configured; skipping load_from_db");
                return Ok(());
            }
        };

        // ---- 1. Load tenant KEKs ------------------------------------------------
        let tenant_kek_rows =
            list_active_keys_with_wrapped_key(pool, &KeyPurpose::TenantKek).await?;

        let mut kek_count: usize = 0;

        {
            let mut writer = self.inner.tenant_keks.write().await;

            for row in &tenant_kek_rows {
                let tenant_id = match &row.tenant_id {
                    Some(t) => t.clone(),
                    None => {
                        warn!(
                            key_id = %row.key_id,
                            "Tenant KEK row has no tenant_id — skipping"
                        );
                        continue;
                    }
                };

                // Unwrap the tenant KEK using the root KEK.
                let aad = format!("tenant-kek:{tenant_id}");
                let plaintext =
                    match decrypt_with_dek(&self.inner.root_kek, &row.wrapped_key, aad.as_bytes())
                    {
                        Ok(p) => p,
                        Err(e) => {
                            warn!(
                                key_id = %row.key_id,
                                tenant_id = %tenant_id,
                                error = %e,
                                "Failed to unwrap tenant KEK — skipping (investigate immediately)"
                            );
                            continue;
                        }
                    };

                if plaintext.len() != 32 {
                    warn!(
                        key_id = %row.key_id,
                        len = plaintext.len(),
                        "Unwrapped tenant KEK has unexpected length — skipping"
                    );
                    continue;
                }

                let mut raw_kek = Zeroizing::new([0u8; 32]);
                raw_kek.copy_from_slice(&plaintext);

                let entry = TenantKekEntry {
                    raw_kek,
                    wrapped_kek_b64: row.wrapped_key.clone(),
                    version: row.version,
                };

                writer.insert(tenant_id.clone(), entry);
                kek_count += 1;
            }
        }

        info!(loaded = kek_count, "Tenant KEKs loaded from database");

        // ---- 2. Load DEKs -------------------------------------------------------
        let dek_rows = list_active_keys_with_wrapped_key(pool, &KeyPurpose::DataEncryption).await?;

        let mut dek_count: usize = 0;

        {
            // Take a read lock on the tenant KEK cache so we can unwrap DEKs.
            let kek_reader = self.inner.tenant_keks.read().await;
            let mut dek_writer = self.inner.deks.write().await;

            for row in &dek_rows {
                let tenant_id = match &row.tenant_id {
                    Some(t) => t.clone(),
                    None => {
                        warn!(
                            key_id = %row.key_id,
                            "DEK row has no tenant_id — skipping"
                        );
                        continue;
                    }
                };

                // Look up the owning tenant's KEK so we can unwrap the DEK.
                let tenant_kek_entry = match kek_reader.get(&tenant_id) {
                    Some(e) => e,
                    None => {
                        warn!(
                            key_id = %row.key_id,
                            tenant_id = %tenant_id,
                            "No in-memory tenant KEK found for DEK's tenant — skipping"
                        );
                        continue;
                    }
                };

                // DEKs are stored without a stable AAD context because each DEK was
                // originally wrapped with a unique per-DEK context string.  We store
                // the AAD alongside the wrapped key during insert; but since we
                // cannot recover the original context string from the DB alone, we
                // use a stable per-key-id AAD for DEKs loaded at startup.  This is
                // consistent with the rotation AAD pattern already in use.
                let aad = format!("dek:reload:{}", row.key_id);
                let plaintext = match decrypt_with_dek(
                    &tenant_kek_entry.raw_kek,
                    &row.wrapped_key,
                    aad.as_bytes(),
                ) {
                    Ok(p) => p,
                    Err(e) => {
                        warn!(
                            key_id = %row.key_id,
                            tenant_id = %tenant_id,
                            error = %e,
                            "Failed to unwrap DEK — skipping (investigate immediately)"
                        );
                        continue;
                    }
                };

                if plaintext.len() != 32 {
                    warn!(
                        key_id = %row.key_id,
                        len = plaintext.len(),
                        "Unwrapped DEK has unexpected length — skipping"
                    );
                    continue;
                }

                let mut raw_dek = Zeroizing::new([0u8; 32]);
                raw_dek.copy_from_slice(&plaintext);

                let entry = DekEntry {
                    raw_dek,
                    wrapped_dek_b64: row.wrapped_key.clone(),
                    tenant_id: tenant_id.clone(),
                    version: row.version,
                    key_id: row.key_id.clone(),
                };

                dek_writer.insert(row.key_id.clone(), entry);
                dek_count += 1;
            }
        }

        info!(loaded = dek_count, "DEKs loaded from database");

        Ok(())
    }

    /// Return the tenant KEK for the given tenant, generating and wrapping it
    /// under the root KEK if this is the first request for that tenant.
    ///
    /// This method is idempotent: multiple concurrent callers for the same tenant
    /// will converge on the same entry due to the write-lock upgrade strategy.
    ///
    /// When a DB pool is configured, newly created tenant KEKs are persisted
    /// (wrapped form only) to PostgreSQL before being returned.
    pub async fn get_or_create_tenant_kek(
        &self,
        tenant_id: &str,
    ) -> Result<Zeroizing<[u8; 32]>, VaultError> {
        // Fast path: tenant KEK already exists in memory.
        {
            let reader = self.inner.tenant_keks.read().await;
            if let Some(entry) = reader.get(tenant_id) {
                let mut out = Zeroizing::new([0u8; 32]);
                out.copy_from_slice(&*entry.raw_kek);
                return Ok(out);
            }
        }

        // Slow path: generate a new tenant KEK and wrap it under the root KEK.
        let mut writer = self.inner.tenant_keks.write().await;

        // Re-check after acquiring the write lock to avoid a double-insert race.
        if let Some(entry) = writer.get(tenant_id) {
            let mut out = Zeroizing::new([0u8; 32]);
            out.copy_from_slice(&*entry.raw_kek);
            return Ok(out);
        }

        // Generate a random 32-byte tenant KEK.
        let raw_kek = generate_random_32_bytes()?;

        // Wrap the new tenant KEK under the root KEK.
        // AAD binds the wrapped key to this tenant so it cannot be transplanted.
        let aad = format!("tenant-kek:{tenant_id}");
        let envelope = encrypt_with_dek(&self.inner.root_kek, &*raw_kek, aad.as_bytes())?;

        let mut raw_kek_stored = Zeroizing::new([0u8; 32]);
        raw_kek_stored.copy_from_slice(&*raw_kek);

        let entry = TenantKekEntry {
            raw_kek: raw_kek_stored,
            wrapped_kek_b64: envelope.ciphertext_b64.clone(),
            version: 1,
        };

        debug!(tenant_id, "Generated new tenant KEK (version 1)");
        writer.insert(tenant_id.to_string(), entry);

        // Persist the wrapped tenant KEK to PostgreSQL if a DB pool is available.
        // We must release the write lock first to avoid holding it across the async
        // DB call, so we drop the writer here and rely on the double-check above to
        // prevent duplicate inserts in any concurrent scenario.
        drop(writer);

        if let Some(pool) = &self.inner.db_pool {
            let tenant_uuid = Uuid::parse_str(tenant_id).map_err(|e| VaultError::Internal {
                reason: format!("tenant_id is not a valid UUID: {e}"),
            })?;

            let desc = KeyDescriptor {
                id: KeyId::new(),
                version: 1,
                algorithm: KeyAlgorithm::Aes256Gcm,
                purpose: KeyPurpose::TenantKek,
                state: KeyState::Active,
                tenant_id: Some(tenant_id.to_string()),
                created_at: chrono::Utc::now(),
                rotated_at: None,
                expires_at: None,
            };

            insert_key_descriptor(pool, &desc, &envelope.ciphertext_b64, None)
                .await
                .map_err(|e| VaultError::Internal {
                    reason: format!("Failed to persist tenant KEK to DB: {e}"),
                })?;

            debug!(tenant_id, "Tenant KEK persisted to database");
        }

        let mut out = Zeroizing::new([0u8; 32]);
        out.copy_from_slice(&*raw_kek);
        Ok(out)
    }

    /// Generate a new DEK for the given tenant, wrap it under the tenant KEK,
    /// and register it in the store.  Returns the new key_id.
    ///
    /// When a DB pool is configured, the wrapped DEK descriptor is also written
    /// to PostgreSQL before this function returns.
    pub async fn generate_and_store_dek(
        &self,
        tenant_id: &str,
        context: &str,
    ) -> Result<String, VaultError> {
        let tenant_kek = self.get_or_create_tenant_kek(tenant_id).await?;

        // Generate a random 32-byte DEK.
        let raw_dek = generate_random_32_bytes()?;

        // Assign a stable UUID for this DEK before wrapping so the UUID can be
        // embedded in the AAD, binding the wrapped form to exactly this key_id.
        // This means the reload AAD at startup ("dek:reload:<key_id>") will not
        // match the original context AAD, so DEKs persisted here can only be
        // unwrapped with the reload path in `load_from_db`.
        let key_id = Uuid::now_v7().to_string();

        // Wrap the DEK under the tenant KEK.  AAD binds the wrapped DEK to its
        // stable key_id so it cannot be transplanted to a different DEK entry.
        let aad = format!("dek:reload:{key_id}");
        let envelope = encrypt_with_dek(&tenant_kek, &*raw_dek, aad.as_bytes())?;

        let mut raw_dek_stored = Zeroizing::new([0u8; 32]);
        raw_dek_stored.copy_from_slice(&*raw_dek);

        let entry = DekEntry {
            raw_dek: raw_dek_stored,
            wrapped_dek_b64: envelope.ciphertext_b64.clone(),
            tenant_id: tenant_id.to_string(),
            version: 1,
            key_id: key_id.clone(),
        };

        debug!(tenant_id, key_id, context, "Generated and stored new DEK");

        self.inner.deks.write().await.insert(key_id.clone(), entry);

        // Persist the wrapped DEK to PostgreSQL if a DB pool is available.
        if let Some(pool) = &self.inner.db_pool {
            let tenant_uuid = Uuid::parse_str(tenant_id).map_err(|e| VaultError::Internal {
                reason: format!("tenant_id is not a valid UUID: {e}"),
            })?;

            let dek_uuid = Uuid::parse_str(&key_id).map_err(|e| VaultError::Internal {
                reason: format!("Generated key_id is not a valid UUID: {e}"),
            })?;

            let desc = KeyDescriptor {
                id: KeyId(dek_uuid),
                version: 1,
                algorithm: KeyAlgorithm::Aes256Gcm,
                purpose: KeyPurpose::DataEncryption,
                state: KeyState::Active,
                tenant_id: Some(tenant_id.to_string()),
                created_at: chrono::Utc::now(),
                rotated_at: None,
                expires_at: None,
            };

            insert_key_descriptor(pool, &desc, &envelope.ciphertext_b64, None)
                .await
                .map_err(|e| VaultError::Internal {
                    reason: format!("Failed to persist DEK to DB: {e}"),
                })?;

            debug!(tenant_id, key_id, "DEK persisted to database");
        }

        Ok(key_id)
    }

    /// Look up an existing DEK by its key_id. Returns a `VaultError::KeyNotFound`
    /// if no DEK with that id is registered.
    pub async fn get_dek(&self, key_id: &str) -> Result<Zeroizing<[u8; 32]>, VaultError> {
        let reader = self.inner.deks.read().await;
        let entry = reader.get(key_id).ok_or_else(|| VaultError::KeyNotFound {
            key_id: key_id.to_string(),
        })?;

        let mut out = Zeroizing::new([0u8; 32]);
        out.copy_from_slice(&*entry.raw_dek);
        Ok(out)
    }

    /// Return the wrapped DEK (base64 envelope) and version for a key_id.
    /// Used when returning `wrapped_dek` in `GenerateDekResponse`.
    pub async fn get_dek_metadata(&self, key_id: &str) -> Result<(String, u32), VaultError> {
        let reader = self.inner.deks.read().await;
        let entry = reader.get(key_id).ok_or_else(|| VaultError::KeyNotFound {
            key_id: key_id.to_string(),
        })?;
        Ok((entry.wrapped_dek_b64.clone(), entry.version))
    }

    /// Rotate the DEK identified by `key_id` for the given tenant.
    ///
    /// Rotation generates a brand-new DEK and wraps it under the current tenant KEK.
    /// The old DEK is replaced in the store and its version is incremented.
    ///
    /// When a DB pool is configured:
    /// - The old descriptor is transitioned to `RotatingOut` state.
    /// - A new descriptor is inserted for the rotated key.
    ///
    /// Data previously encrypted with the old DEK version remains decryptable during
    /// a re-encryption migration window (not implemented here — the old raw_dek is
    /// discarded from memory; in production it would be retained for a grace period).
    pub async fn rotate_dek(&self, tenant_id: &str, key_id: &str) -> Result<u32, VaultError> {
        // Verify the key belongs to this tenant.
        {
            let reader = self.inner.deks.read().await;
            let entry = reader.get(key_id).ok_or_else(|| VaultError::KeyNotFound {
                key_id: key_id.to_string(),
            })?;
            if entry.tenant_id != tenant_id {
                return Err(VaultError::PermissionDenied {
                    resource: format!("key:{key_id}"),
                    reason: "key does not belong to the requesting tenant".into(),
                });
            }
        }

        let tenant_kek = self.get_or_create_tenant_kek(tenant_id).await?;
        let new_raw_dek = generate_random_32_bytes()?;

        // Use the stable reload AAD so the rotated DEK can be unwrapped by load_from_db.
        let aad = format!("dek:reload:{key_id}");
        let envelope = encrypt_with_dek(&tenant_kek, &*new_raw_dek, aad.as_bytes())?;

        let new_version = {
            let mut writer = self.inner.deks.write().await;
            let entry = writer
                .get_mut(key_id)
                .ok_or_else(|| VaultError::KeyNotFound {
                    key_id: key_id.to_string(),
                })?;

            let new_version = entry.version + 1;

            let mut new_raw_stored = Zeroizing::new([0u8; 32]);
            new_raw_stored.copy_from_slice(&*new_raw_dek);

            entry.raw_dek = new_raw_stored;
            entry.wrapped_dek_b64 = envelope.ciphertext_b64.clone();
            entry.version = new_version;

            new_version
        };

        warn!(
            tenant_id,
            key_id,
            new_version,
            "DEK rotated — existing ciphertext encrypted under the previous version must be re-encrypted"
        );

        // Persist rotation to the database when a pool is available.
        // Strategy: mark the old descriptor as RotatingOut and insert a new one.
        if let Some(pool) = &self.inner.db_pool {
            let key_uuid = Uuid::parse_str(key_id).map_err(|e| VaultError::Internal {
                reason: format!("key_id is not a valid UUID: {e}"),
            })?;

            let tenant_uuid = Uuid::parse_str(tenant_id).map_err(|e| VaultError::Internal {
                reason: format!("tenant_id is not a valid UUID: {e}"),
            })?;

            // Transition the current active descriptor to RotatingOut.
            update_key_state(pool, &KeyId(key_uuid), &KeyState::RotatingOut)
                .await
                .map_err(|e| VaultError::Internal {
                    reason: format!("Failed to update old DEK state in DB: {e}"),
                })?;

            // Insert a new active descriptor for the rotated key, reusing the same
            // key_id UUID so all in-memory callers continue to reference it by the
            // same identifier.
            let desc = KeyDescriptor {
                id: KeyId(key_uuid),
                version: new_version,
                algorithm: KeyAlgorithm::Aes256Gcm,
                purpose: KeyPurpose::DataEncryption,
                state: KeyState::Active,
                tenant_id: Some(tenant_id.to_string()),
                created_at: chrono::Utc::now(),
                rotated_at: None,
                expires_at: None,
            };

            insert_key_descriptor(pool, &desc, &envelope.ciphertext_b64, None)
                .await
                .map_err(|e| VaultError::Internal {
                    reason: format!("Failed to persist rotated DEK to DB: {e}"),
                })?;

            debug!(tenant_id, key_id, new_version, "Rotated DEK persisted to database");
        }

        Ok(new_version)
    }

    /// Unwrap a tenant KEK that was previously wrapped under the root KEK.
    ///
    /// Available for callers that have retrieved a wrapped KEK blob from an
    /// external source (e.g. a backup or audit trail) and need to verify it
    /// can be unwrapped with the current root KEK.  Not used in the standard
    /// `load_from_db` flow, which handles unwrapping internally.
    #[allow(dead_code)]
    pub fn unwrap_tenant_kek(
        &self,
        tenant_id: &str,
        wrapped_kek_b64: &str,
    ) -> Result<Zeroizing<[u8; 32]>, VaultError> {
        let aad = format!("tenant-kek:{tenant_id}");
        let plaintext = decrypt_with_dek(&self.inner.root_kek, wrapped_kek_b64, aad.as_bytes())?;

        if plaintext.len() != 32 {
            return Err(VaultError::Internal {
                reason: format!(
                    "Unwrapped tenant KEK has unexpected length {}",
                    plaintext.len()
                ),
            });
        }

        let mut out = Zeroizing::new([0u8; 32]);
        out.copy_from_slice(&plaintext);
        Ok(out)
    }

    // -------------------------------------------------------------------------
    // Private helpers
    // -------------------------------------------------------------------------

    /// Decode and validate the base64-encoded root KEK from the environment.
    fn load_root_kek_from_env() -> Result<Zeroizing<[u8; 32]>, VaultError> {
        let encoded = std::env::var("VAULT_ROOT_KEY").map_err(|_| VaultError::Internal {
            reason: "VAULT_ROOT_KEY environment variable is not set".into(),
        })?;

        let raw_bytes = BASE64
            .decode(encoded.trim())
            .map_err(|e| VaultError::Internal {
                reason: format!("VAULT_ROOT_KEY is not valid base64: {e}"),
            })?;

        if raw_bytes.len() != 32 {
            return Err(VaultError::Internal {
                reason: format!(
                    "VAULT_ROOT_KEY must decode to exactly 32 bytes, got {}",
                    raw_bytes.len()
                ),
            });
        }

        let mut root_kek = Zeroizing::new([0u8; 32]);
        root_kek.copy_from_slice(&raw_bytes);
        Ok(root_kek)
    }
}

/// Generate 32 cryptographically random bytes using the OS CSPRNG.
fn generate_random_32_bytes() -> Result<Zeroizing<[u8; 32]>, VaultError> {
    let mut bytes = Zeroizing::new([0u8; 32]);
    rand::thread_rng()
        .try_fill_bytes(&mut *bytes)
        .map_err(|e| VaultError::EncryptionFailed {
            reason: format!("CSPRNG key generation failed: {e}"),
        })?;
    Ok(bytes)
}
