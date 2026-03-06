//! KEK hierarchy management for the crypto-service.
//!
//! The key hierarchy is:
//!   RootKEK (loaded from VAULT_ROOT_KEY env var at startup)
//!     -> TenantKEK (generated on first request per tenant, wrapped under RootKEK)
//!       -> DEK (generated per-encrypt, wrapped under TenantKEK)
//!
//! All key material in memory is held in `Zeroizing` wrappers so it is wiped on drop.
//! In production the TenantKEKs and their wrapped forms would be persisted to a database;
//! this implementation holds them in memory for the initial service iteration.

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

/// A tenant's Key Encryption Key entry kept in memory.
// `version` and `wrapped_kek_b64` are written now and will be read when
// persistence (DB storage) is wired up in a future iteration.
#[allow(dead_code)]
#[derive(Debug)]
struct TenantKekEntry {
    /// The 32-byte tenant KEK in plaintext form (only held for active use).
    raw_kek: Zeroizing<[u8; 32]>,
    /// The tenant KEK wrapped (encrypted) under the root KEK, for persistence/re-hydration.
    /// Format: base64(nonce || AES-256-GCM ciphertext).
    wrapped_kek_b64: String,
    /// Monotonically increasing version incremented on rotation.
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
    /// String identifier for the DEK; stored here for completeness.
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
}

// Zeroizing<[u8; N]> requires explicit deref (&*) to coerce to &[u8];
// auto-deref does not bridge Deref<Target=[u8; N]> to the unsized slice.
#[allow(clippy::explicit_auto_deref)]
impl KekStore {
    /// Initialise the store by loading the root KEK from the `VAULT_ROOT_KEY` env var.
    ///
    /// `VAULT_ROOT_KEY` must be a standard base64-encoded 32-byte key.
    /// Returns a `VaultError::Internal` if the variable is missing or malformed.
    pub fn from_env() -> Result<Self, VaultError> {
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

        info!("Root KEK loaded from environment variable");

        Ok(Self {
            inner: Arc::new(KekStoreInner {
                root_kek,
                tenant_keks: RwLock::new(HashMap::new()),
                deks: RwLock::new(HashMap::new()),
            }),
        })
    }

    /// Return the tenant KEK for the given tenant, generating and wrapping it
    /// under the root KEK if this is the first request for that tenant.
    ///
    /// This method is idempotent: multiple concurrent callers for the same tenant
    /// will converge on the same entry due to the write-lock upgrade strategy.
    pub async fn get_or_create_tenant_kek(
        &self,
        tenant_id: &str,
    ) -> Result<Zeroizing<[u8; 32]>, VaultError> {
        // Fast path: tenant KEK already exists.
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
            wrapped_kek_b64: envelope.ciphertext_b64,
            version: 1,
        };

        debug!(tenant_id, "Generated new tenant KEK (version 1)");
        writer.insert(tenant_id.to_string(), entry);

        let mut out = Zeroizing::new([0u8; 32]);
        out.copy_from_slice(&*raw_kek);
        Ok(out)
    }

    /// Generate a new DEK for the given tenant, wrap it under the tenant KEK,
    /// and register it in the store. Returns the new [`DekEntry`].
    pub async fn generate_and_store_dek(
        &self,
        tenant_id: &str,
        context: &str,
    ) -> Result<String, VaultError> {
        let tenant_kek = self.get_or_create_tenant_kek(tenant_id).await?;

        // Generate a random 32-byte DEK.
        let raw_dek = generate_random_32_bytes()?;

        // Wrap the DEK under the tenant KEK. AAD binds the wrapped DEK to its context.
        let aad = format!("dek:{tenant_id}:{context}");
        let envelope = encrypt_with_dek(&tenant_kek, &*raw_dek, aad.as_bytes())?;

        let key_id = Uuid::now_v7().to_string();

        let mut raw_dek_stored = Zeroizing::new([0u8; 32]);
        raw_dek_stored.copy_from_slice(&*raw_dek);

        let entry = DekEntry {
            raw_dek: raw_dek_stored,
            wrapped_dek_b64: envelope.ciphertext_b64,
            tenant_id: tenant_id.to_string(),
            version: 1,
            key_id: key_id.clone(),
        };

        debug!(tenant_id, key_id, "Generated and stored new DEK");

        self.inner.deks.write().await.insert(key_id.clone(), entry);

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

        let aad = format!("dek:{tenant_id}:rotation:{key_id}");
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
            entry.wrapped_dek_b64 = envelope.ciphertext_b64;
            entry.version = new_version;

            new_version
        };

        warn!(
            tenant_id,
            key_id,
            new_version,
            "DEK rotated — existing ciphertext encrypted under the previous version must be re-encrypted"
        );

        Ok(new_version)
    }

    /// Unwrap a tenant KEK that was previously wrapped under the root KEK.
    /// Used to re-hydrate tenant KEKs from persistent storage (not yet wired up).
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
