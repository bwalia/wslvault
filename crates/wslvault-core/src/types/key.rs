//! Cryptographic key domain types for the envelope encryption hierarchy.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;
use zeroize::{Zeroize, ZeroizeOnDrop};

/// Newtype wrapper around UUID for type-safe key references.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct KeyId(pub Uuid);

impl KeyId {
    pub fn new() -> Self {
        Self(Uuid::now_v7())
    }
}

impl Default for KeyId {
    fn default() -> Self {
        Self::new()
    }
}

impl std::fmt::Display for KeyId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl std::str::FromStr for KeyId {
    type Err = uuid::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(Self(Uuid::parse_str(s)?))
    }
}

/// Symmetric encryption algorithm used for a given key.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum KeyAlgorithm {
    Aes256Gcm,
    ChaCha20Poly1305,
    XChaCha20Poly1305,
}

/// Purpose classification — determines which operations a key may perform.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum KeyPurpose {
    /// Root Key Encryption Key: encrypts TenantKeks; stored in HSM or KMS.
    RootKek,
    /// Tenant Key Encryption Key: encrypts DEKs for that tenant.
    TenantKek,
    /// Data Encryption Key: encrypts actual secret values.
    DataEncryption,
    /// Asymmetric signing key for transit engine and audit log integrity.
    Signing,
    /// Transit engine encryption key for application-layer encryption.
    Transit,
}

/// Lifecycle state of a key.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum KeyState {
    /// Key is the current primary for new encryptions.
    Active,
    /// New key is primary; this key still decrypts old data during rotation window.
    RotatingOut,
    /// Cannot encrypt; can only decrypt for re-encryption migration.
    Retired,
    /// Key material has been wiped; all data encrypted with it is unrecoverable.
    Destroyed,
}

/// Versioned key descriptor (metadata only — no raw key material).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeyDescriptor {
    pub id: KeyId,
    pub version: u32,
    pub algorithm: KeyAlgorithm,
    pub purpose: KeyPurpose,
    pub state: KeyState,
    /// None for root KEK; set for tenant-scoped keys.
    pub tenant_id: Option<String>,
    pub created_at: DateTime<Utc>,
    pub rotated_at: Option<DateTime<Utc>>,
    pub expires_at: Option<DateTime<Utc>>,
}

/// Holds raw key material in memory. Implements ZeroizeOnDrop so the material
/// is wiped from process memory when the struct is dropped.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct KeyMaterial {
    /// Identifier linking back to the KeyDescriptor.
    #[zeroize(skip)]
    pub id: String,
    /// Key version number.
    #[zeroize(skip)]
    pub version: u32,
    /// Algorithm this key is for; not secret, but carried for convenience.
    #[zeroize(skip)]
    pub algorithm: KeyAlgorithm,
    /// Raw symmetric key bytes (always 32 bytes for AES-256-GCM / ChaCha20).
    pub raw_key: Vec<u8>,
}

// Custom Debug to avoid leaking key material in logs.
impl std::fmt::Debug for KeyMaterial {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("KeyMaterial")
            .field("id", &self.id)
            .field("version", &self.version)
            .field("algorithm", &self.algorithm)
            .field("raw_key", &"[REDACTED]")
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn key_material_debug_redacts() {
        let km = KeyMaterial {
            id: "test".into(),
            version: 1,
            algorithm: KeyAlgorithm::Aes256Gcm,
            raw_key: vec![0xDE, 0xAD, 0xBE, 0xEF],
        };
        let debug = format!("{:?}", km);
        assert!(debug.contains("[REDACTED]"));
        assert!(!debug.contains("DEAD"));
    }
}
