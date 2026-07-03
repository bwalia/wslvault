//! CA private key protection via envelope encryption.
//!
//! CA private keys are encrypted at rest using AES-256-GCM (the same envelope
//! format used throughout the platform in `wslvault_core::crypto::envelope`).
//! The wrapping key is the service-level root KEK loaded from the
//! `PKI_ROOT_KEY` environment variable (standard base64-encoded 32 bytes).
//!
//! # Threat model
//!
//! An attacker who gains read access to the `pki_ca` table cannot recover CA
//! private key material without also compromising `PKI_ROOT_KEY`.  The AAD
//! binds each wrapped key blob to its specific `tenant_id`, preventing
//! ciphertext-transplanting attacks across tenants.
//!
//! # Key rotation
//!
//! The `key_version` column in `pki_ca` records which version of `PKI_ROOT_KEY`
//! was used for wrapping, enabling a future rotation sweep that re-wraps all
//! tenant CA keys under a new root KEK without requiring CA re-issuance.

use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine as _;
use zeroize::Zeroizing;

use wslvault_core::crypto::envelope::{decrypt_with_dek, encrypt_with_dek};
use wslvault_core::error::VaultError;

use crate::error::PkiError;

/// Service-level root KEK, loaded once at startup from `PKI_ROOT_KEY`.
///
/// Wrapped in `Zeroizing` so the bytes are wiped if `RootKek` is dropped
/// (e.g. during a hot-reload in test code).
pub struct RootKek {
    raw: Zeroizing<[u8; 32]>,
    /// Monotonically increasing version label persisted alongside each wrapped
    /// CA key so future rotation sweeps can skip already-current blobs.
    pub version: i32,
}

impl RootKek {
    /// Load the root KEK from the `PKI_ROOT_KEY` environment variable.
    ///
    /// `PKI_ROOT_KEY` must be a standard base64-encoded 32-byte secret.
    /// `PKI_ROOT_KEY_VERSION` is an optional integer (defaults to 1) that
    /// identifies this particular key version for rotation tracking.
    ///
    /// # Errors
    ///
    /// Returns `PkiError::KeyEncryptionError` if the variable is absent,
    /// not valid base64, or does not decode to exactly 32 bytes.
    pub fn from_env() -> Result<Self, PkiError> {
        let encoded = std::env::var("PKI_ROOT_KEY").map_err(|_| {
            PkiError::KeyEncryptionError {
                reason: "PKI_ROOT_KEY environment variable is not set".into(),
            }
        })?;

        let raw_bytes = BASE64
            .decode(encoded.trim())
            .map_err(|e| PkiError::KeyEncryptionError {
                reason: format!("PKI_ROOT_KEY is not valid base64: {e}"),
            })?;

        if raw_bytes.len() != 32 {
            return Err(PkiError::KeyEncryptionError {
                reason: format!(
                    "PKI_ROOT_KEY must decode to exactly 32 bytes, got {}",
                    raw_bytes.len()
                ),
            });
        }

        let mut raw = Zeroizing::new([0u8; 32]);
        raw.copy_from_slice(&raw_bytes);

        let version = std::env::var("PKI_ROOT_KEY_VERSION")
            .ok()
            .and_then(|v| v.parse::<i32>().ok())
            .unwrap_or(1);

        Ok(Self { raw, version })
    }

    /// Construct directly from raw bytes (useful in tests).
    #[cfg(test)]
    pub fn new_for_test(raw_bytes: [u8; 32]) -> Self {
        Self {
            raw: Zeroizing::new(raw_bytes),
            version: 1,
        }
    }

    /// Encrypt a CA private key PEM string.
    ///
    /// The AAD binds the ciphertext to `tenant_id`, preventing transplanting
    /// the encrypted blob to a different tenant's CA record.
    ///
    /// Returns the base64-encoded `nonce‖ciphertext‖tag` envelope.
    pub fn encrypt_ca_key(
        &self,
        tenant_id: &str,
        key_pem: &str,
    ) -> Result<String, PkiError> {
        let aad = build_aad(tenant_id);
        let envelope = encrypt_with_dek(&self.raw, key_pem.as_bytes(), aad.as_bytes())
            .map_err(|e: VaultError| PkiError::KeyEncryptionError {
                reason: format!("failed to encrypt CA key: {e}"),
            })?;
        Ok(envelope.ciphertext_b64)
    }

    /// Decrypt a CA private key envelope previously produced by `encrypt_ca_key`.
    ///
    /// Returns a `Zeroizing` byte buffer so the PEM bytes are wiped when the
    /// caller drops the returned value.
    pub fn decrypt_ca_key(
        &self,
        tenant_id: &str,
        encrypted_b64: &str,
    ) -> Result<Zeroizing<Vec<u8>>, PkiError> {
        let aad = build_aad(tenant_id);
        let plaintext =
            decrypt_with_dek(&self.raw, encrypted_b64, aad.as_bytes()).map_err(|e: VaultError| {
                PkiError::KeyEncryptionError {
                    reason: format!("failed to decrypt CA key: {e}"),
                }
            })?;
        Ok(plaintext)
    }
}

/// Build the Additional Associated Data string that binds an encrypted CA key
/// to a specific tenant so transplanting to another tenant's row fails auth.
fn build_aad(tenant_id: &str) -> String {
    format!("pki-ca-key:{tenant_id}")
}
