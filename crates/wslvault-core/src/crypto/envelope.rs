//! Envelope encryption implementation.
//!
//! The hierarchy is:
//!   RootKEK (HSM/KMS)
//!     -> TenantKEK (encrypted under RootKEK, stored in crypto-service)
//!       -> DEK (encrypted under TenantKEK, stored alongside secret metadata)
//!         -> Secret (encrypted under DEK, stored in PostgreSQL)
//!
//! This module handles the lowest level: DEK -> Secret encryption/decryption
//! using AES-256-GCM. The crypto-service handles the KEK wrapping operations
//! at higher layers of the hierarchy.

use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::{Aes256Gcm, Key, Nonce};
use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine as _;
use zeroize::Zeroizing;

use crate::crypto::nonce::generate_aes_gcm_nonce;
use crate::error::VaultError;

/// Ciphertext envelope produced by `encrypt_with_dek`.
/// Serialized as base64(nonce || ciphertext || GCM tag) for compact storage.
#[derive(Debug)]
pub struct EncryptedEnvelope {
    /// The opaque serialized form stored in PostgreSQL.
    pub ciphertext_b64: String,
    /// The nonce/IV used (stored prepended to ciphertext in the b64 blob).
    pub nonce: [u8; 12],
}

/// Encrypt `plaintext` with the given 32-byte AES-256-GCM DEK.
///
/// `aad` is Additional Associated Data — typically the secret path + tenant_id.
/// Including AAD binds the ciphertext to its storage location, preventing
/// an attacker from transplanting an encrypted value to a different path.
pub fn encrypt_with_dek(
    dek: &[u8; 32],
    plaintext: &[u8],
    aad: &[u8],
) -> Result<EncryptedEnvelope, VaultError> {
    let key = Key::<Aes256Gcm>::from_slice(dek);
    let cipher = Aes256Gcm::new(key);

    let nonce_bytes = generate_aes_gcm_nonce()?;
    let nonce = Nonce::from_slice(&nonce_bytes);

    let payload = Payload {
        msg: plaintext,
        aad,
    };

    let ciphertext = cipher
        .encrypt(nonce, payload)
        .map_err(|_| VaultError::EncryptionFailed {
            reason: "AES-256-GCM encryption failed".into(),
        })?;

    // Wire format: 12-byte nonce prepended to ciphertext+tag.
    let mut combined = Vec::with_capacity(12 + ciphertext.len());
    combined.extend_from_slice(&nonce_bytes);
    combined.extend_from_slice(&ciphertext);

    Ok(EncryptedEnvelope {
        ciphertext_b64: BASE64.encode(&combined),
        nonce: nonce_bytes,
    })
}

/// Decrypt a ciphertext envelope produced by `encrypt_with_dek`.
/// Returns a `Zeroizing<Vec<u8>>` so the plaintext is wiped on drop.
pub fn decrypt_with_dek(
    dek: &[u8; 32],
    ciphertext_b64: &str,
    aad: &[u8],
) -> Result<Zeroizing<Vec<u8>>, VaultError> {
    let combined = BASE64
        .decode(ciphertext_b64)
        .map_err(|_| VaultError::DecryptionFailed)?;

    if combined.len() < 12 {
        return Err(VaultError::DecryptionFailed);
    }

    let (nonce_bytes, ciphertext) = combined.split_at(12);
    let key = Key::<Aes256Gcm>::from_slice(dek);
    let cipher = Aes256Gcm::new(key);
    let nonce = Nonce::from_slice(nonce_bytes);

    let payload = Payload {
        msg: ciphertext,
        aad,
    };

    let plaintext = cipher
        .decrypt(nonce, payload)
        .map_err(|_| VaultError::DecryptionFailed)?;

    Ok(Zeroizing::new(plaintext))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_dek() -> [u8; 32] {
        let mut key = [0u8; 32];
        for (i, byte) in key.iter_mut().enumerate() {
            *byte = i as u8;
        }
        key
    }

    #[test]
    fn encrypt_decrypt_roundtrip() {
        let dek = test_dek();
        let plaintext = b"super-secret-password-123";
        let aad = b"tenant-1:prod/database/password";

        let envelope = encrypt_with_dek(&dek, plaintext, aad).unwrap();
        let decrypted = decrypt_with_dek(&dek, &envelope.ciphertext_b64, aad).unwrap();

        assert_eq!(&*decrypted, plaintext);
    }

    #[test]
    fn wrong_key_fails_decryption() {
        let dek = test_dek();
        let plaintext = b"my-secret";
        let aad = b"tenant-1:path";

        let envelope = encrypt_with_dek(&dek, plaintext, aad).unwrap();

        let wrong_key = [0xFF; 32];
        let result = decrypt_with_dek(&wrong_key, &envelope.ciphertext_b64, aad);
        assert!(result.is_err());
    }

    #[test]
    fn wrong_aad_fails_decryption() {
        let dek = test_dek();
        let plaintext = b"my-secret";
        let aad = b"tenant-1:path-a";

        let envelope = encrypt_with_dek(&dek, plaintext, aad).unwrap();

        let wrong_aad = b"tenant-2:path-b";
        let result = decrypt_with_dek(&dek, &envelope.ciphertext_b64, wrong_aad);
        assert!(result.is_err());
    }

    #[test]
    fn tampered_ciphertext_fails() {
        let dek = test_dek();
        let plaintext = b"my-secret";
        let aad = b"tenant:path";

        let envelope = encrypt_with_dek(&dek, plaintext, aad).unwrap();

        // Flip a bit in the ciphertext.
        let mut raw = BASE64.decode(&envelope.ciphertext_b64).unwrap();
        if let Some(byte) = raw.last_mut() {
            *byte ^= 0x01;
        }
        let tampered = BASE64.encode(&raw);

        let result = decrypt_with_dek(&dek, &tampered, aad);
        assert!(result.is_err());
    }

    #[test]
    fn short_ciphertext_fails() {
        let dek = test_dek();
        let short = BASE64.encode(b"too-short");
        let result = decrypt_with_dek(&dek, &short, b"aad");
        assert!(result.is_err());
    }
}
