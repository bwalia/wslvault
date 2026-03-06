//! Transit cryptographic operations.
//!
//! All symmetric encryption delegates to `wslvault_core::crypto::envelope` for
//! AES-256-GCM so that the cipher implementation is centralised and tested in
//! the core crate.  HMAC-SHA256 signing uses `ring::hmac` directly.
//!
//! Ciphertext wire format for versioned transit:
//!   `vault:v{VERSION}:{BASE64(nonce || ciphertext || tag)}`
//!
//! The version prefix is mandatory so that `decrypt` and `rewrap` can locate
//! the correct key version.

use ring::hmac;

use wslvault_core::crypto::envelope::{decrypt_with_dek, encrypt_with_dek};
use wslvault_core::VaultError;

use crate::key_store::TransitKey;

/// Version prefix prepended to all transit ciphertexts.
const CIPHERTEXT_PREFIX: &str = "vault:v";

/// Encrypt `plaintext` under the latest version of `key`.
///
/// Returns a versioned ciphertext string of the form:
/// `vault:v{VERSION}:{BASE64_ENVELOPE}`
pub fn encrypt(key: &TransitKey, plaintext: &[u8]) -> Result<String, VaultError> {
    let dek = key.current_material();
    // Use the key name as AAD to bind the ciphertext to this specific key,
    // preventing ciphertexts from being transplanted between keys.
    let aad = key.name.as_bytes();

    let envelope = encrypt_with_dek(dek, plaintext, aad)?;

    Ok(format!(
        "{}{}:{}",
        CIPHERTEXT_PREFIX, key.current_version, envelope.ciphertext_b64
    ))
}

/// Decrypt a versioned ciphertext produced by `encrypt`.
///
/// Parses the version from the prefix, locates the appropriate key version,
/// and decrypts using AES-256-GCM.
pub fn decrypt(key: &TransitKey, versioned_ciphertext: &str) -> Result<Vec<u8>, VaultError> {
    let (version, b64_body) = parse_versioned_ciphertext(versioned_ciphertext)?;

    let dek = key
        .material_for_version(version)
        .ok_or_else(|| VaultError::KeyNotFound {
            key_id: format!("{}:v{}", key.name, version),
        })?;

    let aad = key.name.as_bytes();
    let plaintext = decrypt_with_dek(dek, b64_body, aad)?;
    Ok(plaintext.to_vec())
}

/// Compute an HMAC-SHA256 signature over `data` using `key` bytes.
///
/// Returns a hex-encoded signature string.
pub fn sign_data(key: &[u8], data: &[u8]) -> String {
    let signing_key = hmac::Key::new(hmac::HMAC_SHA256, key);
    let tag = hmac::sign(&signing_key, data);
    hex::encode(tag.as_ref())
}

/// Verify that `signature` matches the HMAC-SHA256 of `data` under `key`.
///
/// Uses constant-time comparison via `ring::hmac::verify` to prevent
/// timing-based signature forgery.
pub fn verify_data(key: &[u8], data: &[u8], signature: &str) -> bool {
    let Ok(sig_bytes) = hex::decode(signature) else {
        return false;
    };
    let verification_key = hmac::Key::new(hmac::HMAC_SHA256, key);
    hmac::verify(&verification_key, data, &sig_bytes).is_ok()
}

/// Rewrap a ciphertext by decrypting with the old key version and re-encrypting
/// with the current (latest) version.
///
/// This is used during key rotation to upgrade existing ciphertexts without
/// exposing the plaintext beyond the service boundary.
pub fn rewrap(key: &TransitKey, old_ciphertext: &str) -> Result<String, VaultError> {
    let plaintext = decrypt(key, old_ciphertext)?;
    encrypt(key, &plaintext)
}

/// Parse a versioned ciphertext string into `(version, base64_body)`.
///
/// Expected format: `vault:v{N}:{BASE64}`
fn parse_versioned_ciphertext(ciphertext: &str) -> Result<(u32, &str), VaultError> {
    // Strip the mandatory "vault:v" prefix.
    let after_prefix = ciphertext
        .strip_prefix(CIPHERTEXT_PREFIX)
        .ok_or_else(|| VaultError::DecryptionFailed)?;

    // Split into version and b64 body at the first `:`.
    let colon_pos = after_prefix.find(':').ok_or(VaultError::DecryptionFailed)?;

    let version_str = &after_prefix[..colon_pos];
    let b64_body = &after_prefix[colon_pos + 1..];

    let version: u32 = version_str
        .parse()
        .map_err(|_| VaultError::DecryptionFailed)?;

    Ok((version, b64_body))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::key_store::{KeyAlgorithm, KeyVersion, TransitKey};
    use chrono::Utc;

    fn make_key(name: &str) -> TransitKey {
        TransitKey {
            name: name.to_string(),
            versions: vec![KeyVersion {
                version: 1,
                material: [0x42u8; 32],
            }],
            current_version: 1,
            algorithm: KeyAlgorithm::Aes256Gcm,
            created_at: Utc::now(),
        }
    }

    #[test]
    fn encrypt_decrypt_roundtrip() {
        let key = make_key("my-key");
        let plaintext = b"hello transit";
        let ct = encrypt(&key, plaintext).unwrap();
        assert!(ct.starts_with("vault:v1:"));
        let pt = decrypt(&key, &ct).unwrap();
        assert_eq!(pt, plaintext);
    }

    #[test]
    fn sign_verify_roundtrip() {
        let key_bytes = b"test-hmac-key-must-be-long-enough";
        let data = b"data to sign";
        let sig = sign_data(key_bytes, data);
        assert!(verify_data(key_bytes, data, &sig));
    }

    #[test]
    fn verify_fails_with_wrong_key() {
        let key_bytes = b"test-hmac-key-must-be-long-enough";
        let wrong_key = b"different-key-also-must-be-long!!";
        let data = b"data to sign";
        let sig = sign_data(key_bytes, data);
        assert!(!verify_data(wrong_key, data, &sig));
    }

    #[test]
    fn rewrap_produces_new_ciphertext() {
        let mut key = make_key("my-key");
        let plaintext = b"secret data";
        let old_ct = encrypt(&key, plaintext).unwrap();

        // Add a new key version.
        key.versions.push(KeyVersion {
            version: 2,
            material: [0xABu8; 32],
        });
        key.current_version = 2;

        let new_ct = rewrap(&key, &old_ct).unwrap();
        assert!(new_ct.starts_with("vault:v2:"));

        let pt = decrypt(&key, &new_ct).unwrap();
        assert_eq!(pt, plaintext);
    }
}
