//! Key Derivation Functions for the envelope encryption hierarchy.
//!
//! HKDF-SHA256 is used to derive per-DEK keys from input key material + context.

use hkdf::Hkdf;
use sha2::Sha256;
use zeroize::Zeroizing;

use crate::error::VaultError;

/// Derive a 32-byte symmetric key from input key material using HKDF-SHA256.
///
/// # Arguments
/// - `ikm`: Input key material (e.g. a raw KEK or master secret).
/// - `salt`: Optional domain-specific salt; use `None` for default zero-salt.
/// - `info`: Context string binding the derived key to its purpose
///   (e.g. tenant_id + secret path).
pub fn derive_key(
    ikm: &[u8],
    salt: Option<&[u8]>,
    info: &[u8],
) -> Result<Zeroizing<[u8; 32]>, VaultError> {
    let hkdf = Hkdf::<Sha256>::new(salt, ikm);
    let mut okm = Zeroizing::new([0u8; 32]);
    hkdf.expand(info, okm.as_mut())
        .map_err(|_| VaultError::EncryptionFailed {
            reason: "HKDF expand failed: output length exceeds max".into(),
        })?;
    Ok(okm)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn derive_key_produces_32_bytes() {
        let ikm = [0xAA; 32];
        let key = derive_key(&ikm, None, b"test-context").unwrap();
        assert_eq!(key.len(), 32);
    }

    #[test]
    fn different_contexts_produce_different_keys() {
        let ikm = [0xBB; 32];
        let k1 = derive_key(&ikm, None, b"context-a").unwrap();
        let k2 = derive_key(&ikm, None, b"context-b").unwrap();
        assert_ne!(*k1, *k2);
    }

    #[test]
    fn different_salts_produce_different_keys() {
        let ikm = [0xCC; 32];
        let k1 = derive_key(&ikm, Some(b"salt-1"), b"context").unwrap();
        let k2 = derive_key(&ikm, Some(b"salt-2"), b"context").unwrap();
        assert_ne!(*k1, *k2);
    }

    #[test]
    fn same_inputs_produce_same_key() {
        let ikm = [0xDD; 32];
        let k1 = derive_key(&ikm, Some(b"salt"), b"ctx").unwrap();
        let k2 = derive_key(&ikm, Some(b"salt"), b"ctx").unwrap();
        assert_eq!(*k1, *k2);
    }
}
