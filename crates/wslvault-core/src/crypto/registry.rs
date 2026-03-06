//! Algorithm registry: maps algorithm identifiers to runtime capability checks.

use crate::error::VaultError;
use crate::types::key::KeyAlgorithm;

/// Returns the required key length in bytes for the given algorithm.
pub fn key_length_bytes(alg: KeyAlgorithm) -> usize {
    match alg {
        KeyAlgorithm::Aes256Gcm => 32,
        KeyAlgorithm::ChaCha20Poly1305 => 32,
        KeyAlgorithm::XChaCha20Poly1305 => 32,
    }
}

/// Validate that a raw key slice has the correct length for its algorithm.
pub fn validate_key_length(alg: KeyAlgorithm, key: &[u8]) -> Result<(), VaultError> {
    let expected = key_length_bytes(alg);
    if key.len() != expected {
        return Err(VaultError::ValidationError {
            field: "key_material".into(),
            reason: format!(
                "algorithm {:?} requires {} bytes, got {}",
                alg,
                expected,
                key.len()
            ),
        });
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn aes256_requires_32_bytes() {
        assert_eq!(key_length_bytes(KeyAlgorithm::Aes256Gcm), 32);
    }

    #[test]
    fn valid_key_length_passes() {
        let key = [0u8; 32];
        assert!(validate_key_length(KeyAlgorithm::Aes256Gcm, &key).is_ok());
    }

    #[test]
    fn invalid_key_length_fails() {
        let key = [0u8; 16];
        let err = validate_key_length(KeyAlgorithm::Aes256Gcm, &key);
        assert!(err.is_err());
    }
}
