//! Cryptographically secure nonce generation for AES-256-GCM.

use ring::rand::{SecureRandom, SystemRandom};

use crate::error::VaultError;

/// Nonce length for AES-256-GCM: 96 bits (12 bytes) per NIST recommendation.
pub const AES_GCM_NONCE_LEN: usize = 12;

/// Generate a 12-byte nonce with cryptographically secure random bytes.
pub fn generate_aes_gcm_nonce() -> Result<[u8; AES_GCM_NONCE_LEN], VaultError> {
    let rng = SystemRandom::new();
    let mut nonce = [0u8; AES_GCM_NONCE_LEN];
    rng.fill(&mut nonce)
        .map_err(|_| VaultError::EncryptionFailed {
            reason: "CSPRNG nonce generation failed".into(),
        })?;
    Ok(nonce)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generates_unique_nonces() {
        let n1 = generate_aes_gcm_nonce().unwrap();
        let n2 = generate_aes_gcm_nonce().unwrap();
        // Two random 12-byte nonces should never collide.
        assert_ne!(n1, n2);
    }

    #[test]
    fn nonce_has_correct_length() {
        let nonce = generate_aes_gcm_nonce().unwrap();
        assert_eq!(nonce.len(), 12);
    }
}
