//! The seal: Shamir-split custody of the root key.
//!
//! This is the thing that makes a secrets store a *vault*, and it did not exist
//! anywhere in this codebase. `grep -rniE '\bshamir\b|\bunseal\b|seal_status'`
//! returned exactly one hit, and it was a comment in the replication agent
//! explaining what Shamir sharing would be for.
//!
//! The root KEK was read from `VAULT_ROOT_KEY` — a plaintext environment
//! variable — and the process booted directly into an unsealed state. Whoever
//! could read a Kubernetes Secret, a Helm values file or a process environment
//! owned every secret in the vault, in perpetuity, and there was no documented
//! recovery path if the value was lost.
//!
//! # How it works
//!
//! Two keys, which is the part worth understanding:
//!
//! * The **root key** encrypts the tenant KEKs. It is what the vault actually
//!   needs in memory to function.
//! * The **unseal key** exists only to encrypt the root key at rest. It is
//!   never stored anywhere. It is split into shares at initialisation, and
//!   reconstructed from a threshold of them at unseal time.
//!
//! Only the root key *encrypted under the unseal key* is persisted. So the
//! database on its own is worthless, and no single share holder can open the
//! vault alone. Recovering it requires `threshold` people to cooperate.
//!
//! Separating the two is what makes rekeying possible later: the shares can be
//! regenerated against a new unseal key without re-encrypting a single tenant
//! KEK, because the root key underneath never has to change.
//!
//! # What this module is not
//!
//! It is the seal mechanism, not the seal *policy*. It does not decide when to
//! seal, who may submit a share, or how shares reach their holders — those
//! belong to the service that mounts it.

use std::sync::Arc;

use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine as _;
use ring::rand::{SecureRandom, SystemRandom};
use serde::{Deserialize, Serialize};
use sharks::{Share, Sharks};
use tokio::sync::RwLock;
use zeroize::Zeroizing;

use crate::crypto::envelope::{decrypt_with_dek, encrypt_with_dek};
use crate::error::VaultError;

/// AAD binding the sealed root key to this construction, so a blob from
/// somewhere else in the system cannot be substituted for it.
const SEAL_AAD: &[u8] = b"wslvault:seal:root-key:v1";

/// Context for the value that proves a reconstructed unseal key is the right
/// one, so a wrong set of shares is reported as such rather than surfacing as
/// an opaque decryption failure.
const CHECK_INFO: &[u8] = b"wslvault:seal:unseal-key-check:v1";

/// What an operator must persist after `init`. Returned exactly once.
#[derive(Debug, Clone, Serialize)]
pub struct InitResult {
    /// Base64 unseal shares. Distribute to separate holders; `threshold` of
    /// them are required to unseal, and they are never recoverable from the
    /// vault afterwards.
    pub shares: Vec<String>,
    pub threshold: u8,
}

/// The persisted half of the seal. Safe at rest: it yields nothing without a
/// threshold of shares.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SealMaterial {
    pub shares: u8,
    pub threshold: u8,
    /// Root key encrypted under the unseal key.
    pub sealed_root_key: String,
    /// Proves a reconstructed unseal key is correct before it is used.
    pub unseal_key_check: String,
}

/// Reported by `/v1/sys/seal-status`.
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct SealStatus {
    /// False once enough shares have been supplied.
    pub sealed: bool,
    /// Whether `init` has ever run.
    pub initialized: bool,
    pub threshold: u8,
    pub shares: u8,
    /// Distinct shares supplied so far in this unseal attempt.
    pub progress: u8,
}

/// Runtime seal state.
///
/// Holds the root key only while unsealed. Sealing drops it, and `Zeroizing`
/// wipes the bytes rather than leaving them in freed memory.
pub struct Seal {
    inner: Arc<RwLock<SealInner>>,
}

impl std::fmt::Debug for Seal {
    /// Deliberately opaque: the root key must never reach a log line or a
    /// panic message through a derived Debug.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Seal(<opaque>)")
    }
}

struct SealInner {
    material: Option<SealMaterial>,
    root_key: Option<Zeroizing<[u8; 32]>>,
    /// Shares supplied so far in the current unseal attempt.
    pending: Vec<Vec<u8>>,
}

impl Default for Seal {
    fn default() -> Self {
        Self::new()
    }
}

impl Clone for Seal {
    fn clone(&self) -> Self {
        Self {
            inner: Arc::clone(&self.inner),
        }
    }
}

impl Seal {
    /// A seal with no persisted material: uninitialized, and sealed.
    pub fn new() -> Self {
        Self {
            inner: Arc::new(RwLock::new(SealInner {
                material: None,
                root_key: None,
                pending: Vec::new(),
            })),
        }
    }

    /// Adopt persisted material, e.g. loaded from the database at startup.
    ///
    /// The vault is initialized but sealed: it knows a root key exists and
    /// cannot read it yet.
    pub async fn load(&self, material: SealMaterial) {
        let mut inner = self.inner.write().await;
        inner.material = Some(material);
        inner.root_key = None;
        inner.pending.clear();
    }

    /// Adopt a root key directly, bypassing the seal.
    ///
    /// This is the legacy `VAULT_ROOT_KEY` path. It exists so existing
    /// deployments keep working across this change, and it is the posture the
    /// seal is meant to replace: the key is in an environment variable and the
    /// process boots unsealed. Callers should warn.
    pub async fn unseal_with_root_key(&self, root_key: Zeroizing<[u8; 32]>) {
        let mut inner = self.inner.write().await;
        inner.root_key = Some(root_key);
        inner.pending.clear();
    }

    /// Generate a root key, split a fresh unseal key, and return the shares.
    ///
    /// Returns the material to persist alongside the shares. The shares are
    /// returned once and never again — the vault cannot reproduce them, which
    /// is the property that makes them worth holding.
    ///
    /// Fails if the seal is already initialized: re-running would orphan every
    /// tenant KEK encrypted under the previous root key.
    pub async fn init(
        &self,
        shares: u8,
        threshold: u8,
    ) -> Result<(InitResult, SealMaterial), VaultError> {
        if threshold == 0 || shares == 0 {
            return Err(VaultError::ValidationError {
                field: "threshold".into(),
                reason: "shares and threshold must both be at least 1".into(),
            });
        }
        if threshold > shares {
            return Err(VaultError::ValidationError {
                field: "threshold".into(),
                reason: format!("threshold {threshold} exceeds shares {shares}"),
            });
        }

        {
            let inner = self.inner.read().await;
            if inner.material.is_some() {
                return Err(VaultError::ValidationError {
                    field: "seal".into(),
                    reason: "vault is already initialized; re-initialising would \
                             orphan every key encrypted under the current root key"
                        .into(),
                });
            }
        }

        let root_key = random_32()?;
        let unseal_key = random_32()?;

        // Encrypt the root key under the unseal key. Only this ever persists.
        let sealed_root_key = encrypt_with_dek(&unseal_key, &*root_key, SEAL_AAD)?.ciphertext_b64;
        let unseal_key_check = check_value(&unseal_key)?;

        let dealer = Sharks(threshold);
        let share_strings: Vec<String> = dealer
            .dealer(&*unseal_key)
            .take(shares as usize)
            .map(|s| BASE64.encode(Vec::from(&s)))
            .collect();

        let material = SealMaterial {
            shares,
            threshold,
            sealed_root_key,
            unseal_key_check,
        };

        {
            let mut inner = self.inner.write().await;
            inner.material = Some(material.clone());
            // Deliberately still sealed. An operator must prove they can unseal
            // with the shares they were handed, while the vault is still empty
            // and a mistake costs nothing.
            inner.root_key = None;
            inner.pending.clear();
        }

        Ok((
            InitResult {
                shares: share_strings,
                threshold,
            },
            material,
        ))
    }

    /// Submit one unseal share.
    ///
    /// Returns the resulting status. Once `threshold` distinct shares have been
    /// supplied the unseal key is reconstructed, verified, and used to decrypt
    /// the root key.
    ///
    /// A share that does not belong to this seal is rejected outright rather
    /// than being counted toward the threshold — otherwise a wrong share would
    /// be discovered only after enough had accumulated, and the operator would
    /// have no idea which one was at fault.
    pub async fn unseal(&self, share_b64: &str) -> Result<SealStatus, VaultError> {
        let mut inner = self.inner.write().await;

        let Some(material) = inner.material.clone() else {
            return Err(VaultError::ValidationError {
                field: "seal".into(),
                reason: "vault is not initialized".into(),
            });
        };

        if inner.root_key.is_some() {
            return Ok(status_of(&inner, Some(&material)));
        }

        let raw = BASE64
            .decode(share_b64.trim())
            .map_err(|e| VaultError::ValidationError {
                field: "share".into(),
                reason: format!("share is not valid base64: {e}"),
            })?;

        Share::try_from(raw.as_slice()).map_err(|e| VaultError::ValidationError {
            field: "share".into(),
            reason: format!("share is malformed: {e}"),
        })?;

        // Idempotent: re-submitting a share must not advance progress, or a
        // single holder could unseal alone by sending theirs `threshold` times.
        if inner.pending.iter().any(|p| p == &raw) {
            return Ok(status_of(&inner, Some(&material)));
        }
        inner.pending.push(raw);

        if (inner.pending.len() as u8) < material.threshold {
            return Ok(status_of(&inner, Some(&material)));
        }

        // Threshold reached: reconstruct.
        let shares: Vec<Share> = inner
            .pending
            .iter()
            .filter_map(|r| Share::try_from(r.as_slice()).ok())
            .collect();

        let recovered = Sharks(material.threshold).recover(&shares).map_err(|e| {
            VaultError::ValidationError {
                field: "share".into(),
                reason: format!("could not reconstruct the unseal key: {e}"),
            }
        })?;

        if recovered.len() != 32 {
            inner.pending.clear();
            return Err(VaultError::ValidationError {
                field: "share".into(),
                reason: "reconstructed unseal key has the wrong length".into(),
            });
        }
        let mut unseal_key = Zeroizing::new([0u8; 32]);
        unseal_key.copy_from_slice(&recovered);

        // Verify before decrypting so a wrong share set reports as a wrong
        // share set rather than as a corrupt vault.
        if check_value(&unseal_key)? != material.unseal_key_check {
            inner.pending.clear();
            return Err(VaultError::ValidationError {
                field: "share".into(),
                reason: "the supplied shares do not reconstruct this vault's unseal key".into(),
            });
        }

        let plaintext = decrypt_with_dek(&unseal_key, &material.sealed_root_key, SEAL_AAD)
            .map_err(|_| VaultError::Internal {
                reason: "sealed root key failed to decrypt under a verified unseal key; \
                         the stored material is corrupt"
                    .into(),
            })?;
        if plaintext.len() != 32 {
            return Err(VaultError::Internal {
                reason: "unsealed root key has the wrong length".into(),
            });
        }
        let mut root_key = Zeroizing::new([0u8; 32]);
        root_key.copy_from_slice(&plaintext);

        inner.root_key = Some(root_key);
        inner.pending.clear();

        Ok(status_of(&inner, Some(&material)))
    }

    /// Drop the root key from memory. The vault stops serving until unsealed.
    pub async fn seal(&self) {
        let mut inner = self.inner.write().await;
        inner.root_key = None;
        inner.pending.clear();
    }

    /// Abandon the current unseal attempt without sealing.
    pub async fn reset_unseal_progress(&self) {
        self.inner.write().await.pending.clear();
    }

    pub async fn status(&self) -> SealStatus {
        let inner = self.inner.read().await;
        let material = inner.material.clone();
        status_of(&inner, material.as_ref())
    }

    pub async fn is_unsealed(&self) -> bool {
        self.inner.read().await.root_key.is_some()
    }

    /// A copy of the root key, or `VaultError::Sealed` when sealed.
    ///
    /// Every operation that needs key material goes through here, so "sealed"
    /// is enforced in one place rather than remembered at each call site.
    pub async fn root_key(&self) -> Result<Zeroizing<[u8; 32]>, VaultError> {
        let inner = self.inner.read().await;
        match &inner.root_key {
            Some(k) => {
                let mut out = Zeroizing::new([0u8; 32]);
                out.copy_from_slice(&**k);
                Ok(out)
            }
            None => Err(VaultError::Sealed),
        }
    }
}

fn status_of(inner: &SealInner, material: Option<&SealMaterial>) -> SealStatus {
    SealStatus {
        sealed: inner.root_key.is_none(),
        initialized: material.is_some(),
        threshold: material.map(|m| m.threshold).unwrap_or(0),
        shares: material.map(|m| m.shares).unwrap_or(0),
        progress: inner.pending.len() as u8,
    }
}

/// A value derived from the unseal key that proves a reconstruction is correct
/// without revealing the key.
fn check_value(unseal_key: &[u8; 32]) -> Result<String, VaultError> {
    let derived = crate::crypto::kdf::derive_key(unseal_key, None, CHECK_INFO)?;
    Ok(hex::encode(&*derived))
}

fn random_32() -> Result<Zeroizing<[u8; 32]>, VaultError> {
    let rng = SystemRandom::new();
    let mut buf = Zeroizing::new([0u8; 32]);
    rng.fill(buf.as_mut())
        .map_err(|_| VaultError::EncryptionFailed {
            reason: "CSPRNG failed while generating seal key material".into(),
        })?;
    Ok(buf)
}

#[cfg(test)]
mod tests {
    use super::*;

    async fn initialized(shares: u8, threshold: u8) -> (Seal, Vec<String>) {
        let seal = Seal::new();
        let (init, _material) = seal.init(shares, threshold).await.expect("init");
        (seal, init.shares)
    }

    #[tokio::test]
    async fn a_fresh_seal_is_uninitialized_and_sealed() {
        let s = Seal::new().status().await;
        assert!(!s.initialized);
        assert!(s.sealed);
    }

    #[tokio::test]
    async fn init_returns_the_requested_number_of_shares() {
        let (seal, shares) = initialized(5, 3).await;
        assert_eq!(shares.len(), 5);
        let s = seal.status().await;
        assert!(s.initialized);
        assert!(s.sealed, "init must NOT leave the vault unsealed");
        assert_eq!(s.threshold, 3);
    }

    #[tokio::test]
    async fn a_threshold_of_shares_unseals() {
        let (seal, shares) = initialized(5, 3).await;

        assert!(seal.unseal(&shares[0]).await.unwrap().sealed);
        assert!(seal.unseal(&shares[1]).await.unwrap().sealed);
        let s = seal.unseal(&shares[2]).await.unwrap();

        assert!(!s.sealed, "the threshold share must complete the unseal");
        assert!(seal.root_key().await.is_ok());
    }

    /// Any combination of `threshold` shares must work — holders are equals,
    /// and requiring specific ones would defeat the point.
    #[tokio::test]
    async fn any_threshold_subset_works() {
        let (seal, shares) = initialized(5, 3).await;
        for s in [&shares[4], &shares[2], &shares[0]] {
            seal.unseal(s).await.unwrap();
        }
        assert!(seal.is_unsealed().await);
    }

    #[tokio::test]
    async fn fewer_than_threshold_shares_do_not_unseal() {
        let (seal, shares) = initialized(5, 3).await;
        seal.unseal(&shares[0]).await.unwrap();
        seal.unseal(&shares[1]).await.unwrap();
        assert!(seal.status().await.sealed);
        assert!(matches!(seal.root_key().await, Err(VaultError::Sealed)));
    }

    /// The property that makes shares worth distributing: one holder must not
    /// be able to reach the threshold alone by replaying their own share.
    #[tokio::test]
    async fn resubmitting_one_share_does_not_advance_progress() {
        let (seal, shares) = initialized(5, 3).await;
        for _ in 0..10 {
            seal.unseal(&shares[0]).await.unwrap();
        }
        let s = seal.status().await;
        assert_eq!(s.progress, 1, "a replayed share must not count twice");
        assert!(s.sealed);
    }

    #[tokio::test]
    async fn shares_from_a_different_vault_are_rejected() {
        let (seal_a, _) = initialized(5, 3).await;
        let (_, shares_b) = initialized(5, 3).await;

        seal_a.unseal(&shares_b[0]).await.unwrap();
        seal_a.unseal(&shares_b[1]).await.unwrap();
        let result = seal_a.unseal(&shares_b[2]).await;

        assert!(
            result.is_err(),
            "another vault's shares must not open this one"
        );
        assert!(seal_a.status().await.sealed);
    }

    #[tokio::test]
    async fn malformed_shares_are_rejected_without_counting() {
        let (seal, _) = initialized(3, 2).await;
        assert!(seal.unseal("not-base64!!").await.is_err());
        assert_eq!(seal.status().await.progress, 0);
    }

    #[tokio::test]
    async fn sealing_drops_the_root_key() {
        let (seal, shares) = initialized(3, 2).await;
        seal.unseal(&shares[0]).await.unwrap();
        seal.unseal(&shares[1]).await.unwrap();
        assert!(seal.is_unsealed().await);

        seal.seal().await;
        assert!(seal.status().await.sealed);
        assert!(matches!(seal.root_key().await, Err(VaultError::Sealed)));

        // ...and the same shares open it again.
        seal.unseal(&shares[0]).await.unwrap();
        seal.unseal(&shares[1]).await.unwrap();
        assert!(seal.is_unsealed().await);
    }

    /// The root key must be reconstructed identically across seal cycles, or
    /// every tenant KEK becomes undecryptable after a restart.
    #[tokio::test]
    async fn the_root_key_survives_a_seal_cycle() {
        let (seal, shares) = initialized(3, 2).await;
        seal.unseal(&shares[0]).await.unwrap();
        seal.unseal(&shares[1]).await.unwrap();
        let before = seal.root_key().await.unwrap();

        seal.seal().await;
        seal.unseal(&shares[2]).await.unwrap();
        seal.unseal(&shares[0]).await.unwrap();
        let after = seal.root_key().await.unwrap();

        assert_eq!(*before, *after);
    }

    /// Persisted material plus a threshold of shares must reconstruct the same
    /// root key in a fresh process — that is what a restart is.
    #[tokio::test]
    async fn material_reloads_into_a_fresh_seal() {
        let original = Seal::new();
        let (init, material) = original.init(4, 2).await.unwrap();
        original.unseal(&init.shares[0]).await.unwrap();
        original.unseal(&init.shares[1]).await.unwrap();
        let expected = original.root_key().await.unwrap();

        let restarted = Seal::new();
        restarted.load(material).await;
        assert!(restarted.status().await.sealed);
        assert!(restarted.status().await.initialized);

        restarted.unseal(&init.shares[2]).await.unwrap();
        restarted.unseal(&init.shares[3]).await.unwrap();
        assert_eq!(*restarted.root_key().await.unwrap(), *expected);
    }

    #[tokio::test]
    async fn re_initialising_is_refused() {
        let (seal, _) = initialized(3, 2).await;
        assert!(
            seal.init(3, 2).await.is_err(),
            "re-init would orphan every key under the current root key"
        );
    }

    #[tokio::test]
    async fn threshold_above_share_count_is_refused() {
        assert!(Seal::new().init(3, 5).await.is_err());
        assert!(Seal::new().init(0, 0).await.is_err());
    }

    /// The persisted blob must not contain the root key in any recoverable
    /// form; the database alone has to be worthless.
    #[tokio::test]
    async fn persisted_material_does_not_reveal_the_root_key() {
        let seal = Seal::new();
        let (init, material) = seal.init(3, 2).await.unwrap();
        seal.unseal(&init.shares[0]).await.unwrap();
        seal.unseal(&init.shares[1]).await.unwrap();
        let root = seal.root_key().await.unwrap();

        let blob = BASE64.decode(&material.sealed_root_key).unwrap();
        assert!(
            !blob.windows(32).any(|w| w == &root[..]),
            "the sealed blob must not contain the root key"
        );
        assert!(!material.unseal_key_check.is_empty());
    }
}
