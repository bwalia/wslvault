//! Pluggable root key provider for the crypto-service.
//!
//! The `RootKeyProvider` trait abstracts where the 32-byte root KEK comes from.
//! At startup the provider is selected via the `VAULT_ROOT_KEY_PROVIDER` environment
//! variable and the resulting key material is handed to `KekStore`.
//!
//! ## Available providers
//!
//! | `VAULT_ROOT_KEY_PROVIDER` | Description |
//! |---------------------------|-------------|
//! | `env` (default)           | Reads `VAULT_ROOT_KEY` (base64, 32 bytes). Backward-compatible. |
//! | `aws-kms`                 | Decrypts `VAULT_ROOT_KEY_CIPHERTEXT` via AWS KMS. Requires the `aws-kms` Cargo feature. |
//!
//! ## AWS KMS bootstrap (one-time key generation)
//!
//! If `VAULT_KMS_GENERATE=true` and no `VAULT_ROOT_KEY_CIPHERTEXT` is set, the
//! `AwsKmsRootKeyProvider` calls `GenerateDataKey` to produce a fresh AES-256 key,
//! logs the base64-encoded `CiphertextBlob` at INFO level so the operator can persist
//! it to their secret store, and then uses the plaintext half for the current session.
//! Plaintext bytes are zeroized immediately after being copied into `Zeroizing<[u8;32]>`.

use async_trait::async_trait;
use zeroize::Zeroizing;

use wslvault_core::error::VaultError;

/// A source that can supply the 32-byte root Key Encryption Key at startup.
///
/// Implementations may load the key from the environment, an HSM, a cloud KMS,
/// or any other backend.  The returned value MUST be placed in a `Zeroizing`
/// wrapper so the bytes are wiped from memory when the caller drops them.
#[async_trait]
pub trait RootKeyProvider: Send + Sync {
    /// Load and return the 32-byte root KEK.
    ///
    /// This is called exactly once at service startup.  Callers are responsible
    /// for treating the returned bytes as highly sensitive key material.
    async fn load_root_key(&self) -> Result<Zeroizing<[u8; 32]>, RootKeyError>;
}

/// Errors produced when loading the root key.
#[derive(Debug, thiserror::Error)]
pub enum RootKeyError {
    #[error("VAULT_ROOT_KEY environment variable is not set")]
    EnvVarMissing,

    #[error("VAULT_ROOT_KEY is not valid base64: {0}")]
    InvalidBase64(String),

    #[error("root key must be exactly 32 bytes, got {0}")]
    InvalidLength(usize),

    #[error("AWS KMS decrypt failed: {0}")]
    KmsDecryptFailed(String),

    #[error("AWS KMS GenerateDataKey returned no plaintext")]
    KmsNoPlaintext,

    #[error("AWS KMS GenerateDataKey returned no ciphertext blob")]
    KmsNoCiphertext,

    /// Requested the `aws-kms` provider but the feature is not compiled in.
    #[error(
        "VAULT_ROOT_KEY_PROVIDER=aws-kms was requested but the `aws-kms` feature is not enabled. \
         Rebuild crypto-service with --features aws-kms."
    )]
    AwsKmsFeatureNotEnabled,

    #[error("unknown root key provider {0:?}; valid values: env, aws-kms")]
    UnknownProvider(String),
}

impl From<RootKeyError> for VaultError {
    fn from(err: RootKeyError) -> VaultError {
        VaultError::Internal {
            reason: err.to_string(),
        }
    }
}

// ---------------------------------------------------------------------------
// EnvRootKeyProvider — default, backward-compatible
// ---------------------------------------------------------------------------

/// Loads the root KEK from the `VAULT_ROOT_KEY` environment variable.
///
/// `VAULT_ROOT_KEY` must be a standard (padded) base64 string that decodes to
/// exactly 32 bytes.  This is the original behaviour prior to the pluggable
/// provider model and remains the default.
pub struct EnvRootKeyProvider;

#[async_trait]
impl RootKeyProvider for EnvRootKeyProvider {
    async fn load_root_key(&self) -> Result<Zeroizing<[u8; 32]>, RootKeyError> {
        load_key_from_env_var("VAULT_ROOT_KEY")
    }
}

/// Decode a standard base64 env var into a `Zeroizing<[u8; 32]>`.
///
/// This helper is `pub(crate)` so the unit tests can exercise it directly
/// without going through the trait object machinery.
pub(crate) fn load_key_from_env_var(var_name: &str) -> Result<Zeroizing<[u8; 32]>, RootKeyError> {
    use base64::engine::general_purpose::STANDARD as BASE64;
    use base64::Engine as _;

    let encoded = std::env::var(var_name).map_err(|_| RootKeyError::EnvVarMissing)?;

    let raw_bytes = BASE64
        .decode(encoded.trim())
        .map_err(|e| RootKeyError::InvalidBase64(e.to_string()))?;

    let len = raw_bytes.len();
    if len != 32 {
        return Err(RootKeyError::InvalidLength(len));
    }

    let mut key = Zeroizing::new([0u8; 32]);
    key.copy_from_slice(&raw_bytes);
    // raw_bytes is a Vec that goes out of scope here; we rely on the Zeroizing
    // wrapper on `key` to wipe the copy that lives in our output.
    Ok(key)
}

// ---------------------------------------------------------------------------
// AwsKmsRootKeyProvider — feature-gated
// ---------------------------------------------------------------------------

/// Loads the root KEK by calling AWS KMS `Decrypt` on a persisted ciphertext blob.
///
/// **Configuration env vars:**
///
/// | Variable | Required | Description |
/// |----------|----------|-------------|
/// | `VAULT_KMS_KEY_ID` | Yes | KMS key ID or ARN used to encrypt/decrypt the root key blob. |
/// | `VAULT_ROOT_KEY_CIPHERTEXT` | See below | Base64-encoded `CiphertextBlob` produced by a prior `GenerateDataKey` call. |
/// | `VAULT_KMS_GENERATE` | If no ciphertext | Set to `true` to call `GenerateDataKey` and bootstrap a new root key. The operator MUST persist the logged ciphertext blob before restarting. |
///
/// AWS credentials and region are resolved via the standard AWS SDK credential
/// chain (env vars, `~/.aws/credentials`, IRSA, EC2 instance profile, etc.).
///
/// This provider is only available when the `aws-kms` Cargo feature is enabled.
#[cfg(feature = "aws-kms")]
pub struct AwsKmsRootKeyProvider {
    /// KMS key ID or ARN used to decrypt (or generate) the root key.
    pub key_id: String,
}

#[cfg(feature = "aws-kms")]
#[async_trait]
impl RootKeyProvider for AwsKmsRootKeyProvider {
    async fn load_root_key(&self) -> Result<Zeroizing<[u8; 32]>, RootKeyError> {
        use tracing::{info, warn};

        let config = aws_config::load_defaults(aws_config::BehaviorVersion::latest()).await;
        let kms = aws_sdk_kms::Client::new(&config);

        // Check if we have a pre-existing ciphertext to decrypt.
        match std::env::var("VAULT_ROOT_KEY_CIPHERTEXT") {
            Ok(ciphertext_b64) if !ciphertext_b64.trim().is_empty() => {
                info!(
                    key_id = %self.key_id,
                    "Decrypting root KEK via AWS KMS"
                );
                kms_decrypt(&kms, &self.key_id, ciphertext_b64.trim()).await
            }

            // No pre-existing ciphertext: check whether auto-generation is enabled.
            _ => {
                let should_generate = std::env::var("VAULT_KMS_GENERATE")
                    .map(|v| v.trim().eq_ignore_ascii_case("true"))
                    .unwrap_or(false);

                if should_generate {
                    warn!(
                        key_id = %self.key_id,
                        "VAULT_KMS_GENERATE=true — generating a new root KEK via AWS KMS GenerateDataKey. \
                         PERSIST the logged CiphertextBlob before the next service restart."
                    );
                    kms_generate_data_key(&kms, &self.key_id).await
                } else {
                    Err(RootKeyError::KmsDecryptFailed(
                        "VAULT_ROOT_KEY_CIPHERTEXT is not set and VAULT_KMS_GENERATE is not true. \
                         Either provide the encrypted root key blob or set VAULT_KMS_GENERATE=true \
                         to bootstrap a new one."
                            .to_string(),
                    ))
                }
            }
        }
    }
}

/// Call KMS `Decrypt` and return the 32-byte plaintext as a zeroized buffer.
#[cfg(feature = "aws-kms")]
async fn kms_decrypt(
    kms: &aws_sdk_kms::Client,
    key_id: &str,
    ciphertext_b64: &str,
) -> Result<Zeroizing<[u8; 32]>, RootKeyError> {
    use base64::engine::general_purpose::STANDARD as BASE64;
    use base64::Engine as _;
    use tracing::info;

    let ciphertext_bytes = BASE64
        .decode(ciphertext_b64)
        .map_err(|e| RootKeyError::InvalidBase64(e.to_string()))?;

    let response = kms
        .decrypt()
        .key_id(key_id)
        .ciphertext_blob(aws_sdk_kms::primitives::Blob::new(ciphertext_bytes))
        .encryption_algorithm(aws_sdk_kms::types::EncryptionAlgorithmSpec::SymmetricDefault)
        .send()
        .await
        .map_err(|e| RootKeyError::KmsDecryptFailed(e.to_string()))?;

    let plaintext_blob = response.plaintext.ok_or(RootKeyError::KmsNoPlaintext)?;

    let result = extract_32_bytes_from_blob(plaintext_blob)?;
    info!(key_id, "Root KEK successfully decrypted from AWS KMS");
    Ok(result)
}

/// Call KMS `GenerateDataKey` (AES_256), log the ciphertext blob, and return
/// the plaintext as a zeroized buffer.
#[cfg(feature = "aws-kms")]
async fn kms_generate_data_key(
    kms: &aws_sdk_kms::Client,
    key_id: &str,
) -> Result<Zeroizing<[u8; 32]>, RootKeyError> {
    use base64::engine::general_purpose::STANDARD as BASE64;
    use base64::Engine as _;
    use tracing::{info, warn};

    let response = kms
        .generate_data_key()
        .key_id(key_id)
        .key_spec(aws_sdk_kms::types::DataKeySpec::Aes256)
        .send()
        .await
        .map_err(|e| RootKeyError::KmsDecryptFailed(format!("GenerateDataKey failed: {e}")))?;

    let ciphertext_blob = response
        .ciphertext_blob
        .ok_or(RootKeyError::KmsNoCiphertext)?;

    // Log the encrypted blob so operators can persist it before restarting.
    let ciphertext_b64 = BASE64.encode(ciphertext_blob.as_ref());
    warn!(
        key_id,
        ciphertext_b64 = %ciphertext_b64,
        "Generated new root KEK. PERSIST VAULT_ROOT_KEY_CIPHERTEXT before the next restart."
    );

    let plaintext_blob = response.plaintext.ok_or(RootKeyError::KmsNoPlaintext)?;

    let result = extract_32_bytes_from_blob(plaintext_blob)?;
    info!(key_id, "New root KEK generated via AWS KMS GenerateDataKey");
    Ok(result)
}

/// Copy the first 32 bytes from a KMS `Blob` into a `Zeroizing<[u8; 32]>`.
/// Returns `RootKeyError::InvalidLength` if the blob is not exactly 32 bytes.
#[cfg(feature = "aws-kms")]
fn extract_32_bytes_from_blob(
    blob: aws_sdk_kms::primitives::Blob,
) -> Result<Zeroizing<[u8; 32]>, RootKeyError> {
    let bytes = blob.into_inner();
    // Wrap in a Zeroizing Vec so the bytes are wiped even on the error path.
    let bytes = zeroize::Zeroizing::new(bytes);

    if bytes.len() != 32 {
        return Err(RootKeyError::InvalidLength(bytes.len()));
    }

    let mut key = Zeroizing::new([0u8; 32]);
    key.copy_from_slice(&bytes);
    Ok(key)
}

// ---------------------------------------------------------------------------
// Provider selection
// ---------------------------------------------------------------------------

/// Build the appropriate `RootKeyProvider` based on the `VAULT_ROOT_KEY_PROVIDER`
/// environment variable.
///
/// Fails at startup with a clear error message if `aws-kms` is requested but
/// the feature is not compiled in.
pub fn select_provider() -> Result<Box<dyn RootKeyProvider>, RootKeyError> {
    let provider_name =
        std::env::var("VAULT_ROOT_KEY_PROVIDER").unwrap_or_else(|_| "env".to_string());

    match provider_name.trim().to_lowercase().as_str() {
        "env" => Ok(Box::new(EnvRootKeyProvider)),

        "aws-kms" => {
            #[cfg(feature = "aws-kms")]
            {
                let key_id = std::env::var("VAULT_KMS_KEY_ID").map_err(|_| {
                    RootKeyError::KmsDecryptFailed(
                        "VAULT_KMS_KEY_ID environment variable is required for the aws-kms provider"
                            .to_string(),
                    )
                })?;
                Ok(Box::new(AwsKmsRootKeyProvider { key_id }))
            }
            #[cfg(not(feature = "aws-kms"))]
            {
                Err(RootKeyError::AwsKmsFeatureNotEnabled)
            }
        }

        other => Err(RootKeyError::UnknownProvider(other.to_string())),
    }
}

// ---------------------------------------------------------------------------
// Unit tests
// ---------------------------------------------------------------------------

#[cfg(test)]
// ENV_LOCK below is deliberately held across `.await`: it serialises mutation of
// process-wide env vars for the whole body of each test, which is exactly the
// window the awaited provider call reads them in. An async mutex would not help
// — these tests must exclude each other, not yield.
#[allow(clippy::await_holding_lock)]
mod tests {
    use super::*;
    use std::sync::{Mutex, MutexGuard};

    /// Process-wide env vars are shared across the parallel test runner, so every
    /// test that mutates `VAULT_ROOT_KEY` or `VAULT_ROOT_KEY_PROVIDER` must hold
    /// this lock for its full duration.
    static ENV_LOCK: Mutex<()> = Mutex::new(());

    fn env_guard() -> MutexGuard<'static, ()> {
        ENV_LOCK
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    /// EnvRootKeyProvider succeeds when `VAULT_ROOT_KEY` is a valid base64
    /// 32-byte key.
    #[tokio::test]
    async fn env_provider_loads_valid_key() {
        use base64::engine::general_purpose::STANDARD as BASE64;
        use base64::Engine as _;

        let _guard = env_guard();
        let key_bytes: [u8; 32] = std::array::from_fn(|i| (i as u8).wrapping_mul(3));
        let key_b64 = BASE64.encode(key_bytes);

        std::env::set_var("VAULT_ROOT_KEY", &key_b64);
        let provider = EnvRootKeyProvider;
        let loaded = provider.load_root_key().await.expect("load should succeed");
        assert_eq!(&*loaded, &key_bytes, "loaded key must match what we set");
        std::env::remove_var("VAULT_ROOT_KEY");
    }

    #[tokio::test]
    async fn env_provider_fails_when_var_missing() {
        let _guard = env_guard();
        // Ensure the variable is absent.
        std::env::remove_var("VAULT_ROOT_KEY");
        let provider = EnvRootKeyProvider;
        let result = provider.load_root_key().await;
        assert!(
            matches!(result, Err(RootKeyError::EnvVarMissing)),
            "expected EnvVarMissing, got {result:?}"
        );
    }

    #[tokio::test]
    async fn env_provider_fails_on_invalid_base64() {
        let _guard = env_guard();
        std::env::set_var("VAULT_ROOT_KEY", "not!valid!base64!");
        let provider = EnvRootKeyProvider;
        let result = provider.load_root_key().await;
        assert!(
            matches!(result, Err(RootKeyError::InvalidBase64(_))),
            "expected InvalidBase64, got {result:?}"
        );
        std::env::remove_var("VAULT_ROOT_KEY");
    }

    #[tokio::test]
    async fn env_provider_fails_on_wrong_length() {
        use base64::engine::general_purpose::STANDARD as BASE64;
        use base64::Engine as _;

        let _guard = env_guard();
        // 16 bytes — too short.
        let short_b64 = BASE64.encode([0u8; 16]);
        std::env::set_var("VAULT_ROOT_KEY", &short_b64);
        let provider = EnvRootKeyProvider;
        let result = provider.load_root_key().await;
        assert!(
            matches!(result, Err(RootKeyError::InvalidLength(16))),
            "expected InvalidLength(16), got {result:?}"
        );
        std::env::remove_var("VAULT_ROOT_KEY");
    }

    #[test]
    fn select_provider_defaults_to_env() {
        let _guard = env_guard();
        std::env::remove_var("VAULT_ROOT_KEY_PROVIDER");
        // select_provider() should return an EnvRootKeyProvider without error.
        assert!(
            select_provider().is_ok(),
            "default provider selection must not fail"
        );
    }

    #[test]
    fn select_provider_env_explicit() {
        let _guard = env_guard();
        std::env::set_var("VAULT_ROOT_KEY_PROVIDER", "env");
        assert!(
            select_provider().is_ok(),
            "explicit 'env' provider must succeed"
        );
        std::env::remove_var("VAULT_ROOT_KEY_PROVIDER");
    }

    #[test]
    fn select_provider_unknown_name_errors() {
        let _guard = env_guard();
        std::env::set_var("VAULT_ROOT_KEY_PROVIDER", "vault-transit");
        let result = select_provider();
        assert!(
            matches!(result, Err(RootKeyError::UnknownProvider(_))),
            "expected UnknownProvider error for unknown provider name"
        );
        std::env::remove_var("VAULT_ROOT_KEY_PROVIDER");
    }

    /// When the `aws-kms` feature is NOT compiled, requesting it must produce
    /// `AwsKmsFeatureNotEnabled`.
    #[cfg(not(feature = "aws-kms"))]
    #[test]
    fn select_provider_aws_kms_without_feature_errors() {
        let _guard = env_guard();
        std::env::set_var("VAULT_ROOT_KEY_PROVIDER", "aws-kms");
        let result = select_provider();
        assert!(
            matches!(result, Err(RootKeyError::AwsKmsFeatureNotEnabled)),
            "expected AwsKmsFeatureNotEnabled when feature is not compiled"
        );
        std::env::remove_var("VAULT_ROOT_KEY_PROVIDER");
    }

    /// Integration test: KMS calls require real AWS credentials. Marked `#[ignore]`
    /// so it only runs when explicitly invoked with `cargo test -- --ignored`.
    #[cfg(feature = "aws-kms")]
    #[ignore]
    #[tokio::test]
    async fn aws_kms_provider_decrypt_integration() {
        // Requires VAULT_KMS_KEY_ID and VAULT_ROOT_KEY_CIPHERTEXT to be set.
        std::env::set_var("VAULT_ROOT_KEY_PROVIDER", "aws-kms");
        let provider = select_provider().expect("provider selection should succeed");
        let key = provider
            .load_root_key()
            .await
            .expect("KMS decrypt should succeed");
        assert_eq!(key.len(), 32);
    }
}
