//! gRPC service implementation for the CryptoService proto contract.
//!
//! This module wires the tonic-generated `CryptoService` trait to the actual
//! key-management and envelope-encryption logic in `KekStore` and the
//! `wslvault_core::crypto::envelope` primitives.
//!
//! All `VaultError` variants are mapped to canonical `tonic::Status` codes so
//! that callers receive meaningful gRPC status responses.

use tonic::{Request, Response, Status};
use tracing::{debug, error, info, warn};

use wslvault_core::crypto::envelope::{decrypt_with_dek, encrypt_with_dek};
use wslvault_core::error::VaultError;

use crate::kek_store::KekStore;

/// Include the tonic-generated code for `wslvault.crypto.v1` in a dedicated
/// `proto` sub-module so it does not pollute the crate namespace.
pub mod proto {
    tonic::include_proto!("wslvault.crypto.v1");
}

use proto::crypto_service_server::CryptoService;
use proto::{
    DecryptRequest, DecryptResponse, EncryptRequest, EncryptResponse, GenerateDekRequest,
    GenerateDekResponse, GetKeyDescriptorRequest, GetKeyDescriptorResponse, RotateKeyRequest,
    RotateKeyResponse,
};

/// Convert a `VaultError` to the most appropriate `tonic::Status`.
///
/// Mapping rationale:
/// - `KeyNotFound` / resource-not-found errors -> `NOT_FOUND`
/// - `PermissionDenied` -> `PERMISSION_DENIED`
/// - Cryptographic failures -> `INTERNAL` (details not surfaced to callers for security)
/// - Validation errors -> `INVALID_ARGUMENT`
fn vault_error_to_status(err: VaultError) -> Status {
    match &err {
        VaultError::KeyNotFound { key_id } => Status::not_found(format!("key not found: {key_id}")),
        VaultError::TenantNotFound { tenant_id } => {
            Status::not_found(format!("tenant not found: {tenant_id}"))
        }
        VaultError::PermissionDenied { resource, reason } => {
            Status::permission_denied(format!("permission denied on {resource}: {reason}"))
        }
        VaultError::ValidationError { field, reason } => {
            Status::invalid_argument(format!("validation error on {field}: {reason}"))
        }
        VaultError::EncryptionFailed { .. } => {
            // Do not leak internal cryptographic details.
            error!(error = %err, "Encryption failure");
            Status::internal("encryption operation failed")
        }
        VaultError::DecryptionFailed => {
            // Do not leak internal cryptographic details.
            warn!("Decryption failure — bad key, ciphertext, or AAD");
            Status::internal("decryption operation failed")
        }
        VaultError::Internal { reason } => {
            error!(reason, "Internal error");
            Status::internal("internal service error")
        }
        other => {
            error!(error = %other, "Unexpected error");
            Status::internal("internal service error")
        }
    }
}

/// Validate that a required string field is non-empty, returning an
/// `INVALID_ARGUMENT` status if it is blank.
fn require_non_empty<'a>(value: &'a str, field: &str) -> Result<&'a str, Status> {
    if value.trim().is_empty() {
        Err(Status::invalid_argument(format!(
            "field '{field}' must not be empty"
        )))
    } else {
        Ok(value)
    }
}

/// The concrete gRPC handler struct.
#[derive(Debug, Clone)]
pub struct CryptoServiceImpl {
    /// Shared, async-safe key store.
    kek_store: KekStore,
}

impl CryptoServiceImpl {
    /// Construct a new handler backed by the provided `KekStore`.
    pub fn new(kek_store: KekStore) -> Self {
        Self { kek_store }
    }
}

#[tonic::async_trait]
impl CryptoService for CryptoServiceImpl {
    /// Encrypt arbitrary plaintext using envelope encryption under the tenant's key hierarchy.
    ///
    /// Flow:
    /// 1. Ensure a tenant KEK exists (creating one on first use).
    /// 2. Generate a fresh DEK and register it in the key store.
    /// 3. Encrypt the plaintext with the DEK (AES-256-GCM via `encrypt_with_dek`).
    /// 4. Return the ciphertext (base64-encoded nonce||ct||tag) and the DEK id.
    async fn encrypt(
        &self,
        request: Request<EncryptRequest>,
    ) -> Result<Response<EncryptResponse>, Status> {
        let req = request.into_inner();
        let tenant_id = require_non_empty(&req.tenant_id, "tenant_id")?;

        debug!(tenant_id, "Handling Encrypt request");

        if req.plaintext.is_empty() {
            return Err(Status::invalid_argument("plaintext must not be empty"));
        }

        // Generate a new DEK for this encryption operation.
        // Using a per-encrypt DEK with a unique context derived from the operation
        // provides forward secrecy: compromise of one DEK only exposes one ciphertext.
        let context = format!("encrypt:{tenant_id}:{}", uuid::Uuid::now_v7());
        let key_id = self
            .kek_store
            .generate_and_store_dek(tenant_id, &context)
            .await
            .map_err(vault_error_to_status)?;

        let dek = self
            .kek_store
            .get_dek(&key_id)
            .await
            .map_err(vault_error_to_status)?;

        let envelope =
            encrypt_with_dek(&dek, &req.plaintext, &req.aad).map_err(vault_error_to_status)?;

        info!(tenant_id, key_id, "Encrypt completed");

        Ok(Response::new(EncryptResponse {
            ciphertext_b64: envelope.ciphertext_b64,
            dek_id: key_id,
        }))
    }

    /// Decrypt a ciphertext envelope produced by `Encrypt`.
    ///
    /// Flow:
    /// 1. Look up the DEK registered under the `dek_id` embedded in the ciphertext_b64
    ///    response from the previous `Encrypt` call — callers must pass this back.
    ///    Note: the proto `DecryptRequest` carries `ciphertext_b64` but not a `dek_id`
    ///    field explicitly; callers that use the service are expected to store the
    ///    `dek_id` from `EncryptResponse` alongside the ciphertext and supply it as
    ///    part of the `ciphertext_b64` field using the convention
    ///    `"<dek_id>:<ciphertext_b64>"`.
    ///
    /// Wire convention (chosen to work within the current proto schema):
    ///   `ciphertext_b64` = "<dek_id>:<actual_base64_ciphertext>"
    async fn decrypt(
        &self,
        request: Request<DecryptRequest>,
    ) -> Result<Response<DecryptResponse>, Status> {
        let req = request.into_inner();
        let tenant_id = require_non_empty(&req.tenant_id, "tenant_id")?;

        debug!(tenant_id, "Handling Decrypt request");

        // Parse "<dek_id>:<ciphertext_b64>" from the combined field.
        // The dek_id is a UUID which never contains ':', so splitting on the first ':'
        // is safe and unambiguous.
        let (dek_id, ciphertext_b64) = req.ciphertext_b64.split_once(':').ok_or_else(|| {
            Status::invalid_argument(
                "ciphertext_b64 must be in the format '<dek_id>:<base64_ciphertext>'",
            )
        })?;

        require_non_empty(dek_id, "dek_id (embedded in ciphertext_b64)")?;
        require_non_empty(
            ciphertext_b64,
            "base64 ciphertext (embedded in ciphertext_b64)",
        )?;

        let dek = self
            .kek_store
            .get_dek(dek_id)
            .await
            .map_err(vault_error_to_status)?;

        let plaintext =
            decrypt_with_dek(&dek, ciphertext_b64, &req.aad).map_err(vault_error_to_status)?;

        info!(tenant_id, dek_id, "Decrypt completed");

        Ok(Response::new(DecryptResponse {
            plaintext: plaintext.to_vec(),
        }))
    }

    /// Generate a new DEK, wrap it under the tenant's KEK, and return its metadata.
    ///
    /// Callers (e.g. secret-engine) use this to pre-provision a DEK for a secret path.
    /// The `wrapped_dek` in the response is the DEK encrypted under the tenant KEK and
    /// should be stored alongside the encrypted secret for later decryption.
    async fn generate_dek(
        &self,
        request: Request<GenerateDekRequest>,
    ) -> Result<Response<GenerateDekResponse>, Status> {
        let req = request.into_inner();
        let tenant_id = require_non_empty(&req.tenant_id, "tenant_id")?;
        let context = require_non_empty(&req.context, "context")?;

        debug!(tenant_id, context, "Handling GenerateDek request");

        let key_id = self
            .kek_store
            .generate_and_store_dek(tenant_id, context)
            .await
            .map_err(vault_error_to_status)?;

        let (wrapped_dek_b64, version) = self
            .kek_store
            .get_dek_metadata(&key_id)
            .await
            .map_err(vault_error_to_status)?;

        info!(tenant_id, key_id, version, "GenerateDek completed");

        Ok(Response::new(GenerateDekResponse {
            key_id,
            version,
            algorithm: "AES-256-GCM".to_string(),
            wrapped_dek: wrapped_dek_b64,
        }))
    }

    /// Rotate the DEK identified by `key_id` for a given tenant.
    ///
    /// A new 32-byte random key replaces the current DEK in the store and is wrapped
    /// under the current tenant KEK. The new version number is returned. After rotation,
    /// any new encryptions will use the new DEK; existing ciphertext should be
    /// re-encrypted during the operator's migration window.
    async fn rotate_key(
        &self,
        request: Request<RotateKeyRequest>,
    ) -> Result<Response<RotateKeyResponse>, Status> {
        let req = request.into_inner();
        let tenant_id = require_non_empty(&req.tenant_id, "tenant_id")?;
        let key_id = require_non_empty(&req.key_id, "key_id")?;

        info!(tenant_id, key_id, "Handling RotateKey request");

        let new_version = self
            .kek_store
            .rotate_dek(tenant_id, key_id)
            .await
            .map_err(vault_error_to_status)?;

        Ok(Response::new(RotateKeyResponse {
            key_id: key_id.to_string(),
            new_version,
        }))
    }

    /// Return metadata for a key identified by `key_id`.
    ///
    /// Returns the key's algorithm, purpose, state, and current version.
    /// This endpoint intentionally returns no key material — callers can use it
    /// to check key health and version without needing crypto privileges.
    async fn get_key_descriptor(
        &self,
        request: Request<GetKeyDescriptorRequest>,
    ) -> Result<Response<GetKeyDescriptorResponse>, Status> {
        let req = request.into_inner();
        let key_id_str = require_non_empty(&req.key_id, "key_id")?;

        debug!(key_id = key_id_str, "Handling GetKeyDescriptor request");

        let (_, version) = self
            .kek_store
            .get_dek_metadata(key_id_str)
            .await
            .map_err(vault_error_to_status)?;

        Ok(Response::new(GetKeyDescriptorResponse {
            key_id: key_id_str.to_string(),
            version,
            algorithm: "AES-256-GCM".to_string(),
            purpose: "DataEncryption".to_string(),
            state: "Active".to_string(),
        }))
    }
}
