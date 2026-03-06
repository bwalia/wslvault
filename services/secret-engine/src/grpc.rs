//! gRPC service implementation for the secret engine.
//!
//! This module implements the `SecretService` tonic trait generated from the
//! `wslvault.secret.v1` proto definition. All secret data is encrypted via the
//! crypto-service before being written to the KV store, and decrypted on reads.
//!
//! # Error mapping
//! `VaultError` variants are mapped to appropriate tonic `Status` codes so
//! gRPC clients receive structured, actionable error responses.

use std::sync::Arc;

use tonic::{Request, Response, Status};
use tracing::{error, info, instrument};

use crate::kv_store::KvStore;
use crate::path::normalize_and_validate;

// Include the generated code for both proto packages in separate modules to
// prevent name collisions between identically named messages.
pub mod secret_proto {
    tonic::include_proto!("wslvault.secret.v1");
}

pub mod crypto_proto {
    tonic::include_proto!("wslvault.crypto.v1");
}

use crypto_proto::crypto_service_client::CryptoServiceClient;
use secret_proto::secret_service_server::SecretService;
use secret_proto::{
    DeleteSecretRequest, DeleteSecretResponse, DestroySecretRequest, DestroySecretResponse,
    GetMetadataRequest, GetMetadataResponse, GetSecretRequest, GetSecretResponse,
    ListSecretsRequest, ListSecretsResponse, PutSecretRequest, PutSecretResponse,
};

use wslvault_core::VaultError;

/// Map a `VaultError` to a tonic `Status` with a meaningful description.
fn vault_err_to_status(err: VaultError) -> Status {
    match &err {
        VaultError::SecretNotFound { .. } => Status::not_found(err.to_string()),
        VaultError::InvalidPath { .. } | VaultError::ValidationError { .. } => {
            Status::invalid_argument(err.to_string())
        }
        VaultError::CasConflict { .. } => Status::aborted(err.to_string()),
        VaultError::VersionDestroyed { .. } => Status::not_found(err.to_string()),
        VaultError::PermissionDenied { .. } => Status::permission_denied(err.to_string()),
        VaultError::Unauthenticated { .. } => Status::unauthenticated(err.to_string()),
        VaultError::ServiceUnavailable { .. } => Status::unavailable(err.to_string()),
        VaultError::EncryptionFailed { .. } | VaultError::DecryptionFailed => {
            Status::internal(err.to_string())
        }
        _ => Status::internal(err.to_string()),
    }
}

/// Shared state injected into the gRPC service handler.
///
/// The `crypto_client` field is a `CryptoServiceClient` connected to the
/// upstream crypto-service. It is cloned per-request to satisfy tonic's
/// `Clone` requirements on client types.
#[derive(Debug, Clone)]
pub struct SecretServiceImpl {
    pub store: Arc<KvStore>,
    /// Base endpoint URL for the crypto-service gRPC connection, e.g.
    /// "http://crypto-service:50051". The client is cloned per request.
    pub crypto_endpoint: String,
}

impl SecretServiceImpl {
    pub fn new(store: Arc<KvStore>, crypto_endpoint: String) -> Self {
        Self {
            store,
            crypto_endpoint,
        }
    }

    /// Build an ephemeral crypto-service client for a single request.
    ///
    /// In a production system you would maintain a connection pool. For the
    /// initial in-memory implementation a lazily created client per-call is
    /// sufficient and avoids lifecycle complexity.
    async fn crypto_client(
        &self,
    ) -> Result<CryptoServiceClient<tonic::transport::Channel>, Status> {
        CryptoServiceClient::connect(self.crypto_endpoint.clone())
            .await
            .map_err(|e| {
                error!(error = %e, "failed to connect to crypto-service");
                Status::unavailable(format!("crypto-service unavailable: {}", e))
            })
    }

    /// Build the additional authenticated data (AAD) bytes used for envelope
    /// encryption. Binding the tenant and path into the AAD prevents ciphertext
    /// reuse across different paths or tenants.
    fn build_aad(tenant_id: &str, path: &str) -> Vec<u8> {
        format!("{}:{}", tenant_id, path).into_bytes()
    }
}

#[tonic::async_trait]
impl SecretService for SecretServiceImpl {
    /// Retrieve a secret version and decrypt it via the crypto-service.
    #[instrument(skip(self, request), fields(tenant_id, path, version))]
    async fn get_secret(
        &self,
        request: Request<GetSecretRequest>,
    ) -> Result<Response<GetSecretResponse>, Status> {
        let req = request.into_inner();

        let path = normalize_and_validate(&req.path).map_err(vault_err_to_status)?;

        if req.tenant_id.is_empty() {
            return Err(Status::invalid_argument("tenant_id must not be empty"));
        }

        tracing::Span::current().record("tenant_id", &req.tenant_id.as_str());
        tracing::Span::current().record("path", &path.as_str());
        tracing::Span::current().record("version", &req.version.unwrap_or(0));

        info!("get_secret");

        let ver_entry = self
            .store
            .get(&req.tenant_id, &path, req.version)
            .await
            .map_err(vault_err_to_status)?;

        let aad = Self::build_aad(&req.tenant_id, &path);

        let mut crypto = self.crypto_client().await?;

        let decrypt_resp = crypto
            .decrypt(crypto_proto::DecryptRequest {
                tenant_id: req.tenant_id.clone(),
                ciphertext_b64: ver_entry.ciphertext.clone(),
                aad,
            })
            .await
            .map_err(|e| {
                error!(error = %e, "crypto-service decrypt failed");
                Status::internal(format!("decryption failed: {}", e))
            })?;

        Ok(Response::new(GetSecretResponse {
            data: decrypt_resp.into_inner().plaintext,
            version: ver_entry.version,
            created_at: ver_entry.created_at.to_rfc3339(),
            metadata: ver_entry.custom_metadata,
        }))
    }

    /// Encrypt the provided data via the crypto-service and write a new version.
    #[instrument(skip(self, request), fields(tenant_id, path))]
    async fn put_secret(
        &self,
        request: Request<PutSecretRequest>,
    ) -> Result<Response<PutSecretResponse>, Status> {
        let req = request.into_inner();

        let path = normalize_and_validate(&req.path).map_err(vault_err_to_status)?;

        if req.tenant_id.is_empty() {
            return Err(Status::invalid_argument("tenant_id must not be empty"));
        }

        if req.data.is_empty() {
            return Err(Status::invalid_argument("data must not be empty"));
        }

        tracing::Span::current().record("tenant_id", &req.tenant_id.as_str());
        tracing::Span::current().record("path", &path.as_str());

        info!("put_secret");

        let aad = Self::build_aad(&req.tenant_id, &path);

        let mut crypto = self.crypto_client().await?;

        let encrypt_resp = crypto
            .encrypt(crypto_proto::EncryptRequest {
                tenant_id: req.tenant_id.clone(),
                plaintext: req.data,
                aad,
            })
            .await
            .map_err(|e| {
                error!(error = %e, "crypto-service encrypt failed");
                Status::internal(format!("encryption failed: {}", e))
            })?;

        let enc = encrypt_resp.into_inner();

        let (secret_id, version) = self
            .store
            .put(
                &req.tenant_id,
                &path,
                enc.ciphertext_b64,
                enc.dek_id,
                req.cas,
                req.metadata,
                None,
            )
            .await
            .map_err(vault_err_to_status)?;

        Ok(Response::new(PutSecretResponse { secret_id, version }))
    }

    /// Soft-delete one or more versions of a secret.
    ///
    /// Deleted versions retain their ciphertext and can still appear in metadata
    /// but will not be returned by `get_secret` unless explicitly requested.
    #[instrument(skip(self, request), fields(tenant_id, path))]
    async fn delete_secret(
        &self,
        request: Request<DeleteSecretRequest>,
    ) -> Result<Response<DeleteSecretResponse>, Status> {
        let req = request.into_inner();

        let path = normalize_and_validate(&req.path).map_err(vault_err_to_status)?;

        if req.tenant_id.is_empty() {
            return Err(Status::invalid_argument("tenant_id must not be empty"));
        }

        tracing::Span::current().record("tenant_id", &req.tenant_id.as_str());
        tracing::Span::current().record("path", &path.as_str());

        info!("delete_secret");

        let deleted_count = self
            .store
            .soft_delete(&req.tenant_id, &path, &req.versions)
            .await
            .map_err(vault_err_to_status)?;

        Ok(Response::new(DeleteSecretResponse { deleted_count }))
    }

    /// Permanently destroy one or more versions of a secret.
    ///
    /// Destroyed versions have their ciphertext zeroed. This operation is
    /// irreversible and the data cannot be recovered after destruction.
    #[instrument(skip(self, request), fields(tenant_id, path))]
    async fn destroy_secret(
        &self,
        request: Request<DestroySecretRequest>,
    ) -> Result<Response<DestroySecretResponse>, Status> {
        let req = request.into_inner();

        let path = normalize_and_validate(&req.path).map_err(vault_err_to_status)?;

        if req.tenant_id.is_empty() {
            return Err(Status::invalid_argument("tenant_id must not be empty"));
        }

        tracing::Span::current().record("tenant_id", &req.tenant_id.as_str());
        tracing::Span::current().record("path", &path.as_str());

        info!("destroy_secret");

        let destroyed_count = self
            .store
            .destroy(&req.tenant_id, &path, &req.versions)
            .await
            .map_err(vault_err_to_status)?;

        Ok(Response::new(DestroySecretResponse { destroyed_count }))
    }

    /// List all secret paths under a given prefix within a tenant.
    #[instrument(skip(self, request), fields(tenant_id, prefix))]
    async fn list_secrets(
        &self,
        request: Request<ListSecretsRequest>,
    ) -> Result<Response<ListSecretsResponse>, Status> {
        let req = request.into_inner();

        if req.tenant_id.is_empty() {
            return Err(Status::invalid_argument("tenant_id must not be empty"));
        }

        // Prefix validation: empty prefix lists everything; non-empty prefix must be valid.
        let prefix = if req.prefix.is_empty() {
            String::new()
        } else {
            normalize_and_validate(&req.prefix).map_err(vault_err_to_status)?
        };

        tracing::Span::current().record("tenant_id", &req.tenant_id.as_str());
        tracing::Span::current().record("prefix", &prefix.as_str());

        info!("list_secrets");

        let mut paths = self.store.list(&req.tenant_id, &prefix).await;
        paths.sort();

        Ok(Response::new(ListSecretsResponse { paths }))
    }

    /// Return metadata for a secret path without decrypting any version data.
    #[instrument(skip(self, request), fields(tenant_id, path))]
    async fn get_metadata(
        &self,
        request: Request<GetMetadataRequest>,
    ) -> Result<Response<GetMetadataResponse>, Status> {
        let req = request.into_inner();

        let path = normalize_and_validate(&req.path).map_err(vault_err_to_status)?;

        if req.tenant_id.is_empty() {
            return Err(Status::invalid_argument("tenant_id must not be empty"));
        }

        tracing::Span::current().record("tenant_id", &req.tenant_id.as_str());
        tracing::Span::current().record("path", &path.as_str());

        info!("get_metadata");

        let entry = self
            .store
            .get_metadata(&req.tenant_id, &path)
            .await
            .map_err(vault_err_to_status)?;

        Ok(Response::new(GetMetadataResponse {
            current_version: entry.current_version_number(),
            secret_id: entry.secret_id,
            path: entry.path,
            engine: "kv-v2".to_string(),
            max_versions: entry.max_versions,
            cas_required: entry.cas_required,
            created_at: entry.created_at.to_rfc3339(),
            updated_at: entry.updated_at.to_rfc3339(),
        }))
    }
}
