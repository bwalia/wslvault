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

use crate::audit_client::AuditClient;
use crate::kv_store::SecretStoreBackend;
use crate::lease_client::LeaseClient;
use crate::path::normalize_and_validate;
use crate::policy_client::{extract_grpc_policies, extract_grpc_principal_id, PolicyClient};

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
///
/// `store` is held as `Arc<dyn SecretStoreBackend>` so the handler is
/// independent of the specific backend (in-memory or PostgreSQL).
///
/// `policy_client` is used to authorize every incoming RPC before the
/// handler touches the store or crypto-service (fail-closed).
///
/// `audit_client` is used to emit fire-and-forget audit events after each
/// operation; failures are logged but never propagated to the caller.
///
/// `lease_client` is used to optionally attach TTL-based leases to secret
/// reads.  If the lease-manager is unavailable the RPC still succeeds
/// (degraded mode — no lease is included in the response).
#[derive(Debug, Clone)]
pub struct SecretServiceImpl {
    pub store: Arc<dyn SecretStoreBackend>,
    /// Base endpoint URL for the crypto-service gRPC connection, e.g.
    /// "http://crypto-service:50051". The client is cloned per request.
    /// Lazily-connected, shared channel to the crypto-service.
    pub crypto_channel: tonic::transport::Channel,
    /// Client for the audit-service event emitter.
    pub audit_client: AuditClient,
    /// Client for the policy-engine authorization service.
    pub policy_client: PolicyClient,
    /// Client for the lease-manager; lease creation is best-effort.
    #[allow(dead_code)] // reserved for a future dynamic secret engine
    pub lease_client: LeaseClient,
}

impl SecretServiceImpl {
    pub fn new(
        store: Arc<dyn SecretStoreBackend>,
        crypto_endpoint: String,
        audit_client: AuditClient,
        policy_client: PolicyClient,
        lease_client: LeaseClient,
    ) -> Self {
        Self {
            store,
            crypto_channel: wslvault_core::grpc_channel::lazy_channel(&crypto_endpoint)
                .unwrap_or_else(|e| panic!("crypto-service endpoint is unusable: {e}")),
            audit_client,
            policy_client,
            lease_client,
        }
    }

    /// Build an ephemeral crypto-service client for a single request.
    ///
    /// A client over the shared channel.
    ///
    /// This used to `connect()` per call, so every encrypt and decrypt paid for
    /// a TCP plus HTTP/2 handshake first. The channel multiplexes and
    /// reconnects on its own, so this is now just a cheap clone.
    #[allow(clippy::result_large_err)]
    async fn crypto_client(
        &self,
    ) -> Result<CryptoServiceClient<tonic::transport::Channel>, Status> {
        Ok(CryptoServiceClient::new(self.crypto_channel.clone()))
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
        // Extract identity metadata from request headers before consuming the request.
        let principal_id = extract_grpc_principal_id(request.metadata());
        let policies = extract_grpc_policies(request.metadata());

        let req = request.into_inner();

        let path = normalize_and_validate(&req.path).map_err(vault_err_to_status)?;

        if req.tenant_id.is_empty() {
            return Err(Status::invalid_argument("tenant_id must not be empty"));
        }

        tracing::Span::current().record("tenant_id", &req.tenant_id.as_str());
        tracing::Span::current().record("path", &path.as_str());
        tracing::Span::current().record("version", &req.version.unwrap_or(0));

        info!("get_secret");

        // Authorize before reading from the store.
        let resource = format!("secret/data/{}", path);
        if let Err(e) = self
            .policy_client
            .authorize(&req.tenant_id, &principal_id, &policies, "read", &resource)
            .await
        {
            self.audit_client
                .emit(
                    &req.tenant_id,
                    &principal_id,
                    "secret.read",
                    &path,
                    "failure",
                    &e.to_string(),
                    "",
                    "",
                )
                .await;
            return Err(vault_err_to_status(e));
        }

        let ver_entry = match self.store.get(&req.tenant_id, &path, req.version).await {
            Ok(v) => v,
            Err(e) => {
                self.audit_client
                    .emit(
                        &req.tenant_id,
                        &principal_id,
                        "secret.read",
                        &path,
                        "failure",
                        &e.to_string(),
                        "",
                        "",
                    )
                    .await;
                return Err(vault_err_to_status(e));
            }
        };

        let aad = Self::build_aad(&req.tenant_id, &path);

        let mut crypto = match self.crypto_client().await {
            Ok(c) => c,
            Err(e) => {
                self.audit_client
                    .emit(
                        &req.tenant_id,
                        &principal_id,
                        "secret.read",
                        &path,
                        "failure",
                        e.message(),
                        "",
                        "",
                    )
                    .await;
                return Err(e);
            }
        };

        let decrypt_resp = match crypto
            .decrypt(crypto_proto::DecryptRequest {
                tenant_id: req.tenant_id.clone(),
                ciphertext_b64: ver_entry.ciphertext.clone(),
                aad,
            })
            .await
        {
            Ok(r) => r,
            Err(e) => {
                error!(error = %e, "crypto-service decrypt failed");
                self.audit_client
                    .emit(
                        &req.tenant_id,
                        &principal_id,
                        "secret.read",
                        &path,
                        "failure",
                        &format!("decryption failed: {}", e),
                        "",
                        "",
                    )
                    .await;
                return Err(Status::internal(format!("decryption failed: {}", e)));
            }
        };

        self.audit_client
            .emit(
                &req.tenant_id,
                &principal_id,
                "secret.read",
                &path,
                "success",
                "",
                "",
                "",
            )
            .await;

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
        // Extract identity metadata from request headers before consuming the request.
        let principal_id = extract_grpc_principal_id(request.metadata());
        let policies = extract_grpc_policies(request.metadata());

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

        // Authorize before writing to the crypto-service or store.
        let resource = format!("secret/data/{}", path);
        if let Err(e) = self
            .policy_client
            .authorize(&req.tenant_id, &principal_id, &policies, "write", &resource)
            .await
        {
            self.audit_client
                .emit(
                    &req.tenant_id,
                    &principal_id,
                    "secret.write",
                    &path,
                    "failure",
                    &e.to_string(),
                    "",
                    "",
                )
                .await;
            return Err(vault_err_to_status(e));
        }

        let aad = Self::build_aad(&req.tenant_id, &path);

        let mut crypto = match self.crypto_client().await {
            Ok(c) => c,
            Err(e) => {
                self.audit_client
                    .emit(
                        &req.tenant_id,
                        &principal_id,
                        "secret.write",
                        &path,
                        "failure",
                        e.message(),
                        "",
                        "",
                    )
                    .await;
                return Err(e);
            }
        };

        let encrypt_resp = match crypto
            .encrypt(crypto_proto::EncryptRequest {
                tenant_id: req.tenant_id.clone(),
                plaintext: req.data,
                aad,
            })
            .await
        {
            Ok(r) => r,
            Err(e) => {
                error!(error = %e, "crypto-service encrypt failed");
                self.audit_client
                    .emit(
                        &req.tenant_id,
                        &principal_id,
                        "secret.write",
                        &path,
                        "failure",
                        &format!("encryption failed: {}", e),
                        "",
                        "",
                    )
                    .await;
                return Err(Status::internal(format!("encryption failed: {}", e)));
            }
        };

        let enc = encrypt_resp.into_inner();

        let (secret_id, version) = match self
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
        {
            Ok(r) => r,
            Err(e) => {
                self.audit_client
                    .emit(
                        &req.tenant_id,
                        &principal_id,
                        "secret.write",
                        &path,
                        "failure",
                        &e.to_string(),
                        "",
                        "",
                    )
                    .await;
                return Err(vault_err_to_status(e));
            }
        };

        self.audit_client
            .emit(
                &req.tenant_id,
                &principal_id,
                "secret.write",
                &path,
                "success",
                "",
                "",
                "",
            )
            .await;

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
        // Extract identity metadata from request headers before consuming the request.
        let principal_id = extract_grpc_principal_id(request.metadata());
        let policies = extract_grpc_policies(request.metadata());

        let req = request.into_inner();

        let path = normalize_and_validate(&req.path).map_err(vault_err_to_status)?;

        if req.tenant_id.is_empty() {
            return Err(Status::invalid_argument("tenant_id must not be empty"));
        }

        tracing::Span::current().record("tenant_id", &req.tenant_id.as_str());
        tracing::Span::current().record("path", &path.as_str());

        info!("delete_secret");

        // Authorize before soft-deleting from the store.
        let resource = format!("secret/data/{}", path);
        if let Err(e) = self
            .policy_client
            .authorize(
                &req.tenant_id,
                &principal_id,
                &policies,
                "delete",
                &resource,
            )
            .await
        {
            self.audit_client
                .emit(
                    &req.tenant_id,
                    &principal_id,
                    "secret.delete",
                    &path,
                    "failure",
                    &e.to_string(),
                    "",
                    "",
                )
                .await;
            return Err(vault_err_to_status(e));
        }

        let deleted_count = match self
            .store
            .soft_delete(&req.tenant_id, &path, &req.versions)
            .await
        {
            Ok(c) => c,
            Err(e) => {
                self.audit_client
                    .emit(
                        &req.tenant_id,
                        &principal_id,
                        "secret.delete",
                        &path,
                        "failure",
                        &e.to_string(),
                        "",
                        "",
                    )
                    .await;
                return Err(vault_err_to_status(e));
            }
        };

        self.audit_client
            .emit(
                &req.tenant_id,
                &principal_id,
                "secret.delete",
                &path,
                "success",
                "",
                "",
                "",
            )
            .await;

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
        // Extract identity metadata from request headers before consuming the request.
        let principal_id = extract_grpc_principal_id(request.metadata());
        let policies = extract_grpc_policies(request.metadata());

        let req = request.into_inner();

        let path = normalize_and_validate(&req.path).map_err(vault_err_to_status)?;

        if req.tenant_id.is_empty() {
            return Err(Status::invalid_argument("tenant_id must not be empty"));
        }

        tracing::Span::current().record("tenant_id", &req.tenant_id.as_str());
        tracing::Span::current().record("path", &path.as_str());

        info!("destroy_secret");

        // Authorize before permanently destroying versions in the store.
        let resource = format!("secret/data/{}", path);
        if let Err(e) = self
            .policy_client
            .authorize(
                &req.tenant_id,
                &principal_id,
                &policies,
                "delete",
                &resource,
            )
            .await
        {
            self.audit_client
                .emit(
                    &req.tenant_id,
                    &principal_id,
                    "secret.destroy",
                    &path,
                    "failure",
                    &e.to_string(),
                    "",
                    "",
                )
                .await;
            return Err(vault_err_to_status(e));
        }

        let destroyed_count = match self
            .store
            .destroy(&req.tenant_id, &path, &req.versions)
            .await
        {
            Ok(c) => c,
            Err(e) => {
                self.audit_client
                    .emit(
                        &req.tenant_id,
                        &principal_id,
                        "secret.destroy",
                        &path,
                        "failure",
                        &e.to_string(),
                        "",
                        "",
                    )
                    .await;
                return Err(vault_err_to_status(e));
            }
        };

        self.audit_client
            .emit(
                &req.tenant_id,
                &principal_id,
                "secret.destroy",
                &path,
                "success",
                "",
                "",
                "",
            )
            .await;

        Ok(Response::new(DestroySecretResponse { destroyed_count }))
    }

    /// List all secret paths under a given prefix within a tenant.
    #[instrument(skip(self, request), fields(tenant_id, prefix))]
    async fn list_secrets(
        &self,
        request: Request<ListSecretsRequest>,
    ) -> Result<Response<ListSecretsResponse>, Status> {
        // Extract identity metadata from request headers before consuming the request.
        let principal_id = extract_grpc_principal_id(request.metadata());
        let policies = extract_grpc_policies(request.metadata());

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

        // Authorize before listing from the store.
        if let Err(e) = self
            .policy_client
            .authorize(
                &req.tenant_id,
                &principal_id,
                &policies,
                "list",
                "secret/list",
            )
            .await
        {
            self.audit_client
                .emit(
                    &req.tenant_id,
                    &principal_id,
                    "secret.list",
                    &prefix,
                    "failure",
                    &e.to_string(),
                    "",
                    "",
                )
                .await;
            return Err(vault_err_to_status(e));
        }

        let mut paths = self.store.list(&req.tenant_id, &prefix).await;
        paths.sort();

        self.audit_client
            .emit(
                &req.tenant_id,
                &principal_id,
                "secret.list",
                &prefix,
                "success",
                "",
                "",
                "",
            )
            .await;

        Ok(Response::new(ListSecretsResponse { paths }))
    }

    /// Return metadata for a secret path without decrypting any version data.
    #[instrument(skip(self, request), fields(tenant_id, path))]
    async fn get_metadata(
        &self,
        request: Request<GetMetadataRequest>,
    ) -> Result<Response<GetMetadataResponse>, Status> {
        // Extract identity metadata from request headers before consuming the request.
        let principal_id = extract_grpc_principal_id(request.metadata());
        let policies = extract_grpc_policies(request.metadata());

        let req = request.into_inner();

        let path = normalize_and_validate(&req.path).map_err(vault_err_to_status)?;

        if req.tenant_id.is_empty() {
            return Err(Status::invalid_argument("tenant_id must not be empty"));
        }

        tracing::Span::current().record("tenant_id", &req.tenant_id.as_str());
        tracing::Span::current().record("path", &path.as_str());

        info!("get_metadata");

        // Authorize before reading metadata from the store.
        let resource = format!("secret/metadata/{}", path);
        if let Err(e) = self
            .policy_client
            .authorize(&req.tenant_id, &principal_id, &policies, "read", &resource)
            .await
        {
            self.audit_client
                .emit(
                    &req.tenant_id,
                    &principal_id,
                    "secret.metadata.read",
                    &path,
                    "failure",
                    &e.to_string(),
                    "",
                    "",
                )
                .await;
            return Err(vault_err_to_status(e));
        }

        let entry = match self.store.get_metadata(&req.tenant_id, &path).await {
            Ok(e) => e,
            Err(e) => {
                self.audit_client
                    .emit(
                        &req.tenant_id,
                        &principal_id,
                        "secret.metadata.read",
                        &path,
                        "failure",
                        &e.to_string(),
                        "",
                        "",
                    )
                    .await;
                return Err(vault_err_to_status(e));
            }
        };

        self.audit_client
            .emit(
                &req.tenant_id,
                &principal_id,
                "secret.metadata.read",
                &path,
                "success",
                "",
                "",
                "",
            )
            .await;

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
