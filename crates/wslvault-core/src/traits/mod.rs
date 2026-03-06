//! Core trait definitions that decouple service interfaces from implementations.
//!
//! Each service implements the relevant traits from this module.
//! Services communicate through these contracts, enabling testability with mock backends.

use std::collections::HashMap;

use async_trait::async_trait;

use crate::error::VaultError;
use crate::types::key::{KeyDescriptor, KeyMaterial};
use crate::types::lease::Lease;
use crate::types::principal::Principal;
use crate::types::secret::{SecretMetadata, SecretReadResult};
use crate::types::tenant::TenantId;

/// The core secret storage interface. Implemented by the secret-engine service.
/// All operations are tenant-scoped via the Principal's tenant_id.
#[async_trait]
pub trait SecretBackend: Send + Sync {
    /// Read a secret at the given path. If version is None, returns current version.
    async fn get(
        &self,
        principal: &Principal,
        path: &str,
        version: Option<u32>,
    ) -> Result<SecretReadResult, VaultError>;

    /// Write a new version of a secret.
    /// If `cas` is Some(n), the write only succeeds if the current version is n.
    async fn put(
        &self,
        principal: &Principal,
        path: &str,
        data: &[u8],
        cas: Option<u32>,
        metadata: HashMap<String, String>,
    ) -> Result<SecretMetadata, VaultError>;

    /// Soft-delete secret versions (marked deleted but not destroyed).
    async fn delete(
        &self,
        principal: &Principal,
        path: &str,
        versions: &[u32],
    ) -> Result<(), VaultError>;

    /// Permanently destroy secret versions; key material for them will be wiped.
    async fn destroy(
        &self,
        principal: &Principal,
        path: &str,
        versions: &[u32],
    ) -> Result<(), VaultError>;

    /// List secret paths under a given prefix.
    async fn list(&self, principal: &Principal, prefix: &str) -> Result<Vec<String>, VaultError>;
}

/// Interface for all cryptographic operations. Implemented by the crypto-service.
/// In test environments, an in-process SoftwareCryptoBackend can be used.
#[async_trait]
pub trait CryptoBackend: Send + Sync {
    /// Generate a new DEK for a given tenant + path context.
    async fn generate_dek(
        &self,
        tenant_id: &TenantId,
        context: &str,
    ) -> Result<KeyMaterial, VaultError>;

    /// Encrypt plaintext using envelope encryption under the tenant's key hierarchy.
    /// Returns the ciphertext as a base64-encoded string.
    async fn encrypt(
        &self,
        tenant_id: &TenantId,
        plaintext: &[u8],
        aad: &[u8],
    ) -> Result<String, VaultError>;

    /// Decrypt a ciphertext envelope produced by `encrypt`.
    async fn decrypt(
        &self,
        tenant_id: &TenantId,
        ciphertext_b64: &str,
        aad: &[u8],
    ) -> Result<Vec<u8>, VaultError>;

    /// Rotate the tenant's active DEK; old versions remain decryptable.
    async fn rotate_key(
        &self,
        tenant_id: &TenantId,
        key_id: &str,
    ) -> Result<KeyDescriptor, VaultError>;
}

/// A structured, tamper-evident audit record. Every secret read/write/auth event
/// produces one of these. The `signature` field is an HMAC-SHA256 of the serialized
/// event, keyed by the tenant's audit signing key.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct AuditEvent {
    pub id: uuid::Uuid,
    pub tenant_id: String,
    pub principal_id: String,
    /// Action identifier, e.g. "secret.read", "secret.write", "auth.login".
    pub action: String,
    /// Path or resource identifier.
    pub resource: String,
    pub outcome: AuditOutcome,
    pub details: serde_json::Value,
    pub client_ip: Option<String>,
    pub timestamp: chrono::DateTime<chrono::Utc>,
    /// Populated by audit-service before persisting; HMAC-SHA256 integrity signature.
    pub signature: Option<String>,
}

/// Outcome of an audited operation.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum AuditOutcome {
    Success,
    Failure { reason: String },
    Denied { policy: String },
}

/// Interface for writing audit events. Multiple sink implementations are possible
/// (PostgreSQL, S3, Kafka). The audit-service fans out to all configured sinks.
#[async_trait]
pub trait AuditSink: Send + Sync {
    async fn emit(&self, event: AuditEvent) -> Result<(), VaultError>;
}

/// Policy evaluation interface. Implemented by the policy-engine service.
#[async_trait]
pub trait PolicyEvaluator: Send + Sync {
    /// Returns Ok(()) if the principal is allowed to perform `action` on `resource`.
    /// Returns Err(VaultError::PermissionDenied) otherwise.
    async fn authorize(
        &self,
        principal: &Principal,
        action: &str,
        resource: &str,
    ) -> Result<(), VaultError>;
}

/// Lease management interface. Implemented by the lease-manager service.
#[async_trait]
pub trait LeaseManager: Send + Sync {
    /// Create a new lease for the given target.
    async fn create_lease(
        &self,
        tenant_id: &TenantId,
        target: crate::types::lease::LeaseTarget,
        ttl_seconds: u64,
        max_ttl_seconds: u64,
        renewable: bool,
    ) -> Result<Lease, VaultError>;

    /// Renew an existing lease, extending its expiration.
    async fn renew_lease(
        &self,
        lease_id: &crate::types::lease::LeaseId,
        increment_seconds: u64,
    ) -> Result<Lease, VaultError>;

    /// Revoke a lease immediately.
    async fn revoke_lease(&self, lease_id: &crate::types::lease::LeaseId)
        -> Result<(), VaultError>;
}
