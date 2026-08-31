//! Unified error hierarchy for the WSLVault platform.
//!
//! All services translate their internal errors to VaultError variants
//! before returning them to callers, ensuring consistent gRPC status codes
//! and structured error context in API responses.

use thiserror::Error;

#[derive(Debug, Error)]
pub enum VaultError {
    /// The vault is sealed: the root key is not in memory, so no key material
    /// can be read or written until a threshold of unseal shares is supplied.
    #[error("vault is sealed")]
    Sealed,

    // Authentication and authorization errors
    #[error("authentication required: {reason}")]
    Unauthenticated { reason: String },

    #[error("permission denied on {resource}: {reason}")]
    PermissionDenied { resource: String, reason: String },

    // Resource errors
    #[error("secret not found at path {path:?} (version {version:?})")]
    SecretNotFound { path: String, version: Option<u32> },

    #[error("tenant not found: {tenant_id}")]
    TenantNotFound { tenant_id: String },

    #[error("key not found: {key_id}")]
    KeyNotFound { key_id: String },

    #[error("lease not found: {lease_id}")]
    LeaseNotFound { lease_id: String },

    // Cryptographic errors
    #[error("encryption failed: {reason}")]
    EncryptionFailed { reason: String },

    #[error("decryption failed: invalid ciphertext or key")]
    DecryptionFailed,

    #[error("key rotation failed: {reason}")]
    KeyRotationFailed { reason: String },

    // Validation errors
    #[error("invalid path {path:?}: {reason}")]
    InvalidPath { path: String, reason: String },

    #[error("check-and-set conflict: expected version {expected}, got {actual}")]
    CasConflict { expected: u32, actual: u32 },

    #[error("secret version {version} has been destroyed")]
    VersionDestroyed { version: u32 },

    #[error("validation error: {field}: {reason}")]
    ValidationError { field: String, reason: String },

    #[error("invalid operation: {reason}")]
    InvalidOperation { reason: String },

    #[error("quota exceeded: {reason}")]
    QuotaExceeded { reason: String },

    // Storage errors
    #[error("database error: {reason}")]
    Database { reason: String },

    #[error("storage error: {reason}")]
    Storage { reason: String },

    // Service errors
    #[error("upstream service unavailable: {service}")]
    ServiceUnavailable { service: String },

    #[error("lease expired: {lease_id}")]
    LeaseExpired { lease_id: String },

    #[error("operation not supported by engine {engine_type}: {operation}")]
    UnsupportedOperation {
        engine_type: String,
        operation: String,
    },

    // Internal errors
    #[error("internal error: {reason}")]
    Internal { reason: String },

    #[error(transparent)]
    Other(#[from] anyhow::Error),
}

impl VaultError {
    /// Returns the machine-readable error code for API responses.
    pub fn code(&self) -> &'static str {
        match self {
            VaultError::Sealed => "sealed",
            VaultError::Unauthenticated { .. } => "unauthenticated",
            VaultError::PermissionDenied { .. } => "permission_denied",
            VaultError::SecretNotFound { .. } => "not_found",
            VaultError::TenantNotFound { .. } => "not_found",
            VaultError::KeyNotFound { .. } => "not_found",
            VaultError::LeaseNotFound { .. } => "not_found",
            VaultError::EncryptionFailed { .. } => "encryption_failed",
            VaultError::DecryptionFailed => "decryption_failed",
            VaultError::KeyRotationFailed { .. } => "key_rotation_failed",
            VaultError::InvalidPath { .. } => "invalid_path",
            VaultError::CasConflict { .. } => "cas_conflict",
            VaultError::VersionDestroyed { .. } => "version_destroyed",
            VaultError::ValidationError { .. } => "validation_error",
            VaultError::InvalidOperation { .. } => "invalid_operation",
            VaultError::QuotaExceeded { .. } => "quota_exceeded",
            VaultError::Database { .. } => "database_error",
            VaultError::Storage { .. } => "storage_error",
            VaultError::ServiceUnavailable { .. } => "service_unavailable",
            VaultError::LeaseExpired { .. } => "lease_expired",
            VaultError::UnsupportedOperation { .. } => "unsupported_operation",
            VaultError::Internal { .. } => "internal_error",
            VaultError::Other(_) => "internal_error",
        }
    }

    /// Returns the HTTP status code appropriate for this error.
    pub fn http_status(&self) -> u16 {
        match self {
            // 503, matching HashiCorp Vault: sealed is a temporary service
            // condition an operator resolves by unsealing, not a client error.
            VaultError::Sealed => 503,
            VaultError::Unauthenticated { .. } => 401,
            VaultError::PermissionDenied { .. } => 403,
            VaultError::SecretNotFound { .. }
            | VaultError::TenantNotFound { .. }
            | VaultError::KeyNotFound { .. }
            | VaultError::LeaseNotFound { .. } => 404,
            VaultError::CasConflict { .. } => 409,
            VaultError::VersionDestroyed { .. } => 410,
            VaultError::QuotaExceeded { .. } => 429,
            VaultError::ValidationError { .. }
            | VaultError::InvalidPath { .. }
            | VaultError::InvalidOperation { .. } => 400,
            VaultError::ServiceUnavailable { .. } => 503,
            VaultError::LeaseExpired { .. } => 403,
            _ => 500,
        }
    }
}
