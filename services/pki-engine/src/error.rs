//! PKI-engine-specific error type that wraps `VaultError` and adds
//! certificate-specific variants for richer context at the HTTP layer.

use thiserror::Error;
use wslvault_core::VaultError;

#[derive(Debug, Error)]
pub enum PkiError {
    /// CA has not been configured for this tenant.
    #[error("no CA configured for tenant {tenant_id}")]
    CaNotFound { tenant_id: String },

    /// A role with the requested name does not exist.
    #[error("role '{name}' not found for tenant {tenant_id}")]
    RoleNotFound { name: String, tenant_id: String },

    /// The requested certificate serial was not found.
    #[error("certificate serial {serial} not found for tenant {tenant_id}")]
    CertNotFound { serial: String, tenant_id: String },

    /// A CA already exists for this tenant and must be deleted before re-generating.
    #[error("CA already exists for tenant {tenant_id}; delete it before re-generating")]
    CaAlreadyExists { tenant_id: String },

    /// Role constraint violation (domain, subdomain, TTL, etc.).
    #[error("role constraint violated: {reason}")]
    RoleConstraintViolated { reason: String },

    /// The CSR submitted for signing is malformed or has been tampered with.
    #[error("invalid CSR: {reason}")]
    InvalidCsr { reason: String },

    /// The requested certificate has already been revoked.
    #[error("certificate {serial} is already revoked")]
    AlreadyRevoked { serial: String },

    /// Envelope encryption/decryption of the CA private key failed.
    #[error("CA key encryption error: {reason}")]
    KeyEncryptionError { reason: String },

    /// Certificate generation failed (rcgen reported an error).
    #[error("certificate generation failed: {reason}")]
    CertGenerationFailed { reason: String },

    /// Delegate to the shared `VaultError` hierarchy.
    #[error(transparent)]
    Vault(#[from] VaultError),
}

impl PkiError {
    /// Map to an HTTP status code for use in axum responses.
    pub fn http_status(&self) -> u16 {
        match self {
            PkiError::CaNotFound { .. }
            | PkiError::RoleNotFound { .. }
            | PkiError::CertNotFound { .. } => 404,

            PkiError::CaAlreadyExists { .. } | PkiError::AlreadyRevoked { .. } => 409,

            PkiError::RoleConstraintViolated { .. }
            | PkiError::InvalidCsr { .. }
            | PkiError::CertGenerationFailed { .. } => 400,

            PkiError::KeyEncryptionError { .. } => 500,

            PkiError::Vault(ve) => ve.http_status(),
        }
    }
}
