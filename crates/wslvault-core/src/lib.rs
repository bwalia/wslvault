//! wslvault-core: shared kernel for the WSLVault secrets platform.
//!
//! Provides:
//! - Domain types (TenantId, SecretId, LeaseId, Principal, etc.)
//! - Core traits (SecretBackend, CryptoBackend, AuditSink, PolicyEvaluator)
//! - Cryptographic primitives (envelope encryption, KDF, algorithm registry)
//! - Configuration types
//! - Unified error hierarchy

pub mod config;
pub mod crypto;
pub mod error;
pub mod traits;
pub mod types;

// Re-export the most commonly used types at crate root for ergonomics.
pub use error::VaultError;

pub use types::key::{KeyAlgorithm, KeyDescriptor, KeyId, KeyMaterial, KeyPurpose, KeyState};
pub use types::lease::{Lease, LeaseId, LeaseState, LeaseTarget};
pub use types::principal::{AuthMethod, Principal, PrincipalId};
pub use types::secret::{SecretEngine, SecretId, SecretMetadata, SecretVersion};
pub use types::tenant::{Tenant, TenantId, TenantTier};

pub use traits::{AuditEvent, AuditOutcome, AuditSink, CryptoBackend, PolicyEvaluator, SecretBackend};
