//! PKI store backend trait + in-memory implementation.
//!
//! The `PkiStore` trait decouples the HTTP handlers and CA/role operations from
//! any concrete storage implementation.  Two implementations exist:
//!
//! - `InMemoryPkiStore` — ephemeral, thread-safe, used in unit tests and when
//!   `DATABASE_URL` is absent.
//! - `PgPkiStore` (in `pg_store`) — PostgreSQL-backed, used in production.

use std::collections::HashMap;
use std::sync::Arc;

use async_trait::async_trait;
use tokio::sync::RwLock;

use crate::error::PkiError;
use crate::types::{IssuedCert, PkiRole, TenantCa};

// ---------------------------------------------------------------------------
// Trait
// ---------------------------------------------------------------------------

/// Abstraction over PKI data storage.
///
/// All methods take `tenant_id` as the first string argument so that the
/// implementations can enforce row-level isolation between tenants.
#[async_trait]
pub trait PkiStore: Send + Sync {
    // -- CA management -------------------------------------------------------

    /// Persist a new CA record for `tenant_id`.
    ///
    /// Returns `PkiError::CaAlreadyExists` if a CA already exists for this tenant.
    async fn create_ca(&self, ca: TenantCa) -> Result<(), PkiError>;

    /// Retrieve the CA record for `tenant_id`.
    async fn get_ca(&self, tenant_id: &str) -> Result<TenantCa, PkiError>;

    /// Overwrite the CA record for `tenant_id` (used by the `import` endpoint).
    ///
    /// Creates the record if it does not exist.
    async fn upsert_ca(&self, ca: TenantCa) -> Result<(), PkiError>;

    // -- Role management -----------------------------------------------------

    /// Persist a new role.  Overwrites any existing role with the same name.
    async fn upsert_role(&self, role: PkiRole) -> Result<(), PkiError>;

    /// Fetch a role by `(tenant_id, name)`.
    async fn get_role(&self, tenant_id: &str, name: &str) -> Result<PkiRole, PkiError>;

    /// Delete a role by `(tenant_id, name)`.
    async fn delete_role(&self, tenant_id: &str, name: &str) -> Result<(), PkiError>;

    // -- Certificate tracking ------------------------------------------------

    /// Record a newly issued certificate.
    async fn record_cert(&self, cert: IssuedCert) -> Result<(), PkiError>;

    /// Mark a certificate as revoked.  Returns `PkiError::AlreadyRevoked` if
    /// it was already revoked, and `PkiError::CertNotFound` if not found.
    async fn revoke_cert(&self, tenant_id: &str, serial: &str) -> Result<(), PkiError>;

    /// Return all active (non-revoked) certs for this tenant.
    ///
    /// Used for quota enforcement and audit listing; not yet wired to an HTTP
    /// handler but retained in the trait for completeness.
    #[allow(dead_code)]
    async fn list_active_certs(&self, tenant_id: &str) -> Result<Vec<IssuedCert>, PkiError>;

    /// Return all revoked certs for this tenant (for CRL generation).
    async fn list_revoked_certs(&self, tenant_id: &str) -> Result<Vec<IssuedCert>, PkiError>;
}

// ---------------------------------------------------------------------------
// In-memory implementation
// ---------------------------------------------------------------------------

/// Pure in-memory `PkiStore`.  All state is lost on process exit.
/// Suitable for unit tests and development runs without a database.
#[derive(Default)]
pub struct InMemoryPkiStore {
    inner: Arc<InMemoryInner>,
}

#[derive(Default)]
struct InMemoryInner {
    /// tenant_id → TenantCa
    cas: RwLock<HashMap<String, TenantCa>>,
    /// (tenant_id, role_name) → PkiRole
    roles: RwLock<HashMap<(String, String), PkiRole>>,
    /// (tenant_id, serial) → IssuedCert
    certs: RwLock<HashMap<(String, String), IssuedCert>>,
}

impl InMemoryPkiStore {
    /// Create a new, empty in-memory store.
    pub fn new() -> Self {
        Self::default()
    }
}

#[async_trait]
impl PkiStore for InMemoryPkiStore {
    async fn create_ca(&self, ca: TenantCa) -> Result<(), PkiError> {
        let mut guard = self.inner.cas.write().await;
        if guard.contains_key(&ca.tenant_id) {
            return Err(PkiError::CaAlreadyExists {
                tenant_id: ca.tenant_id.clone(),
            });
        }
        guard.insert(ca.tenant_id.clone(), ca);
        Ok(())
    }

    async fn get_ca(&self, tenant_id: &str) -> Result<TenantCa, PkiError> {
        let guard = self.inner.cas.read().await;
        guard
            .get(tenant_id)
            .cloned()
            .ok_or_else(|| PkiError::CaNotFound {
                tenant_id: tenant_id.to_string(),
            })
    }

    async fn upsert_ca(&self, ca: TenantCa) -> Result<(), PkiError> {
        let mut guard = self.inner.cas.write().await;
        guard.insert(ca.tenant_id.clone(), ca);
        Ok(())
    }

    async fn upsert_role(&self, role: PkiRole) -> Result<(), PkiError> {
        let mut guard = self.inner.roles.write().await;
        guard.insert((role.tenant_id.clone(), role.name.clone()), role);
        Ok(())
    }

    async fn get_role(&self, tenant_id: &str, name: &str) -> Result<PkiRole, PkiError> {
        let guard = self.inner.roles.read().await;
        guard
            .get(&(tenant_id.to_string(), name.to_string()))
            .cloned()
            .ok_or_else(|| PkiError::RoleNotFound {
                name: name.to_string(),
                tenant_id: tenant_id.to_string(),
            })
    }

    async fn delete_role(&self, tenant_id: &str, name: &str) -> Result<(), PkiError> {
        let mut guard = self.inner.roles.write().await;
        if guard
            .remove(&(tenant_id.to_string(), name.to_string()))
            .is_none()
        {
            return Err(PkiError::RoleNotFound {
                name: name.to_string(),
                tenant_id: tenant_id.to_string(),
            });
        }
        Ok(())
    }

    async fn record_cert(&self, cert: IssuedCert) -> Result<(), PkiError> {
        let mut guard = self.inner.certs.write().await;
        guard.insert((cert.tenant_id.clone(), cert.serial.clone()), cert);
        Ok(())
    }

    async fn revoke_cert(&self, tenant_id: &str, serial: &str) -> Result<(), PkiError> {
        let mut guard = self.inner.certs.write().await;
        let key = (tenant_id.to_string(), serial.to_string());
        let cert = guard.get_mut(&key).ok_or_else(|| PkiError::CertNotFound {
            serial: serial.to_string(),
            tenant_id: tenant_id.to_string(),
        })?;
        if cert.revoked_at.is_some() {
            return Err(PkiError::AlreadyRevoked {
                serial: serial.to_string(),
            });
        }
        cert.revoked_at = Some(chrono::Utc::now());
        Ok(())
    }

    async fn list_active_certs(&self, tenant_id: &str) -> Result<Vec<IssuedCert>, PkiError> {
        let guard = self.inner.certs.read().await;
        let certs = guard
            .iter()
            .filter(|((tid, _), c)| tid == tenant_id && c.revoked_at.is_none())
            .map(|(_, c)| c.clone())
            .collect();
        Ok(certs)
    }

    async fn list_revoked_certs(&self, tenant_id: &str) -> Result<Vec<IssuedCert>, PkiError> {
        let guard = self.inner.certs.read().await;
        let certs = guard
            .iter()
            .filter(|((tid, _), c)| tid == tenant_id && c.revoked_at.is_some())
            .map(|(_, c)| c.clone())
            .collect();
        Ok(certs)
    }
}
