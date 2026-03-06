//! In-memory principal store for the identity-service.
//!
//! Keyed by `(tenant_id, principal_id)` pairs so lookups across tenant
//! boundaries are structurally impossible.  Backed by an `Arc<RwLock<…>>`
//! so the store is cheaply cloneable and safe to share across async tasks.

use std::{
    collections::HashMap,
    sync::{Arc, RwLock},
};

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use wslvault_core::{types::principal::AuthMethod, VaultError};

/// Stable identity record stored for every registered principal.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PrincipalRecord {
    /// Unique identifier for this principal (UUID string).
    pub id: String,
    /// Tenant the principal belongs to.
    pub tenant_id: String,
    /// Human-readable name (display_name or service-account name).
    pub display_name: String,
    /// How this principal authenticates.
    pub auth_method: AuthMethod,
    /// Ordered list of policy names currently attached to this principal.
    pub policies: Vec<String>,
    /// Immutable creation timestamp.
    pub created_at: DateTime<Utc>,
}

/// Composite key used to isolate principals per tenant.
type StoreKey = (String, String);

/// Thread-safe, cloneable in-memory store for principal records.
#[derive(Clone)]
pub struct PrincipalStore {
    inner: Arc<RwLock<HashMap<StoreKey, PrincipalRecord>>>,
}

impl PrincipalStore {
    /// Creates an empty store.
    pub fn new() -> Self {
        Self {
            inner: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Inserts a new `PrincipalRecord`.
    ///
    /// Returns `VaultError::ValidationError` if a principal with the same
    /// `(tenant_id, principal_id)` already exists, preventing accidental
    /// overwrites of existing records.
    pub fn create_principal(&self, record: PrincipalRecord) -> Result<(), VaultError> {
        let key = (record.tenant_id.clone(), record.id.clone());

        let mut map = self.inner.write().map_err(|e| VaultError::Internal {
            reason: format!("store lock poisoned: {e}"),
        })?;

        if map.contains_key(&key) {
            return Err(VaultError::ValidationError {
                field: "principal_id".to_string(),
                reason: format!(
                    "principal '{}' already exists in tenant '{}'",
                    record.id, record.tenant_id
                ),
            });
        }

        map.insert(key, record);
        Ok(())
    }

    /// Retrieves a single principal by `(tenant_id, principal_id)`.
    ///
    /// Returns `VaultError::TenantNotFound` if the principal does not exist
    /// so the caller does not need to distinguish between missing tenant and
    /// missing principal at this layer.
    pub fn get_principal(
        &self,
        tenant_id: &str,
        principal_id: &str,
    ) -> Result<PrincipalRecord, VaultError> {
        let key = (tenant_id.to_string(), principal_id.to_string());

        let map = self.inner.read().map_err(|e| VaultError::Internal {
            reason: format!("store lock poisoned: {e}"),
        })?;

        map.get(&key)
            .cloned()
            .ok_or_else(|| VaultError::TenantNotFound {
                tenant_id: format!("principal '{principal_id}' in tenant '{tenant_id}'"),
            })
    }

    /// Lists all principals belonging to a given tenant.
    pub fn list_principals(&self, tenant_id: &str) -> Result<Vec<PrincipalRecord>, VaultError> {
        let map = self.inner.read().map_err(|e| VaultError::Internal {
            reason: format!("store lock poisoned: {e}"),
        })?;

        let records = map
            .iter()
            .filter(|((tid, _), _)| tid == tenant_id)
            .map(|(_, record)| record.clone())
            .collect();

        Ok(records)
    }

    /// Replaces the policy list for the identified principal.
    ///
    /// This is a full replacement — callers that want additive updates must
    /// read the current policies first, merge them, and pass the merged list.
    pub fn update_policies(
        &self,
        tenant_id: &str,
        principal_id: &str,
        new_policies: Vec<String>,
    ) -> Result<(), VaultError> {
        let key = (tenant_id.to_string(), principal_id.to_string());

        let mut map = self.inner.write().map_err(|e| VaultError::Internal {
            reason: format!("store lock poisoned: {e}"),
        })?;

        let record = map
            .get_mut(&key)
            .ok_or_else(|| VaultError::TenantNotFound {
                tenant_id: format!("principal '{principal_id}' in tenant '{tenant_id}'"),
            })?;

        record.policies = new_policies;
        Ok(())
    }
}

impl Default for PrincipalStore {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use wslvault_core::types::principal::AuthMethod;

    fn sample_record(tenant_id: &str, id: &str, name: &str) -> PrincipalRecord {
        PrincipalRecord {
            id: id.to_string(),
            tenant_id: tenant_id.to_string(),
            display_name: name.to_string(),
            auth_method: AuthMethod::Token,
            policies: vec!["default".to_string()],
            created_at: Utc::now(),
        }
    }

    #[test]
    fn create_and_get_principal() {
        let store = PrincipalStore::new();
        let rec = sample_record("tenant-1", "principal-1", "Alice");
        store.create_principal(rec.clone()).unwrap();

        let fetched = store.get_principal("tenant-1", "principal-1").unwrap();
        assert_eq!(fetched.display_name, "Alice");
    }

    #[test]
    fn duplicate_create_is_rejected() {
        let store = PrincipalStore::new();
        let rec = sample_record("t", "p", "Alice");
        store.create_principal(rec.clone()).unwrap();
        let result = store.create_principal(rec);
        assert!(matches!(result, Err(VaultError::ValidationError { .. })));
    }

    #[test]
    fn get_missing_principal_returns_not_found() {
        let store = PrincipalStore::new();
        let result = store.get_principal("t", "missing");
        assert!(matches!(result, Err(VaultError::TenantNotFound { .. })));
    }

    #[test]
    fn list_principals_scoped_to_tenant() {
        let store = PrincipalStore::new();
        store
            .create_principal(sample_record("tenant-a", "p1", "Alice"))
            .unwrap();
        store
            .create_principal(sample_record("tenant-a", "p2", "Bob"))
            .unwrap();
        store
            .create_principal(sample_record("tenant-b", "p3", "Carol"))
            .unwrap();

        let tenant_a = store.list_principals("tenant-a").unwrap();
        assert_eq!(tenant_a.len(), 2);

        let tenant_b = store.list_principals("tenant-b").unwrap();
        assert_eq!(tenant_b.len(), 1);
    }

    #[test]
    fn update_policies_replaces_existing() {
        let store = PrincipalStore::new();
        store
            .create_principal(sample_record("t", "p", "Alice"))
            .unwrap();

        store
            .update_policies("t", "p", vec!["admin".to_string()])
            .unwrap();

        let rec = store.get_principal("t", "p").unwrap();
        assert_eq!(rec.policies, vec!["admin"]);
    }
}
