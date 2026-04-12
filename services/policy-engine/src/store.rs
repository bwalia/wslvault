//! In-memory policy store for the WSLVault policy engine.
//!
//! `PolicyStore` is the authoritative mutable store of raw `PolicyDocument`s.
//! The compiled evaluation snapshot (`CompiledPolicies`) is derived from this
//! store by the background compilation task in `main.rs`.
//!
//! All operations are async-safe via a `tokio::sync::RwLock`.
//!
//! The `PolicyStoreBackend` trait abstracts storage so that the in-memory
//! `PolicyStore` and the PostgreSQL-backed `PgPolicyBackend` can be used
//! interchangeably at runtime.

use std::collections::HashMap;
use std::sync::Arc;

use async_trait::async_trait;
use tokio::sync::RwLock;
use tracing::{debug, instrument};

use crate::model::PolicyDocument;

// ---------------------------------------------------------------------------
// Storage backend trait
// ---------------------------------------------------------------------------

/// Abstracts the underlying policy storage mechanism.
///
/// Implementors include the in-memory [`PolicyStore`] (used in tests and when
/// `DATABASE_URL` is not set) and the PostgreSQL-backed `PgPolicyBackend`
/// (used in production when `DATABASE_URL` is provided).
#[async_trait]
pub trait PolicyStoreBackend: Send + Sync + std::fmt::Debug {
    /// Insert or replace the policy document for `(tenant_id, policy.name)`.
    ///
    /// Returns the previous document if one existed. Backends that cannot
    /// cheaply retrieve the old value (e.g. a Postgres upsert) SHOULD return
    /// `None`.
    async fn put_policy(&self, tenant_id: &str, document: PolicyDocument) -> Option<PolicyDocument>;

    /// Retrieve a single policy by tenant and name.
    ///
    /// Returns `None` if the policy does not exist.
    async fn get_policy(&self, tenant_id: &str, name: &str) -> Option<PolicyDocument>;

    /// Remove a policy by tenant and name.
    ///
    /// Returns the removed document, or `None` if it was not present (or if
    /// the backend cannot return the removed document cheaply).
    async fn delete_policy(&self, tenant_id: &str, name: &str) -> Option<PolicyDocument>;

    /// Return the names of all policies belonging to `tenant_id`.
    async fn list_policies(&self, tenant_id: &str) -> Vec<String>;

    /// Return all `PolicyDocument`s belonging to `tenant_id`.
    async fn get_all_for_tenant(&self, tenant_id: &str) -> Vec<PolicyDocument>;

    /// Return every `(tenant_id, PolicyDocument)` pair in the store.
    ///
    /// Used by the background compilation task to rebuild the entire compiled
    /// snapshot without requiring a per-tenant refresh cycle.
    async fn get_all(&self) -> Vec<(String, PolicyDocument)>;
}

/// Composite key used to namespace policies by tenant.
type PolicyKey = (String, String); // (tenant_id, policy_name)

/// Thread-safe, in-memory store for raw policy documents.
///
/// Cloning a `PolicyStore` returns a second handle to the same underlying
/// data — the `Arc<RwLock<…>>` is shared.
#[derive(Debug, Clone)]
pub struct PolicyStore {
    inner: Arc<RwLock<HashMap<PolicyKey, PolicyDocument>>>,
}

impl PolicyStore {
    /// Create a new, empty policy store.
    pub fn new() -> Self {
        Self {
            inner: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Insert or replace the policy document for `(tenant_id, policy.name)`.
    ///
    /// Returns the previous document if one existed.
    #[instrument(skip(self, document), fields(tenant_id, name = %document.name))]
    pub async fn put_policy(
        &self,
        tenant_id: &str,
        document: PolicyDocument,
    ) -> Option<PolicyDocument> {
        let key = (tenant_id.to_string(), document.name.clone());
        debug!(tenant_id, name = %document.name, "storing policy");
        let mut guard = self.inner.write().await;
        guard.insert(key, document)
    }

    /// Retrieve a single policy by tenant and name.
    ///
    /// Returns `None` if the policy does not exist.
    #[instrument(skip(self), fields(tenant_id, name))]
    pub async fn get_policy(&self, tenant_id: &str, name: &str) -> Option<PolicyDocument> {
        let key = (tenant_id.to_string(), name.to_string());
        let guard = self.inner.read().await;
        guard.get(&key).cloned()
    }

    /// Remove a policy by tenant and name.
    ///
    /// Returns the removed document, or `None` if it was not present.
    #[instrument(skip(self), fields(tenant_id, name))]
    pub async fn delete_policy(&self, tenant_id: &str, name: &str) -> Option<PolicyDocument> {
        let key = (tenant_id.to_string(), name.to_string());
        debug!(tenant_id, name, "deleting policy");
        let mut guard = self.inner.write().await;
        guard.remove(&key)
    }

    /// Return the names of all policies belonging to `tenant_id`.
    #[instrument(skip(self), fields(tenant_id))]
    pub async fn list_policies(&self, tenant_id: &str) -> Vec<String> {
        let guard = self.inner.read().await;
        guard
            .keys()
            .filter(|(tid, _)| tid == tenant_id)
            .map(|(_, name)| name.clone())
            .collect()
    }

    /// Return all `PolicyDocument`s belonging to `tenant_id`.
    ///
    /// Used by the background compilation task to rebuild the evaluated snapshot.
    #[allow(dead_code)]
    #[instrument(skip(self), fields(tenant_id))]
    pub async fn get_all_for_tenant(&self, tenant_id: &str) -> Vec<PolicyDocument> {
        let guard = self.inner.read().await;
        guard
            .iter()
            .filter(|((tid, _), _)| tid == tenant_id)
            .map(|(_, doc)| doc.clone())
            .collect()
    }

    /// Return every `PolicyDocument` in the store regardless of tenant.
    ///
    /// Used by the background task to rebuild the entire compiled snapshot
    /// without requiring a per-tenant refresh cycle.
    pub async fn get_all(&self) -> Vec<(String, PolicyDocument)> {
        let guard = self.inner.read().await;
        guard
            .iter()
            .map(|((tenant_id, _), doc)| (tenant_id.clone(), doc.clone()))
            .collect()
    }
}

impl Default for PolicyStore {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// PolicyStoreBackend implementation for the in-memory store
// ---------------------------------------------------------------------------

/// Delegates every trait method to the corresponding inherent method on
/// [`PolicyStore`], so that the in-memory store and the Postgres backend are
/// fully interchangeable behind `Arc<dyn PolicyStoreBackend>`.
#[async_trait]
impl PolicyStoreBackend for PolicyStore {
    async fn put_policy(&self, tenant_id: &str, document: PolicyDocument) -> Option<PolicyDocument> {
        PolicyStore::put_policy(self, tenant_id, document).await
    }

    async fn get_policy(&self, tenant_id: &str, name: &str) -> Option<PolicyDocument> {
        PolicyStore::get_policy(self, tenant_id, name).await
    }

    async fn delete_policy(&self, tenant_id: &str, name: &str) -> Option<PolicyDocument> {
        PolicyStore::delete_policy(self, tenant_id, name).await
    }

    async fn list_policies(&self, tenant_id: &str) -> Vec<String> {
        PolicyStore::list_policies(self, tenant_id).await
    }

    async fn get_all_for_tenant(&self, tenant_id: &str) -> Vec<PolicyDocument> {
        PolicyStore::get_all_for_tenant(self, tenant_id).await
    }

    async fn get_all(&self) -> Vec<(String, PolicyDocument)> {
        PolicyStore::get_all(self).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::PolicyRule;
    use std::collections::HashSet;

    fn sample_doc(name: &str) -> PolicyDocument {
        PolicyDocument {
            name: name.to_string(),
            rules: vec![PolicyRule {
                paths: vec!["secret/*".to_string()],
                capabilities: HashSet::new(),
            }],
        }
    }

    #[tokio::test]
    async fn put_and_get_round_trip() {
        let store = PolicyStore::new();
        store.put_policy("tenant-1", sample_doc("admin")).await;
        let got = store.get_policy("tenant-1", "admin").await;
        assert!(got.is_some());
        assert_eq!(got.unwrap().name, "admin");
    }

    #[tokio::test]
    async fn get_missing_returns_none() {
        let store = PolicyStore::new();
        assert!(store.get_policy("tenant-1", "missing").await.is_none());
    }

    #[tokio::test]
    async fn delete_removes_policy() {
        let store = PolicyStore::new();
        store.put_policy("tenant-1", sample_doc("admin")).await;
        let removed = store.delete_policy("tenant-1", "admin").await;
        assert!(removed.is_some());
        assert!(store.get_policy("tenant-1", "admin").await.is_none());
    }

    #[tokio::test]
    async fn list_returns_only_tenant_policies() {
        let store = PolicyStore::new();
        store.put_policy("tenant-1", sample_doc("policy-a")).await;
        store.put_policy("tenant-1", sample_doc("policy-b")).await;
        store.put_policy("tenant-2", sample_doc("policy-c")).await;

        let mut names = store.list_policies("tenant-1").await;
        names.sort();
        assert_eq!(names, vec!["policy-a", "policy-b"]);
    }

    #[tokio::test]
    async fn get_all_for_tenant_isolates_correctly() {
        let store = PolicyStore::new();
        store.put_policy("tenant-1", sample_doc("x")).await;
        store.put_policy("tenant-2", sample_doc("y")).await;

        let docs = store.get_all_for_tenant("tenant-1").await;
        assert_eq!(docs.len(), 1);
        assert_eq!(docs[0].name, "x");
    }

    #[tokio::test]
    async fn clone_shares_state() {
        let store = PolicyStore::new();
        let cloned = store.clone();
        store.put_policy("tenant-1", sample_doc("shared")).await;
        assert!(cloned.get_policy("tenant-1", "shared").await.is_some());
    }
}
