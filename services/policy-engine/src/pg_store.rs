//! PostgreSQL-backed policy store for the WSLVault policy engine.
//!
//! `PgPolicyBackend` implements [`PolicyStoreBackend`] using the
//! `wslvault_storage::policy_store` functions so that the policy-engine can
//! persist and retrieve policy documents from the `shared.policies` table
//! when a `DATABASE_URL` is available at start-up.
//!
//! # Conversion strategy
//!
//! `PolicyDocument` (and its nested `PolicyRule` / `Capability` types) all
//! derive `serde::Serialize` / `serde::Deserialize`, so the round-trip between
//! the domain type and the JSONB `document` column is handled entirely by
//! `serde_json`.
//!
//! Tenant identifiers arrive as plain `&str` from the gRPC layer.  The
//! database layer requires `uuid::Uuid`, so we parse them with
//! `Uuid::parse_str`.  An unparseable string is treated as "no matching
//! tenant" and causes the affected operation to return an empty result rather
//! than an error — matching the silent-failure semantics of the in-memory
//! store for unknown tenants.

use async_trait::async_trait;
use tracing::{error, instrument, warn};
use uuid::Uuid;

use wslvault_storage::policy_store;
use wslvault_storage::pool::DbPool;

use crate::model::PolicyDocument;
use crate::store::PolicyStoreBackend;

// ---------------------------------------------------------------------------
// PgPolicyBackend
// ---------------------------------------------------------------------------

/// A [`PolicyStoreBackend`] that delegates all persistence to PostgreSQL via
/// the `wslvault_storage::policy_store` module.
///
/// Cloning this struct is cheap: the inner `DbPool` wraps a connection pool
/// and is `Clone`.
#[derive(Clone)]
pub struct PgPolicyBackend {
    pool: DbPool,
}

/// Manual `Debug` implementation because `DbPool` does not derive `Debug`.
/// The pool's internal connection details are omitted for security.
impl std::fmt::Debug for PgPolicyBackend {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PgPolicyBackend")
            .field("pool", &"<DbPool>")
            .finish()
    }
}

impl PgPolicyBackend {
    /// Construct a new backend wrapping the provided connection pool.
    pub fn new(pool: DbPool) -> Self {
        Self { pool }
    }
}

// ---------------------------------------------------------------------------
// Helper: tenant_id string → Uuid
// ---------------------------------------------------------------------------

/// Parse `tenant_id` as a `Uuid`.
///
/// Returns `None` and logs a warning when the string is not a valid UUID.
/// Callers should treat a `None` result as "tenant not found" and return an
/// empty/default response rather than propagating an error, which matches the
/// in-memory store's behaviour for unknown tenants.
fn parse_tenant_uuid(tenant_id: &str) -> Option<Uuid> {
    Uuid::parse_str(tenant_id).ok().or_else(|| {
        warn!(
            tenant_id,
            "received tenant_id that is not a valid UUID; treating as unknown tenant"
        );
        None
    })
}

// ---------------------------------------------------------------------------
// Helper: StoredPolicy.document → PolicyDocument
// ---------------------------------------------------------------------------

/// Deserialise a JSONB `document` value into a [`PolicyDocument`].
///
/// Returns `None` and logs an error when deserialisation fails so that a
/// single corrupt row does not abort a bulk listing operation.
fn deserialize_document(
    document: &serde_json::Value,
    name: &str,
    tenant_id: &str,
) -> Option<PolicyDocument> {
    match serde_json::from_value::<PolicyDocument>(document.clone()) {
        Ok(doc) => Some(doc),
        Err(err) => {
            error!(
                %tenant_id,
                %name,
                error = %err,
                "failed to deserialise policy document from database; skipping row"
            );
            None
        }
    }
}

// ---------------------------------------------------------------------------
// Helper: PolicyDocument → serde_json::Value
// ---------------------------------------------------------------------------

/// Serialise a [`PolicyDocument`] into a `serde_json::Value` suitable for
/// storage in the `document` JSONB column.
///
/// Returns `None` and logs an error on the (highly unlikely) event that
/// serialisation fails.
fn serialize_document(document: &PolicyDocument) -> Option<serde_json::Value> {
    match serde_json::to_value(document) {
        Ok(value) => Some(value),
        Err(err) => {
            error!(
                name = %document.name,
                error = %err,
                "failed to serialise policy document for database storage"
            );
            None
        }
    }
}

// ---------------------------------------------------------------------------
// PolicyStoreBackend implementation
// ---------------------------------------------------------------------------

#[async_trait]
impl PolicyStoreBackend for PgPolicyBackend {
    /// Upsert the policy document into PostgreSQL.
    ///
    /// Always returns `None` because the Postgres upsert (`INSERT … ON
    /// CONFLICT … DO UPDATE`) does not return the previous row cheaply.
    #[instrument(skip(self, document), fields(tenant_id, name = %document.name))]
    async fn put_policy(
        &self,
        tenant_id: &str,
        document: PolicyDocument,
    ) -> Option<PolicyDocument> {
        let tenant_uuid = match parse_tenant_uuid(tenant_id) {
            Some(u) => u,
            None => return None,
        };

        let json_doc = match serialize_document(&document) {
            Some(v) => v,
            None => return None,
        };

        if let Err(err) =
            policy_store::put_policy(&self.pool, &tenant_uuid, &document.name, &json_doc).await
        {
            error!(
                %tenant_id,
                name = %document.name,
                error = %err,
                "failed to upsert policy into database"
            );
        }

        // Postgres upsert does not return the previous document, so we always
        // return None — matching the documented contract of this method.
        None
    }

    /// Fetch a single policy document from PostgreSQL.
    #[instrument(skip(self), fields(tenant_id, name))]
    async fn get_policy(&self, tenant_id: &str, name: &str) -> Option<PolicyDocument> {
        let tenant_uuid = parse_tenant_uuid(tenant_id)?;

        match policy_store::get_policy(&self.pool, &tenant_uuid, name).await {
            Ok(stored) => deserialize_document(&stored.document, name, tenant_id),
            Err(_) => {
                // VaultError::Storage means "not found"; other errors are
                // also silently treated as not-found to keep the return type
                // clean.  Logging is intentionally omitted for the common
                // not-found case; the storage module already logs at debug.
                None
            }
        }
    }

    /// Delete a policy from PostgreSQL.
    ///
    /// Always returns `None` because the Postgres `DELETE` does not cheaply
    /// return the deleted row.  The gRPC handler in `grpc.rs` relies on a
    /// separate `get_policy` call to decide whether to return NOT_FOUND, so
    /// this simplified contract is acceptable.
    #[instrument(skip(self), fields(tenant_id, name))]
    async fn delete_policy(&self, tenant_id: &str, name: &str) -> Option<PolicyDocument> {
        let tenant_uuid = match parse_tenant_uuid(tenant_id) {
            Some(u) => u,
            None => return None,
        };

        if let Err(err) = policy_store::delete_policy(&self.pool, &tenant_uuid, name).await {
            error!(
                %tenant_id,
                %name,
                error = %err,
                "failed to delete policy from database"
            );
        }

        // Postgres DELETE does not return the removed document cheaply.
        None
    }

    /// Return the sorted names of all policies belonging to `tenant_id`.
    #[instrument(skip(self), fields(tenant_id))]
    async fn list_policies(&self, tenant_id: &str) -> Vec<String> {
        let tenant_uuid = match parse_tenant_uuid(tenant_id) {
            Some(u) => u,
            None => return Vec::new(),
        };

        match policy_store::list_policies(&self.pool, &tenant_uuid).await {
            Ok(names) => names,
            Err(err) => {
                error!(
                    %tenant_id,
                    error = %err,
                    "failed to list policies from database; returning empty list"
                );
                Vec::new()
            }
        }
    }

    /// Return all `PolicyDocument`s belonging to `tenant_id`.
    #[instrument(skip(self), fields(tenant_id))]
    async fn get_all_for_tenant(&self, tenant_id: &str) -> Vec<PolicyDocument> {
        let tenant_uuid = match parse_tenant_uuid(tenant_id) {
            Some(u) => u,
            None => return Vec::new(),
        };

        match policy_store::get_all_for_tenant(&self.pool, &tenant_uuid).await {
            Ok(stored_policies) => stored_policies
                .iter()
                .filter_map(|sp| deserialize_document(&sp.document, &sp.name, tenant_id))
                .collect(),
            Err(err) => {
                error!(
                    %tenant_id,
                    error = %err,
                    "failed to fetch tenant policies from database; returning empty list"
                );
                Vec::new()
            }
        }
    }

    /// Return every `(tenant_id, PolicyDocument)` pair in the store.
    ///
    /// Used by the background compilation task to rebuild the full evaluated
    /// snapshot.
    #[instrument(skip(self))]
    async fn get_all(&self) -> Vec<(String, PolicyDocument)> {
        match policy_store::get_all_policies(&self.pool).await {
            Ok(stored_policies) => stored_policies
                .iter()
                .filter_map(|sp| {
                    let tenant_id_str = sp.tenant_id.to_string();
                    deserialize_document(&sp.document, &sp.name, &tenant_id_str)
                        .map(|doc| (tenant_id_str, doc))
                })
                .collect(),
            Err(err) => {
                error!(
                    error = %err,
                    "failed to fetch all policies from database; returning empty list"
                );
                Vec::new()
            }
        }
    }
}
