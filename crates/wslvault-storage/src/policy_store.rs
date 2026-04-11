//! Policy CRUD operations against the shared.policies table.
//!
//! Provides free-standing async functions that mirror the operations of the
//! in-memory `PolicyStore` in the policy-engine service, backed by PostgreSQL.
//! All mutations use `INSERT ... ON CONFLICT ... DO UPDATE` (upsert) semantics
//! so callers do not need to distinguish between create and update paths.

use serde::{Deserialize, Serialize};
use sqlx::Row;
use uuid::Uuid;

use crate::pool::DbPool;
use wslvault_core::VaultError;

/// A policy document as persisted in the database.
///
/// The `document` field holds the JSON-serialised `PolicyDocument` (rules,
/// capabilities, etc.) and is stored as a JSONB column in Postgres.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StoredPolicy {
    pub id: Uuid,
    pub tenant_id: Uuid,
    pub name: String,
    pub document: serde_json::Value,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub updated_at: chrono::DateTime<chrono::Utc>,
}

/// Helper to map a database row to a [`StoredPolicy`].
fn row_to_stored_policy(row: &sqlx::postgres::PgRow) -> StoredPolicy {
    StoredPolicy {
        id: row.get::<Uuid, _>("id"),
        tenant_id: row.get::<Uuid, _>("tenant_id"),
        name: row.get("name"),
        document: row.get("document"),
        created_at: row.get("created_at"),
        updated_at: row.get("updated_at"),
    }
}

/// Upsert a policy document for a given tenant.
///
/// If a policy with the same `(tenant_id, name)` already exists it is
/// overwritten; otherwise a new row is inserted.  The `updated_at` column is
/// refreshed on every upsert by the database trigger defined in the schema.
///
/// Returns the `UUID` of the inserted or updated policy row.
pub async fn put_policy(
    pool: &DbPool,
    tenant_id: &Uuid,
    name: &str,
    document: &serde_json::Value,
) -> Result<Uuid, VaultError> {
    let row = sqlx::query(
        "INSERT INTO shared.policies (tenant_id, name, document)
         VALUES ($1, $2, $3)
         ON CONFLICT (tenant_id, name)
         DO UPDATE SET document = EXCLUDED.document, updated_at = now()
         RETURNING id",
    )
    .bind(tenant_id)
    .bind(name)
    .bind(document)
    .fetch_one(pool.inner())
    .await
    .map_err(|e| VaultError::Database {
        reason: e.to_string(),
    })?;

    Ok(row.get::<Uuid, _>("id"))
}

/// Retrieve a single policy by tenant and name.
///
/// Returns [`VaultError::Storage`] with a descriptive message when the policy
/// does not exist, keeping the error type distinct from secret-not-found so
/// callers can map it to the correct gRPC status code.
pub async fn get_policy(
    pool: &DbPool,
    tenant_id: &Uuid,
    name: &str,
) -> Result<StoredPolicy, VaultError> {
    let row = sqlx::query(
        "SELECT id, tenant_id, name, document, created_at, updated_at
         FROM shared.policies
         WHERE tenant_id = $1 AND name = $2",
    )
    .bind(tenant_id)
    .bind(name)
    .fetch_optional(pool.inner())
    .await
    .map_err(|e| VaultError::Database {
        reason: e.to_string(),
    })?
    .ok_or_else(|| VaultError::Storage {
        reason: format!("policy '{}' not found for tenant {}", name, tenant_id),
    })?;

    Ok(row_to_stored_policy(&row))
}

/// Delete a policy by tenant and name.
///
/// Succeeds silently when no matching row exists, matching the behaviour of
/// the in-memory `PolicyStore::delete_policy` which returns `None` rather than
/// an error on a missing key.
pub async fn delete_policy(
    pool: &DbPool,
    tenant_id: &Uuid,
    name: &str,
) -> Result<(), VaultError> {
    sqlx::query(
        "DELETE FROM shared.policies
         WHERE tenant_id = $1 AND name = $2",
    )
    .bind(tenant_id)
    .bind(name)
    .execute(pool.inner())
    .await
    .map_err(|e| VaultError::Database {
        reason: e.to_string(),
    })?;

    Ok(())
}

/// Return the names of all policies belonging to a tenant, ordered
/// alphabetically.
pub async fn list_policies(
    pool: &DbPool,
    tenant_id: &Uuid,
) -> Result<Vec<String>, VaultError> {
    let rows = sqlx::query(
        "SELECT name FROM shared.policies
         WHERE tenant_id = $1
         ORDER BY name",
    )
    .bind(tenant_id)
    .fetch_all(pool.inner())
    .await
    .map_err(|e| VaultError::Database {
        reason: e.to_string(),
    })?;

    Ok(rows.into_iter().map(|r| r.get("name")).collect())
}

/// Return every policy in the store regardless of tenant.
///
/// Used by background compilation tasks that rebuild the full evaluated
/// snapshot without requiring a per-tenant refresh cycle.
pub async fn get_all_policies(pool: &DbPool) -> Result<Vec<StoredPolicy>, VaultError> {
    let rows = sqlx::query(
        "SELECT id, tenant_id, name, document, created_at, updated_at
         FROM shared.policies
         ORDER BY tenant_id, name",
    )
    .fetch_all(pool.inner())
    .await
    .map_err(|e| VaultError::Database {
        reason: e.to_string(),
    })?;

    Ok(rows.iter().map(row_to_stored_policy).collect())
}

/// Return all policies belonging to a single tenant.
///
/// Used by the policy-engine background task to rebuild the per-tenant
/// compiled snapshot.
pub async fn get_all_for_tenant(
    pool: &DbPool,
    tenant_id: &Uuid,
) -> Result<Vec<StoredPolicy>, VaultError> {
    let rows = sqlx::query(
        "SELECT id, tenant_id, name, document, created_at, updated_at
         FROM shared.policies
         WHERE tenant_id = $1
         ORDER BY name",
    )
    .bind(tenant_id)
    .fetch_all(pool.inner())
    .await
    .map_err(|e| VaultError::Database {
        reason: e.to_string(),
    })?;

    Ok(rows.iter().map(row_to_stored_policy).collect())
}
