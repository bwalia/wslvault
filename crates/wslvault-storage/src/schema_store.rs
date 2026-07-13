//! Dedicated / sovereign tenant schema management.
//!
//! Provides typed wrappers around the `system.provision_tenant_schema()` and
//! `system.deprovision_tenant_schema()` stored functions, plus queries against
//! the `system.tenant_schemas` registry.

use sqlx::FromRow;
use uuid::Uuid;

use crate::pool::DbPool;

// ---------------------------------------------------------------------------
// Row types
// ---------------------------------------------------------------------------

/// Mirrors a row in `system.tenant_schemas`.
#[derive(Debug, Clone, FromRow)]
pub struct TenantSchemaRow {
    pub tenant_id: Uuid,
    pub schema_name: String,
    pub tier: String,
    pub provisioned_at: chrono::DateTime<chrono::Utc>,
    pub deprovisioned_at: Option<chrono::DateTime<chrono::Utc>>,
}

// ---------------------------------------------------------------------------
// Error
// ---------------------------------------------------------------------------

#[derive(Debug, thiserror::Error)]
pub enum SchemaStoreError {
    #[error("database error: {0}")]
    Database(#[from] sqlx::Error),

    #[error("schema not found for tenant {tenant_id}")]
    NotFound { tenant_id: Uuid },
}

// ---------------------------------------------------------------------------
// Queries
// ---------------------------------------------------------------------------

/// Provision an isolated schema for a dedicated or sovereign tenant.
///
/// Calls the `system.provision_tenant_schema(uuid, text)` stored function
/// which creates the schema, tables, indexes, and triggers.
///
/// Returns the schema name (e.g. `tenant_<hex>`).
pub async fn provision_schema(
    pool: &DbPool,
    tenant_id: Uuid,
    tier: &str,
) -> Result<String, SchemaStoreError> {
    let row: (String,) = sqlx::query_as("SELECT system.provision_tenant_schema($1, $2)")
        .bind(tenant_id)
        .bind(tier)
        .fetch_one(pool.inner())
        .await?;

    Ok(row.0)
}

/// Deprovision (drop) the dedicated schema for a tenant.
///
/// The registry row is preserved with `deprovisioned_at` set for audit.
pub async fn deprovision_schema(pool: &DbPool, tenant_id: Uuid) -> Result<(), SchemaStoreError> {
    sqlx::query("SELECT system.deprovision_tenant_schema($1)")
        .bind(tenant_id)
        .execute(pool.inner())
        .await?;

    Ok(())
}

/// Resolve the schema name for a given tenant.
///
/// Returns `"shared"` for shared-tier tenants and the per-tenant schema
/// name for dedicated/sovereign tenants.
pub async fn resolve_schema(pool: &DbPool, tenant_id: Uuid) -> Result<String, SchemaStoreError> {
    let row: (String,) = sqlx::query_as("SELECT system.resolve_tenant_schema($1)")
        .bind(tenant_id)
        .fetch_one(pool.inner())
        .await?;

    Ok(row.0)
}

/// Get the schema registry entry for a tenant.
pub async fn get_tenant_schema(
    pool: &DbPool,
    tenant_id: Uuid,
) -> Result<TenantSchemaRow, SchemaStoreError> {
    let row = sqlx::query_as::<_, TenantSchemaRow>(
        "SELECT * FROM system.tenant_schemas WHERE tenant_id = $1 AND deprovisioned_at IS NULL",
    )
    .bind(tenant_id)
    .fetch_optional(pool.inner())
    .await?
    .ok_or(SchemaStoreError::NotFound { tenant_id })?;

    Ok(row)
}

/// List all active (non-deprovisioned) dedicated/sovereign schemas.
pub async fn list_active_schemas(pool: &DbPool) -> Result<Vec<TenantSchemaRow>, SchemaStoreError> {
    let rows = sqlx::query_as::<_, TenantSchemaRow>(
        "SELECT * FROM system.tenant_schemas \
         WHERE deprovisioned_at IS NULL \
         ORDER BY provisioned_at",
    )
    .fetch_all(pool.inner())
    .await?;

    Ok(rows)
}
