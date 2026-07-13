//! Tenant CRUD operations against the system.tenants table.

use sqlx::Row;
use uuid::Uuid;

use crate::pool::DbPool;
use wslvault_core::types::tenant::{Tenant, TenantId, TenantTier};
use wslvault_core::VaultError;

/// Map a tier string from the database to the enum.
fn parse_tier(s: &str) -> TenantTier {
    match s {
        "dedicated" => TenantTier::Dedicated,
        "sovereign" => TenantTier::Sovereign,
        _ => TenantTier::Shared,
    }
}

/// Map the enum to a database tier string.
fn tier_str(tier: &TenantTier) -> &'static str {
    match tier {
        TenantTier::Shared => "shared",
        TenantTier::Dedicated => "dedicated",
        TenantTier::Sovereign => "sovereign",
    }
}

/// Retrieve a tenant by its ID.
pub async fn get_tenant(pool: &DbPool, tenant_id: &TenantId) -> Result<Tenant, VaultError> {
    let row = sqlx::query(
        "SELECT id, slug, display_name, tier, root_key_id, created_at, updated_at, deleted_at
         FROM system.tenants WHERE id = $1",
    )
    .bind(tenant_id.as_uuid())
    .fetch_optional(pool.inner())
    .await
    .map_err(|e| VaultError::Database {
        reason: e.to_string(),
    })?
    .ok_or_else(|| VaultError::TenantNotFound {
        tenant_id: tenant_id.to_string(),
    })?;

    Ok(Tenant {
        id: TenantId(row.get::<Uuid, _>("id")),
        slug: row.get("slug"),
        display_name: row.get("display_name"),
        tier: parse_tier(row.get("tier")),
        root_key_id: row.get("root_key_id"),
        created_at: row.get("created_at"),
        updated_at: row.get("updated_at"),
        deleted_at: row.get("deleted_at"),
    })
}

/// Retrieve a tenant by its slug.
pub async fn get_tenant_by_slug(pool: &DbPool, slug: &str) -> Result<Tenant, VaultError> {
    let row = sqlx::query(
        "SELECT id, slug, display_name, tier, root_key_id, created_at, updated_at, deleted_at
         FROM system.tenants WHERE slug = $1 AND deleted_at IS NULL",
    )
    .bind(slug)
    .fetch_optional(pool.inner())
    .await
    .map_err(|e| VaultError::Database {
        reason: e.to_string(),
    })?
    .ok_or_else(|| VaultError::TenantNotFound {
        tenant_id: slug.to_string(),
    })?;

    Ok(Tenant {
        id: TenantId(row.get::<Uuid, _>("id")),
        slug: row.get("slug"),
        display_name: row.get("display_name"),
        tier: parse_tier(row.get("tier")),
        root_key_id: row.get("root_key_id"),
        created_at: row.get("created_at"),
        updated_at: row.get("updated_at"),
        deleted_at: row.get("deleted_at"),
    })
}

/// Create a new tenant.
pub async fn create_tenant(pool: &DbPool, tenant: &Tenant) -> Result<(), VaultError> {
    sqlx::query(
        "INSERT INTO system.tenants (id, slug, display_name, tier, root_key_id)
         VALUES ($1, $2, $3, $4, $5)",
    )
    .bind(tenant.id.as_uuid())
    .bind(&tenant.slug)
    .bind(&tenant.display_name)
    .bind(tier_str(&tenant.tier))
    .bind(&tenant.root_key_id)
    .execute(pool.inner())
    .await
    .map_err(|e| VaultError::Database {
        reason: e.to_string(),
    })?;

    Ok(())
}

/// Soft-delete a tenant by stamping `deleted_at`.
///
/// Only affects rows that are not already deleted; returns `TenantNotFound`
/// when no active row matches so callers can distinguish a no-op from success.
pub async fn soft_delete_tenant(pool: &DbPool, tenant_id: &TenantId) -> Result<(), VaultError> {
    let result = sqlx::query(
        "UPDATE system.tenants SET deleted_at = now()
         WHERE id = $1 AND deleted_at IS NULL",
    )
    .bind(tenant_id.as_uuid())
    .execute(pool.inner())
    .await
    .map_err(|e| VaultError::Database {
        reason: e.to_string(),
    })?;

    if result.rows_affected() == 0 {
        return Err(VaultError::TenantNotFound {
            tenant_id: tenant_id.to_string(),
        });
    }

    Ok(())
}

/// List all active tenants.
pub async fn list_tenants(pool: &DbPool) -> Result<Vec<Tenant>, VaultError> {
    let rows = sqlx::query(
        "SELECT id, slug, display_name, tier, root_key_id, created_at, updated_at, deleted_at
         FROM system.tenants WHERE deleted_at IS NULL ORDER BY slug",
    )
    .fetch_all(pool.inner())
    .await
    .map_err(|e| VaultError::Database {
        reason: e.to_string(),
    })?;

    Ok(rows
        .into_iter()
        .map(|row| Tenant {
            id: TenantId(row.get::<Uuid, _>("id")),
            slug: row.get("slug"),
            display_name: row.get("display_name"),
            tier: parse_tier(row.get("tier")),
            root_key_id: row.get("root_key_id"),
            created_at: row.get("created_at"),
            updated_at: row.get("updated_at"),
            deleted_at: row.get("deleted_at"),
        })
        .collect())
}
