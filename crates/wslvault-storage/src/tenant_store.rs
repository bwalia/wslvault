//! Tenant CRUD operations against the system.tenants table.

use sqlx::Row;
use uuid::Uuid;

use crate::pool::DbPool;
use wslvault_core::types::secret::SecretEnvironment;
use wslvault_core::types::tenant::{Tenant, TenantId, TenantKind, TenantTier};
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

fn parse_kind(s: &str) -> TenantKind {
    s.parse().unwrap_or(TenantKind::Project)
}

fn parse_env_list(raw: Vec<String>) -> Vec<SecretEnvironment> {
    raw.into_iter()
        .filter_map(|s| s.parse::<SecretEnvironment>().ok())
        .collect()
}

fn env_list_strs(envs: &[SecretEnvironment]) -> Vec<String> {
    envs.iter().map(|e| e.as_str().to_string()).collect()
}

fn parse_env(s: &str) -> SecretEnvironment {
    s.parse().unwrap_or(SecretEnvironment::Int)
}

const TENANT_COLS: &str = "id, slug, display_name, tier, root_key_id, tenant_kind, \
     allowed_environments, default_environment, tags, created_at, updated_at, deleted_at";

fn row_to_tenant(row: sqlx::postgres::PgRow) -> Tenant {
    let allowed: Vec<String> = row.get("allowed_environments");
    let default_env: String = row.get("default_environment");
    let tags: Vec<String> = row.get("tags");
    let kind_s: String = row.get("tenant_kind");
    Tenant {
        id: TenantId(row.get::<Uuid, _>("id")),
        slug: row.get("slug"),
        display_name: row.get("display_name"),
        tier: parse_tier(row.get("tier")),
        root_key_id: row.get("root_key_id"),
        tenant_kind: parse_kind(&kind_s),
        allowed_environments: {
            let parsed = parse_env_list(allowed);
            if parsed.is_empty() {
                parse_kind(&kind_s).default_allowed()
            } else {
                parsed
            }
        },
        default_environment: parse_env(&default_env),
        tags,
        created_at: row.get("created_at"),
        updated_at: row.get("updated_at"),
        deleted_at: row.get("deleted_at"),
    }
}

/// Retrieve a tenant by its ID.
pub async fn get_tenant(pool: &DbPool, tenant_id: &TenantId) -> Result<Tenant, VaultError> {
    let row = sqlx::query(&format!(
        "SELECT {TENANT_COLS} FROM system.tenants WHERE id = $1"
    ))
    .bind(tenant_id.as_uuid())
    .fetch_optional(pool.inner())
    .await
    .map_err(|e| VaultError::Database {
        reason: e.to_string(),
    })?
    .ok_or_else(|| VaultError::TenantNotFound {
        tenant_id: tenant_id.to_string(),
    })?;

    Ok(row_to_tenant(row))
}

/// Retrieve a tenant by its slug.
pub async fn get_tenant_by_slug(pool: &DbPool, slug: &str) -> Result<Tenant, VaultError> {
    let row = sqlx::query(&format!(
        "SELECT {TENANT_COLS} FROM system.tenants WHERE slug = $1 AND deleted_at IS NULL"
    ))
    .bind(slug)
    .fetch_optional(pool.inner())
    .await
    .map_err(|e| VaultError::Database {
        reason: e.to_string(),
    })?
    .ok_or_else(|| VaultError::TenantNotFound {
        tenant_id: slug.to_string(),
    })?;

    Ok(row_to_tenant(row))
}

/// Create a new tenant.
pub async fn create_tenant(pool: &DbPool, tenant: &Tenant) -> Result<(), VaultError> {
    sqlx::query(
        "INSERT INTO system.tenants (
            id, slug, display_name, tier, root_key_id,
            tenant_kind, allowed_environments, default_environment, tags
         ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)",
    )
    .bind(tenant.id.as_uuid())
    .bind(&tenant.slug)
    .bind(&tenant.display_name)
    .bind(tier_str(&tenant.tier))
    .bind(&tenant.root_key_id)
    .bind(tenant.tenant_kind.as_str())
    .bind(env_list_strs(&tenant.allowed_environments))
    .bind(tenant.default_environment.as_str())
    .bind(&tenant.tags)
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
    let rows = sqlx::query(&format!(
        "SELECT {TENANT_COLS} FROM system.tenants WHERE deleted_at IS NULL ORDER BY slug"
    ))
    .fetch_all(pool.inner())
    .await
    .map_err(|e| VaultError::Database {
        reason: e.to_string(),
    })?;

    Ok(rows.into_iter().map(row_to_tenant).collect())
}
