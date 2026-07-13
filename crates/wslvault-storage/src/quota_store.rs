//! Quota persistence — CRUD for `shared.tenant_quotas`.
//!
//! Provides typed query wrappers for reading and updating per-tenant resource
//! quotas.  Used by the identity-service (admin CRUD) and secret-engine
//! (enforcement on write paths).

use sqlx::FromRow;
use uuid::Uuid;

use crate::pool::DbPool;

// ---------------------------------------------------------------------------
// Row types
// ---------------------------------------------------------------------------

/// Mirrors the `shared.tenant_quotas` table.
#[derive(Debug, Clone, FromRow)]
pub struct TenantQuotaRow {
    pub tenant_id: Uuid,
    pub max_secrets: i32,
    pub max_secret_versions: i32,
    pub max_secret_size_bytes: i32,
    pub max_transit_keys: i32,
    pub read_rate_limit: i32,
    pub write_rate_limit: i32,
    pub max_storage_bytes: i64,
    pub current_storage_bytes: i64,
    pub current_secret_count: i32,
    pub current_transit_key_count: i32,
    pub tier: String,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub updated_at: chrono::DateTime<chrono::Utc>,
}

/// Lightweight row for the write-path enforcement check.
/// Only fetches the two columns the secret-engine needs.
#[derive(Debug, Clone, FromRow)]
pub struct QuotaCheckRow {
    pub max_secrets: i32,
    pub current_secret_count: i32,
    pub max_secret_size_bytes: i32,
}

// ---------------------------------------------------------------------------
// Error
// ---------------------------------------------------------------------------

#[derive(Debug, thiserror::Error)]
pub enum QuotaStoreError {
    #[error("database error: {0}")]
    Database(#[from] sqlx::Error),

    #[error("quota not found for tenant {tenant_id}")]
    NotFound { tenant_id: Uuid },

    #[error("secret count limit reached ({current}/{max})")]
    SecretCountExceeded { current: i32, max: i32 },

    #[error("secret value exceeds maximum size ({size}/{max} bytes)")]
    SecretSizeExceeded { size: usize, max: i32 },
}

// ---------------------------------------------------------------------------
// Queries
// ---------------------------------------------------------------------------

/// Fetch the full quota record for a tenant.
pub async fn get_quota(pool: &DbPool, tenant_id: Uuid) -> Result<TenantQuotaRow, QuotaStoreError> {
    let row = sqlx::query_as::<_, TenantQuotaRow>(
        "SELECT * FROM shared.tenant_quotas WHERE tenant_id = $1",
    )
    .bind(tenant_id)
    .fetch_optional(pool.inner())
    .await?
    .ok_or(QuotaStoreError::NotFound { tenant_id })?;

    Ok(row)
}

/// Fast-path check: can the tenant create one more secret of the given size?
///
/// Returns `Ok(())` when within limits, or a descriptive error when a quota
/// would be exceeded.  This does NOT lock the row — the count trigger on
/// `shared.secrets` is the source of truth.  The check here is advisory to
/// reject obviously over-quota writes before they hit the DB.
pub async fn check_write_quota(
    pool: &DbPool,
    tenant_id: Uuid,
    plaintext_size: usize,
) -> Result<(), QuotaStoreError> {
    let row = sqlx::query_as::<_, QuotaCheckRow>(
        "SELECT max_secrets, current_secret_count, max_secret_size_bytes \
         FROM shared.tenant_quotas WHERE tenant_id = $1",
    )
    .bind(tenant_id)
    .fetch_optional(pool.inner())
    .await?;

    // If no quota row exists, allow the write (the trigger will create one).
    let Some(q) = row else {
        return Ok(());
    };

    if q.current_secret_count >= q.max_secrets {
        return Err(QuotaStoreError::SecretCountExceeded {
            current: q.current_secret_count,
            max: q.max_secrets,
        });
    }

    if plaintext_size > q.max_secret_size_bytes as usize {
        return Err(QuotaStoreError::SecretSizeExceeded {
            size: plaintext_size,
            max: q.max_secret_size_bytes,
        });
    }

    Ok(())
}

/// Updatable fields for `PATCH /v1/quotas/:tenant_id`.
#[derive(Debug, Default)]
pub struct QuotaUpdate {
    pub max_secrets: Option<i32>,
    pub max_secret_versions: Option<i32>,
    pub max_secret_size_bytes: Option<i32>,
    pub max_transit_keys: Option<i32>,
    pub read_rate_limit: Option<i32>,
    pub write_rate_limit: Option<i32>,
    pub max_storage_bytes: Option<i64>,
    pub tier: Option<String>,
}

/// Update selected quota fields for a tenant.
///
/// Only non-`None` fields are written; others keep their current values.
/// Returns the updated row.
pub async fn update_quota(
    pool: &DbPool,
    tenant_id: Uuid,
    update: &QuotaUpdate,
) -> Result<TenantQuotaRow, QuotaStoreError> {
    let row = sqlx::query_as::<_, TenantQuotaRow>(
        r#"
        UPDATE shared.tenant_quotas
        SET max_secrets           = COALESCE($2, max_secrets),
            max_secret_versions   = COALESCE($3, max_secret_versions),
            max_secret_size_bytes = COALESCE($4, max_secret_size_bytes),
            max_transit_keys      = COALESCE($5, max_transit_keys),
            read_rate_limit       = COALESCE($6, read_rate_limit),
            write_rate_limit      = COALESCE($7, write_rate_limit),
            max_storage_bytes     = COALESCE($8, max_storage_bytes),
            tier                  = COALESCE($9, tier)
        WHERE tenant_id = $1
        RETURNING *
        "#,
    )
    .bind(tenant_id)
    .bind(update.max_secrets)
    .bind(update.max_secret_versions)
    .bind(update.max_secret_size_bytes)
    .bind(update.max_transit_keys)
    .bind(update.read_rate_limit)
    .bind(update.write_rate_limit)
    .bind(update.max_storage_bytes)
    .bind(&update.tier)
    .fetch_optional(pool.inner())
    .await?
    .ok_or(QuotaStoreError::NotFound { tenant_id })?;

    Ok(row)
}

/// List quotas for all active tenants (used by admin dashboards).
pub async fn list_quotas(pool: &DbPool) -> Result<Vec<TenantQuotaRow>, QuotaStoreError> {
    let rows = sqlx::query_as::<_, TenantQuotaRow>(
        r#"
        SELECT tq.*
        FROM shared.tenant_quotas tq
        JOIN system.tenants t ON t.id = tq.tenant_id
        WHERE t.deleted_at IS NULL
        ORDER BY tq.tier, tq.tenant_id
        "#,
    )
    .fetch_all(pool.inner())
    .await?;

    Ok(rows)
}
