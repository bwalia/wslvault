//! Lease storage operations.

use sqlx::Row;
use uuid::Uuid;

use crate::pool::DbPool;
use wslvault_core::types::lease::{Lease, LeaseId, LeaseState, LeaseTarget};
use wslvault_core::types::tenant::TenantId;
use wslvault_core::VaultError;

fn parse_state(s: &str) -> LeaseState {
    match s {
        "renewing" => LeaseState::Renewing,
        "expired" => LeaseState::Expired,
        "revoked" => LeaseState::Revoked,
        _ => LeaseState::Active,
    }
}

fn state_str(s: &LeaseState) -> &'static str {
    match s {
        LeaseState::Active => "active",
        LeaseState::Renewing => "renewing",
        LeaseState::Expired => "expired",
        LeaseState::Revoked => "revoked",
    }
}

fn target_type_str(t: &LeaseTarget) -> &'static str {
    match t {
        LeaseTarget::Token { .. } => "token",
        LeaseTarget::DynamicSecret { .. } => "dynamic_secret",
        LeaseTarget::ServiceCredential { .. } => "service_credential",
    }
}

/// Insert a new lease.
pub async fn create_lease(pool: &DbPool, lease: &Lease) -> Result<(), VaultError> {
    let target_data = serde_json::to_value(&lease.target).map_err(|e| VaultError::Internal {
        reason: e.to_string(),
    })?;

    sqlx::query(
        "INSERT INTO shared.leases
         (id, tenant_id, target_type, target_data, state, ttl_seconds, max_ttl_seconds, renewable, issued_at, expires_at)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)",
    )
    .bind(lease.id.0)
    .bind(lease.tenant_id.as_uuid())
    .bind(target_type_str(&lease.target))
    .bind(target_data)
    .bind(state_str(&lease.state))
    .bind(lease.ttl_seconds as i64)
    .bind(lease.max_ttl_seconds as i64)
    .bind(lease.renewable)
    .bind(lease.issued_at)
    .bind(lease.expires_at)
    .execute(pool.inner())
    .await
    .map_err(|e| VaultError::Database {
        reason: e.to_string(),
    })?;

    Ok(())
}

/// Retrieve a lease by ID.
pub async fn get_lease(pool: &DbPool, lease_id: &LeaseId) -> Result<Lease, VaultError> {
    let row = sqlx::query(
        "SELECT id, tenant_id, target_type, target_data, state, ttl_seconds, max_ttl_seconds,
                renewable, issued_at, expires_at, revoked_at
         FROM shared.leases WHERE id = $1",
    )
    .bind(lease_id.0)
    .fetch_optional(pool.inner())
    .await
    .map_err(|e| VaultError::Database {
        reason: e.to_string(),
    })?
    .ok_or_else(|| VaultError::LeaseNotFound {
        lease_id: lease_id.to_string(),
    })?;

    row_to_lease(row)
}

/// Update a lease's expiration (for renewal).
pub async fn renew_lease(
    pool: &DbPool,
    lease_id: &LeaseId,
    new_expires_at: chrono::DateTime<chrono::Utc>,
    new_ttl_seconds: u64,
) -> Result<(), VaultError> {
    let result = sqlx::query(
        "UPDATE shared.leases
         SET expires_at = $2, ttl_seconds = $3, state = 'active'
         WHERE id = $1 AND state IN ('active', 'renewing')",
    )
    .bind(lease_id.0)
    .bind(new_expires_at)
    .bind(new_ttl_seconds as i64)
    .execute(pool.inner())
    .await
    .map_err(|e| VaultError::Database {
        reason: e.to_string(),
    })?;

    if result.rows_affected() == 0 {
        return Err(VaultError::LeaseNotFound {
            lease_id: lease_id.to_string(),
        });
    }

    Ok(())
}

/// Revoke a lease.
///
/// Idempotent for an existing row (already-revoked still succeeds). A missing
/// id is [`VaultError::LeaseNotFound`].
pub async fn revoke_lease(pool: &DbPool, lease_id: &LeaseId) -> Result<(), VaultError> {
    let result =
        sqlx::query("UPDATE shared.leases SET state = 'revoked', revoked_at = now() WHERE id = $1")
            .bind(lease_id.0)
            .execute(pool.inner())
            .await
            .map_err(|e| VaultError::Database {
                reason: e.to_string(),
            })?;

    if result.rows_affected() == 0 {
        return Err(VaultError::LeaseNotFound {
            lease_id: lease_id.to_string(),
        });
    }

    Ok(())
}

/// List leases for a tenant, optionally filtered by state.
///
/// `tenant_id` is required — list-without-tenant is forbidden (RLS is not
/// yet applied via `app.current_tenant_id`).
pub async fn list_leases(
    pool: &DbPool,
    tenant_id: &TenantId,
    state_filter: Option<&str>,
) -> Result<Vec<Lease>, VaultError> {
    let rows = sqlx::query(
        "SELECT id, tenant_id, target_type, target_data, state, ttl_seconds, max_ttl_seconds,
                renewable, issued_at, expires_at, revoked_at
         FROM shared.leases
         WHERE tenant_id = $1
           AND ($2::text IS NULL OR state = $2)
         ORDER BY issued_at DESC",
    )
    .bind(tenant_id.as_uuid())
    .bind(state_filter)
    .fetch_all(pool.inner())
    .await
    .map_err(|e| VaultError::Database {
        reason: e.to_string(),
    })?;

    rows.into_iter().map(row_to_lease).collect()
}

/// Active leases whose `expires_at` has passed, up to `batch_size`.
pub async fn list_stale_leases(pool: &DbPool, batch_size: i32) -> Result<Vec<Lease>, VaultError> {
    let rows = sqlx::query(
        "SELECT id, tenant_id, target_type, target_data, state, ttl_seconds, max_ttl_seconds,
                renewable, issued_at, expires_at, revoked_at
         FROM shared.leases
         WHERE state = 'active' AND expires_at < now()
         ORDER BY expires_at
         LIMIT $1",
    )
    .bind(batch_size)
    .fetch_all(pool.inner())
    .await
    .map_err(|e| VaultError::Database {
        reason: e.to_string(),
    })?;

    rows.into_iter().map(row_to_lease).collect()
}

/// Mark a single active lease expired. No-op (and not an error) if it is
/// already in a terminal state.
pub async fn mark_lease_expired(pool: &DbPool, lease_id: &LeaseId) -> Result<(), VaultError> {
    sqlx::query("UPDATE shared.leases SET state = 'expired' WHERE id = $1 AND state = 'active'")
        .bind(lease_id.0)
        .execute(pool.inner())
        .await
        .map_err(|e| VaultError::Database {
            reason: e.to_string(),
        })?;
    Ok(())
}

fn row_to_lease(row: sqlx::postgres::PgRow) -> Result<Lease, VaultError> {
    let target_data: serde_json::Value = row.get("target_data");
    let target: LeaseTarget =
        serde_json::from_value(target_data).map_err(|e| VaultError::Internal {
            reason: format!("failed to deserialize lease target: {}", e),
        })?;

    Ok(Lease {
        id: LeaseId(row.get::<Uuid, _>("id")),
        tenant_id: TenantId(row.get::<Uuid, _>("tenant_id")),
        target,
        state: parse_state(row.get("state")),
        ttl_seconds: row.get::<i64, _>("ttl_seconds") as u64,
        max_ttl_seconds: row.get::<i64, _>("max_ttl_seconds") as u64,
        renewable: row.get("renewable"),
        issued_at: row.get("issued_at"),
        expires_at: row.get("expires_at"),
        revoked_at: row.get("revoked_at"),
    })
}

/// Batch-expire active leases that have passed their expiration time.
/// Returns the IDs of expired leases.
pub async fn expire_leases(pool: &DbPool, batch_size: i32) -> Result<Vec<LeaseId>, VaultError> {
    let rows = sqlx::query("SELECT * FROM shared.vault_expire_leases($1)")
        .bind(batch_size)
        .fetch_all(pool.inner())
        .await
        .map_err(|e| VaultError::Database {
            reason: e.to_string(),
        })?;

    Ok(rows
        .into_iter()
        .map(|r| LeaseId(r.get::<Uuid, _>(0)))
        .collect())
}

#[cfg(test)]
mod tests {
    use super::*;
    use wslvault_core::types::lease::LeaseId;

    #[tokio::test]
    async fn revoke_missing_id_is_not_found_when_database_configured() {
        let Ok(url) = std::env::var("DATABASE_URL") else {
            return;
        };
        let config = wslvault_core::config::DatabaseConfig {
            url,
            ..Default::default()
        };
        let Ok(pool) = crate::pool::DbPool::connect(&config).await else {
            return;
        };
        let missing = LeaseId::new();
        let err = revoke_lease(&pool, &missing)
            .await
            .expect_err("missing lease must not look like success");
        assert!(
            matches!(err, VaultError::LeaseNotFound { .. }),
            "got {err:?}"
        );
    }
}
