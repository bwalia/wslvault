//! API key persistence — CRUD for `shared.api_keys`.
//!
//! The identity-service held API keys in a process-local `HashMap` until this
//! module existed, so every pod restart silently invalidated every key that
//! had ever been issued and a second replica could not see keys minted by the
//! first. These wrappers move that state into PostgreSQL.
//!
//! # What is stored
//!
//! Only the SHA-256 hash of the raw key (`key_hash`), never the key itself.
//! `key_prefix` is the first few characters of the random portion and is not a
//! secret — it exists so operators can identify a key in a UI or audit log.
//!
//! # Revocation is a tombstone, not a delete
//!
//! Revoking sets `revoked_at`; the row stays for the audit trail. Every lookup
//! here filters on `revoked_at IS NULL` except [`find_by_hash`], which returns
//! revoked rows so the caller can distinguish "revoked" from "never existed"
//! and log the difference.

use sqlx::{FromRow, PgConnection, Row};
use uuid::Uuid;

use crate::pool::DbPool;
use wslvault_core::VaultError;

// ---------------------------------------------------------------------------
// Row type
// ---------------------------------------------------------------------------

/// Mirrors the `shared.api_keys` table.
///
/// `tenant_id` is a UUID here because the column carries a foreign key into
/// `system.tenants(id)`. Callers that work in tenant slugs must resolve them
/// with [`resolve_tenant_id`] before touching this module.
#[derive(Debug, Clone, FromRow)]
pub struct ApiKeyRow {
    pub id: Uuid,
    pub tenant_id: Uuid,
    pub name: String,
    pub key_hash: Vec<u8>,
    pub key_prefix: String,
    pub path_prefixes: Vec<String>,
    pub policies: Vec<String>,
    pub created_by: String,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub expires_at: Option<chrono::DateTime<chrono::Utc>>,
    pub last_used_at: Option<chrono::DateTime<chrono::Utc>>,
    pub revoked_at: Option<chrono::DateTime<chrono::Utc>>,
    pub rate_limit_per_minute: i32,
    /// Grants cross-tenant access. Always paired with `mfa_required` — the
    /// schema enforces that, so a future code path cannot mint a superuser key
    /// without MFA by simply forgetting to set it.
    pub is_superuser: bool,
    /// Whether exchanging this key for a token requires a TOTP code.
    pub mfa_required: bool,
}

/// Column list shared by every SELECT so the `FromRow` derive always matches.
const COLUMNS: &str = "id, tenant_id, name, key_hash, key_prefix, path_prefixes, \
                       policies, created_by, created_at, expires_at, last_used_at, \
                       revoked_at, rate_limit_per_minute, is_superuser, mfa_required";

/// Wraps a sqlx error in the crate-wide error type with operation context.
fn db_err(op: &str, e: sqlx::Error) -> VaultError {
    VaultError::Database {
        reason: format!("api_keys {op}: {e}"),
    }
}

// ---------------------------------------------------------------------------
// Tenant resolution
// ---------------------------------------------------------------------------

/// Resolves a tenant reference — either a UUID or a slug — to its UUID.
///
/// The HTTP surface accepts whatever the caller types in `tenant_id`, but the
/// column is a foreign key into `system.tenants`. Resolving here turns an
/// unknown tenant into a clean `TenantNotFound` instead of an opaque foreign
/// key violation at insert time. Soft-deleted tenants do not resolve.
pub async fn resolve_tenant_id(pool: &DbPool, reference: &str) -> Result<Uuid, VaultError> {
    // A UUID still has to exist and be live — do not trust it blindly.
    let row = if let Ok(uuid) = reference.parse::<Uuid>() {
        sqlx::query("SELECT id FROM system.tenants WHERE id = $1 AND deleted_at IS NULL")
            .bind(uuid)
            .fetch_optional(pool.inner())
            .await
    } else {
        sqlx::query("SELECT id FROM system.tenants WHERE slug = $1 AND deleted_at IS NULL")
            .bind(reference)
            .fetch_optional(pool.inner())
            .await
    }
    .map_err(|e| db_err("resolve_tenant", e))?;

    row.map(|r| r.get::<Uuid, _>("id"))
        .ok_or_else(|| VaultError::TenantNotFound {
            tenant_id: reference.to_string(),
        })
}

// ---------------------------------------------------------------------------
// Reads
// ---------------------------------------------------------------------------

/// Looks up a key by the SHA-256 hash of its raw value.
///
/// Returns revoked and expired rows too; the caller decides what those mean so
/// it can log a revoked-key use attempt rather than treating it as a miss.
///
/// # Why this one is not tenant-scoped
///
/// It cannot be. This is the authentication path: the caller presents a key and
/// this lookup is what *determines* which tenant they are. There is no tenant
/// to scope to until it returns, so the query must run outside any
/// `app.current_tenant_id`.
///
/// That is safe because the predicate is a 256-bit hash of a secret nobody can
/// enumerate — unlike a listing, it cannot be used to discover another tenant's
/// keys. Callers must open the scope from the row this returns before touching
/// anything else.
///
/// Under an enforcing role this therefore needs
/// [`crate::tenant_scope::TenantScope::begin_cross_tenant`], with
/// "api key authentication precedes tenant identity" as the reason.
pub async fn find_by_hash(
    conn: &mut PgConnection,
    key_hash: &[u8],
) -> Result<Option<ApiKeyRow>, VaultError> {
    sqlx::query_as::<_, ApiKeyRow>(&format!(
        "SELECT {COLUMNS} FROM shared.api_keys WHERE key_hash = $1"
    ))
    .bind(key_hash)
    .fetch_optional(&mut *conn)
    .await
    .map_err(|e| db_err("find_by_hash", e))
}

/// Fetches one key by ID, scoped to its owning tenant.
///
/// The tenant predicate is what stops a leaked key UUID from being revoked or
/// rotated by a different tenant.
pub async fn find_by_id(
    conn: &mut PgConnection,
    key_id: Uuid,
    tenant_id: Uuid,
) -> Result<Option<ApiKeyRow>, VaultError> {
    sqlx::query_as::<_, ApiKeyRow>(&format!(
        "SELECT {COLUMNS} FROM shared.api_keys WHERE id = $1 AND tenant_id = $2"
    ))
    .bind(key_id)
    .bind(tenant_id)
    .fetch_optional(&mut *conn)
    .await
    .map_err(|e| db_err("find_by_id", e))
}

/// Lists a tenant's active keys — not revoked, not past their expiry —
/// newest first.
pub async fn list_active_for_tenant(
    conn: &mut PgConnection,
    tenant_id: Uuid,
) -> Result<Vec<ApiKeyRow>, VaultError> {
    sqlx::query_as::<_, ApiKeyRow>(&format!(
        "SELECT {COLUMNS} FROM shared.api_keys
          WHERE tenant_id = $1
            AND revoked_at IS NULL
            AND (expires_at IS NULL OR expires_at >= now())
          ORDER BY created_at DESC"
    ))
    .bind(tenant_id)
    .fetch_all(&mut *conn)
    .await
    .map_err(|e| db_err("list_active", e))
}

/// Returns `true` when the tenant already has an active key by this name.
///
/// Mirrored by the partial unique index added in migration 016, which is what
/// actually enforces it under concurrency; this check exists to return a clean
/// 409 instead of a constraint violation on the common path.
pub async fn active_name_exists(
    conn: &mut PgConnection,
    tenant_id: Uuid,
    name: &str,
) -> Result<bool, VaultError> {
    let row = sqlx::query(
        "SELECT 1 FROM shared.api_keys
          WHERE tenant_id = $1 AND name = $2 AND revoked_at IS NULL
          LIMIT 1",
    )
    .bind(tenant_id)
    .bind(name)
    .fetch_optional(&mut *conn)
    .await
    .map_err(|e| db_err("active_name_exists", e))?;

    Ok(row.is_some())
}

// ---------------------------------------------------------------------------
// Writes
// ---------------------------------------------------------------------------

/// Inserts a freshly minted key.
///
/// A unique violation on the active-name index surfaces as
/// `ValidationError { field: "name" }` so the handler can map it to 409
/// without inspecting sqlx error codes itself.
pub async fn insert(conn: &mut PgConnection, row: &ApiKeyRow) -> Result<(), VaultError> {
    let result = insert_query(row).execute(&mut *conn).await;
    map_insert_result(result, &row.name)
}

/// The INSERT itself, shared so the pooled and transactional paths cannot drift
/// — in particular the `mfa_required || is_superuser` bind below.
fn insert_query(
    row: &ApiKeyRow,
) -> sqlx::query::Query<'_, sqlx::Postgres, sqlx::postgres::PgArguments> {
    sqlx::query(
        "INSERT INTO shared.api_keys
             (id, tenant_id, name, key_hash, key_prefix, path_prefixes, policies,
              created_by, created_at, expires_at, rate_limit_per_minute,
              is_superuser, mfa_required)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13)",
    )
    .bind(row.id)
    .bind(row.tenant_id)
    .bind(&row.name)
    .bind(&row.key_hash)
    .bind(&row.key_prefix)
    .bind(&row.path_prefixes)
    .bind(&row.policies)
    .bind(&row.created_by)
    .bind(row.created_at)
    .bind(row.expires_at)
    .bind(row.rate_limit_per_minute)
    .bind(row.is_superuser)
    // Superuser keys always require MFA; the schema enforces it too, so a
    // caller that forgets gets a constraint violation rather than a hole.
    .bind(row.mfa_required || row.is_superuser)
}

fn map_insert_result(
    result: Result<sqlx::postgres::PgQueryResult, sqlx::Error>,
    name: &str,
) -> Result<(), VaultError> {
    match result {
        Ok(_) => Ok(()),
        Err(sqlx::Error::Database(db)) if db.is_unique_violation() => {
            Err(VaultError::ValidationError {
                field: "name".to_string(),
                reason: format!("an active api key named '{name}' already exists"),
            })
        }
        Err(e) => Err(db_err("insert", e)),
    }
}

/// Marks a key revoked. Returns `false` when no active row matched, which
/// covers both "no such key for this tenant" and "already revoked".
pub async fn revoke(
    conn: &mut PgConnection,
    key_id: Uuid,
    tenant_id: Uuid,
) -> Result<bool, VaultError> {
    let result = sqlx::query(
        "UPDATE shared.api_keys
            SET revoked_at = now()
          WHERE id = $1 AND tenant_id = $2 AND revoked_at IS NULL",
    )
    .bind(key_id)
    .bind(tenant_id)
    .execute(&mut *conn)
    .await
    .map_err(|e| db_err("revoke", e))?;

    Ok(result.rows_affected() > 0)
}

/// Stamps `last_used_at` after a successful authentication.
///
/// Deliberately best-effort at the call site: a failure here must not fail an
/// otherwise valid authentication, so callers log and continue.
///
/// Takes the tenant so it can run inside the caller's own scope. Every call
/// site has just authenticated and therefore knows it; a cross-tenant bypass
/// here would be a permanent hole opened for a bookkeeping update.
pub async fn touch_last_used(
    conn: &mut PgConnection,
    key_id: Uuid,
    tenant_id: Uuid,
) -> Result<(), VaultError> {
    sqlx::query(
        "UPDATE shared.api_keys SET last_used_at = now()
          WHERE id = $1 AND tenant_id = $2",
    )
    .bind(key_id)
    .bind(tenant_id)
    .execute(&mut *conn)
    .await
    .map_err(|e| db_err("touch_last_used", e))?;

    Ok(())
}
