//! Per-tenant token signing keys — `system.tenant_signing_keys`.
//!
//! See `024_tenant_signing_keys.sql` for why these exist. In short: tokens were
//! HS256 under one shared secret, so every service that could verify a token
//! could also mint one, and there was no cryptographic boundary between tenants
//! at the token layer.
//!
//! This module stores key *records*. It never sees a private key in the clear —
//! the caller wraps it before handing it over and unwraps after reading it back.

use sqlx::Row;
use uuid::Uuid;

use crate::pool::DbPool;
use wslvault_core::VaultError;

/// One signing key as stored.
#[derive(Debug, Clone)]
pub struct SigningKeyRecord {
    /// JWT `kid`. How a verifier selects this key.
    pub kid: String,
    /// Owning tenant, or `None` for the system key that signs superuser tokens.
    pub tenant_id: Option<Uuid>,
    /// base64url-unpadded Ed25519 public key — the `x` of an OKP JWK.
    pub public_key: String,
    /// PKCS#8 private key, wrapped by the crypto-service. Opaque here.
    pub wrapped_private_key: String,
    pub state: String,
}

/// The tenant's active signing key, or `None` if it has never signed anything.
pub async fn active_for_tenant(
    pool: &DbPool,
    tenant_id: &Uuid,
) -> Result<Option<SigningKeyRecord>, VaultError> {
    fetch_one(
        pool,
        "SELECT kid, tenant_id, public_key, wrapped_private_key, state
         FROM system.tenant_signing_keys
         WHERE tenant_id = $1 AND state = 'active'",
        Some(tenant_id),
    )
    .await
}

/// The active system key, which signs superuser tokens.
///
/// Superuser tokens are not bound to one tenant, so signing them with a
/// tenant's key would be a category error — and would let that tenant's key
/// mint cross-tenant authority.
pub async fn active_system_key(pool: &DbPool) -> Result<Option<SigningKeyRecord>, VaultError> {
    fetch_one(
        pool,
        "SELECT kid, tenant_id, public_key, wrapped_private_key, state
         FROM system.tenant_signing_keys
         WHERE tenant_id IS NULL AND state = 'active'",
        None,
    )
    .await
}

async fn fetch_one(
    pool: &DbPool,
    sql: &str,
    tenant_id: Option<&Uuid>,
) -> Result<Option<SigningKeyRecord>, VaultError> {
    let mut q = sqlx::query(sql);
    if let Some(t) = tenant_id {
        q = q.bind(t);
    }
    let row = q
        .fetch_optional(pool.inner())
        .await
        .map_err(|e| VaultError::Database {
            reason: format!("signing key lookup failed: {e}"),
        })?;

    Ok(row.map(|r| SigningKeyRecord {
        kid: r.get("kid"),
        tenant_id: r.get::<Option<Uuid>, _>("tenant_id"),
        public_key: r.get("public_key"),
        wrapped_private_key: r.get("wrapped_private_key"),
        state: r.get("state"),
    }))
}

/// Look up one key by `kid`, regardless of state.
///
/// Verification needs retired-but-not-yet-expired keys too: a token signed
/// before a rotation is still valid until its own `exp`.
pub async fn by_kid(pool: &DbPool, kid: &str) -> Result<Option<SigningKeyRecord>, VaultError> {
    let row = sqlx::query(
        "SELECT kid, tenant_id, public_key, wrapped_private_key, state
         FROM system.tenant_signing_keys WHERE kid = $1",
    )
    .bind(kid)
    .fetch_optional(pool.inner())
    .await
    .map_err(|e| VaultError::Database {
        reason: format!("signing key lookup failed: {e}"),
    })?;

    Ok(row.map(|r| SigningKeyRecord {
        kid: r.get("kid"),
        tenant_id: r.get::<Option<Uuid>, _>("tenant_id"),
        public_key: r.get("public_key"),
        wrapped_private_key: r.get("wrapped_private_key"),
        state: r.get("state"),
    }))
}

/// Every key a live token might have been signed with. Backs the JWKS endpoint.
///
/// `rotating_out` keys are included deliberately: dropping them the moment a
/// new key is issued would invalidate every token already in flight.
pub async fn publishable(pool: &DbPool) -> Result<Vec<SigningKeyRecord>, VaultError> {
    let rows = sqlx::query(
        "SELECT kid, tenant_id, public_key, wrapped_private_key, state
         FROM system.tenant_signing_keys
         WHERE state IN ('active', 'rotating_out')
         ORDER BY created_at DESC",
    )
    .fetch_all(pool.inner())
    .await
    .map_err(|e| VaultError::Database {
        reason: format!("could not list signing keys: {e}"),
    })?;

    Ok(rows
        .into_iter()
        .map(|r| SigningKeyRecord {
            kid: r.get("kid"),
            tenant_id: r.get::<Option<Uuid>, _>("tenant_id"),
            public_key: r.get("public_key"),
            wrapped_private_key: r.get("wrapped_private_key"),
            state: r.get("state"),
        })
        .collect())
}

/// Insert a newly generated key as the tenant's active one.
///
/// Races are resolved by the partial unique index on `(tenant_id) WHERE state =
/// 'active'`: two processes generating a first key for the same tenant at once
/// means one insert fails, and the caller re-reads rather than ending up with
/// two "active" keys that verifiers would have to choose between.
pub async fn insert_active(pool: &DbPool, key: &SigningKeyRecord) -> Result<(), VaultError> {
    sqlx::query(
        "INSERT INTO system.tenant_signing_keys
             (kid, tenant_id, algorithm, public_key, wrapped_private_key, state)
         VALUES ($1, $2, 'EdDSA', $3, $4, 'active')",
    )
    .bind(&key.kid)
    .bind(key.tenant_id)
    .bind(&key.public_key)
    .bind(&key.wrapped_private_key)
    .execute(pool.inner())
    .await
    .map_err(|e| VaultError::Database {
        reason: format!("could not store signing key: {e}"),
    })?;
    Ok(())
}

/// Retire a key so it stops signing but keeps verifying.
///
/// Rotation is deliberately two-phase. Deleting the old key immediately would
/// invalidate every token already issued under it; `rotating_out` keeps it in
/// JWKS until those expire naturally.
pub async fn mark_rotating_out(pool: &DbPool, kid: &str) -> Result<(), VaultError> {
    sqlx::query(
        "UPDATE system.tenant_signing_keys
         SET state = 'rotating_out', retired_at = now()
         WHERE kid = $1 AND state = 'active'",
    )
    .bind(kid)
    .execute(pool.inner())
    .await
    .map_err(|e| VaultError::Database {
        reason: format!("could not retire signing key: {e}"),
    })?;
    Ok(())
}
