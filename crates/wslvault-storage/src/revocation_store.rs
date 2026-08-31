//! Durable token revocation — `system.revoked_tokens`.
//!
//! The identity-service held revocations in a process-local
//! `Arc<RwLock<HashSet<String>>>` until this module existed. That made
//! "revoke this token" untrue in three separate ways: the set lived in one
//! pod (the chart runs two, so revoking on A left the token live on B), it was
//! erased by every restart and rolling deploy, and nothing ever evicted an
//! entry, so it grew without bound. secret-engine never consulted it at all.
//!
//! # What is stored
//!
//! Only the SHA-256 of the raw token, hex-encoded — never the token. This
//! table would otherwise be a live credential store, and a database dump would
//! hand over working tokens. A hash is sufficient because revocation only ever
//! answers "is *this* token revoked", never "list them".
//!
//! # Revocations expire
//!
//! A revocation only has to outlive the token it revokes. Past the token's own
//! `exp` the JWT validator rejects it regardless, so [`reap_expired`] deletes
//! rows whose `expires_at` has passed. That is what keeps the table bounded.

use sqlx::Row;

use crate::pool::DbPool;
use wslvault_core::VaultError;

/// Hex-encoded SHA-256 of a raw token string.
///
/// Callers pass the raw token; hashing happens here so no caller can
/// accidentally persist the token itself.
pub fn token_hash(token: &str) -> String {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(token.as_bytes());
    hex::encode(hasher.finalize())
}

/// Record a revocation. Idempotent — revoking twice is not an error.
///
/// `expires_at` is the token's own `exp` claim, as a Unix timestamp. It is
/// what makes the row reapable later; passing a value in the past means the
/// row is eligible for immediate reaping, which is harmless because the token
/// is already expired.
pub async fn revoke(
    pool: &DbPool,
    token: &str,
    tenant_id: &str,
    principal_id: &str,
    expires_at_unix: i64,
) -> Result<(), VaultError> {
    let expires_at = chrono::DateTime::from_timestamp(expires_at_unix, 0).ok_or_else(|| {
        VaultError::ValidationError {
            field: "expires_at".into(),
            reason: format!("token exp {expires_at_unix} is not a representable timestamp"),
        }
    })?;

    sqlx::query(
        "INSERT INTO system.revoked_tokens
             (token_hash, tenant_id, principal_id, expires_at)
         VALUES ($1, $2, $3, $4)
         ON CONFLICT (token_hash) DO NOTHING",
    )
    .bind(token_hash(token))
    .bind(tenant_id)
    .bind(principal_id)
    .bind(expires_at)
    .execute(pool.inner())
    .await
    .map_err(|e| VaultError::Database {
        reason: format!("failed to record token revocation: {e}"),
    })?;

    Ok(())
}

/// Whether this exact token has been revoked.
///
/// Propagates database errors rather than returning `false`. The caller must
/// **fail closed** on the error: answering "not revoked" because the database
/// was briefly unreachable is precisely the behaviour that made the old
/// in-memory implementation unsafe (a poisoned lock was treated as
/// "not revoked").
pub async fn is_revoked(pool: &DbPool, token: &str) -> Result<bool, VaultError> {
    let row = sqlx::query(
        "SELECT EXISTS (
             SELECT 1 FROM system.revoked_tokens
             WHERE token_hash = $1 AND expires_at > now()
         ) AS revoked",
    )
    .bind(token_hash(token))
    .fetch_one(pool.inner())
    .await
    .map_err(|e| VaultError::Database {
        reason: format!("revocation lookup failed: {e}"),
    })?;

    Ok(row.try_get::<bool, _>("revoked").unwrap_or(true))
}

/// Delete revocations for tokens that have since expired on their own.
///
/// Returns the number of rows reaped. Safe to run concurrently from any
/// replica.
pub async fn reap_expired(pool: &DbPool) -> Result<i64, VaultError> {
    let row = sqlx::query("SELECT system.reap_expired_revocations() AS reaped")
        .fetch_one(pool.inner())
        .await
        .map_err(|e| VaultError::Database {
            reason: format!("revocation reaper failed: {e}"),
        })?;

    Ok(row.try_get::<i64, _>("reaped").unwrap_or(0))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hash_is_stable_and_distinct() {
        assert_eq!(token_hash("abc"), token_hash("abc"));
        assert_ne!(token_hash("abc"), token_hash("abd"));
    }

    #[test]
    fn hash_is_hex_sha256() {
        let h = token_hash("token");
        assert_eq!(h.len(), 64, "SHA-256 hex is 64 characters");
        assert!(h.chars().all(|c| c.is_ascii_hexdigit()));
    }

    /// The raw token must never appear in what we persist.
    #[test]
    fn hash_does_not_contain_the_token() {
        let token = "wslv-super-secret-token-value";
        assert!(!token_hash(token).contains("secret"));
    }
}
