//! One-time tenant invitations — `shared.tenant_invitations`.
//!
//! Creating a tenant used to produce an empty shell: a row with no API key and
//! no way for anyone at that organisation to get one. An invitation closes that
//! gap — an operator invites an address, and the recipient mints their own
//! first key by redeeming it.
//!
//! # What is stored
//!
//! Only the SHA-256 of the token, hex-encoded — never the token. An invitation
//! is a bearer credential: whoever holds it can obtain a working API key, so
//! this table would otherwise be a credential store and a database dump would
//! hand over live access. Same reasoning as [`crate::revocation_store`] and the
//! recovery codes in [`crate::mfa_store`].
//!
//! # Single use
//!
//! [`redeem`] is one statement guarded by `WHERE used_at IS NULL`, not a read
//! followed by a write. Two requests presenting the same token would both see
//! `used_at IS NULL` in application code and both mint a key; here the second
//! UPDATE matches no row and its caller is told the invitation is spent.

use chrono::{DateTime, Utc};
use sqlx::Row;
use uuid::Uuid;

use crate::api_key_store::ApiKeyRow;
use crate::pool::DbPool;
use wslvault_core::VaultError;

/// An invitation as an operator sees it. Never carries the token.
#[derive(Debug, Clone)]
pub struct Invitation {
    pub id: Uuid,
    pub tenant_id: Uuid,
    pub email: String,
    pub policies: Vec<String>,
    pub created_by: String,
    pub created_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
    pub used_at: Option<DateTime<Utc>>,
}

impl Invitation {
    /// Whether this invitation can still be redeemed.
    pub fn is_redeemable(&self) -> bool {
        self.used_at.is_none() && self.expires_at > Utc::now()
    }
}

/// Hex-encoded SHA-256 of a raw invitation token.
///
/// Callers pass the raw token; hashing happens here so no caller can
/// accidentally persist the token itself.
pub fn token_hash(token: &str) -> String {
    use sha2::{Digest, Sha256};
    hex::encode(Sha256::digest(token.trim().as_bytes()))
}

fn row_to_invitation(r: &sqlx::postgres::PgRow) -> Invitation {
    Invitation {
        id: r.get("id"),
        tenant_id: r.get("tenant_id"),
        email: r.get("email"),
        policies: r.get("policies"),
        created_by: r.get("created_by"),
        created_at: r.get("created_at"),
        expires_at: r.get("expires_at"),
        used_at: r.get("used_at"),
    }
}

/// Record a new invitation. `token` is the raw token; only its hash is stored.
#[allow(clippy::too_many_arguments)]
pub async fn create(
    pool: &DbPool,
    tenant_id: Uuid,
    email: &str,
    token: &str,
    policies: &[String],
    created_by: &str,
    expires_at: DateTime<Utc>,
) -> Result<Invitation, VaultError> {
    let id = Uuid::now_v7();

    let row = sqlx::query(
        "INSERT INTO shared.tenant_invitations
             (id, tenant_id, email, token_hash, policies, created_by, expires_at)
         VALUES ($1, $2, $3, $4, $5, $6, $7)
         RETURNING id, tenant_id, email, policies, created_by, created_at,
                   expires_at, used_at",
    )
    .bind(id)
    .bind(tenant_id)
    .bind(email.trim())
    .bind(token_hash(token))
    .bind(policies)
    .bind(created_by)
    .bind(expires_at)
    .fetch_one(pool.inner())
    .await
    .map_err(|e| VaultError::Database {
        reason: format!("could not create the invitation: {e}"),
    })?;

    Ok(row_to_invitation(&row))
}

/// Look an invitation up by token *without* consuming it.
///
/// This is what the landing page calls to show "you have been invited to
/// $TENANT" before the recipient commits to anything. It deliberately does not
/// mark the invitation used: a visitor who opens the link twice, or whose
/// browser prefetches it, must not burn their one chance to get a key.
pub async fn find_by_token(pool: &DbPool, token: &str) -> Result<Option<Invitation>, VaultError> {
    let row = sqlx::query(
        "SELECT id, tenant_id, email, policies, created_by, created_at,
                expires_at, used_at
         FROM shared.tenant_invitations
         WHERE token_hash = $1",
    )
    .bind(token_hash(token))
    .fetch_optional(pool.inner())
    .await
    .map_err(|e| VaultError::Database {
        reason: format!("invitation lookup failed: {e}"),
    })?;

    Ok(row.as_ref().map(row_to_invitation))
}

/// Why a redemption did not produce a key.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RedeemFailure {
    /// No invitation with this token. Also the answer for a token that never
    /// existed — the two are indistinguishable to the caller on purpose.
    NotFound,
    /// Already redeemed.
    AlreadyUsed,
    /// Past `expires_at`.
    Expired,
}

/// Redeem an invitation and mint the key it grants, atomically.
///
/// Both writes commit together or neither does. Split apart, a failure between
/// them leaves the recipient holding a spent invitation and no key — locked out
/// with nothing to retry, and no way for them to tell that from a link that was
/// never valid.
///
/// The guard is in SQL (`WHERE used_at IS NULL AND expires_at > now()`) rather
/// than checked here first: two concurrent redemptions of the same token both
/// pass an application-level check, and only one can match the UPDATE.
///
/// On failure the reason is distinguished only *after* the UPDATE misses, by a
/// second read — so the fast path stays one statement and the diagnosis costs
/// nothing in the common case.
pub async fn redeem(
    pool: &DbPool,
    token: &str,
    key: &ApiKeyRow,
) -> Result<Invitation, RedeemFailure> {
    let hash = token_hash(token);

    let mut tx = pool.inner().begin().await.map_err(|e| {
        tracing::error!(error = %e, "could not open transaction to redeem invitation");
        RedeemFailure::NotFound
    })?;

    // The key row goes in FIRST: `tenant_invitations.api_key_id` references
    // `shared.api_keys(id)`, so pointing the invitation at a key that does not
    // exist yet violates the foreign key. Doing it in this order is also the
    // safer arrangement — if the claim below matches nothing, this insert rolls
    // back with it, so a spent or expired token never leaves a stray key behind.
    // `&mut *tx` derefs to the connection: the insert runs on the same
    // connection as the claim below, inside this transaction.
    crate::api_key_store::insert(&mut tx, key)
        .await
        .map_err(|e| {
            tracing::error!(error = %e, "could not mint the invited key; rolling back");
            RedeemFailure::NotFound
        })?;

    let claimed = sqlx::query(
        "UPDATE shared.tenant_invitations
         SET used_at = now(), api_key_id = $2
         WHERE token_hash = $1
           AND used_at IS NULL
           AND expires_at > now()
         RETURNING id, tenant_id, email, policies, created_by, created_at,
                   expires_at, used_at",
    )
    .bind(&hash)
    .bind(key.id)
    .fetch_optional(&mut *tx)
    .await
    .map_err(|e| {
        tracing::error!(error = %e, "invitation redemption failed");
        RedeemFailure::NotFound
    })?;

    let Some(row) = claimed else {
        // Nothing matched. Work out which of the three reasons it was, so the
        // recipient gets "this link has expired" rather than a blank refusal.
        // The rollback also discards the key inserted above.
        let reason = classify_miss(&mut tx, &hash).await;
        let _ = tx.rollback().await;
        return Err(reason);
    };

    let invitation = row_to_invitation(&row);

    // The key must carry the tenant the invitation was issued for, whatever the
    // caller assembled. An invitation is authority to join ONE organisation.
    debug_assert_eq!(
        key.tenant_id, invitation.tenant_id,
        "the minted key must belong to the invitation's tenant"
    );

    tx.commit().await.map_err(|e| {
        tracing::error!(error = %e, "could not commit invitation redemption");
        RedeemFailure::NotFound
    })?;

    Ok(invitation)
}

/// Distinguish "no such token" from "spent" from "expired", for the error
/// message only. Runs inside the failed transaction, which is about to roll
/// back either way.
async fn classify_miss(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    hash: &str,
) -> RedeemFailure {
    let row = sqlx::query(
        "SELECT used_at, expires_at FROM shared.tenant_invitations WHERE token_hash = $1",
    )
    .bind(hash)
    .fetch_optional(&mut **tx)
    .await;

    match row {
        Ok(Some(r)) => {
            if r.get::<Option<DateTime<Utc>>, _>("used_at").is_some() {
                RedeemFailure::AlreadyUsed
            } else {
                RedeemFailure::Expired
            }
        }
        // A lookup failure is reported as NotFound rather than guessed at:
        // telling someone their link expired when the database was unreachable
        // sends them to ask for a new one that they did not need.
        _ => RedeemFailure::NotFound,
    }
}

/// Outstanding invitations for a tenant, newest first. Spent and expired ones
/// are included so an operator can see what happened.
pub async fn list_for_tenant(
    pool: &DbPool,
    tenant_id: Uuid,
) -> Result<Vec<Invitation>, VaultError> {
    let rows = sqlx::query(
        "SELECT id, tenant_id, email, policies, created_by, created_at,
                expires_at, used_at
         FROM shared.tenant_invitations
         WHERE tenant_id = $1
         ORDER BY created_at DESC
         LIMIT 200",
    )
    .bind(tenant_id)
    .fetch_all(pool.inner())
    .await
    .map_err(|e| VaultError::Database {
        reason: format!("could not list invitations: {e}"),
    })?;

    Ok(rows.iter().map(row_to_invitation).collect())
}

/// Withdraw an unredeemed invitation. Returns whether one was revoked.
///
/// Implemented as a delete rather than a flag: an invitation that was never
/// used leaves nothing worth auditing beyond the audit log entry for issuing
/// it, and a row that cannot be redeemed is just clutter.
pub async fn revoke(pool: &DbPool, id: Uuid, tenant_id: Uuid) -> Result<bool, VaultError> {
    let result = sqlx::query(
        "DELETE FROM shared.tenant_invitations
         WHERE id = $1 AND tenant_id = $2 AND used_at IS NULL",
    )
    .bind(id)
    .bind(tenant_id)
    .execute(pool.inner())
    .await
    .map_err(|e| VaultError::Database {
        reason: format!("could not revoke the invitation: {e}"),
    })?;

    Ok(result.rows_affected() > 0)
}

/// Delete long-expired and long-spent rows. Returns how many went.
pub async fn reap_expired(pool: &DbPool) -> Result<i64, VaultError> {
    let row = sqlx::query("SELECT shared.reap_expired_invitations() AS reaped")
        .fetch_one(pool.inner())
        .await
        .map_err(|e| VaultError::Database {
            reason: format!("invitation reaper failed: {e}"),
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
        let h = token_hash("some-token");
        assert_eq!(h.len(), 64);
        assert!(h.chars().all(|c| c.is_ascii_hexdigit()));
    }

    /// The raw token must never be recoverable from what we persist.
    #[test]
    fn hash_does_not_contain_the_token() {
        assert!(!token_hash("invite-secret-value").contains("secret"));
    }

    /// Whitespace from a copy-pasted link must not change the identity.
    #[test]
    fn hash_ignores_surrounding_whitespace() {
        assert_eq!(token_hash("  tok  "), token_hash("tok"));
    }

    #[test]
    fn redeemable_only_while_unused_and_unexpired() {
        let base = Invitation {
            id: Uuid::nil(),
            tenant_id: Uuid::nil(),
            email: "a@b.test".into(),
            policies: vec!["default".into()],
            created_by: "op".into(),
            created_at: Utc::now(),
            expires_at: Utc::now() + chrono::Duration::hours(1),
            used_at: None,
        };
        assert!(base.is_redeemable());

        let spent = Invitation {
            used_at: Some(Utc::now()),
            ..base.clone()
        };
        assert!(!spent.is_redeemable(), "a used invitation is spent");

        let stale = Invitation {
            expires_at: Utc::now() - chrono::Duration::minutes(1),
            ..base.clone()
        };
        assert!(!stale.is_redeemable(), "an expired invitation is spent");
    }
}
