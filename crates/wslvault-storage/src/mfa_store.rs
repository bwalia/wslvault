//! TOTP enrolments and recovery codes — `shared.mfa_totp`, `shared.mfa_recovery_codes`.
//!
//! The TOTP secret arrives here already wrapped by the crypto-service, so this
//! module never sees one in the clear. Recovery codes are stored as SHA-256
//! hashes for the same reason API keys are: neither table should be a
//! credential store.

use sqlx::{PgConnection, Row};
use uuid::Uuid;

use wslvault_core::VaultError;

/// A TOTP enrolment.
#[derive(Debug, Clone)]
pub struct TotpEnrolment {
    pub api_key_id: Uuid,
    pub tenant_id: Uuid,
    /// Wrapped by the crypto-service. Opaque here.
    pub wrapped_secret: String,
    /// Highest TOTP step already accepted. A code at or below this is a replay.
    pub last_used_step: i64,
    /// `None` while enrolment is issued but unproven.
    pub confirmed_at: Option<chrono::DateTime<chrono::Utc>>,
}

impl TotpEnrolment {
    /// Whether this enrolment can satisfy a login challenge.
    ///
    /// An unconfirmed enrolment must not: the user has been shown a secret but
    /// has not proven they can generate codes from it, so treating it as active
    /// would lock them out of their own account.
    pub fn is_active(&self) -> bool {
        self.confirmed_at.is_some()
    }
}

pub async fn find(
    conn: &mut PgConnection,
    api_key_id: Uuid,
) -> Result<Option<TotpEnrolment>, VaultError> {
    let row = sqlx::query(
        "SELECT api_key_id, tenant_id, wrapped_secret, last_used_step, confirmed_at
         FROM shared.mfa_totp WHERE api_key_id = $1",
    )
    .bind(api_key_id)
    .fetch_optional(&mut *conn)
    .await
    .map_err(|e| VaultError::Database {
        reason: format!("mfa lookup failed: {e}"),
    })?;

    Ok(row.map(|r| TotpEnrolment {
        api_key_id: r.get("api_key_id"),
        tenant_id: r.get("tenant_id"),
        wrapped_secret: r.get("wrapped_secret"),
        last_used_step: r.get::<i64, _>("last_used_step"),
        confirmed_at: r.get("confirmed_at"),
    }))
}

/// Begin enrolment, replacing any unconfirmed attempt.
///
/// Re-enrolling over a *confirmed* enrolment is refused: that would let anyone
/// holding the API key silently swap out the second factor, which defeats the
/// point of having one. Removing MFA is a deliberate act via [`delete`].
pub async fn upsert_pending(
    conn: &mut PgConnection,
    api_key_id: Uuid,
    tenant_id: Uuid,
    wrapped_secret: &str,
) -> Result<(), VaultError> {
    let result = sqlx::query(
        "INSERT INTO shared.mfa_totp (api_key_id, tenant_id, wrapped_secret)
         VALUES ($1, $2, $3)
         ON CONFLICT (api_key_id) DO UPDATE
             SET wrapped_secret = EXCLUDED.wrapped_secret,
                 last_used_step = 0,
                 confirmed_at   = NULL
             WHERE shared.mfa_totp.confirmed_at IS NULL",
    )
    .bind(api_key_id)
    .bind(tenant_id)
    .bind(wrapped_secret)
    .execute(&mut *conn)
    .await
    .map_err(|e| VaultError::Database {
        reason: format!("could not start MFA enrolment: {e}"),
    })?;

    if result.rows_affected() == 0 {
        return Err(VaultError::ValidationError {
            field: "mfa".into(),
            reason: "this key already has a confirmed authenticator; remove it before re-enrolling"
                .into(),
        });
    }
    Ok(())
}

/// Mark an enrolment confirmed, and make the key actually demand it.
///
/// Both updates commit together. `mfa_required` was previously only ever
/// written by the INSERT in `api_key_store` (see its `mfa_required ||
/// is_superuser` bind), so a key created without it stayed exempt no matter
/// what the holder enrolled — the UI told them "signing in with this key now
/// asks for a code" and it did not. Enrolling is the act of asking for the
/// protection, so it is what turns it on.
///
/// Splitting these across two statements would leave a window either way round:
/// required with nothing enrolled locks the holder out, enrolled without
/// required silently leaves them unprotected while telling them otherwise.
///
/// The enrolment row must exist. Setting `mfa_required` with no confirmed
/// authenticator is the lock-out case above, so a missing row rolls the
/// transaction back rather than flipping the flag alone.
///
/// Setting `mfa_required` true can never violate `superuser_requires_mfa`
/// (025_superuser.sql) — that constraint only forbids the false case.
pub async fn confirm(
    conn: &mut PgConnection,
    api_key_id: Uuid,
    step: i64,
) -> Result<(), VaultError> {
    let confirmed = sqlx::query(
        "UPDATE shared.mfa_totp
         SET confirmed_at = now(), last_used_step = $2
         WHERE api_key_id = $1",
    )
    .bind(api_key_id)
    .bind(step)
    .execute(&mut *conn)
    .await
    .map_err(|e| VaultError::Database {
        reason: format!("could not confirm MFA enrolment: {e}"),
    })?;

    if confirmed.rows_affected() == 0 {
        return Err(VaultError::ValidationError {
            field: "mfa".into(),
            reason: "no enrolment to confirm".into(),
        });
    }

    sqlx::query("UPDATE shared.api_keys SET mfa_required = true WHERE id = $1")
        .bind(api_key_id)
        .execute(&mut *conn)
        .await
        .map_err(|e| VaultError::Database {
            reason: format!("could not enable MFA on the key: {e}"),
        })?;

    Ok(())
}

/// Record a successfully used step, rejecting replays.
///
/// The `WHERE last_used_step < $2` is the replay defence, and it is in the
/// database rather than the application on purpose: two concurrent requests
/// presenting the same code both read the same `last_used_step`, so checking in
/// Rust and then writing would let both through. Here the second update matches
/// no row and the caller sees `false`.
pub async fn try_consume_step(
    conn: &mut PgConnection,
    api_key_id: Uuid,
    step: i64,
) -> Result<bool, VaultError> {
    let result = sqlx::query(
        "UPDATE shared.mfa_totp SET last_used_step = $2
         WHERE api_key_id = $1 AND last_used_step < $2",
    )
    .bind(api_key_id)
    .bind(step)
    .execute(&mut *conn)
    .await
    .map_err(|e| VaultError::Database {
        reason: format!("could not record the MFA step: {e}"),
    })?;

    Ok(result.rows_affected() > 0)
}

/// Remove an enrolment and its recovery codes.
pub async fn delete(conn: &mut PgConnection, api_key_id: Uuid) -> Result<(), VaultError> {
    sqlx::query("DELETE FROM shared.mfa_totp WHERE api_key_id = $1")
        .bind(api_key_id)
        .execute(&mut *conn)
        .await
        .map_err(|e| VaultError::Database {
            reason: format!("could not remove MFA enrolment: {e}"),
        })?;
    Ok(())
}

/// Replace this key's recovery codes with a fresh set.
pub async fn replace_recovery_codes(
    conn: &mut PgConnection,
    api_key_id: Uuid,
    tenant_id: Uuid,
    hashes: &[String],
) -> Result<(), VaultError> {
    // No transaction of its own: the caller's ScopedTx already makes the
    // delete and the re-insert one atomic unit, and nesting one inside it
    // would be a savepoint pretending to be a transaction.
    sqlx::query("DELETE FROM shared.mfa_recovery_codes WHERE api_key_id = $1")
        .bind(api_key_id)
        .execute(&mut *conn)
        .await
        .map_err(|e| VaultError::Database {
            reason: format!("could not clear old recovery codes: {e}"),
        })?;

    for hash in hashes {
        sqlx::query(
            "INSERT INTO shared.mfa_recovery_codes (api_key_id, tenant_id, code_hash)
             VALUES ($1, $2, $3)",
        )
        .bind(api_key_id)
        .bind(tenant_id)
        .bind(hash)
        .execute(&mut *conn)
        .await
        .map_err(|e| VaultError::Database {
            reason: format!("could not store a recovery code: {e}"),
        })?;
    }

    Ok(())
}

/// Burn a recovery code. Returns whether an unused one matched.
///
/// Single-use is enforced by `used_at IS NULL` in the UPDATE rather than a
/// read-then-write, so two requests racing the same code cannot both succeed.
/// How many recovery codes a key holds, and how many are still usable.
///
/// Counts only — the codes themselves are unrecoverable by design, and a hash
/// of a sixteen-character secret from a known alphabet is the secret, so
/// neither ever leaves this table.
pub async fn count_recovery_codes(
    conn: &mut PgConnection,
    api_key_id: Uuid,
) -> Result<(i64, i64), VaultError> {
    let row = sqlx::query(
        "SELECT count(*) AS total, count(*) FILTER (WHERE used_at IS NULL) AS unused
         FROM shared.mfa_recovery_codes WHERE api_key_id = $1",
    )
    .bind(api_key_id)
    .fetch_one(&mut *conn)
    .await
    .map_err(|e| VaultError::Database {
        reason: format!("could not count recovery codes: {e}"),
    })?;

    Ok((row.get("total"), row.get("unused")))
}

pub async fn consume_recovery_code(
    conn: &mut PgConnection,
    api_key_id: Uuid,
    code_hashes: &[String],
) -> Result<bool, VaultError> {
    // Several candidate hashes, not one: a code typed today is hashed in the
    // canonical form, while rows written before separators were normalised hold
    // the hyphenated hash and cannot be recomputed. Matching any of them is
    // what keeps existing recovery codes working across that change.
    //
    // Still exactly one row: `used_at IS NULL` and the unique code, so a single
    // statement both finds and spends it and two concurrent attempts cannot
    // both succeed.
    let result = sqlx::query(
        "UPDATE shared.mfa_recovery_codes SET used_at = now()
         WHERE api_key_id = $1 AND code_hash = ANY($2) AND used_at IS NULL",
    )
    .bind(api_key_id)
    .bind(code_hashes)
    .execute(&mut *conn)
    .await
    .map_err(|e| VaultError::Database {
        reason: format!("could not consume a recovery code: {e}"),
    })?;

    Ok(result.rows_affected() > 0)
}
