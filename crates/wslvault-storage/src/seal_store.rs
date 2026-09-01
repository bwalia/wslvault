//! Persistence for the seal — `system.seal_config`.
//!
//! Stores only the root key encrypted under an unseal key that is never stored.
//! See `023_seal.sql` and `wslvault_core::seal` for why that division matters.

use sqlx::Row;

use crate::pool::DbPool;
use wslvault_core::seal::SealMaterial;
use wslvault_core::VaultError;

/// Load the seal material, or `None` when the vault has never been initialized.
pub async fn load(pool: &DbPool) -> Result<Option<SealMaterial>, VaultError> {
    let row = sqlx::query(
        "SELECT shares, threshold, sealed_root_key, unseal_key_check
         FROM system.seal_config WHERE id = 1",
    )
    .fetch_optional(pool.inner())
    .await
    .map_err(|e| VaultError::Database {
        reason: format!("could not read the seal configuration: {e}"),
    })?;

    Ok(row.map(|r| SealMaterial {
        shares: r.get::<i16, _>("shares") as u8,
        threshold: r.get::<i16, _>("threshold") as u8,
        sealed_root_key: r.get("sealed_root_key"),
        unseal_key_check: r.get("unseal_key_check"),
    }))
}

/// Persist seal material for a vault being initialized.
///
/// Refuses to overwrite: `ON CONFLICT DO NOTHING` plus a row-count check, so a
/// second `sys/init` cannot replace the root key that every existing tenant KEK
/// is encrypted under. Losing that quietly would render the whole vault
/// unreadable with no error at the moment it happened.
pub async fn save_initial(pool: &DbPool, material: &SealMaterial) -> Result<(), VaultError> {
    let result = sqlx::query(
        "INSERT INTO system.seal_config
             (id, shares, threshold, sealed_root_key, unseal_key_check)
         VALUES (1, $1, $2, $3, $4)
         ON CONFLICT (id) DO NOTHING",
    )
    .bind(material.shares as i16)
    .bind(material.threshold as i16)
    .bind(&material.sealed_root_key)
    .bind(&material.unseal_key_check)
    .execute(pool.inner())
    .await
    .map_err(|e| VaultError::Database {
        reason: format!("could not persist the seal configuration: {e}"),
    })?;

    if result.rows_affected() == 0 {
        return Err(VaultError::ValidationError {
            field: "seal".into(),
            reason: "vault is already initialized; refusing to replace the root key".into(),
        });
    }
    Ok(())
}
