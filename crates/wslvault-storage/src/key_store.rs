//! Key descriptor storage operations.

use sqlx::Row;
use uuid::Uuid;

use crate::pool::DbPool;
use wslvault_core::types::key::{KeyAlgorithm, KeyDescriptor, KeyId, KeyPurpose, KeyState};
use wslvault_core::VaultError;

fn parse_algorithm(s: &str) -> KeyAlgorithm {
    match s {
        "chacha20-poly1305" => KeyAlgorithm::ChaCha20Poly1305,
        "xchacha20-poly1305" => KeyAlgorithm::XChaCha20Poly1305,
        _ => KeyAlgorithm::Aes256Gcm,
    }
}

fn algorithm_str(a: &KeyAlgorithm) -> &'static str {
    match a {
        KeyAlgorithm::Aes256Gcm => "aes-256-gcm",
        KeyAlgorithm::ChaCha20Poly1305 => "chacha20-poly1305",
        KeyAlgorithm::XChaCha20Poly1305 => "xchacha20-poly1305",
    }
}

fn parse_purpose(s: &str) -> KeyPurpose {
    match s {
        "root_kek" => KeyPurpose::RootKek,
        "tenant_kek" => KeyPurpose::TenantKek,
        "data_encryption" => KeyPurpose::DataEncryption,
        "signing" => KeyPurpose::Signing,
        "transit" => KeyPurpose::Transit,
        _ => KeyPurpose::DataEncryption,
    }
}

fn purpose_str(p: &KeyPurpose) -> &'static str {
    match p {
        KeyPurpose::RootKek => "root_kek",
        KeyPurpose::TenantKek => "tenant_kek",
        KeyPurpose::DataEncryption => "data_encryption",
        KeyPurpose::Signing => "signing",
        KeyPurpose::Transit => "transit",
    }
}

fn parse_state(s: &str) -> KeyState {
    match s {
        "rotating_out" => KeyState::RotatingOut,
        "retired" => KeyState::Retired,
        "destroyed" => KeyState::Destroyed,
        _ => KeyState::Active,
    }
}

fn state_str(s: &KeyState) -> &'static str {
    match s {
        KeyState::Active => "active",
        KeyState::RotatingOut => "rotating_out",
        KeyState::Retired => "retired",
        KeyState::Destroyed => "destroyed",
    }
}

/// Retrieve a key descriptor by ID.
pub async fn get_key_descriptor(
    pool: &DbPool,
    key_id: &KeyId,
) -> Result<KeyDescriptor, VaultError> {
    let row = sqlx::query(
        "SELECT id, version, algorithm, purpose, state, tenant_id, created_at, rotated_at, expires_at
         FROM system.key_descriptors WHERE id = $1",
    )
    .bind(key_id.0)
    .fetch_optional(pool.inner())
    .await
    .map_err(|e| VaultError::Database {
        reason: e.to_string(),
    })?
    .ok_or_else(|| VaultError::KeyNotFound {
        key_id: key_id.to_string(),
    })?;

    Ok(KeyDescriptor {
        id: KeyId(row.get::<Uuid, _>("id")),
        version: row.get::<i32, _>("version") as u32,
        algorithm: parse_algorithm(row.get("algorithm")),
        purpose: parse_purpose(row.get("purpose")),
        state: parse_state(row.get("state")),
        tenant_id: row.get::<Option<Uuid>, _>("tenant_id").map(|u| u.to_string()),
        created_at: row.get("created_at"),
        rotated_at: row.get("rotated_at"),
        expires_at: row.get("expires_at"),
    })
}

/// Get the active key for a given tenant and purpose.
pub async fn get_active_key(
    pool: &DbPool,
    tenant_id: &Uuid,
    purpose: &KeyPurpose,
) -> Result<KeyDescriptor, VaultError> {
    let row = sqlx::query(
        "SELECT id, version, algorithm, purpose, state, tenant_id, created_at, rotated_at, expires_at
         FROM system.key_descriptors
         WHERE tenant_id = $1 AND purpose = $2 AND state = 'active'
         ORDER BY version DESC LIMIT 1",
    )
    .bind(tenant_id)
    .bind(purpose_str(purpose))
    .fetch_optional(pool.inner())
    .await
    .map_err(|e| VaultError::Database {
        reason: e.to_string(),
    })?
    .ok_or_else(|| VaultError::KeyNotFound {
        key_id: format!("{}:{:?}", tenant_id, purpose),
    })?;

    Ok(KeyDescriptor {
        id: KeyId(row.get::<Uuid, _>("id")),
        version: row.get::<i32, _>("version") as u32,
        algorithm: parse_algorithm(row.get("algorithm")),
        purpose: parse_purpose(row.get("purpose")),
        state: parse_state(row.get("state")),
        tenant_id: row.get::<Option<Uuid>, _>("tenant_id").map(|u| u.to_string()),
        created_at: row.get("created_at"),
        rotated_at: row.get("rotated_at"),
        expires_at: row.get("expires_at"),
    })
}

/// Insert a new key descriptor.
pub async fn insert_key_descriptor(
    pool: &DbPool,
    desc: &KeyDescriptor,
    wrapped_key: &str,
    parent_key_id: Option<&Uuid>,
) -> Result<(), VaultError> {
    sqlx::query(
        "INSERT INTO system.key_descriptors
         (id, version, algorithm, purpose, state, tenant_id, wrapped_key, parent_key_id, expires_at)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)",
    )
    .bind(desc.id.0)
    .bind(desc.version as i32)
    .bind(algorithm_str(&desc.algorithm))
    .bind(purpose_str(&desc.purpose))
    .bind(state_str(&desc.state))
    .bind(desc.tenant_id.as_ref().and_then(|s| Uuid::parse_str(s).ok()))
    .bind(wrapped_key)
    .bind(parent_key_id)
    .bind(desc.expires_at)
    .execute(pool.inner())
    .await
    .map_err(|e| VaultError::Database {
        reason: e.to_string(),
    })?;

    Ok(())
}

/// Transition a key to a new state (e.g. active -> rotating_out -> retired -> destroyed).
pub async fn update_key_state(
    pool: &DbPool,
    key_id: &KeyId,
    new_state: &KeyState,
) -> Result<(), VaultError> {
    sqlx::query(
        "UPDATE system.key_descriptors SET state = $2, rotated_at = now() WHERE id = $1",
    )
    .bind(key_id.0)
    .bind(state_str(new_state))
    .execute(pool.inner())
    .await
    .map_err(|e| VaultError::Database {
        reason: e.to_string(),
    })?;

    Ok(())
}
