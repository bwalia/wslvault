//! Secret and secret version CRUD operations.

use std::collections::HashMap;

use sqlx::Row;
use uuid::Uuid;

use crate::pool::DbPool;
use wslvault_core::types::secret::{SecretEngine, SecretMetadata, SecretVersion};
use wslvault_core::types::tenant::TenantId;
use wslvault_core::VaultError;

fn parse_engine(s: &str) -> SecretEngine {
    match s {
        "transit" => SecretEngine::Transit,
        "dynamic_database" => SecretEngine::DynamicDatabase,
        "ssh" => SecretEngine::Ssh,
        "pki" => SecretEngine::Pki,
        "cloud_aws" => SecretEngine::CloudAws,
        "cloud_gcp" => SecretEngine::CloudGcp,
        "cloud_azure" => SecretEngine::CloudAzure,
        _ => SecretEngine::KvV2,
    }
}

fn engine_str(e: &SecretEngine) -> &'static str {
    match e {
        SecretEngine::KvV2 => "kv_v2",
        SecretEngine::Transit => "transit",
        SecretEngine::DynamicDatabase => "dynamic_database",
        SecretEngine::Ssh => "ssh",
        SecretEngine::Pki => "pki",
        SecretEngine::CloudAws => "cloud_aws",
        SecretEngine::CloudGcp => "cloud_gcp",
        SecretEngine::CloudAzure => "cloud_azure",
    }
}

/// Retrieve secret metadata by tenant + path.
pub async fn get_secret_metadata(
    pool: &DbPool,
    tenant_id: &TenantId,
    path: &str,
) -> Result<SecretMetadata, VaultError> {
    let row = sqlx::query(
        "SELECT id, tenant_id, path, engine, current_version, max_versions, cas_required,
                custom_metadata, created_at, updated_at
         FROM shared.secrets
         WHERE tenant_id = $1 AND path = $2",
    )
    .bind(tenant_id.as_uuid())
    .bind(path)
    .fetch_optional(pool.inner())
    .await
    .map_err(|e| VaultError::Database {
        reason: e.to_string(),
    })?
    .ok_or_else(|| VaultError::SecretNotFound {
        path: path.to_string(),
        version: None,
    })?;

    let custom_metadata: serde_json::Value = row.get("custom_metadata");
    let custom_map: HashMap<String, String> =
        serde_json::from_value(custom_metadata).unwrap_or_default();

    Ok(SecretMetadata {
        id: wslvault_core::SecretId(row.get::<Uuid, _>("id")),
        tenant_id: TenantId(row.get::<Uuid, _>("tenant_id")),
        path: row.get("path"),
        engine: parse_engine(row.get("engine")),
        current_version: row.get::<i32, _>("current_version") as u32,
        max_versions: row.get::<i32, _>("max_versions") as u32,
        cas_required: row.get("cas_required"),
        created_at: row.get("created_at"),
        updated_at: row.get("updated_at"),
        custom_metadata: custom_map,
    })
}

/// Retrieve a specific version of a secret.
pub async fn get_secret_version(
    pool: &DbPool,
    secret_id: &wslvault_core::SecretId,
    version: u32,
) -> Result<SecretVersion, VaultError> {
    let row = sqlx::query(
        "SELECT version, ciphertext, dek_id, custom_metadata, created_at, deleted_at, destroyed
         FROM shared.secret_versions
         WHERE secret_id = $1 AND version = $2",
    )
    .bind(secret_id.0)
    .bind(version as i32)
    .fetch_optional(pool.inner())
    .await
    .map_err(|e| VaultError::Database {
        reason: e.to_string(),
    })?
    .ok_or_else(|| VaultError::SecretNotFound {
        path: String::new(),
        version: Some(version),
    })?;

    let destroyed: bool = row.get("destroyed");
    if destroyed {
        return Err(VaultError::VersionDestroyed { version });
    }

    let custom_metadata: serde_json::Value = row.get("custom_metadata");
    let custom_map: HashMap<String, String> =
        serde_json::from_value(custom_metadata).unwrap_or_default();

    Ok(SecretVersion {
        version: row.get::<i32, _>("version") as u32,
        ciphertext: row.get("ciphertext"),
        dek_id: row.get("dek_id"),
        custom_metadata: custom_map,
        created_at: row.get("created_at"),
        deleted_at: row.get("deleted_at"),
        destroyed,
    })
}

/// List secret paths under a prefix for a given tenant.
pub async fn list_secret_paths(
    pool: &DbPool,
    tenant_id: &TenantId,
    prefix: &str,
) -> Result<Vec<String>, VaultError> {
    let pattern = format!("{}%", prefix);
    let rows = sqlx::query(
        "SELECT path FROM shared.secrets
         WHERE tenant_id = $1 AND path LIKE $2
         ORDER BY path",
    )
    .bind(tenant_id.as_uuid())
    .bind(&pattern)
    .fetch_all(pool.inner())
    .await
    .map_err(|e| VaultError::Database {
        reason: e.to_string(),
    })?;

    Ok(rows.into_iter().map(|r| r.get("path")).collect())
}

/// Write a new secret version using the atomic upsert function.
pub async fn upsert_secret_version(
    pool: &DbPool,
    tenant_id: &TenantId,
    path: &str,
    engine: &SecretEngine,
    ciphertext: &str,
    dek_id: &str,
    cas_version: Option<u32>,
    max_versions: u32,
    cas_required: bool,
) -> Result<(wslvault_core::SecretId, u32), VaultError> {
    let row = sqlx::query(
        "SELECT * FROM shared.vault_upsert_secret($1, $2, $3, $4, $5, $6, $7, $8)",
    )
    .bind(tenant_id.as_uuid())
    .bind(path)
    .bind(engine_str(engine))
    .bind(ciphertext)
    .bind(dek_id)
    .bind(cas_version.map(|v| v as i32))
    .bind(max_versions as i32)
    .bind(cas_required)
    .fetch_one(pool.inner())
    .await
    .map_err(|e| {
        let msg = e.to_string();
        if msg.contains("CAS conflict") {
            VaultError::CasConflict {
                expected: cas_version.unwrap_or(0),
                actual: 0,
            }
        } else {
            VaultError::Database { reason: msg }
        }
    })?;

    let secret_id = wslvault_core::SecretId(row.get::<Uuid, _>("secret_id"));
    let new_version = row.get::<i32, _>("new_version") as u32;

    Ok((secret_id, new_version))
}

/// Soft-delete secret versions.
pub async fn soft_delete_versions(
    pool: &DbPool,
    secret_id: &wslvault_core::SecretId,
    versions: &[u32],
) -> Result<u32, VaultError> {
    let versions_i32: Vec<i32> = versions.iter().map(|v| *v as i32).collect();
    let row = sqlx::query("SELECT shared.vault_soft_delete_versions($1, $2) AS count")
        .bind(secret_id.0)
        .bind(&versions_i32)
        .fetch_one(pool.inner())
        .await
        .map_err(|e| VaultError::Database {
            reason: e.to_string(),
        })?;

    Ok(row.get::<i32, _>("count") as u32)
}

/// Permanently destroy secret versions (irreversible).
pub async fn destroy_versions(
    pool: &DbPool,
    secret_id: &wslvault_core::SecretId,
    versions: &[u32],
) -> Result<u32, VaultError> {
    let versions_i32: Vec<i32> = versions.iter().map(|v| *v as i32).collect();
    let row = sqlx::query("SELECT shared.vault_destroy_versions($1, $2) AS count")
        .bind(secret_id.0)
        .bind(&versions_i32)
        .fetch_one(pool.inner())
        .await
        .map_err(|e| VaultError::Database {
            reason: e.to_string(),
        })?;

    Ok(row.get::<i32, _>("count") as u32)
}
