//! Secret and secret version CRUD operations.

use std::collections::HashMap;

use sqlx::Row;
use uuid::Uuid;

use crate::pool::DbPool;
use wslvault_core::types::secret::{
    RotationPolicy, RotationRecord, SecretEngine, SecretMetadata, SecretType, SecretVersion,
    VersionStatus,
};
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
                custom_metadata, created_at, updated_at,
                COALESCE(secret_type, 'STALE_TTL') AS secret_type,
                ttl_seconds, soft_warn_seconds, rotation_interval_seconds,
                grace_period_seconds, webhook_url,
                expires_at, last_rotated_at, next_rotation_at,
                COALESCE(rotation_status, 'none') AS rotation_status
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

    let secret_type: SecretType = row
        .get::<Option<&str>, _>("secret_type")
        .and_then(|s| s.parse().ok())
        .unwrap_or_default();

    let rotation_policy = RotationPolicy {
        ttl_seconds: row.get::<Option<i32>, _>("ttl_seconds").map(|v| v as i64),
        soft_warn_seconds: row
            .get::<Option<i32>, _>("soft_warn_seconds")
            .map(|v| v as i64),
        rotation_interval_seconds: row
            .get::<Option<i32>, _>("rotation_interval_seconds")
            .map(|v| v as i64),
        grace_period_seconds: row
            .get::<Option<i32>, _>("grace_period_seconds")
            .map(|v| v as i64),
        webhook_url: row.get("webhook_url"),
    };

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
        secret_type,
        rotation_policy,
        expires_at: row.get("expires_at"),
        last_rotated_at: row.get("last_rotated_at"),
        next_rotation_at: row.get("next_rotation_at"),
        rotation_status: row
            .get::<Option<&str>, _>("rotation_status")
            .unwrap_or("none")
            .to_string(),
    })
}

/// Retrieve a specific version of a secret.
pub async fn get_secret_version(
    pool: &DbPool,
    secret_id: &wslvault_core::SecretId,
    version: u32,
) -> Result<SecretVersion, VaultError> {
    let row = sqlx::query(
        "SELECT version, ciphertext, dek_id, custom_metadata, created_at, deleted_at, destroyed,
                COALESCE(status, 'active') AS status,
                created_by, deprecated_at, revoked_at
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

    let status: VersionStatus = row
        .get::<Option<&str>, _>("status")
        .and_then(|s| s.parse().ok())
        .unwrap_or_default();

    Ok(SecretVersion {
        version: row.get::<i32, _>("version") as u32,
        ciphertext: row.get("ciphertext"),
        dek_id: row.get("dek_id"),
        custom_metadata: custom_map,
        created_at: row.get("created_at"),
        deleted_at: row.get("deleted_at"),
        destroyed,
        status,
        created_by: row.get("created_by"),
        deprecated_at: row.get("deprecated_at"),
        revoked_at: row.get("revoked_at"),
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
#[allow(clippy::too_many_arguments)]
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
    let row =
        sqlx::query("SELECT * FROM shared.vault_upsert_secret($1, $2, $3, $4, $5, $6, $7, $8)")
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

/// Initiate a two-phase rotation for a secret. Returns (rotation_id, new_version).
pub async fn initiate_rotation(
    pool: &DbPool,
    tenant_id: &TenantId,
    path: &str,
    ciphertext: &str,
    dek_id: &str,
    initiated_by: &str,
    webhook_url: Option<&str>,
    timeout_secs: Option<i32>,
) -> Result<(String, u32), VaultError> {
    let row = sqlx::query(
        "SELECT rotation_id, new_version
         FROM shared.vault_initiate_rotation($1, $2, $3, $4, $5, $6, $7)",
    )
    .bind(tenant_id.as_uuid())
    .bind(path)
    .bind(ciphertext)
    .bind(dek_id)
    .bind(initiated_by)
    .bind(webhook_url)
    .bind(timeout_secs)
    .fetch_one(pool.inner())
    .await
    .map_err(|e| {
        let msg = e.to_string();
        if msg.contains("rotation already pending") {
            VaultError::InvalidOperation {
                reason: format!("rotation already pending for secret: {path}"),
            }
        } else if msg.contains("secret not found") {
            VaultError::SecretNotFound {
                path: path.to_string(),
                version: None,
            }
        } else {
            VaultError::Database { reason: msg }
        }
    })?;

    let rotation_id: uuid::Uuid = row.get("rotation_id");
    let new_version = row.get::<i32, _>("new_version") as u32;
    Ok((rotation_id.to_string(), new_version))
}

/// Confirm a pending rotation — activates the new version and deprecates the old.
/// Returns (old_version, new_version, grace_ends_at).
pub async fn confirm_rotation(
    pool: &DbPool,
    rotation_id: &str,
    confirmed_by: &str,
) -> Result<(u32, u32, chrono::DateTime<chrono::Utc>), VaultError> {
    let rid: uuid::Uuid = rotation_id
        .parse()
        .map_err(|_| VaultError::InvalidOperation {
            reason: format!("invalid rotation_id: {rotation_id}"),
        })?;

    let row = sqlx::query(
        "SELECT old_version, new_version, grace_ends_at
         FROM shared.vault_confirm_rotation($1, $2)",
    )
    .bind(rid)
    .bind(confirmed_by)
    .fetch_one(pool.inner())
    .await
    .map_err(|e| {
        let msg = e.to_string();
        if msg.contains("not found or expired") {
            VaultError::InvalidOperation {
                reason: format!("rotation {rotation_id} not found or expired"),
            }
        } else {
            VaultError::Database { reason: msg }
        }
    })?;

    let old_version = row.get::<i32, _>("old_version") as u32;
    let new_version = row.get::<i32, _>("new_version") as u32;
    let grace_ends_at: chrono::DateTime<chrono::Utc> = row.get("grace_ends_at");
    Ok((old_version, new_version, grace_ends_at))
}

/// Rollback to a previous version (creates a new version row with the same ciphertext).
pub async fn rollback_secret(
    pool: &DbPool,
    tenant_id: &TenantId,
    path: &str,
    target_version: u32,
    rolled_back_by: &str,
) -> Result<u32, VaultError> {
    let row = sqlx::query(
        "SELECT new_version FROM shared.vault_rollback_secret($1, $2, $3, $4)",
    )
    .bind(tenant_id.as_uuid())
    .bind(path)
    .bind(target_version as i32)
    .bind(rolled_back_by)
    .fetch_one(pool.inner())
    .await
    .map_err(|e| {
        let msg = e.to_string();
        if msg.contains("secret not found") {
            VaultError::SecretNotFound {
                path: path.to_string(),
                version: None,
            }
        } else if msg.contains("not found or destroyed") {
            VaultError::SecretNotFound {
                path: path.to_string(),
                version: Some(target_version),
            }
        } else {
            VaultError::Database { reason: msg }
        }
    })?;

    Ok(row.get::<i32, _>("new_version") as u32)
}

/// List all versions with lifecycle metadata for a secret (no ciphertext).
pub async fn list_version_history(
    pool: &DbPool,
    tenant_id: &TenantId,
    path: &str,
) -> Result<Vec<wslvault_core::types::secret::VersionMeta>, VaultError> {
    let rows = sqlx::query(
        "SELECT version, status, created_by, created_at,
                deleted_at, deprecated_at, revoked_at, destroyed
         FROM shared.vault_list_version_history($1, $2)",
    )
    .bind(tenant_id.as_uuid())
    .bind(path)
    .fetch_all(pool.inner())
    .await
    .map_err(|e| VaultError::Database {
        reason: e.to_string(),
    })?;

    let versions = rows
        .into_iter()
        .map(|r| {
            let status: VersionStatus = r
                .get::<Option<&str>, _>("status")
                .and_then(|s| s.parse().ok())
                .unwrap_or_default();
            wslvault_core::types::secret::VersionMeta {
                version: r.get::<i32, _>("version") as u32,
                status,
                created_by: r.get("created_by"),
                created_at: r.get("created_at"),
                deleted_at: r.get("deleted_at"),
                deprecated_at: r.get("deprecated_at"),
                revoked_at: r.get("revoked_at"),
                destroyed: r.get("destroyed"),
            }
        })
        .collect();

    Ok(versions)
}

/// Retrieve the active (pending_activation) rotation record for a secret path.
pub async fn get_active_rotation(
    pool: &DbPool,
    tenant_id: &TenantId,
    path: &str,
) -> Result<Option<RotationRecord>, VaultError> {
    let row = sqlx::query(
        "SELECT r.id, r.secret_id, r.path, r.old_version, r.new_version,
                r.status, r.initiated_by, r.confirmed_by,
                r.created_at, r.confirmed_at, r.grace_ends_at, r.expires_at
         FROM shared.secret_rotations r
         JOIN shared.secrets s ON s.id = r.secret_id
         WHERE s.tenant_id = $1 AND s.path = $2
           AND r.status = 'pending_activation'
         ORDER BY r.created_at DESC
         LIMIT 1",
    )
    .bind(tenant_id.as_uuid())
    .bind(path)
    .fetch_optional(pool.inner())
    .await
    .map_err(|e| VaultError::Database {
        reason: e.to_string(),
    })?;

    Ok(row.map(|r| RotationRecord {
        rotation_id: r.get::<uuid::Uuid, _>("id").to_string(),
        secret_id: r.get::<uuid::Uuid, _>("secret_id").to_string(),
        path: r.get("path"),
        old_version: r.get::<i32, _>("old_version") as u32,
        new_version: r.get::<i32, _>("new_version") as u32,
        status: r.get::<&str, _>("status").to_string(),
        initiated_by: r.get::<&str, _>("initiated_by").to_string(),
        confirmed_by: r.get("confirmed_by"),
        created_at: r.get("created_at"),
        confirmed_at: r.get("confirmed_at"),
        grace_ends_at: r.get("grace_ends_at"),
        expires_at: r.get("expires_at"),
    }))
}
