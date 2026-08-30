//! PostgreSQL-backed PKI store.
//!
//! Persists CA records, roles, and issued certificate metadata to the three
//! tables created by `014_pki.sql`:
//!
//! - `pki.pki_ca`    — one row per tenant (CA cert PEM + encrypted key)
//! - `pki.pki_roles` — role definitions (domain policy, TTL, key type, …)
//! - `pki.pki_certs` — issued certificate metadata (serial, not_after, revoked_at)
//!
//! All queries are tenant-scoped via a `tenant_id` `UUID` column.  The
//! `tenant_id_to_uuid` helper from the transit-engine's pg_store is replicated
//! here so that non-UUID tenant strings (e.g. in tests or legacy callers) are
//! deterministically mapped to a UUID without enabling extra crate features.
//!
//! # No compile-time query checking
//!
//! The regular `sqlx::query` API (not the `query!` macro) is used here because
//! the PKI schema is not available at compile time on developer machines.  This
//! trades compile-time column-type checking for build portability.  Integration
//! tests that target a real database should enable `SQLX_OFFLINE=false`.

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use sqlx::Row;
use uuid::Uuid;

use wslvault_storage::pool::DbPool;

use crate::error::PkiError;
use crate::store::PkiStore;
use crate::types::{IssuedCert, KeyType, KeyUsage, PkiRole, TenantCa};

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Convert a `tenant_id` string to a `Uuid`, deriving one deterministically
/// (SHA-256 → first 16 bytes, variant/version bits set) when the string is
/// not already a valid UUID.
fn tenant_id_to_uuid(tenant_id: &str) -> Uuid {
    Uuid::parse_str(tenant_id).unwrap_or_else(|_| {
        use ring::digest;
        let digest = digest::digest(&digest::SHA256, tenant_id.as_bytes());
        let bytes = digest.as_ref();
        let mut buf = [0u8; 16];
        buf.copy_from_slice(&bytes[..16]);
        // Set version 4 bits.
        buf[6] = (buf[6] & 0x0f) | 0x40;
        // Set variant bits.
        buf[8] = (buf[8] & 0x3f) | 0x80;
        Uuid::from_bytes(buf)
    })
}

fn db_err(e: sqlx::Error) -> PkiError {
    PkiError::Vault(wslvault_core::VaultError::Database {
        reason: e.to_string(),
    })
}

// ---------------------------------------------------------------------------
// PgPkiStore
// ---------------------------------------------------------------------------

/// PostgreSQL-backed implementation of `PkiStore`.
pub struct PgPkiStore {
    pool: DbPool,
}

impl PgPkiStore {
    /// Wrap an existing `DbPool`.
    pub fn new(pool: DbPool) -> Self {
        Self { pool }
    }

    fn pool(&self) -> &sqlx::PgPool {
        self.pool.inner()
    }
}

#[async_trait]
impl PkiStore for PgPkiStore {
    // ---- CA ------------------------------------------------------------------

    async fn create_ca(&self, ca: TenantCa) -> Result<(), PkiError> {
        let tenant_uuid = tenant_id_to_uuid(&ca.tenant_id);
        let result = sqlx::query(
            r#"
            INSERT INTO pki.pki_ca (tenant_id, cert_pem, encrypted_key_b64, key_version, created_at)
            VALUES ($1, $2, $3, $4, $5)
            "#,
        )
        .bind(tenant_uuid)
        .bind(&ca.cert_pem)
        .bind(&ca.encrypted_key_b64)
        .bind(ca.key_version)
        .bind(ca.created_at)
        .execute(self.pool())
        .await;

        match result {
            Ok(_) => Ok(()),
            Err(sqlx::Error::Database(db_e)) if db_e.code().as_deref() == Some("23505") => {
                Err(PkiError::CaAlreadyExists {
                    tenant_id: ca.tenant_id,
                })
            }
            Err(e) => Err(db_err(e)),
        }
    }

    async fn get_ca(&self, tenant_id: &str) -> Result<TenantCa, PkiError> {
        let tenant_uuid = tenant_id_to_uuid(tenant_id);
        let row = sqlx::query(
            r#"
            SELECT cert_pem, encrypted_key_b64, key_version, created_at
            FROM pki.pki_ca
            WHERE tenant_id = $1
            "#,
        )
        .bind(tenant_uuid)
        .fetch_optional(self.pool())
        .await
        .map_err(db_err)?;

        match row {
            Some(r) => Ok(TenantCa {
                tenant_id: tenant_id.to_string(),
                cert_pem: r.get("cert_pem"),
                encrypted_key_b64: r.get("encrypted_key_b64"),
                key_version: r.get("key_version"),
                created_at: r.get("created_at"),
            }),
            None => Err(PkiError::CaNotFound {
                tenant_id: tenant_id.to_string(),
            }),
        }
    }

    async fn upsert_ca(&self, ca: TenantCa) -> Result<(), PkiError> {
        let tenant_uuid = tenant_id_to_uuid(&ca.tenant_id);
        sqlx::query(
            r#"
            INSERT INTO pki.pki_ca (tenant_id, cert_pem, encrypted_key_b64, key_version, created_at)
            VALUES ($1, $2, $3, $4, $5)
            ON CONFLICT (tenant_id) DO UPDATE
                SET cert_pem          = EXCLUDED.cert_pem,
                    encrypted_key_b64 = EXCLUDED.encrypted_key_b64,
                    key_version       = EXCLUDED.key_version,
                    created_at        = EXCLUDED.created_at
            "#,
        )
        .bind(tenant_uuid)
        .bind(&ca.cert_pem)
        .bind(&ca.encrypted_key_b64)
        .bind(ca.key_version)
        .bind(ca.created_at)
        .execute(self.pool())
        .await
        .map_err(db_err)?;
        Ok(())
    }

    // ---- Roles ---------------------------------------------------------------

    async fn upsert_role(&self, role: PkiRole) -> Result<(), PkiError> {
        let tenant_uuid = tenant_id_to_uuid(&role.tenant_id);
        let key_usages_json = serde_json::to_value(&role.key_usages).map_err(|e| {
            PkiError::Vault(wslvault_core::VaultError::Internal {
                reason: format!("failed to serialize key_usages: {e}"),
            })
        })?;

        sqlx::query(
            r#"
            INSERT INTO pki.pki_roles (
                tenant_id, name, allowed_domains, allow_subdomains, allow_bare_domains,
                max_ttl_seconds, key_type, key_usages, allow_ip_sans, created_at, updated_at
            ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
            ON CONFLICT (tenant_id, name) DO UPDATE
                SET allowed_domains    = EXCLUDED.allowed_domains,
                    allow_subdomains   = EXCLUDED.allow_subdomains,
                    allow_bare_domains = EXCLUDED.allow_bare_domains,
                    max_ttl_seconds    = EXCLUDED.max_ttl_seconds,
                    key_type           = EXCLUDED.key_type,
                    key_usages         = EXCLUDED.key_usages,
                    allow_ip_sans      = EXCLUDED.allow_ip_sans,
                    updated_at         = EXCLUDED.updated_at
            "#,
        )
        .bind(tenant_uuid)
        .bind(&role.name)
        .bind(&role.allowed_domains)
        .bind(role.allow_subdomains)
        .bind(role.allow_bare_domains)
        .bind(role.max_ttl_seconds)
        .bind(role.key_type.to_string())
        .bind(key_usages_json)
        .bind(role.allow_ip_sans)
        .bind(role.created_at)
        .bind(role.updated_at)
        .execute(self.pool())
        .await
        .map_err(db_err)?;
        Ok(())
    }

    async fn get_role(&self, tenant_id: &str, name: &str) -> Result<PkiRole, PkiError> {
        let tenant_uuid = tenant_id_to_uuid(tenant_id);
        let row = sqlx::query(
            r#"
            SELECT name, allowed_domains, allow_subdomains, allow_bare_domains,
                   max_ttl_seconds, key_type, key_usages, allow_ip_sans, created_at, updated_at
            FROM pki.pki_roles
            WHERE tenant_id = $1 AND name = $2
            "#,
        )
        .bind(tenant_uuid)
        .bind(name)
        .fetch_optional(self.pool())
        .await
        .map_err(db_err)?;

        match row {
            Some(r) => {
                let key_type_str: String = r.get("key_type");
                let key_type: KeyType = key_type_str.parse().unwrap_or_default();
                let key_usages_json: serde_json::Value = r.get("key_usages");
                let key_usages: Vec<KeyUsage> =
                    serde_json::from_value(key_usages_json).unwrap_or_default();
                let created_at: DateTime<Utc> = r.get("created_at");
                let updated_at: DateTime<Utc> = r.get("updated_at");

                Ok(PkiRole {
                    tenant_id: tenant_id.to_string(),
                    name: r.get("name"),
                    allowed_domains: r.get("allowed_domains"),
                    allow_subdomains: r.get("allow_subdomains"),
                    allow_bare_domains: r.get("allow_bare_domains"),
                    max_ttl_seconds: r.get("max_ttl_seconds"),
                    key_type,
                    key_usages,
                    allow_ip_sans: r.get("allow_ip_sans"),
                    created_at,
                    updated_at,
                })
            }
            None => Err(PkiError::RoleNotFound {
                name: name.to_string(),
                tenant_id: tenant_id.to_string(),
            }),
        }
    }

    async fn delete_role(&self, tenant_id: &str, name: &str) -> Result<(), PkiError> {
        let tenant_uuid = tenant_id_to_uuid(tenant_id);
        let result = sqlx::query("DELETE FROM pki.pki_roles WHERE tenant_id = $1 AND name = $2")
            .bind(tenant_uuid)
            .bind(name)
            .execute(self.pool())
            .await
            .map_err(db_err)?;

        if result.rows_affected() == 0 {
            return Err(PkiError::RoleNotFound {
                name: name.to_string(),
                tenant_id: tenant_id.to_string(),
            });
        }
        Ok(())
    }

    // ---- Certificates --------------------------------------------------------

    async fn record_cert(&self, cert: IssuedCert) -> Result<(), PkiError> {
        let tenant_uuid = tenant_id_to_uuid(&cert.tenant_id);
        let cert_id = Uuid::parse_str(&cert.id).unwrap_or_else(|_| Uuid::now_v7());
        sqlx::query(
            r#"
            INSERT INTO pki.pki_certs (
                id, tenant_id, role_name, serial, common_name, not_after, revoked_at, created_at
            ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
            ON CONFLICT (tenant_id, serial) DO NOTHING
            "#,
        )
        .bind(cert_id)
        .bind(tenant_uuid)
        .bind(&cert.role_name)
        .bind(&cert.serial)
        .bind(&cert.common_name)
        .bind(cert.not_after)
        .bind(cert.revoked_at)
        .bind(cert.created_at)
        .execute(self.pool())
        .await
        .map_err(db_err)?;
        Ok(())
    }

    async fn revoke_cert(&self, tenant_id: &str, serial: &str) -> Result<(), PkiError> {
        let tenant_uuid = tenant_id_to_uuid(tenant_id);

        // First check existence and current revocation state.
        let existing = sqlx::query(
            "SELECT revoked_at FROM pki.pki_certs WHERE tenant_id = $1 AND serial = $2",
        )
        .bind(tenant_uuid)
        .bind(serial)
        .fetch_optional(self.pool())
        .await
        .map_err(db_err)?;

        match existing {
            None => Err(PkiError::CertNotFound {
                serial: serial.to_string(),
                tenant_id: tenant_id.to_string(),
            }),
            Some(r) => {
                let revoked_at: Option<DateTime<Utc>> = r.get("revoked_at");
                if revoked_at.is_some() {
                    return Err(PkiError::AlreadyRevoked {
                        serial: serial.to_string(),
                    });
                }
                sqlx::query(
                    "UPDATE pki.pki_certs SET revoked_at = $1 WHERE tenant_id = $2 AND serial = $3",
                )
                .bind(Utc::now())
                .bind(tenant_uuid)
                .bind(serial)
                .execute(self.pool())
                .await
                .map_err(db_err)?;
                Ok(())
            }
        }
    }

    async fn list_active_certs(&self, tenant_id: &str) -> Result<Vec<IssuedCert>, PkiError> {
        let tenant_uuid = tenant_id_to_uuid(tenant_id);
        let rows = sqlx::query(
            r#"
            SELECT id, role_name, serial, common_name, not_after, revoked_at, created_at
            FROM pki.pki_certs
            WHERE tenant_id = $1 AND revoked_at IS NULL
            ORDER BY created_at DESC
            "#,
        )
        .bind(tenant_uuid)
        .fetch_all(self.pool())
        .await
        .map_err(db_err)?;

        Ok(rows
            .into_iter()
            .map(|r| IssuedCert {
                id: r.get::<Uuid, _>("id").to_string(),
                tenant_id: tenant_id.to_string(),
                role_name: r.get("role_name"),
                serial: r.get("serial"),
                common_name: r.get("common_name"),
                not_after: r.get("not_after"),
                revoked_at: r.get("revoked_at"),
                created_at: r.get("created_at"),
            })
            .collect())
    }

    async fn list_revoked_certs(&self, tenant_id: &str) -> Result<Vec<IssuedCert>, PkiError> {
        let tenant_uuid = tenant_id_to_uuid(tenant_id);
        let rows = sqlx::query(
            r#"
            SELECT id, role_name, serial, common_name, not_after, revoked_at, created_at
            FROM pki.pki_certs
            WHERE tenant_id = $1 AND revoked_at IS NOT NULL
            ORDER BY revoked_at DESC
            "#,
        )
        .bind(tenant_uuid)
        .fetch_all(self.pool())
        .await
        .map_err(db_err)?;

        Ok(rows
            .into_iter()
            .map(|r| IssuedCert {
                id: r.get::<Uuid, _>("id").to_string(),
                tenant_id: tenant_id.to_string(),
                role_name: r.get("role_name"),
                serial: r.get("serial"),
                common_name: r.get("common_name"),
                not_after: r.get("not_after"),
                revoked_at: r.get("revoked_at"),
                created_at: r.get("created_at"),
            })
            .collect())
    }
}
