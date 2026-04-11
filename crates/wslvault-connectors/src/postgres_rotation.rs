//! PostgreSQL dynamic credential rotation.
//!
//! Enabled by the `postgres-rotation` Cargo feature.
//!
//! This module provides utilities for managing short-lived PostgreSQL
//! credentials — creating roles, rotating passwords, and revoking access.
//! It is intended to be used in combination with the WSLVault lease engine:
//! when a lease expires the caller invokes [`PostgresCredentialRotator::revoke_user`]
//! to drop the ephemeral role.
//!
//! # Security considerations
//!
//! - The admin pool user must hold `CREATEROLE` and the ability to GRANT the
//!   requested privileges. It MUST NOT be a superuser.
//! - Generated passwords are 32 bytes of CSPRNG output, base64-encoded, giving
//!   ~43 characters of high entropy.
//! - Passwords are returned in a [`NewCredentials`] struct that implements
//!   `ZeroizeOnDrop`; callers MUST store the value in WSLVault's encrypted KV
//!   store and discard this struct as soon as possible.
//!
//! # Example
//!
//! ```rust,no_run
//! # #[cfg(feature = "postgres-rotation")]
//! # async fn example() -> Result<(), Box<dyn std::error::Error>> {
//! use wslvault_connectors::postgres_rotation::{PostgresCredentialRotator, DatabasePermission};
//!
//! let rotator = PostgresCredentialRotator::connect(
//!     "postgres://vault_admin:adminpass@localhost:5432/mydb",
//! ).await?;
//!
//! let creds = rotator.rotate_credentials("app_user").await?;
//! println!("new password stored; version {}", creds.version);
//!
//! rotator.revoke_user("app_user").await?;
//! # Ok(())
//! # }
//! ```

#[cfg(feature = "postgres-rotation")]
mod inner {
    use std::fmt;

    use base64::Engine;
    use sqlx::PgPool;
    use tracing::{debug, info, instrument, warn};
    use zeroize::{Zeroize, ZeroizeOnDrop};

    use crate::error::ConnectorError;

    // -------------------------------------------------------------------------
    // Public types
    // -------------------------------------------------------------------------

    /// A set of newly-generated credentials for a PostgreSQL role.
    ///
    /// SECURITY: implement `ZeroizeOnDrop` so the password bytes are wiped from
    /// memory as soon as this struct is dropped.
    #[derive(Zeroize, ZeroizeOnDrop)]
    pub struct NewCredentials {
        /// The PostgreSQL role / username.
        #[zeroize(skip)]
        pub username: String,
        /// The new plaintext password (high-entropy, randomly generated).
        /// Store this in WSLVault's KV store and discard the struct immediately.
        pub password: String,
        /// Monotonically increasing counter incremented on every rotation.
        #[zeroize(skip)]
        pub version: u32,
    }

    // Redact password from debug output to prevent accidental log exposure.
    impl fmt::Debug for NewCredentials {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            f.debug_struct("NewCredentials")
                .field("username", &self.username)
                .field("password", &"[REDACTED]")
                .field("version", &self.version)
                .finish()
        }
    }

    /// Privilege set to grant to a dynamically-created PostgreSQL role.
    #[derive(Debug, Clone)]
    pub enum DatabasePermission {
        /// `SELECT` on all tables in the schema.
        ReadOnly { schema: String },
        /// `SELECT, INSERT, UPDATE, DELETE` on all tables in the schema.
        ReadWrite { schema: String },
        /// Full DDL access (`ALL PRIVILEGES`) on the database.
        Admin,
        /// Raw SQL fragment appended to the `GRANT` statement (escape carefully!).
        Custom(String),
    }

    // -------------------------------------------------------------------------
    // Rotator struct
    // -------------------------------------------------------------------------

    /// Manages dynamic PostgreSQL credential lifecycle.
    ///
    /// Requires an admin connection pool whose credentials have `CREATEROLE`
    /// and the ability to grant the permissions requested via
    /// [`PostgresCredentialRotator::create_user`].
    pub struct PostgresCredentialRotator {
        admin_pool: PgPool,
    }

    impl PostgresCredentialRotator {
        /// Connect to PostgreSQL using `database_url` and create an admin pool.
        pub async fn connect(database_url: &str) -> Result<Self, ConnectorError> {
            let pool = PgPool::connect(database_url)
                .await
                .map_err(|e| ConnectorError::Configuration {
                    reason: format!("failed to connect to PostgreSQL admin pool: {e}"),
                })?;

            Ok(Self { admin_pool: pool })
        }

        /// Construct from a pre-existing pool (useful for testing).
        pub fn from_pool(admin_pool: PgPool) -> Self {
            Self { admin_pool }
        }

        // ---------------------------------------------------------------------
        // Core operations
        // ---------------------------------------------------------------------

        /// Rotate the password for an existing PostgreSQL role.
        ///
        /// Generates a new 32-byte random password and issues `ALTER ROLE …
        /// PASSWORD '…'`.  The previous password is immediately invalidated by
        /// PostgreSQL once this command succeeds.
        ///
        /// Returns the new credentials which the caller MUST store in WSLVault.
        #[instrument(skip(self), fields(username = username))]
        pub async fn rotate_credentials(
            &self,
            username: &str,
        ) -> Result<NewCredentials, ConnectorError> {
            debug!("rotating credentials");

            validate_identifier(username)?;

            let new_password = generate_password();

            // ALTER ROLE uses an identifier (cannot parameterise it) but the
            // password IS parameterisable via the `PASSWORD` clause.
            // We quote the identifier manually; sqlx does not support
            // parameterised DDL identifiers.
            let sql = format!(
                "ALTER ROLE {} PASSWORD $1",
                quote_identifier(username)
            );

            sqlx::query(&sql)
                .bind(&new_password)
                .execute(&self.admin_pool)
                .await
                .map_err(|e| ConnectorError::Database {
                    username: username.to_string(),
                    source: e,
                })?;

            // Retrieve the current version from the role comment, if any, and
            // increment it. We store the version as a role comment for
            // persistence without a separate state table.
            let version = self.increment_role_version(username).await?;

            info!(username = username, version = version, "credential rotation completed");

            Ok(NewCredentials {
                username: username.to_string(),
                password: new_password,
                version,
            })
        }

        /// Create a new ephemeral PostgreSQL role and grant the requested
        /// permissions.
        ///
        /// The created role has:
        /// - `NOLOGIN` cleared (login is allowed)
        /// - `NOSUPERUSER`
        /// - `NOCREATEDB`
        /// - `NOCREATEROLE`
        /// - `CONNECTION LIMIT 10` (override via `DatabasePermission::Custom` if needed)
        ///
        /// Returns the initial credentials for the new role.
        #[instrument(skip(self, initial_password), fields(username = username, database = database))]
        pub async fn create_user(
            &self,
            username: &str,
            database: &str,
            permissions: &DatabasePermission,
            initial_password: Option<&str>,
        ) -> Result<NewCredentials, ConnectorError> {
            debug!("creating dynamic database user");

            validate_identifier(username)?;
            validate_identifier(database)?;

            let password = match initial_password {
                Some(p) => p.to_string(),
                None => generate_password(),
            };

            // Create the role.
            let create_sql = format!(
                "CREATE ROLE {} WITH LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE \
                 CONNECTION LIMIT 10 PASSWORD $1",
                quote_identifier(username)
            );

            sqlx::query(&create_sql)
                .bind(&password)
                .execute(&self.admin_pool)
                .await
                .map_err(|e| ConnectorError::Database {
                    username: username.to_string(),
                    source: e,
                })?;

            // Grant the requested permissions.
            self.grant_permissions(username, database, permissions)
                .await?;

            info!(
                username = username,
                database = database,
                "dynamic database user created"
            );

            Ok(NewCredentials {
                username: username.to_string(),
                password,
                version: 1,
            })
        }

        /// Revoke all privileges from `username` and drop the role.
        ///
        /// Issues `REVOKE ALL PRIVILEGES ON ALL TABLES` for every schema,
        /// then `DROP ROLE`.  Call this when the associated WSLVault lease
        /// expires.
        #[instrument(skip(self), fields(username = username))]
        pub async fn revoke_user(&self, username: &str) -> Result<(), ConnectorError> {
            debug!("revoking user and dropping role");

            validate_identifier(username)?;

            // Revoke database connect privilege first to force existing sessions
            // to terminate at the next checkpoint (best-effort; we do not
            // TERMINATE active connections here to avoid disruption).
            let revoke_connect_sql = format!(
                "REVOKE CONNECT ON DATABASE {} FROM {}",
                // We need the current database name.
                quote_identifier(&current_database(&self.admin_pool).await?),
                quote_identifier(username)
            );

            if let Err(e) = sqlx::query(&revoke_connect_sql)
                .execute(&self.admin_pool)
                .await
            {
                // Non-fatal: the role may not have had connect privilege.
                warn!(
                    username = username,
                    error = %e,
                    "failed to revoke CONNECT privilege; continuing with DROP ROLE"
                );
            }

            // Revoke all table-level privileges across all schemas.
            let schemas = list_schemas(&self.admin_pool).await?;
            for schema in &schemas {
                let revoke_sql = format!(
                    "REVOKE ALL PRIVILEGES ON ALL TABLES IN SCHEMA {} FROM {}",
                    quote_identifier(schema),
                    quote_identifier(username)
                );
                if let Err(e) = sqlx::query(&revoke_sql).execute(&self.admin_pool).await {
                    warn!(
                        username = username,
                        schema = schema,
                        error = %e,
                        "failed to revoke table privileges in schema; continuing"
                    );
                }

                let revoke_seq_sql = format!(
                    "REVOKE ALL PRIVILEGES ON ALL SEQUENCES IN SCHEMA {} FROM {}",
                    quote_identifier(schema),
                    quote_identifier(username)
                );
                if let Err(e) = sqlx::query(&revoke_seq_sql)
                    .execute(&self.admin_pool)
                    .await
                {
                    warn!(
                        username = username,
                        schema = schema,
                        error = %e,
                        "failed to revoke sequence privileges in schema; continuing"
                    );
                }
            }

            // Drop the role.  `IF EXISTS` avoids an error if it was already removed.
            let drop_sql = format!(
                "DROP ROLE IF EXISTS {}",
                quote_identifier(username)
            );

            sqlx::query(&drop_sql)
                .execute(&self.admin_pool)
                .await
                .map_err(|e| ConnectorError::Database {
                    username: username.to_string(),
                    source: e,
                })?;

            info!(username = username, "role revoked and dropped");
            Ok(())
        }

        // ---------------------------------------------------------------------
        // Private helpers
        // ---------------------------------------------------------------------

        /// Grant permissions described by `permissions` to `username` in `database`.
        async fn grant_permissions(
            &self,
            username: &str,
            database: &str,
            permissions: &DatabasePermission,
        ) -> Result<(), ConnectorError> {
            let grant_sql = match permissions {
                DatabasePermission::ReadOnly { schema } => {
                    validate_identifier(schema)?;
                    format!(
                        "GRANT SELECT ON ALL TABLES IN SCHEMA {} TO {}",
                        quote_identifier(schema),
                        quote_identifier(username)
                    )
                }
                DatabasePermission::ReadWrite { schema } => {
                    validate_identifier(schema)?;
                    format!(
                        "GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA {} TO {}",
                        quote_identifier(schema),
                        quote_identifier(username)
                    )
                }
                DatabasePermission::Admin => {
                    format!(
                        "GRANT ALL PRIVILEGES ON DATABASE {} TO {}",
                        quote_identifier(database),
                        quote_identifier(username)
                    )
                }
                DatabasePermission::Custom(sql_fragment) => sql_fragment.clone(),
            };

            sqlx::query(&grant_sql)
                .execute(&self.admin_pool)
                .await
                .map_err(|e| ConnectorError::Database {
                    username: username.to_string(),
                    source: e,
                })?;

            Ok(())
        }

        /// Read and increment the rotation version stored as a role comment.
        ///
        /// The version is stored in the `pg_catalog.pg_description` system
        /// catalogue as a JSON comment on the role object.  If no comment
        /// exists the version starts at 1.
        async fn increment_role_version(&self, username: &str) -> Result<u32, ConnectorError> {
            // Retrieve the OID for the role.
            // Cast oid to bigint (int8) because sqlx maps PostgreSQL int8 → i64,
            // and u32 does not implement sqlx::Decode<Postgres>.
            let row: Option<(i64,)> = sqlx::query_as(
                "SELECT oid::bigint FROM pg_catalog.pg_roles WHERE rolname = $1",
            )
            .bind(username)
            .fetch_optional(&self.admin_pool)
            .await
            .map_err(|e| ConnectorError::Database {
                username: username.to_string(),
                source: e,
            })?;

            let role_oid: i64 = match row {
                Some((oid,)) => oid,
                None => {
                    return Err(ConnectorError::Internal {
                        reason: format!("could not find OID for role '{username}'"),
                    })
                }
            };

            // Read existing description.
            let existing: Option<(String,)> = sqlx::query_as(
                "SELECT description FROM pg_catalog.pg_description \
                 WHERE objoid = $1 AND classoid = 'pg_catalog.pg_authid'::regclass",
            )
            .bind(role_oid)
            .fetch_optional(&self.admin_pool)
            .await
            .map_err(|e| ConnectorError::Database {
                username: username.to_string(),
                source: e,
            })?;

            let current_version: u32 = existing
                .as_ref()
                .and_then(|(desc,)| serde_json::from_str::<serde_json::Value>(desc).ok())
                .and_then(|v| v["rotation_version"].as_u64())
                .map(|v| v as u32)
                .unwrap_or(0);

            let new_version = current_version + 1;
            let comment = serde_json::json!({ "rotation_version": new_version }).to_string();

            // COMMENT ON ROLE requires an identifier, not a parameter.
            let comment_sql = format!(
                "COMMENT ON ROLE {} IS $1",
                quote_identifier(username)
            );

            sqlx::query(&comment_sql)
                .bind(&comment)
                .execute(&self.admin_pool)
                .await
                .map_err(|e| ConnectorError::Database {
                    username: username.to_string(),
                    source: e,
                })?;

            Ok(new_version)
        }
    }

    // -------------------------------------------------------------------------
    // Private utility functions
    // -------------------------------------------------------------------------

    /// Generate a cryptographically random password: 32 bytes → base64 (43 chars).
    fn generate_password() -> String {
        use rand::RngCore;
        let mut bytes = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut bytes);
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes)
    }

    /// Validate that `identifier` is safe to embed in a quoted PostgreSQL identifier.
    ///
    /// Rejects identifiers that are empty, too long (PostgreSQL max is 63 bytes),
    /// or contain NUL bytes (which cannot be quoted safely).
    fn validate_identifier(identifier: &str) -> Result<(), ConnectorError> {
        if identifier.is_empty() {
            return Err(ConnectorError::Configuration {
                reason: "PostgreSQL identifier must not be empty".to_string(),
            });
        }
        if identifier.len() > 63 {
            return Err(ConnectorError::Configuration {
                reason: format!(
                    "PostgreSQL identifier '{identifier}' exceeds 63-byte limit"
                ),
            });
        }
        if identifier.contains('\0') {
            return Err(ConnectorError::Configuration {
                reason: "PostgreSQL identifier must not contain NUL bytes".to_string(),
            });
        }
        Ok(())
    }

    /// Wrap `identifier` in double-quotes, escaping any embedded double-quotes by
    /// doubling them (as per the SQL standard).
    fn quote_identifier(identifier: &str) -> String {
        format!("\"{}\"", identifier.replace('"', "\"\""))
    }

    /// Query the name of the current database.
    async fn current_database(pool: &PgPool) -> Result<String, ConnectorError> {
        let row: (String,) = sqlx::query_as("SELECT current_database()")
            .fetch_one(pool)
            .await
            .map_err(|e| ConnectorError::Internal {
                reason: format!("failed to query current database: {e}"),
            })?;
        Ok(row.0)
    }

    /// List all user-created schemas in the current database (excludes `pg_*`
    /// and `information_schema`).
    async fn list_schemas(pool: &PgPool) -> Result<Vec<String>, ConnectorError> {
        let rows: Vec<(String,)> = sqlx::query_as(
            "SELECT schema_name FROM information_schema.schemata \
             WHERE schema_name NOT LIKE 'pg_%' AND schema_name <> 'information_schema'",
        )
        .fetch_all(pool)
        .await
        .map_err(|e| ConnectorError::Internal {
            reason: format!("failed to list schemas: {e}"),
        })?;

        Ok(rows.into_iter().map(|(s,)| s).collect())
    }
}

#[cfg(feature = "postgres-rotation")]
pub use inner::{DatabasePermission, NewCredentials, PostgresCredentialRotator};
