//! API key management for machine-to-machine authentication.
//!
//! API keys provide a simpler alternative to OIDC/JWT for service accounts and
//! automation pipelines that do not participate in an OIDC flow.  Each key is
//! scoped to a tenant and optionally to a set of secret path prefixes and
//! policy names.
//!
//! # Security design
//!
//! - The raw key (`wslv_<base64url-32-bytes>`) is generated once, returned in
//!   the creation response, and **never stored**.
//! - Only the SHA-256 hash of the raw key is stored, in `shared.api_keys`.
//!   Keys therefore survive restarts and are shared across replicas; the
//!   in-memory backend remains for tests and for running without a database.
//! - The management endpoints carry their own authentication ([`AdminAuth`]),
//!   independent of the gateway-origin check, because minting a key grants
//!   whatever policies the request asks for.
//! - Lookup during validation uses a constant-time XOR-fold comparison
//!   (`ct_bytes_equal`) to prevent timing-based key enumeration.
//! - The `key_prefix` (first 8 characters after the `wslv_` sentinel) is
//!   stored in plain text solely so operators can identify a key in audit logs
//!   without access to the raw secret.
//!
//! # Endpoints
//!
//! | Method | Path                        | Description                        |
//! |--------|-----------------------------|------------------------------------|
//! | POST   | /v1/api-keys                | Create a new API key               |
//! | GET    | /v1/api-keys                | List active API keys for a tenant  |
//! | DELETE | /v1/api-keys/:id            | Revoke an API key                  |
//! | POST   | /v1/api-keys/:id/rotate     | Rotate an API key                  |
//! | POST   | /v1/auth/api-key            | Exchange an API key for a JWT      |

use std::{collections::HashMap, sync::Arc};

use axum::{
    extract::{Path, Request, State},
    http::{HeaderMap, StatusCode},
    middleware::Next,
    response::IntoResponse,
    routing::{delete, get, post},
    Extension, Json, Router,
};
use chrono::{DateTime, Utc};
use rand::RngCore;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tokio::sync::RwLock;
use tracing::{error, info, warn};
use uuid::Uuid;

use wslvault_core::types::tenant::TenantId;
use wslvault_storage::{api_key_store, pool::DbPool};

use crate::token::TokenManager;

// ---------------------------------------------------------------------------
// Key generation constants
// ---------------------------------------------------------------------------

/// Human-readable sentinel prefix prepended to every raw API key.
/// Allows tooling (git scanners, etc.) to detect accidentally committed keys.
const RAW_KEY_PREFIX: &str = "wslv_";

/// Number of random bytes that form the secret portion of the key.
/// 32 bytes = 256 bits of entropy, encoded as ~43 base64url characters.
const KEY_SECRET_BYTES: usize = 32;

/// Number of characters retained from the random portion for the `key_prefix`
/// identification field (not a secret; stored in plain text for audit use).
const KEY_PREFIX_DISPLAY_LEN: usize = 8;

/// TTL (in seconds) of JWTs issued via the `/v1/auth/api-key` exchange endpoint.
const API_KEY_JWT_TTL_SECONDS: i64 = 3600;

// ---------------------------------------------------------------------------
// Error type
// ---------------------------------------------------------------------------

#[allow(dead_code)] // wire/DTO type: fields exist for serde and validation, not direct reads
/// Errors that can be returned by [`ApiKeyManager`] operations.
#[derive(Debug, thiserror::Error)]
pub enum ApiKeyError {
    #[error("api key not found")]
    KeyNotFound,

    #[error("api key has expired")]
    KeyExpired,

    #[error("api key has been revoked")]
    KeyRevoked,

    #[error("an api key with name '{0}' already exists for this tenant")]
    DuplicateName(String),

    /// The message names what a valid key looks like *and* the most common
    /// thing supplied instead. Deployment secrets — `VAULT_ADMIN_TOKEN` above
    /// all — are the same shape as an API key to the eye and sit next to each
    /// other in a local `.env`, so "invalid format" alone leaves someone
    /// re-checking a value that was never the right kind of credential.
    #[error(
        "api key format is invalid; expected '{RAW_KEY_PREFIX}<base64url>'. \
         This must be an API key from POST /v1/api-keys — not VAULT_ADMIN_TOKEN \
         or another deployment secret"
    )]
    InvalidKeyFormat,

    #[error("rate limit exceeded")]
    #[allow(dead_code)]
    RateLimitExceeded,

    /// Wraps internal JWT-issuance failures surfaced from [`TokenManager`].
    #[error("token issuance failed: {0}")]
    TokenIssuance(String),

    /// The `tenant_id` on the request does not name a live tenant. Only the
    /// database backend can tell — the in-memory one has no tenant registry.
    #[error("tenant '{0}' does not exist")]
    TenantNotFound(String),

    /// The backing store failed. Distinct from a key simply not being there.
    #[error("api key store unavailable: {0}")]
    Storage(String),

    /// The bootstrap token is not tenant scoped, so a request authenticated
    /// with it has to name the tenant it acts on.
    #[error("{0}")]
    MissingTenantId(String),
}

impl ApiKeyError {
    /// Map this error to an appropriate HTTP status code.
    fn status_code(&self) -> StatusCode {
        match self {
            ApiKeyError::KeyNotFound => StatusCode::NOT_FOUND,
            ApiKeyError::KeyExpired => StatusCode::UNAUTHORIZED,
            ApiKeyError::KeyRevoked => StatusCode::UNAUTHORIZED,
            ApiKeyError::DuplicateName(_) => StatusCode::CONFLICT,
            ApiKeyError::InvalidKeyFormat => StatusCode::BAD_REQUEST,
            ApiKeyError::RateLimitExceeded => StatusCode::TOO_MANY_REQUESTS,
            ApiKeyError::TokenIssuance(_) => StatusCode::INTERNAL_SERVER_ERROR,
            ApiKeyError::TenantNotFound(_) => StatusCode::NOT_FOUND,
            ApiKeyError::Storage(_) => StatusCode::INTERNAL_SERVER_ERROR,
            ApiKeyError::MissingTenantId(_) => StatusCode::BAD_REQUEST,
        }
    }

    /// Stable machine-readable error code included in JSON error bodies.
    fn error_code(&self) -> &'static str {
        match self {
            ApiKeyError::KeyNotFound => "key_not_found",
            ApiKeyError::KeyExpired => "key_expired",
            ApiKeyError::KeyRevoked => "key_revoked",
            ApiKeyError::DuplicateName(_) => "duplicate_name",
            ApiKeyError::InvalidKeyFormat => "invalid_key_format",
            ApiKeyError::RateLimitExceeded => "rate_limit_exceeded",
            ApiKeyError::TokenIssuance(_) => "token_issuance_failed",
            ApiKeyError::TenantNotFound(_) => "tenant_not_found",
            ApiKeyError::Storage(_) => "storage_error",
            ApiKeyError::MissingTenantId(_) => "missing_tenant_id",
        }
    }
}

impl IntoResponse for ApiKeyError {
    fn into_response(self) -> axum::response::Response {
        (
            self.status_code(),
            Json(serde_json::json!({
                "code": self.error_code(),
                "message": self.to_string(),
            })),
        )
            .into_response()
    }
}

// ---------------------------------------------------------------------------
// Domain types
// ---------------------------------------------------------------------------

/// Persisted representation of an API key.
///
/// The raw key is **never** stored here; only the SHA-256 hash and a short
/// display prefix are retained.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApiKeyRecord {
    pub id: Uuid,
    pub tenant_id: String,
    pub name: String,
    /// SHA-256 hash of the raw key (the raw key itself is never stored).
    pub key_hash: Vec<u8>,
    /// First [`KEY_PREFIX_DISPLAY_LEN`] characters of the random key portion,
    /// used for identification in logs and UIs.  Not a secret.
    pub key_prefix: String,
    /// Allowed secret path prefixes.  An empty list means all paths are allowed.
    pub path_prefixes: Vec<String>,
    /// Policy names granted to bearers of this key.
    pub policies: Vec<String>,
    pub created_by: String,
    pub created_at: DateTime<Utc>,
    /// `None` means the key never expires.
    pub expires_at: Option<DateTime<Utc>>,
    pub last_used_at: Option<DateTime<Utc>>,
    /// Cross-tenant access. See [`ApiKeyCreateRequest::is_superuser`].
    pub is_superuser: bool,
    /// Whether a TOTP code is required to exchange this key.
    pub mfa_required: bool,
    /// `None` means the key is active; `Some(_)` means it has been revoked.
    pub revoked_at: Option<DateTime<Utc>>,
    pub rate_limit_per_minute: i32,
}

/// Response body returned from `POST /v1/api-keys`.
///
/// This is the **only** time the raw `key` is exposed.  The caller must
/// store it securely immediately; it cannot be retrieved later.
#[derive(Debug, Serialize, utoipa::ToSchema)]
pub struct ApiKeyCreateResponse {
    pub id: Uuid,
    /// The raw API key string.  Shown **once at creation** and never again.
    pub key: String,
    pub key_prefix: String,
    pub name: String,
    pub tenant_id: String,
    pub policies: Vec<String>,
    pub path_prefixes: Vec<String>,
    pub expires_at: Option<DateTime<Utc>>,
    pub created_at: DateTime<Utc>,
}

/// Request body for `POST /v1/api-keys`.
#[derive(Debug, Deserialize, utoipa::ToSchema)]
pub struct ApiKeyCreateRequest {
    /// Human-readable name; must be unique within the tenant.
    pub name: String,
    pub tenant_id: String,
    /// Optional list of policy names to attach to this key.
    pub policies: Option<Vec<String>>,
    /// Optional list of secret path prefixes this key may access.
    /// `None` or an empty list grants access to all paths.
    pub path_prefixes: Option<Vec<String>>,
    /// If set, the key expires after this many seconds from creation.
    pub expires_in_seconds: Option<i64>,
    /// Maximum requests per minute; defaults to 60.
    pub rate_limit_per_minute: Option<i32>,
    /// Grant cross-tenant access.
    ///
    /// A superuser is a deliberate hole in the isolation this system otherwise
    /// enforces, so it is narrow and loud: MFA is forced on (the schema
    /// enforces that too), tokens are signed by the system key rather than any
    /// tenant's, and every use is audited with the acting tenant recorded.
    #[serde(default)]
    pub is_superuser: bool,
    /// Require a TOTP code when exchanging this key for a token.
    ///
    /// Default false so machine keys — the External Secrets Operator, CI, the
    /// SDKs — keep working; a service account cannot read an authenticator app.
    /// Forced true for superuser keys.
    #[serde(default)]
    pub mfa_required: bool,
}

#[allow(dead_code)] // wire/DTO type: fields exist for serde and validation, not direct reads
/// Successful result of validating a raw API key.
#[derive(Debug)]
pub struct ApiKeyValidationResult {
    pub key_id: Uuid,
    pub tenant_id: String,
    pub policies: Vec<String>,
    #[allow(dead_code)]
    pub path_prefixes: Vec<String>,
    pub rate_limit_per_minute: i32,
    /// Whether this key grants cross-tenant access.
    pub is_superuser: bool,
    /// Whether a TOTP code is required before a token is issued.
    pub mfa_required: bool,
}

// ---------------------------------------------------------------------------
// Constant-time helpers
// ---------------------------------------------------------------------------

/// Compares two byte slices in constant time to prevent timing side-channels.
///
/// The comparison XORs every byte pair and accumulates the differences so that
/// the execution time does not reveal where (or whether) the first differing
/// byte occurs.  Slices of unequal length are treated as non-equal without
/// short-circuiting.
fn ct_bytes_equal(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    // Fold all XOR differences into a single accumulator; a non-zero result
    // means at least one byte differed.
    let diff: u8 = a
        .iter()
        .zip(b.iter())
        .fold(0u8, |acc, (x, y)| acc | (x ^ y));
    diff == 0
}

// ---------------------------------------------------------------------------
// Manager
// ---------------------------------------------------------------------------

/// Where an [`ApiKeyManager`] keeps its records.
///
/// PostgreSQL is the production backend. The in-memory variant is retained for
/// tests and for running without `DATABASE_URL`; it loses every key when the
/// process exits, which is exactly the failure this enum exists to end.
#[derive(Clone)]
enum Backend {
    /// Durable, shared across replicas and restarts.
    Database(DbPool),
    /// Process-local. Primary index by key hash, secondary by key UUID.
    Memory {
        by_hash: Arc<RwLock<HashMap<Vec<u8>, ApiKeyRecord>>>,
        id_to_hash: Arc<RwLock<HashMap<Uuid, Vec<u8>>>>,
    },
}

/// Translates a storage-layer error into the HTTP-facing error type.
///
/// `ValidationError` on the `name` field is the active-name unique index
/// firing; the caller re-labels it with the name it tried to use.
fn store_err(e: wslvault_core::VaultError) -> ApiKeyError {
    match e {
        wslvault_core::VaultError::TenantNotFound { tenant_id } => {
            ApiKeyError::TenantNotFound(tenant_id)
        }
        other => ApiKeyError::Storage(other.to_string()),
    }
}

/// Manages API key lifecycle: generation, validation, revocation, and rotation.
///
/// Against PostgreSQL every operation is a single indexed statement; the
/// authentication path looks a key up by the unique `key_hash` column rather
/// than scanning. Against the in-memory backend the primary index is a
/// [`HashMap`] keyed by the SHA-256 hash of the raw key, with a secondary index
/// by [`Uuid`] for management operations.
#[derive(Clone)]
pub struct ApiKeyManager {
    backend: Backend,
}

impl ApiKeyManager {
    /// Creates an in-memory manager. Keys do not survive the process.
    pub fn new() -> Self {
        Self {
            backend: Backend::Memory {
                by_hash: Arc::new(RwLock::new(HashMap::new())),
                id_to_hash: Arc::new(RwLock::new(HashMap::new())),
            },
        }
    }

    /// Creates a PostgreSQL-backed manager. Keys survive restarts and are
    /// visible to every replica sharing the database.
    pub fn with_pool(pool: DbPool) -> Self {
        Self {
            backend: Backend::Database(pool),
        }
    }

    // -----------------------------------------------------------------------
    // Cryptographic helpers
    // -----------------------------------------------------------------------

    /// Generates a new raw API key: `"wslv_" + base64url(32 random bytes)`.
    ///
    /// The raw key is returned only here and must never be logged or stored.
    fn generate_key() -> String {
        let mut random_bytes = [0u8; KEY_SECRET_BYTES];
        // `rand::thread_rng()` uses the OS CSPRNG (via getrandom).
        rand::thread_rng().fill_bytes(&mut random_bytes);
        let encoded = base64::Engine::encode(
            &base64::engine::general_purpose::URL_SAFE_NO_PAD,
            &random_bytes,
        );
        format!("{RAW_KEY_PREFIX}{encoded}")
    }

    /// Computes the SHA-256 hash of a raw API key.
    ///
    /// The hash is what is stored and compared; the raw key must never persist.
    fn hash_key(raw_key: &str) -> Vec<u8> {
        let mut hasher = Sha256::new();
        hasher.update(raw_key.as_bytes());
        hasher.finalize().to_vec()
    }

    /// Validates that a raw key has the expected `wslv_` prefix and non-empty
    /// random suffix, returning the random portion on success.
    fn parse_key_random_portion(raw_key: &str) -> Result<&str, ApiKeyError> {
        raw_key
            .strip_prefix(RAW_KEY_PREFIX)
            .filter(|s| !s.is_empty())
            .ok_or(ApiKeyError::InvalidKeyFormat)
    }

    /// Builds the record for a newly generated key, returning it alongside the
    /// raw key string. Shared by the create and rotate paths.
    fn mint(req: &ApiKeyCreateRequest, name: &str, created_by: &str) -> (String, ApiKeyRecord) {
        let raw_key = Self::generate_key();
        let key_hash = Self::hash_key(&raw_key);

        // The display prefix is taken from the random portion, after `wslv_`.
        let key_prefix = raw_key
            .strip_prefix(RAW_KEY_PREFIX)
            .unwrap_or(&raw_key)
            .chars()
            .take(KEY_PREFIX_DISPLAY_LEN)
            .collect::<String>();

        let now = Utc::now();
        let record = ApiKeyRecord {
            // v7 UUIDs sort by creation time, consistent with the rest of the codebase.
            id: Uuid::new_v7(uuid::Timestamp::now(uuid::NoContext)),
            tenant_id: req.tenant_id.clone(),
            name: name.to_string(),
            key_hash,
            key_prefix,
            path_prefixes: req.path_prefixes.clone().unwrap_or_default(),
            policies: req.policies.clone().unwrap_or_default(),
            created_by: created_by.to_string(),
            created_at: now,
            expires_at: req
                .expires_in_seconds
                .map(|secs| now + chrono::Duration::seconds(secs)),
            last_used_at: None,
            revoked_at: None,
            rate_limit_per_minute: req.rate_limit_per_minute.unwrap_or(60),
            is_superuser: req.is_superuser,
            // Superuser implies MFA. Enforced here and in the schema, so
            // neither a caller nor a future code path can skip it by omission.
            mfa_required: req.mfa_required || req.is_superuser,
        };

        (raw_key, record)
    }

    /// Mint a key as a storage row, without writing it.
    ///
    /// Redeeming an invitation must insert the key in the *same transaction*
    /// that marks the invitation spent, so it needs the row rather than a
    /// persisted key. Built on [`Self::mint`] so an invited key is identical to
    /// one created through the API — same generation, same prefix derivation,
    /// same `mfa_required || is_superuser` rule.
    pub(crate) fn mint_row(
        tenant_uuid: Uuid,
        name: &str,
        policies: Vec<String>,
        created_by: &str,
        mfa_required: bool,
    ) -> (String, api_key_store::ApiKeyRow) {
        let req = ApiKeyCreateRequest {
            tenant_id: tenant_uuid.to_string(),
            name: name.to_string(),
            policies: Some(policies),
            path_prefixes: None,
            expires_in_seconds: None,
            rate_limit_per_minute: None,
            // An invitation never confers cross-tenant authority. It is issued
            // for one organisation, and a superuser belongs to none of them.
            is_superuser: false,
            mfa_required,
        };

        let (raw_key, record) = Self::mint(&req, name, created_by);

        let row = api_key_store::ApiKeyRow {
            id: record.id,
            tenant_id: tenant_uuid,
            name: record.name,
            key_hash: record.key_hash,
            key_prefix: record.key_prefix,
            path_prefixes: record.path_prefixes,
            policies: record.policies,
            created_by: record.created_by,
            created_at: record.created_at,
            expires_at: record.expires_at,
            last_used_at: None,
            revoked_at: None,
            rate_limit_per_minute: record.rate_limit_per_minute,
            is_superuser: record.is_superuser,
            mfa_required: record.mfa_required,
        };

        (raw_key, row)
    }

    // -----------------------------------------------------------------------
    // Public API
    // -----------------------------------------------------------------------

    /// Creates a new API key from the given request.
    ///
    /// Returns an [`ApiKeyCreateResponse`] containing the raw key string.
    /// **This is the only time the raw key is accessible.**
    ///
    /// On the database backend `req.tenant_id` may be a tenant UUID or a slug;
    /// either is resolved against `system.tenants` and the response reports the
    /// canonical UUID.
    pub async fn create_key(
        &self,
        req: ApiKeyCreateRequest,
        created_by: &str,
    ) -> Result<ApiKeyCreateResponse, ApiKeyError> {
        // Reject blank names early to avoid cluttering the store.
        let name = req.name.trim().to_string();
        if name.is_empty() {
            return Err(ApiKeyError::InvalidKeyFormat);
        }

        match &self.backend {
            Backend::Database(pool) => {
                let tenant_uuid = api_key_store::resolve_tenant_id(pool, &req.tenant_id)
                    .await
                    .map_err(store_err)?;

                // One scope for the pre-check and the insert. Splitting them
                // across two would let the check read a different connection
                // from the write, which is the race the partial unique index
                // exists to catch — no reason to widen the window.
                let mut scope = pool
                    .begin_tenant(&TenantId(tenant_uuid))
                    .await
                    .map_err(store_err)?;

                // Pre-check for a friendly 409. The partial unique index added
                // in migration 016 is what actually enforces this under
                // concurrency; the insert below maps that violation too.
                if api_key_store::active_name_exists(scope.conn(), tenant_uuid, &name)
                    .await
                    .map_err(store_err)?
                {
                    return Err(ApiKeyError::DuplicateName(name));
                }

                // Report the canonical tenant UUID rather than whatever
                // reference the caller happened to pass.
                let canonical = ApiKeyCreateRequest {
                    tenant_id: tenant_uuid.to_string(),
                    name: name.clone(),
                    policies: req.policies.clone(),
                    path_prefixes: req.path_prefixes.clone(),
                    expires_in_seconds: req.expires_in_seconds,
                    rate_limit_per_minute: req.rate_limit_per_minute,
                    is_superuser: req.is_superuser,
                    mfa_required: req.mfa_required,
                };
                let (raw_key, record) = Self::mint(&canonical, &name, created_by);

                let row = api_key_store::ApiKeyRow {
                    id: record.id,
                    tenant_id: tenant_uuid,
                    name: record.name.clone(),
                    key_hash: record.key_hash.clone(),
                    key_prefix: record.key_prefix.clone(),
                    path_prefixes: record.path_prefixes.clone(),
                    policies: record.policies.clone(),
                    created_by: record.created_by.clone(),
                    created_at: record.created_at,
                    expires_at: record.expires_at,
                    last_used_at: None,
                    revoked_at: None,
                    rate_limit_per_minute: record.rate_limit_per_minute,
                    is_superuser: record.is_superuser,
                    mfa_required: record.mfa_required,
                };

                api_key_store::insert(scope.conn(), &row)
                    .await
                    .map_err(|e| match e {
                        // The unique index fired between the pre-check and the insert.
                        wslvault_core::VaultError::ValidationError { ref field, .. }
                            if field == "name" =>
                        {
                            ApiKeyError::DuplicateName(name.clone())
                        }
                        other => store_err(other),
                    })?;

                scope.commit().await.map_err(store_err)?;

                info!(
                    key_id = %record.id,
                    tenant_id = %tenant_uuid,
                    key_prefix = %record.key_prefix,
                    "api key created"
                );

                Ok(Self::create_response(raw_key, &record))
            }

            Backend::Memory {
                by_hash,
                id_to_hash,
            } => {
                // Duplicate-name guard: scan existing active keys for the tenant.
                {
                    let guard = by_hash.read().await;
                    let duplicate = guard.values().any(|record| {
                        record.tenant_id == req.tenant_id
                            && record.name == name
                            && record.revoked_at.is_none()
                    });
                    if duplicate {
                        return Err(ApiKeyError::DuplicateName(name));
                    }
                }

                let (raw_key, record) = Self::mint(&req, &name, created_by);
                let response = Self::create_response(raw_key, &record);

                // Persist under both indexes, acquiring write locks in a
                // consistent order (hash map first, then id map) to avoid deadlocks.
                let mut by_hash = by_hash.write().await;
                let mut id_to_hash = id_to_hash.write().await;
                id_to_hash.insert(record.id, record.key_hash.clone());
                by_hash.insert(record.key_hash.clone(), record.clone());

                info!(
                    key_id = %record.id,
                    tenant_id = %record.tenant_id,
                    key_prefix = %record.key_prefix,
                    "api key created"
                );

                Ok(response)
            }
        }
    }

    /// Builds the one-time creation response for a freshly minted record.
    fn create_response(raw_key: String, record: &ApiKeyRecord) -> ApiKeyCreateResponse {
        ApiKeyCreateResponse {
            id: record.id,
            key: raw_key,
            key_prefix: record.key_prefix.clone(),
            name: record.name.clone(),
            tenant_id: record.tenant_id.clone(),
            policies: record.policies.clone(),
            path_prefixes: record.path_prefixes.clone(),
            expires_at: record.expires_at,
            created_at: record.created_at,
        }
    }

    /// Validates a raw API key string, returning tenant / policy metadata.
    ///
    /// `last_used_at` is stamped on success. On the database backend that
    /// stamp is best-effort: a write failure is logged but does not fail an
    /// otherwise valid authentication.
    pub async fn validate_key(&self, raw_key: &str) -> Result<ApiKeyValidationResult, ApiKeyError> {
        // Reject obviously malformed keys before touching the store.
        Self::parse_key_random_portion(raw_key)?;

        let candidate_hash = Self::hash_key(raw_key);

        match &self.backend {
            Backend::Database(pool) => {
                // Cross-tenant by necessity: this lookup is what DETERMINES
                // the tenant, so there is none to scope to yet. Safe because
                // the predicate is a SHA-256 of the presented key — it cannot
                // enumerate anything, only confirm a secret the caller already
                // holds. A listing could never justify the same bypass.
                let row = {
                    let mut scope = pool
                        .begin_cross_tenant("api key authentication precedes tenant identity")
                        .await
                        .map_err(store_err)?;

                    // Indexed equality lookup on the unique key_hash column. The
                    // hash is a SHA-256 digest of the presented key, so an attacker
                    // cannot steer the comparison toward a stored value without
                    // already holding a key that hashes to it.
                    let found = api_key_store::find_by_hash(scope.conn(), &candidate_hash)
                        .await
                        .map_err(store_err)?;

                    // Read-only: let the scope roll back on drop rather than
                    // holding the bypass open across the checks below.
                    found.ok_or(ApiKeyError::KeyNotFound)?
                };

                if row.revoked_at.is_some() {
                    warn!(key_id = %row.id, "attempt to use revoked api key");
                    return Err(ApiKeyError::KeyRevoked);
                }

                if let Some(expires_at) = row.expires_at {
                    if Utc::now() > expires_at {
                        warn!(key_id = %row.id, "attempt to use expired api key");
                        return Err(ApiKeyError::KeyExpired);
                    }
                }

                // Now the tenant IS known, so the stamp runs scoped rather
                // than under the bypass above. Best-effort throughout: a
                // bookkeeping write must not fail an otherwise valid
                // authentication, so both the scope and the update only warn.
                match pool.begin_tenant(&TenantId(row.tenant_id)).await {
                    Ok(mut scope) => {
                        if let Err(e) =
                            api_key_store::touch_last_used(scope.conn(), row.id, row.tenant_id)
                                .await
                        {
                            warn!(key_id = %row.id, error = %e, "failed to stamp last_used_at");
                        } else if let Err(e) = scope.commit().await {
                            warn!(key_id = %row.id, error = %e, "failed to commit last_used_at");
                        }
                    }
                    Err(e) => {
                        warn!(key_id = %row.id, error = %e, "could not scope last_used_at update")
                    }
                }

                Ok(ApiKeyValidationResult {
                    key_id: row.id,
                    tenant_id: row.tenant_id.to_string(),
                    policies: row.policies,
                    path_prefixes: row.path_prefixes,
                    rate_limit_per_minute: row.rate_limit_per_minute,
                    is_superuser: row.is_superuser,
                    mfa_required: row.mfa_required,
                })
            }

            Backend::Memory { by_hash, .. } => {
                let mut by_hash = by_hash.write().await;

                // Constant-time compare across the map so that execution time
                // does not reveal where (or whether) a differing byte occurs,
                // preventing timing-based key enumeration.
                let record = by_hash
                    .iter_mut()
                    .find(|(stored_hash, _)| ct_bytes_equal(stored_hash, &candidate_hash))
                    .map(|(_, record)| record)
                    .ok_or(ApiKeyError::KeyNotFound)?;

                if record.revoked_at.is_some() {
                    warn!(key_id = %record.id, "attempt to use revoked api key");
                    return Err(ApiKeyError::KeyRevoked);
                }

                if let Some(expires_at) = record.expires_at {
                    if Utc::now() > expires_at {
                        warn!(key_id = %record.id, "attempt to use expired api key");
                        return Err(ApiKeyError::KeyExpired);
                    }
                }

                // Stamp last_used_at in-place; the record lives behind the write lock.
                record.last_used_at = Some(Utc::now());

                Ok(ApiKeyValidationResult {
                    key_id: record.id,
                    tenant_id: record.tenant_id.clone(),
                    policies: record.policies.clone(),
                    path_prefixes: record.path_prefixes.clone(),
                    rate_limit_per_minute: record.rate_limit_per_minute,
                    is_superuser: record.is_superuser,
                    mfa_required: record.mfa_required,
                })
            }
        }
    }

    /// Revokes an API key by its UUID.
    ///
    /// The caller must supply the owning `tenant_id` to prevent cross-tenant
    /// revocation (even if a key UUID is somehow leaked). Revoking a key that
    /// is already revoked is a no-op.
    pub async fn revoke_key(&self, key_id: Uuid, tenant_id: &str) -> Result<(), ApiKeyError> {
        match &self.backend {
            Backend::Database(pool) => {
                let tenant_uuid = api_key_store::resolve_tenant_id(pool, tenant_id)
                    .await
                    .map_err(store_err)?;

                let mut scope = pool
                    .begin_tenant(&TenantId(tenant_uuid))
                    .await
                    .map_err(store_err)?;

                if api_key_store::revoke(scope.conn(), key_id, tenant_uuid)
                    .await
                    .map_err(store_err)?
                {
                    scope.commit().await.map_err(store_err)?;
                    info!(key_id = %key_id, tenant_id = %tenant_uuid, "api key revoked");
                    return Ok(());
                }

                // Nothing was updated: either the key belongs to another
                // tenant (or does not exist), or it was already revoked. The
                // read shares the scope above — it exists only to explain that
                // miss, so it has to see the same rows the write did.
                let existing = api_key_store::find_by_id(scope.conn(), key_id, tenant_uuid)
                    .await
                    .map_err(store_err)?;
                scope.commit().await.map_err(store_err)?;

                match existing {
                    Some(_) => Ok(()),
                    None => Err(ApiKeyError::KeyNotFound),
                }
            }

            Backend::Memory {
                by_hash,
                id_to_hash,
            } => {
                let hash = {
                    let id_to_hash = id_to_hash.read().await;
                    id_to_hash
                        .get(&key_id)
                        .ok_or(ApiKeyError::KeyNotFound)?
                        .clone()
                };

                let mut by_hash = by_hash.write().await;
                let record = by_hash.get_mut(&hash).ok_or(ApiKeyError::KeyNotFound)?;

                if record.tenant_id != tenant_id {
                    // Do not reveal that the key exists under a different tenant.
                    return Err(ApiKeyError::KeyNotFound);
                }

                if record.revoked_at.is_some() {
                    // Idempotent: revoking an already-revoked key is a no-op.
                    return Ok(());
                }

                record.revoked_at = Some(Utc::now());
                info!(key_id = %key_id, tenant_id = %tenant_id, "api key revoked");
                Ok(())
            }
        }
    }

    /// Lists all active (non-revoked, non-expired) API keys for a tenant.
    ///
    /// The returned records never carry the raw key or its hash; only metadata
    /// safe for administrative display.
    pub async fn list_keys(&self, tenant_id: &str) -> Result<Vec<ApiKeyRecord>, ApiKeyError> {
        match &self.backend {
            Backend::Database(pool) => {
                let tenant_uuid = api_key_store::resolve_tenant_id(pool, tenant_id)
                    .await
                    .map_err(store_err)?;

                let mut scope = pool
                    .begin_tenant(&TenantId(tenant_uuid))
                    .await
                    .map_err(store_err)?;
                let rows = api_key_store::list_active_for_tenant(scope.conn(), tenant_uuid)
                    .await
                    .map_err(store_err)?;
                scope.commit().await.map_err(store_err)?;

                Ok(rows.into_iter().map(record_from_row).collect())
            }

            Backend::Memory { by_hash, .. } => {
                let now = Utc::now();
                let by_hash = by_hash.read().await;

                let mut keys: Vec<ApiKeyRecord> = by_hash
                    .values()
                    .filter(|record| {
                        record.tenant_id == tenant_id
                            && record.revoked_at.is_none()
                            && record.expires_at.is_none_or(|exp| now <= exp)
                    })
                    .map(|record| ApiKeyRecord {
                        // Zero the digest so it is never serialised into a response.
                        key_hash: vec![],
                        ..record.clone()
                    })
                    .collect();

                // Stable ordering: newest first for UI convenience.
                keys.sort_by_key(|k| std::cmp::Reverse(k.created_at));
                Ok(keys)
            }
        }
    }

    /// Rotates an API key: revokes the existing key and issues a new one with
    /// the same name, tenant, policies, path prefixes, and rate limit.
    ///
    /// Returns the creation response for the new key (with the new raw key).
    pub async fn rotate_key(
        &self,
        key_id: Uuid,
        tenant_id: &str,
    ) -> Result<ApiKeyCreateResponse, ApiKeyError> {
        // Capture the old record's configuration before revoking it.
        let (
            old_name,
            old_policies,
            old_path_prefixes,
            old_rate_limit,
            old_created_by,
            old_is_superuser,
            old_mfa_required,
        ) = match &self.backend {
            Backend::Database(pool) => {
                let tenant_uuid = api_key_store::resolve_tenant_id(pool, tenant_id)
                    .await
                    .map_err(store_err)?;

                let mut scope = pool
                    .begin_tenant(&TenantId(tenant_uuid))
                    .await
                    .map_err(store_err)?;
                let found = api_key_store::find_by_id(scope.conn(), key_id, tenant_uuid)
                    .await
                    .map_err(store_err)?;
                scope.commit().await.map_err(store_err)?;
                let row = found.ok_or(ApiKeyError::KeyNotFound)?;

                (
                    row.name,
                    row.policies,
                    row.path_prefixes,
                    row.rate_limit_per_minute,
                    row.created_by,
                    row.is_superuser,
                    row.mfa_required,
                )
            }

            Backend::Memory {
                by_hash,
                id_to_hash,
            } => {
                let hash = {
                    let id_to_hash = id_to_hash.read().await;
                    id_to_hash
                        .get(&key_id)
                        .ok_or(ApiKeyError::KeyNotFound)?
                        .clone()
                };

                let by_hash = by_hash.read().await;
                let record = by_hash.get(&hash).ok_or(ApiKeyError::KeyNotFound)?;

                if record.tenant_id != tenant_id {
                    return Err(ApiKeyError::KeyNotFound);
                }

                (
                    record.name.clone(),
                    record.policies.clone(),
                    record.path_prefixes.clone(),
                    record.rate_limit_per_minute,
                    record.created_by.clone(),
                    record.is_superuser,
                    record.mfa_required,
                )
            }
        };

        // Revoke the old key first so the name frees up for the replacement.
        self.revoke_key(key_id, tenant_id).await?;

        // Create the replacement key with the same logical identity.
        let new_req = ApiKeyCreateRequest {
            name: old_name,
            tenant_id: tenant_id.to_string(),
            policies: Some(old_policies),
            path_prefixes: Some(old_path_prefixes),
            // Preserve the original rate limit; do not reset it on rotation.
            rate_limit_per_minute: Some(old_rate_limit),
            // The new key inherits no expiry from the old one; callers that
            // want expiry should set it on the create request directly.
            expires_in_seconds: None,
            // Rotation replaces a key, it does not re-grade it. Dropping these
            // would silently demote a superuser key — or worse, quietly turn
            // MFA off — on what an operator thinks is a routine rotation.
            is_superuser: old_is_superuser,
            mfa_required: old_mfa_required,
        };

        let response = self.create_key(new_req, &old_created_by).await?;

        info!(
            old_key_id = %key_id,
            new_key_id = %response.id,
            tenant_id = %tenant_id,
            "api key rotated"
        );

        Ok(response)
    }
}

/// Converts a persisted row into the in-process record shape.
///
/// The stored digest is dropped rather than carried across: nothing downstream
/// of a list operation needs it, and leaving it behind removes any chance of it
/// reaching a response body.
fn record_from_row(row: api_key_store::ApiKeyRow) -> ApiKeyRecord {
    ApiKeyRecord {
        id: row.id,
        tenant_id: row.tenant_id.to_string(),
        name: row.name,
        key_hash: vec![],
        key_prefix: row.key_prefix,
        path_prefixes: row.path_prefixes,
        policies: row.policies,
        created_by: row.created_by,
        created_at: row.created_at,
        is_superuser: row.is_superuser,
        mfa_required: row.mfa_required,
        expires_at: row.expires_at,
        last_used_at: row.last_used_at,
        revoked_at: row.revoked_at,
        rate_limit_per_minute: row.rate_limit_per_minute,
    }
}

impl Default for ApiKeyManager {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// Shared app state for HTTP handlers
// ---------------------------------------------------------------------------

/// State passed to every API-key HTTP handler.
#[derive(Clone)]
pub struct ApiKeyState {
    pub manager: ApiKeyManager,
    pub token_manager: TokenManager,
    /// Per-tenant Ed25519 signing keys. `None` falls back to the shared HS256
    /// secret, which is the legacy posture — see `signing_keys`.
    pub signing_keys: Option<crate::signing_keys::SigningKeys>,
    /// Database pool for MFA enrolments. `None` disables the second factor.
    pub mfa_pool: Option<wslvault_storage::pool::DbPool>,
    /// Wraps TOTP secrets, so they sit under the root KEK like every other
    /// piece of key material here.
    pub crypto: Option<crate::crypto_client::CryptoClient>,
    /// Logins that have passed the key check and are waiting on a code.
    pub challenges: crate::mfa::ChallengeStore,
}

// ---------------------------------------------------------------------------
// Administrative authentication
// ---------------------------------------------------------------------------

/// Environment variable holding the bootstrap administrator token.
pub const ADMIN_TOKEN_ENV: &str = "VAULT_ADMIN_TOKEN";

/// Environment variable naming the policy a JWT must carry to manage keys.
///
/// Re-exported from core rather than declared again: region-health gates its
/// operator endpoints on the same name, and two copies of a security-relevant
/// string are two things to change and one to forget.
pub use wslvault_core::auth::{ADMIN_POLICY_ENV, DEFAULT_ADMIN_POLICY};

/// Header carrying the bootstrap administrator token.
pub const ADMIN_TOKEN_HEADER: &str = "x-admin-token";

/// Who is making a key-management request, once authenticated.
#[derive(Clone, Debug)]
pub struct AdminIdentity {
    /// Recorded as `created_by` on any key this request mints.
    pub principal_id: String,
    /// Tenant this caller is confined to. `Some` for a JWT caller, taken from
    /// its own claims; `None` for the bootstrap token, which is not tenant
    /// scoped and must therefore name its tenant explicitly on each request.
    pub tenant_id: Option<String>,
    /// Whether this caller may mint *superuser* keys.
    ///
    /// True only for an existing superuser (from the signed claim) and for the
    /// bootstrap token, which is how the first superuser comes into existence.
    /// Everyone else — including a platform administrator — cannot create one.
    ///
    /// Without this the `is_superuser` flag on a create request was taken at
    /// face value, so anyone who could reach key management could mint
    /// themselves cross-tenant access. Reproduced against a running instance:
    /// three superuser keys minted from an ordinary tenant credential.
    pub superuser: bool,
}

/// Authenticates callers of the key-management endpoints.
///
/// Minting an API key is a privilege-granting operation: the returned key
/// carries whatever policies the request asks for. These endpoints are designed
/// to sit behind the gateway, but a deployment that routes around the gateway —
/// or simply leaves `VAULT_GATEWAY_SECRET` unset, which disables that check —
/// would otherwise expose key creation to anyone who can reach the port. This
/// gate is enforced by the service itself and fails closed.
///
/// Two credentials are accepted:
///
/// 1. `Authorization: Bearer <jwt>` — a token minted by this deployment whose
///    `policies` claim contains the configured administrator policy. The
///    caller is pinned to the tenant in its own claims.
/// 2. `X-Admin-Token: <secret>` — the bootstrap credential from
///    `VAULT_ADMIN_TOKEN`, for creating the first key of a deployment, before
///    any JWT can be obtained. Not tenant scoped.
#[derive(Clone)]
pub struct AdminAuth {
    /// `None` when `VAULT_ADMIN_TOKEN` is unset; the bootstrap path is then
    /// unavailable and only JWT callers can manage keys.
    bootstrap_token: Option<Arc<Vec<u8>>>,
    /// Policy a JWT must carry to be treated as an administrator.
    required_policy: Arc<String>,
    /// Verifies legacy HS256 JWTs under the shared secret.
    token_manager: TokenManager,
    /// Verifies per-tenant EdDSA JWTs. `None` leaves only the legacy path.
    signing_keys: Option<crate::signing_keys::SigningKeys>,
}

impl AdminAuth {
    /// Builds the gate from the environment.
    ///
    /// Logs at startup which credentials are live so an operator can tell,
    /// from the logs alone, whether bootstrap is possible.
    /// Attach per-tenant signing keys so EdDSA tokens can be verified.
    ///
    /// Without them the gate falls back to HS256 only, which rejects every
    /// token issued under per-tenant keys.
    pub fn with_signing_keys(mut self, keys: Option<crate::signing_keys::SigningKeys>) -> Self {
        self.signing_keys = keys;
        self
    }

    pub fn from_env(token_manager: TokenManager) -> Self {
        let bootstrap_token = std::env::var(ADMIN_TOKEN_ENV)
            .ok()
            .filter(|s| !s.is_empty())
            .map(|s| Arc::new(s.into_bytes()));

        let required_policy = std::env::var(ADMIN_POLICY_ENV)
            .ok()
            .filter(|s| !s.is_empty())
            .unwrap_or_else(|| DEFAULT_ADMIN_POLICY.to_string());

        if bootstrap_token.is_none() {
            warn!(
                "{ADMIN_TOKEN_ENV} is not set — api key management accepts only JWTs carrying \
                 the '{required_policy}' policy. Set it to bootstrap the first key."
            );
        }

        Self {
            bootstrap_token,
            required_policy: Arc::new(required_policy),
            token_manager,
            signing_keys: None,
        }
    }

    /// Builds the gate explicitly. Used by tests.
    #[cfg(test)]
    pub fn new(
        token_manager: TokenManager,
        bootstrap_token: Option<Vec<u8>>,
        required_policy: impl Into<String>,
    ) -> Self {
        Self {
            bootstrap_token: bootstrap_token.map(Arc::new),
            required_policy: Arc::new(required_policy.into()),
            token_manager,
            signing_keys: None,
        }
    }

    /// Authenticates one request, returning the caller's identity.
    ///
    /// Distinguishes "no usable credential" from "authenticated but not
    /// permitted". Collapsing both into `None` made every policy failure a
    /// `401`, and the UI logs out on `401` — so a signed-in user without the
    /// administrator policy was silently ejected the moment any page fetched an
    /// admin-gated resource. The dashboard fetches one on load, so those users
    /// could not stay signed in at all.
    pub async fn authenticate(&self, headers: &HeaderMap) -> Result<AdminIdentity, AdminRejection> {
        // 1. Bootstrap token, compared in constant time.
        if let Some(expected) = &self.bootstrap_token {
            if let Some(provided) = headers.get(ADMIN_TOKEN_HEADER).map(|v| v.as_bytes()) {
                if ct_bytes_equal(provided, expected) {
                    return Ok(AdminIdentity {
                        principal_id: "bootstrap-admin".to_string(),
                        tenant_id: None,
                        // The bootstrap token exists precisely to create the
                        // first superuser, before any superuser exists to do it.
                        superuser: true,
                    });
                }
            }
        }

        // 2. Bearer JWT carrying the administrator policy.
        let bearer = headers
            .get(axum::http::header::AUTHORIZATION)
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.strip_prefix("Bearer "))
            .map(str::trim)
            .filter(|t| !t.is_empty())
            .ok_or(AdminRejection::Unauthenticated)?;

        // Revocation is checked before the signature is even considered, so a
        // revoked token cannot mint keys. This gate verifies tokens itself
        // rather than going through `resolve_identity`, so it does not inherit
        // that function's revocation check and had none of its own: a revoked
        // administrator token could call POST /v1/api-keys, receive a working
        // key, and exchange it for clean tokens.
        //
        // Fails closed. An unreachable revocation list denies the request,
        // because answering "not revoked" when the answer is unknown is exactly
        // how a revoked credential keeps working.
        match wslvault_core::auth::is_token_revoked(bearer).await {
            Ok(false) => {}
            Ok(true) => {
                warn!("a revoked token was presented to api key management");
                return Err(AdminRejection::Unauthenticated);
            }
            Err(e) => {
                error!(error = %e.0, "revocation lookup failed — denying");
                return Err(AdminRejection::Unauthenticated);
            }
        }

        // Try the per-tenant EdDSA path first, then the legacy shared HS256.
        //
        // This used to be HS256 only, which broke every Bearer-authorised admin
        // operation the moment issuance moved to per-tenant keys: the token was
        // valid, the policy was right, and it could not be decoded. Found by
        // logging into the UI and watching API-key management fail.
        let claims = match &self.signing_keys {
            Some(keys) => match keys.verify(bearer).await {
                Ok(c) => c,
                Err(_) => self
                    .token_manager
                    .validate_token(bearer)
                    .map_err(|_| AdminRejection::Unauthenticated)?,
            },
            None => self
                .token_manager
                .validate_token(bearer)
                .map_err(|_| AdminRejection::Unauthenticated)?,
        };

        // A superuser is an administrator by definition: the claim already
        // grants cross-tenant access, so requiring a separate policy on top
        // would only mean a superuser could not administer the platform it has
        // authority over.
        if claims.superuser {
            return Ok(AdminIdentity {
                principal_id: claims.sub,
                tenant_id: Some(claims.tenant_id),
                superuser: true,
            });
        }

        if !claims
            .policies
            .iter()
            .any(|p| p == self.required_policy.as_str())
        {
            warn!(
                principal = %claims.sub,
                "token presented to api key management lacks the '{}' policy",
                self.required_policy
            );
            // Authenticated, just not permitted — 403, not 401. See the note on
            // this function.
            return Err(AdminRejection::Forbidden);
        }

        Ok(AdminIdentity {
            principal_id: claims.sub,
            tenant_id: Some(claims.tenant_id),
            // Carrying the administrator policy is not the same as being a
            // superuser: a platform administrator manages tenants, a superuser
            // reads across them. Escalating between the two must be deliberate.
            superuser: false,
        })
    }
}

/// Why an admin-gated request was turned away.
///
/// The distinction is load-bearing for the UI, not cosmetic: `401` means "your
/// session is no good, sign in again" and the dashboard acts on it by logging
/// out, while `403` means "you are signed in, this is simply not yours".
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AdminRejection {
    /// No credential, or one that does not verify.
    Unauthenticated,
    /// A valid credential that does not carry the required policy.
    Forbidden,
}

/// Axum middleware enforcing [`AdminAuth`] on the key-management routes.
///
/// Inserts the resolved [`AdminIdentity`] into the request extensions on
/// success, so handlers never re-parse credentials. On failure it answers `401`
/// or `403` per [`AdminRejection`] — the two are not interchangeable, because
/// the UI treats `401` as "session is dead" and logs the user out.
pub async fn require_admin(
    State(auth): State<AdminAuth>,
    mut request: Request,
    next: Next,
) -> axum::response::Response {
    match auth.authenticate(request.headers()).await {
        Ok(identity) => {
            request.extensions_mut().insert(identity);
            next.run(request).await
        }
        Err(AdminRejection::Unauthenticated) => (
            StatusCode::UNAUTHORIZED,
            Json(serde_json::json!({
                "code": "admin_auth_required",
                "message": "api key management requires an administrator credential: \
                            a Bearer token carrying the administrator policy, or X-Admin-Token",
            })),
        )
            .into_response(),
        Err(AdminRejection::Forbidden) => (
            StatusCode::FORBIDDEN,
            Json(serde_json::json!({
                "code": "admin_policy_required",
                "message": "this account is signed in but does not carry the administrator \
                            policy required to manage tenants and API keys",
            })),
        )
            .into_response(),
    }
}

/// Determines which tenant a management request acts on.
///
/// A JWT caller is pinned to the tenant in its own claims — an `X-Tenant-Id`
/// header cannot widen that, which is what stops one tenant's administrator
/// from minting keys inside another. The bootstrap token is not tenant scoped,
/// so it must name the tenant on each request.
fn request_tenant(identity: &AdminIdentity, headers: &HeaderMap) -> Result<String, ApiKeyError> {
    if let Some(tenant) = &identity.tenant_id {
        return Ok(tenant.clone());
    }

    headers
        .get("x-tenant-id")
        .and_then(|v| v.to_str().ok())
        .filter(|s| !s.is_empty())
        .map(str::to_string)
        .ok_or_else(|| {
            ApiKeyError::MissingTenantId(
                "X-Tenant-Id header is required when authenticating with X-Admin-Token".to_string(),
            )
        })
}

// ---------------------------------------------------------------------------
// HTTP request / response wire types
// ---------------------------------------------------------------------------

/// Response body for list and single-key operations (no raw key exposed).
#[derive(Debug, Serialize, utoipa::ToSchema)]
pub struct ApiKeyMetadataResponse {
    pub id: Uuid,
    pub name: String,
    pub tenant_id: String,
    pub key_prefix: String,
    pub policies: Vec<String>,
    pub path_prefixes: Vec<String>,
    pub created_by: String,
    pub created_at: DateTime<Utc>,
    pub expires_at: Option<DateTime<Utc>>,
    pub last_used_at: Option<DateTime<Utc>>,
    pub rate_limit_per_minute: i32,
    /// Whether exchanging this key for a token requires an authenticator code.
    pub mfa_required: bool,
}

impl From<&ApiKeyRecord> for ApiKeyMetadataResponse {
    fn from(record: &ApiKeyRecord) -> Self {
        Self {
            id: record.id,
            name: record.name.clone(),
            tenant_id: record.tenant_id.clone(),
            key_prefix: record.key_prefix.clone(),
            policies: record.policies.clone(),
            path_prefixes: record.path_prefixes.clone(),
            created_by: record.created_by.clone(),
            created_at: record.created_at,
            expires_at: record.expires_at,
            last_used_at: record.last_used_at,
            rate_limit_per_minute: record.rate_limit_per_minute,
            mfa_required: record.mfa_required,
        }
    }
}

/// Request body for `POST /v1/auth/api-key`.
#[derive(Debug, Deserialize, utoipa::ToSchema)]
pub struct ApiKeyAuthRequest {
    /// Raw API key string (format: `wslv_<base64url>`).
    pub api_key: String,
}

/// Response body from `POST /v1/auth/api-key`.
#[derive(Debug, Serialize, utoipa::ToSchema)]
pub struct ApiKeyAuthResponse {
    pub token: String,
    pub expires_at: DateTime<Utc>,
    pub tenant_id: String,
    pub policies: Vec<String>,
    /// Present when lease-manager accepted the token lease. Omitted when
    /// lease-manager is down (login still succeeds).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub lease_id: Option<String>,
}

// ---------------------------------------------------------------------------
// HTTP handlers
// ---------------------------------------------------------------------------

/// `POST /v1/api-keys` — create a new API key.
///
/// Requires an administrator credential (see [`AdminAuth`]) and a JSON body of
/// [`ApiKeyCreateRequest`].  `created_by` is taken from the authenticated
/// identity, never from a caller-supplied header, so it stands as audit
/// evidence.  A JWT caller may only mint keys inside its own tenant.
#[utoipa::path(
    post,
    path = "/v1/api-keys",
    params(
        ("authorization" = Option<String>, Header, description = "Bearer JWT carrying the administrator policy"),
        ("x-admin-token" = Option<String>, Header, description = "Bootstrap administrator token (alternative to the Bearer JWT)"),
    ),
    request_body = ApiKeyCreateRequest,
    responses(
        (status = 201, description = "API key created; raw key is shown only once", body = ApiKeyCreateResponse),
        (status = 401, description = "Missing or insufficient administrator credential"),
        (status = 404, description = "The named tenant does not exist"),
        (status = 409, description = "An active API key with this name already exists for the tenant"),
        (status = 500, description = "Internal error during key creation"),
    ),
    tag = "api-keys"
)]
pub async fn handle_create_api_key(
    State(state): State<ApiKeyState>,
    Extension(identity): Extension<AdminIdentity>,
    Json(mut payload): Json<ApiKeyCreateRequest>,
) -> impl IntoResponse {
    // The creator is whoever the admin gate authenticated, not a header the
    // caller controls — `created_by` is audit evidence and must not be forgeable.
    let created_by = identity.principal_id.clone();

    // Only a superuser mints a superuser. `is_superuser` used to be taken
    // straight from the request body, so any caller who reached this handler
    // could grant themselves cross-tenant access to every secret in the
    // deployment — one request, no further credential. Reproduced live: three
    // superuser keys minted from an ordinary tenant credential, in a tenant the
    // caller did not belong to.
    //
    // Checked here rather than in `AdminAuth` because it is an authorisation
    // decision about *this* request's payload, not about who the caller is.
    if payload.is_superuser && !identity.superuser {
        warn!(
            principal = %identity.principal_id,
            "refused an attempt to mint a superuser key without superuser authority"
        );
        return (
            StatusCode::FORBIDDEN,
            Json(serde_json::json!({
                "code": "superuser_grant_denied",
                "message": "only a superuser can create a superuser key",
            })),
        )
            .into_response();
    }

    // A JWT caller mints only inside its own tenant, whatever the body says.
    if let Some(tenant) = &identity.tenant_id {
        payload.tenant_id = tenant.clone();
    } else if payload.tenant_id.trim().is_empty() {
        return ApiKeyError::MissingTenantId(
            "tenant_id is required when authenticating with X-Admin-Token".to_string(),
        )
        .into_response();
    }

    match state.manager.create_key(payload, &created_by).await {
        Ok(response) => (StatusCode::CREATED, Json(response)).into_response(),
        Err(err) => {
            warn!(error = %err, "failed to create api key");
            err.into_response()
        }
    }
}

/// `GET /v1/api-keys` — list active API keys for a tenant.
///
/// Requires the `X-Tenant-Id` header to identify the tenant scope.
#[utoipa::path(
    get,
    path = "/v1/api-keys",
    params(
        ("x-tenant-id" = String, Header, description = "Tenant identifier (required)"),
    ),
    responses(
        (status = 200, description = "Active API keys for the tenant (key hashes never included)", body = Vec<ApiKeyMetadataResponse>),
        (status = 400, description = "Missing X-Tenant-Id header"),
        (status = 401, description = "Missing or insufficient administrator credential"),
    ),
    tag = "api-keys"
)]
pub async fn handle_list_api_keys(
    State(state): State<ApiKeyState>,
    Extension(identity): Extension<AdminIdentity>,
    headers: HeaderMap,
) -> impl IntoResponse {
    let tenant_id = match request_tenant(&identity, &headers) {
        Ok(id) => id,
        Err(err) => return err.into_response(),
    };

    match state.manager.list_keys(&tenant_id).await {
        Ok(keys) => {
            let body: Vec<ApiKeyMetadataResponse> =
                keys.iter().map(ApiKeyMetadataResponse::from).collect();
            (StatusCode::OK, Json(body)).into_response()
        }
        Err(err) => {
            warn!(error = %err, tenant_id = %tenant_id, "failed to list api keys");
            err.into_response()
        }
    }
}

/// `DELETE /v1/api-keys/:id` — revoke an API key.
///
/// Requires the `X-Tenant-Id` header for cross-tenant isolation enforcement.
#[utoipa::path(
    delete,
    path = "/v1/api-keys/{id}",
    params(
        ("id" = String, Path, description = "UUID of the API key to revoke"),
        ("x-tenant-id" = String, Header, description = "Tenant identifier (required for cross-tenant isolation)"),
    ),
    responses(
        (status = 204, description = "API key revoked (idempotent)"),
        (status = 400, description = "Invalid UUID or missing X-Tenant-Id header"),
        (status = 401, description = "Missing or insufficient administrator credential"),
        (status = 404, description = "API key not found"),
    ),
    tag = "api-keys"
)]
pub async fn handle_revoke_api_key(
    State(state): State<ApiKeyState>,
    Extension(identity): Extension<AdminIdentity>,
    Path(id_str): Path<String>,
    headers: HeaderMap,
) -> impl IntoResponse {
    let key_id = match id_str.parse::<Uuid>() {
        Ok(id) => id,
        Err(_) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({
                    "code": "invalid_id",
                    "message": "api key id must be a valid UUID",
                })),
            )
                .into_response();
        }
    };

    let tenant_id = match request_tenant(&identity, &headers) {
        Ok(id) => id,
        Err(err) => return err.into_response(),
    };

    match state.manager.revoke_key(key_id, &tenant_id).await {
        Ok(()) => StatusCode::NO_CONTENT.into_response(),
        Err(err) => {
            warn!(error = %err, key_id = %key_id, "failed to revoke api key");
            err.into_response()
        }
    }
}

/// `POST /v1/api-keys/:id/rotate` — rotate an API key.
///
/// Revokes the current key and issues a replacement with the same configuration.
/// The new raw key is returned in the response body.
#[utoipa::path(
    post,
    path = "/v1/api-keys/{id}/rotate",
    params(
        ("id" = String, Path, description = "UUID of the API key to rotate"),
        ("x-tenant-id" = String, Header, description = "Tenant identifier (required)"),
    ),
    responses(
        (status = 200, description = "Old key revoked and new key issued; raw key shown once", body = ApiKeyCreateResponse),
        (status = 400, description = "Invalid UUID or missing X-Tenant-Id header"),
        (status = 401, description = "Missing or insufficient administrator credential"),
        (status = 404, description = "API key not found"),
    ),
    tag = "api-keys"
)]
pub async fn handle_rotate_api_key(
    State(state): State<ApiKeyState>,
    Extension(identity): Extension<AdminIdentity>,
    Path(id_str): Path<String>,
    headers: HeaderMap,
) -> impl IntoResponse {
    let key_id = match id_str.parse::<Uuid>() {
        Ok(id) => id,
        Err(_) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({
                    "code": "invalid_id",
                    "message": "api key id must be a valid UUID",
                })),
            )
                .into_response();
        }
    };

    let tenant_id = match request_tenant(&identity, &headers) {
        Ok(id) => id,
        Err(err) => return err.into_response(),
    };

    match state.manager.rotate_key(key_id, &tenant_id).await {
        Ok(response) => (StatusCode::OK, Json(response)).into_response(),
        Err(err) => {
            warn!(error = %err, key_id = %key_id, "failed to rotate api key");
            err.into_response()
        }
    }
}

/// Open a tenant scope for the MFA tables.
///
/// MFA rows belong to one key, which belongs to one tenant, so every operation
/// here is scoped — none of them takes the cross-tenant bypass. The tenant
/// arrives as a string from the claim or the challenge, so parsing it is part
/// of opening the scope rather than repeated at each call site.
///
/// # Committing
///
/// A scope that WRITES must be committed explicitly. Dropping one rolls it
/// back, and that is not a compile error — the confirm handler was written
/// without its commit and would have reported "confirmed" while silently
/// discarding the enrolment and leaving `mfa_required` false.
///
/// A read-only scope may simply be dropped, and two here are:
/// `mfa_enrolment_active` and the lookup in `handle_mfa_verify`.
async fn mfa_scope<'p>(
    pool: &'p wslvault_storage::pool::DbPool,
    tenant_id: &str,
) -> Result<wslvault_storage::tenant_scope::ScopedTx<'p>, String> {
    let uuid =
        Uuid::parse_str(tenant_id.trim()).map_err(|e| format!("tenant is not a UUID: {e}"))?;
    pool.begin_tenant(&TenantId(uuid))
        .await
        .map_err(|e| format!("could not open the tenant scope: {e}"))
}

async fn mfa_enrolment_active(
    state: &ApiKeyState,
    api_key_id: Uuid,
    tenant_id: &str,
) -> Result<bool, String> {
    let Some(pool) = state.mfa_pool.as_ref() else {
        return Ok(false);
    };
    let mut scope = mfa_scope(pool, tenant_id).await?;
    Ok(wslvault_storage::mfa_store::find(scope.conn(), api_key_id)
        .await
        .map_err(|e| e.to_string())?
        .map(|e| e.is_active())
        .unwrap_or(false))
}

/// Mint a token signed with the tenant's own key, falling back to the shared
/// HS256 secret only where per-tenant keys are not configured.
///
/// The fallback exists so an upgrade does not require the crypto-service to be
/// reachable before anyone can log in. It warns, because a shared symmetric
/// secret means any service that can verify a token can also forge one.
pub(crate) async fn issue_for_tenant(
    state: &ApiKeyState,
    subject: &str,
    tenant_id: &str,
    policies: Vec<String>,
    superuser: bool,
) -> Result<(String, chrono::DateTime<chrono::Utc>), String> {
    let Some(signing_keys) = state.signing_keys.as_ref() else {
        if superuser {
            // A superuser token authorises across every tenant. Minting one
            // under a secret every service already holds would mean any of them
            // could forge cross-tenant authority.
            return Err(
                "per-tenant signing keys are required to issue a superuser token".to_string(),
            );
        }
        warn!(
            "issuing a legacy HS256 token: per-tenant signing keys are not configured, \
             so any service holding VAULT_JWT_SECRET can forge this token"
        );
        return state
            .token_manager
            .issue_token(subject, tenant_id, policies, API_KEY_JWT_TTL_SECONDS)
            .map_err(|e| e.to_string());
    };

    // Superuser tokens are signed by the system key rather than any tenant's,
    // so no tenant key can mint cross-tenant authority.
    let key_tenant = if superuser {
        None
    } else {
        Some(Uuid::parse_str(tenant_id).map_err(|e| format!("tenant_id is not a UUID: {e}"))?)
    };

    let signer = signing_keys.signer_for(key_tenant.as_ref()).await?;
    state
        .token_manager
        .issue_token_with_key(
            subject,
            tenant_id,
            policies,
            API_KEY_JWT_TTL_SECONDS,
            &signer.encoding,
            crate::signing_keys::SigningKeys::header(&signer.kid),
            superuser,
        )
        .map_err(|e| e.to_string())
}

/// `POST /v1/auth/api-key` — exchange a raw API key for a short-lived JWT.
///
/// Accepts `{ "api_key": "wslv_..." }` and returns a JWT token that downstream
/// services can verify using the shared `VAULT_JWT_SECRET`.
#[utoipa::path(
    post,
    path = "/v1/auth/api-key",
    request_body = ApiKeyAuthRequest,
    responses(
        (status = 200, description = "JWT issued for the API key's tenant and policies", body = ApiKeyAuthResponse),
        (status = 400, description = "Malformed API key format"),
        (status = 401, description = "API key is expired or revoked"),
        (status = 404, description = "API key not found"),
        (status = 500, description = "JWT issuance failed"),
    ),
    tag = "auth"
)]
pub async fn handle_auth_api_key(
    State(state): State<ApiKeyState>,
    Json(payload): Json<ApiKeyAuthRequest>,
) -> impl IntoResponse {
    // Validate the key and retrieve its associated metadata.
    let validation_result = match state.manager.validate_key(&payload.api_key).await {
        Ok(result) => result,
        Err(err) => {
            warn!(error = %err, "api key authentication failed");
            return err.into_response();
        }
    };

    // A key marked `mfa_required` gets a challenge, not a token. The check is
    // per key so machine clients — ESO, CI, the SDKs — keep the one-step
    // exchange; a service account cannot read an authenticator app.
    if validation_result.mfa_required {
        match mfa_enrolment_active(
            &state,
            validation_result.key_id,
            &validation_result.tenant_id,
        )
        .await
        {
            Ok(true) => {
                let challenge = state
                    .challenges
                    .issue(crate::mfa::PendingChallenge {
                        api_key_id: validation_result.key_id,
                        tenant_id: validation_result.tenant_id.clone(),
                        policies: validation_result.policies.clone(),
                        superuser: validation_result.is_superuser,
                        expires_at: crate::mfa::challenge_expiry(),
                    })
                    .await;
                info!(
                    key_id = %validation_result.key_id,
                    "api key accepted; awaiting authenticator code"
                );
                return crate::mfa::challenge_response(challenge);
            }
            Ok(false) => {
                // The key demands a second factor and none is enrolled. Fail
                // closed: issuing a token here would silently make the
                // requirement optional, which is the same as not having it.
                warn!(
                    key_id = %validation_result.key_id,
                    "key requires MFA but has no confirmed authenticator; refusing"
                );
                return (
                    StatusCode::FORBIDDEN,
                    Json(serde_json::json!({
                        "message": "this key requires an authenticator; \
                                    enrol one via /v1/auth/mfa/totp/enroll"
                    })),
                )
                    .into_response();
            }
            Err(e) => {
                error!(error = %e, "could not check MFA enrolment");
                return (
                    StatusCode::SERVICE_UNAVAILABLE,
                    Json(serde_json::json!({ "message": "could not verify the second factor" })),
                )
                    .into_response();
            }
        }
    }

    // Issue a short-lived JWT using the key's UUID as the subject so that
    // downstream services can correlate the token back to the originating key.
    let subject = validation_result.key_id.to_string();
    let (token, expires_at) = match issue_for_tenant(
        &state,
        &subject,
        &validation_result.tenant_id,
        validation_result.policies.clone(),
        validation_result.is_superuser,
    )
    .await
    {
        Ok(pair) => pair,
        Err(err) => {
            let api_err = ApiKeyError::TokenIssuance(err);
            return api_err.into_response();
        }
    };

    if validation_result.is_superuser {
        // A superuser token authorises across every tenant. It is the
        // highest-value credential in the system, so its issuance is never a
        // routine log line.
        warn!(
            key_id = %validation_result.key_id,
            home_tenant = %validation_result.tenant_id,
            "SUPERUSER token issued — this credential grants cross-tenant access"
        );
    }

    info!(
        key_id = %validation_result.key_id,
        tenant_id = %validation_result.tenant_id,
        superuser = validation_result.is_superuser,
        "api key exchanged for jwt"
    );

    let lease_id = crate::lease_client::try_create_token_lease(
        &validation_result.tenant_id,
        &subject,
        &token,
        API_KEY_JWT_TTL_SECONDS,
    )
    .await;

    (
        StatusCode::OK,
        Json(ApiKeyAuthResponse {
            token,
            expires_at,
            tenant_id: validation_result.tenant_id,
            policies: validation_result.policies,
            lease_id,
        }),
    )
        .into_response()
}

// ---------------------------------------------------------------------------
// Router builder
// ---------------------------------------------------------------------------

/// `GET /v1/identity/.well-known/jwks.json` — public keys for token verification.
///
/// Serves every key a live token might carry, including ones rotating out, so a
/// rotation does not invalidate tokens already in flight.
pub async fn handle_jwks(State(state): State<ApiKeyState>) -> impl IntoResponse {
    let Some(signing_keys) = state.signing_keys.as_ref() else {
        // Empty rather than an error: a deployment still on the legacy shared
        // secret has no per-tenant public keys, and that is a valid state.
        return (StatusCode::OK, Json(serde_json::json!({ "keys": [] }))).into_response();
    };

    match signing_keys.jwks().await {
        Ok(jwks) => (StatusCode::OK, Json(jwks)).into_response(),
        Err(e) => {
            warn!(error = %e, "could not build the JWKS document");
            (
                StatusCode::SERVICE_UNAVAILABLE,
                Json(serde_json::json!({ "message": "signing keys are unavailable" })),
            )
                .into_response()
        }
    }
}

/// `POST /v1/auth/mfa/totp` — complete a login with an authenticator code.
///
/// Accepts either a six-digit TOTP code or a single-use recovery code, so a
/// lost phone is a nuisance rather than a lockout.
pub async fn handle_mfa_verify(
    State(state): State<ApiKeyState>,
    Json(req): Json<crate::mfa::VerifyRequest>,
) -> impl IntoResponse {
    // Taking the challenge removes it, so it cannot be replayed even inside its
    // TTL. A failed code therefore costs a fresh login rather than allowing
    // unlimited guesses against one challenge — which is the rate limit.
    let Some(pending) = state.challenges.take(&req.challenge).await else {
        return (
            StatusCode::FORBIDDEN,
            Json(serde_json::json!({ "message": "challenge is unknown or expired" })),
        )
            .into_response();
    };

    let (Some(pool), Some(crypto)) = (state.mfa_pool.as_ref(), state.crypto.as_ref()) else {
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(serde_json::json!({ "message": "MFA is not configured" })),
        )
            .into_response();
    };

    let mut scope = match mfa_scope(pool, &pending.tenant_id).await {
        Ok(s) => s,
        Err(e) => {
            error!(error = %e, "could not scope the MFA lookup");
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({ "message": "MFA is temporarily unavailable" })),
            )
                .into_response();
        }
    };
    let enrolment = match wslvault_storage::mfa_store::find(scope.conn(), pending.api_key_id).await
    {
        Ok(Some(e)) if e.is_active() => e,
        Ok(_) => {
            return (
                StatusCode::FORBIDDEN,
                Json(serde_json::json!({ "message": "no confirmed authenticator for this key" })),
            )
                .into_response()
        }
        Err(e) => {
            error!(error = %e, "MFA lookup failed");
            return (
                StatusCode::SERVICE_UNAVAILABLE,
                Json(serde_json::json!({ "message": "could not verify the second factor" })),
            )
                .into_response();
        }
    };

    let accepted = match verify_second_factor(pool, crypto, &enrolment, &pending, &req.code).await {
        Ok(v) => v,
        Err(e) => {
            error!(error = %e, "second factor verification failed");
            return (
                StatusCode::SERVICE_UNAVAILABLE,
                Json(serde_json::json!({ "message": "could not verify the second factor" })),
            )
                .into_response();
        }
    };

    if !accepted {
        warn!(
            key_id = %pending.api_key_id,
            tenant_id = %pending.tenant_id,
            "authenticator code rejected"
        );
        return (
            StatusCode::FORBIDDEN,
            Json(serde_json::json!({ "message": "invalid or already-used code" })),
        )
            .into_response();
    }

    let (token, expires_at) = match issue_for_tenant(
        &state,
        &pending.api_key_id.to_string(),
        &pending.tenant_id,
        pending.policies.clone(),
        pending.superuser,
    )
    .await
    {
        Ok(pair) => pair,
        Err(err) => return ApiKeyError::TokenIssuance(err).into_response(),
    };

    if pending.superuser {
        warn!(
            key_id = %pending.api_key_id,
            "SUPERUSER token issued after MFA — grants cross-tenant access"
        );
    }
    info!(key_id = %pending.api_key_id, "MFA accepted; token issued");

    let lease_id = crate::lease_client::try_create_token_lease(
        &pending.tenant_id,
        &pending.api_key_id.to_string(),
        &token,
        API_KEY_JWT_TTL_SECONDS,
    )
    .await;

    (
        StatusCode::OK,
        Json(ApiKeyAuthResponse {
            token,
            expires_at,
            tenant_id: pending.tenant_id.clone(),
            policies: pending.policies.clone(),
            lease_id,
        }),
    )
        .into_response()
}

/// Check a TOTP code, falling back to a recovery code.
///
/// TOTP first: a recovery code is the expensive path and burns a code, so it
/// should only be reached when the normal factor genuinely was not supplied.
async fn verify_second_factor(
    pool: &wslvault_storage::pool::DbPool,
    crypto: &crate::crypto_client::CryptoClient,
    enrolment: &wslvault_storage::mfa_store::TotpEnrolment,
    pending: &crate::mfa::PendingChallenge,
    code: &str,
) -> Result<bool, String> {
    let secret_bytes = crypto
        .unwrap(
            enrolment.tenant_id.to_string(),
            &enrolment.wrapped_secret,
            totp_aad(pending.api_key_id),
        )
        .await?;
    let secret = String::from_utf8(secret_bytes)
        .map_err(|_| "stored TOTP secret is not valid UTF-8".to_string())?;

    // Its own scope: this runs from a match arm where the caller's scope is
    // already borrowed, and both writes below belong to the same tenant anyway.
    let mut scope = mfa_scope(pool, &pending.tenant_id).await?;

    let now = chrono::Utc::now().timestamp();
    if let Some(step) = crate::mfa::verify_code(&secret, code, now) {
        // Replay defence lives in the UPDATE, not here: two requests presenting
        // the same code would otherwise both pass this check before either
        // wrote. See `try_consume_step`.
        let ok =
            wslvault_storage::mfa_store::try_consume_step(scope.conn(), pending.api_key_id, step)
                .await
                .map_err(|e| e.to_string())?;
        scope.commit().await.map_err(|e| e.to_string())?;
        return Ok(ok);
    }

    // Every hash this code could legitimately be stored under — see
    // `mfa::recovery_code_hash_candidates` for why there is more than one.
    let candidates = crate::mfa::recovery_code_hash_candidates(code);
    let ok = wslvault_storage::mfa_store::consume_recovery_code(
        scope.conn(),
        pending.api_key_id,
        &candidates,
    )
    .await
    .map_err(|e| e.to_string())?;
    scope.commit().await.map_err(|e| e.to_string())?;
    Ok(ok)
}

/// AAD binding a wrapped TOTP secret to the key it protects.
fn totp_aad(api_key_id: Uuid) -> Vec<u8> {
    format!("wslvault:mfa:totp:{api_key_id}").into_bytes()
}

/// Request body for enrolment and confirmation.
#[derive(Debug, Deserialize)]
pub struct MfaEnrollRequest {
    /// The API key being enrolled. Proving possession of it is what authorises
    /// enrolment — the same credential the second factor will protect.
    pub api_key: String,
}

#[derive(Debug, Deserialize)]
pub struct MfaConfirmRequest {
    pub api_key: String,
    /// A code generated from the secret just issued, proving the authenticator
    /// was set up correctly before it becomes required.
    pub code: String,
}

#[derive(Debug, Serialize)]
pub struct MfaEnrollResponse {
    /// Base32 secret, for manual entry.
    pub secret: String,
    /// `otpauth://` URI to render as a QR code.
    pub otpauth_uri: String,
    /// Single-use fallbacks. Shown once; only hashes are stored.
    pub recovery_codes: Vec<String>,
    pub warning: String,
}

/// `POST /v1/auth/mfa/totp/enroll` — begin enrolment for an API key.
///
/// Authorised by presenting the key itself. Enrolment does not take effect
/// until confirmed, so a half-finished attempt cannot lock anyone out.
pub async fn handle_mfa_enroll(
    State(state): State<ApiKeyState>,
    Json(req): Json<MfaEnrollRequest>,
) -> impl IntoResponse {
    let validated = match state.manager.validate_key(&req.api_key).await {
        Ok(v) => v,
        Err(e) => return e.into_response(),
    };

    let (Some(pool), Some(crypto)) = (state.mfa_pool.as_ref(), state.crypto.as_ref()) else {
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(serde_json::json!({ "message": "MFA is not configured" })),
        )
            .into_response();
    };

    let tenant_uuid = match Uuid::parse_str(&validated.tenant_id) {
        Ok(u) => u,
        Err(e) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({ "message": format!("tenant is not a UUID: {e}") })),
            )
                .into_response()
        }
    };

    let secret = match crate::mfa::generate_secret() {
        Ok(s) => s,
        Err(e) => {
            error!(error = %e, "TOTP secret generation failed");
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({ "message": "could not generate a secret" })),
            )
                .into_response();
        }
    };

    // Wrapped before storage, so the second factor sits under the root KEK like
    // every other piece of key material and a database dump does not yield it.
    let wrapped = match crypto
        .wrap(
            validated.tenant_id.clone(),
            secret.as_bytes(),
            totp_aad(validated.key_id),
        )
        .await
    {
        Ok(w) => w,
        Err(e) => {
            error!(error = %e, "could not wrap the TOTP secret");
            return (
                StatusCode::SERVICE_UNAVAILABLE,
                Json(serde_json::json!({ "message": format!("could not store the secret: {e}") })),
            )
                .into_response();
        }
    };

    let mut scope = match mfa_scope(pool, &validated.tenant_id).await {
        Ok(s) => s,
        Err(e) => {
            error!(error = %e, "could not scope the MFA enrolment");
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({ "message": "MFA is temporarily unavailable" })),
            )
                .into_response();
        }
    };

    if let Err(e) = wslvault_storage::mfa_store::upsert_pending(
        scope.conn(),
        validated.key_id,
        tenant_uuid,
        &wrapped,
    )
    .await
    {
        return (
            StatusCode::CONFLICT,
            Json(serde_json::json!({ "message": e.to_string() })),
        )
            .into_response();
    }

    let codes = match crate::mfa::generate_recovery_codes(8) {
        Ok(c) => c,
        Err(e) => {
            error!(error = %e, "recovery code generation failed");
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({ "message": "could not generate recovery codes" })),
            )
                .into_response();
        }
    };
    let hashes: Vec<String> = codes.iter().map(|(_, h)| h.clone()).collect();
    if let Err(e) = wslvault_storage::mfa_store::replace_recovery_codes(
        scope.conn(),
        validated.key_id,
        tenant_uuid,
        &hashes,
    )
    .await
    {
        error!(error = %e, "could not store recovery codes");
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(serde_json::json!({ "message": "could not store recovery codes" })),
        )
            .into_response();
    }

    // Both writes commit together: an enrolment without its recovery codes
    // would leave the holder one lost phone away from a dead account.
    if let Err(e) = scope.commit().await {
        error!(error = %e, "could not commit the MFA enrolment");
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(serde_json::json!({ "message": "could not store the enrolment" })),
        )
            .into_response();
    }

    info!(key_id = %validated.key_id, "TOTP enrolment started; awaiting confirmation");

    (
        StatusCode::OK,
        Json(MfaEnrollResponse {
            otpauth_uri: crate::mfa::otpauth_uri(
                &secret,
                &validated.key_id.to_string(),
                "WSLVault",
            ),
            secret,
            recovery_codes: codes.into_iter().map(|(c, _)| c).collect(),
            warning: "Scan the QR code, then confirm with a generated code. Recovery codes are \
                      shown once and stored only as hashes: keep them somewhere you can reach \
                      without this vault."
                .to_string(),
        }),
    )
        .into_response()
}

/// `POST /v1/auth/mfa/totp/confirm` — prove the authenticator works.
///
/// Until this succeeds the enrolment is inert: it neither satisfies a login
/// challenge nor blocks one.
pub async fn handle_mfa_confirm(
    State(state): State<ApiKeyState>,
    Json(req): Json<MfaConfirmRequest>,
) -> impl IntoResponse {
    let validated = match state.manager.validate_key(&req.api_key).await {
        Ok(v) => v,
        Err(e) => return e.into_response(),
    };

    let (Some(pool), Some(crypto)) = (state.mfa_pool.as_ref(), state.crypto.as_ref()) else {
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(serde_json::json!({ "message": "MFA is not configured" })),
        )
            .into_response();
    };

    let mut scope = match mfa_scope(pool, &validated.tenant_id).await {
        Ok(s) => s,
        Err(e) => {
            error!(error = %e, "could not scope the MFA lookup");
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({ "message": "MFA is temporarily unavailable" })),
            )
                .into_response();
        }
    };
    let enrolment = match wslvault_storage::mfa_store::find(scope.conn(), validated.key_id).await {
        Ok(Some(e)) => e,
        Ok(None) => {
            return (
                StatusCode::NOT_FOUND,
                Json(serde_json::json!({ "message": "no enrolment in progress" })),
            )
                .into_response()
        }
        Err(e) => {
            error!(error = %e, "MFA lookup failed");
            return (
                StatusCode::SERVICE_UNAVAILABLE,
                Json(serde_json::json!({ "message": "could not read the enrolment" })),
            )
                .into_response();
        }
    };

    let secret = match crypto
        .unwrap(
            enrolment.tenant_id.to_string(),
            &enrolment.wrapped_secret,
            totp_aad(validated.key_id),
        )
        .await
        .map(String::from_utf8)
    {
        Ok(Ok(s)) => s,
        _ => {
            return (
                StatusCode::SERVICE_UNAVAILABLE,
                Json(serde_json::json!({ "message": "could not read the enrolment secret" })),
            )
                .into_response()
        }
    };

    let now = chrono::Utc::now().timestamp();
    let Some(step) = crate::mfa::verify_code(&secret, &req.code, now) else {
        return (
            StatusCode::FORBIDDEN,
            Json(serde_json::json!({ "message": "that code does not match the enrolment" })),
        )
            .into_response();
    };

    if let Err(e) = wslvault_storage::mfa_store::confirm(scope.conn(), validated.key_id, step).await
    {
        error!(error = %e, "could not confirm the enrolment");
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(serde_json::json!({ "message": "could not confirm the enrolment" })),
        )
            .into_response();
    }

    // Without this the ScopedTx rolls back on drop and the confirmation is
    // silently discarded: the caller is told "confirmed" while the enrolment
    // stays pending and mfa_required stays false. Dropping a transaction is not
    // a compile error, so this is the one line the type system cannot enforce.
    if let Err(e) = scope.commit().await {
        error!(error = %e, "could not commit the MFA confirmation");
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(serde_json::json!({ "message": "could not confirm the enrolment" })),
        )
            .into_response();
    }

    info!(key_id = %validated.key_id, "TOTP enrolment confirmed");
    (
        StatusCode::OK,
        Json(serde_json::json!({
            "confirmed": true,
            "message": "authenticator confirmed; it is now required for this key"
        })),
    )
        .into_response()
}

/// Builds an [`axum::Router`] containing all API-key routes.
///
/// The four management routes sit behind [`require_admin`]; `/v1/auth/api-key`
/// deliberately does not, because it *is* the login endpoint — its credential
/// is the API key in the request body.
///
/// Mount alongside other service routers at startup:
/// ```no_run
/// let app = health::router()
///     .merge(tenant_handlers::router(tenant_store))
///     .merge(api_keys::router(api_key_state, admin_auth));
/// ```
pub fn router(state: ApiKeyState, admin_auth: AdminAuth) -> Router {
    let management = Router::new()
        .route(
            "/v1/api-keys",
            post(handle_create_api_key).get(handle_list_api_keys),
        )
        .route("/v1/api-keys/:id", delete(handle_revoke_api_key))
        .route("/v1/api-keys/:id/rotate", post(handle_rotate_api_key))
        .with_state(state.clone())
        .layer(axum::middleware::from_fn_with_state(
            admin_auth,
            require_admin,
        ));

    let exchange = Router::new()
        .route("/v1/auth/api-key", post(handle_auth_api_key))
        // Public on purpose: it serves public keys. Verifiers need it without
        // holding a credential, and a public key confers no ability to sign.
        .route("/v1/identity/.well-known/jwks.json", get(handle_jwks))
        // Second-factor routes. Not token-authenticated on purpose: possession
        // of the API key authorises them, and the whole point is that a token
        // has not been issued yet.
        .route("/v1/auth/mfa/totp", post(handle_mfa_verify))
        .route("/v1/auth/mfa/totp/enroll", post(handle_mfa_enroll))
        .route("/v1/auth/mfa/totp/confirm", post(handle_mfa_confirm))
        .with_state(state);

    management.merge(exchange)
}

// ---------------------------------------------------------------------------
// Unit tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{
        body::Body,
        http::{Request, StatusCode},
    };
    use tower::ServiceExt;

    fn make_token_manager() -> TokenManager {
        TokenManager::new(b"test-secret-that-is-at-least-32-bytes-long!!")
    }

    fn make_state() -> ApiKeyState {
        ApiKeyState {
            signing_keys: None,
            mfa_pool: None,
            crypto: None,
            challenges: crate::mfa::ChallengeStore::new(),
            manager: ApiKeyManager::new(),
            token_manager: make_token_manager(),
        }
    }

    /// Bootstrap credential used by the HTTP tests.
    const TEST_ADMIN_TOKEN: &str = "test-bootstrap-admin-token";

    fn make_admin_auth() -> AdminAuth {
        AdminAuth::new(
            make_token_manager(),
            Some(TEST_ADMIN_TOKEN.as_bytes().to_vec()),
            "admin",
        )
    }

    /// Builds the full router with the admin gate active.
    fn make_app() -> Router {
        router(make_state(), make_admin_auth())
    }

    // -----------------------------------------------------------------------
    // Key generation / hashing
    // -----------------------------------------------------------------------

    #[test]
    fn generated_key_has_correct_prefix() {
        let key = ApiKeyManager::generate_key();
        assert!(
            key.starts_with(RAW_KEY_PREFIX),
            "key should start with '{RAW_KEY_PREFIX}', got: {key}"
        );
    }

    #[test]
    fn generated_key_has_sufficient_entropy() {
        let key = ApiKeyManager::generate_key();
        let random_part = key.strip_prefix(RAW_KEY_PREFIX).unwrap();
        // 32 bytes base64url-encoded = ceil(32*4/3) = 43 characters.
        assert!(
            random_part.len() >= 40,
            "random portion should be at least 40 chars, got: {}",
            random_part.len()
        );
    }

    #[test]
    fn hash_key_is_deterministic() {
        let hash1 = ApiKeyManager::hash_key("wslv_test_key");
        let hash2 = ApiKeyManager::hash_key("wslv_test_key");
        assert_eq!(hash1, hash2);
    }

    #[test]
    fn hash_key_differs_for_different_keys() {
        let hash1 = ApiKeyManager::hash_key("wslv_key_one");
        let hash2 = ApiKeyManager::hash_key("wslv_key_two");
        assert_ne!(hash1, hash2);
    }

    #[test]
    fn parse_key_random_portion_rejects_missing_prefix() {
        assert!(ApiKeyManager::parse_key_random_portion("noprefix_abc").is_err());
    }

    #[test]
    fn parse_key_random_portion_rejects_prefix_only() {
        assert!(ApiKeyManager::parse_key_random_portion("wslv_").is_err());
    }

    // -----------------------------------------------------------------------
    // Create
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn create_key_returns_raw_key_once() {
        let mgr = ApiKeyManager::new();
        let req = ApiKeyCreateRequest {
            name: "ci-bot".into(),
            tenant_id: "tenant-1".into(),
            policies: Some(vec!["read".into()]),
            path_prefixes: None,
            expires_in_seconds: None,
            rate_limit_per_minute: None,
            is_superuser: false,
            mfa_required: false,
        };
        let response = mgr.create_key(req, "operator").await.unwrap();

        assert!(response.key.starts_with(RAW_KEY_PREFIX));
        assert_eq!(response.name, "ci-bot");
        assert_eq!(response.tenant_id, "tenant-1");
        assert_eq!(response.policies, vec!["read"]);
        assert_eq!(response.key_prefix.len(), KEY_PREFIX_DISPLAY_LEN);
    }

    #[tokio::test]
    async fn create_key_rejects_duplicate_name_within_tenant() {
        let mgr = ApiKeyManager::new();
        let make_req = || ApiKeyCreateRequest {
            name: "dup-key".into(),
            tenant_id: "tenant-dup".into(),
            policies: None,
            path_prefixes: None,
            expires_in_seconds: None,
            rate_limit_per_minute: None,
            is_superuser: false,
            mfa_required: false,
        };
        mgr.create_key(make_req(), "op").await.unwrap();
        let err = mgr.create_key(make_req(), "op").await.unwrap_err();
        assert!(matches!(err, ApiKeyError::DuplicateName(_)));
    }

    #[tokio::test]
    async fn create_key_allows_same_name_across_tenants() {
        let mgr = ApiKeyManager::new();
        let req1 = ApiKeyCreateRequest {
            name: "deploy-key".into(),
            tenant_id: "tenant-a".into(),
            policies: None,
            path_prefixes: None,
            expires_in_seconds: None,
            rate_limit_per_minute: None,
            is_superuser: false,
            mfa_required: false,
        };
        let req2 = ApiKeyCreateRequest {
            name: "deploy-key".into(),
            tenant_id: "tenant-b".into(),
            policies: None,
            path_prefixes: None,
            expires_in_seconds: None,
            rate_limit_per_minute: None,
            is_superuser: false,
            mfa_required: false,
        };
        assert!(mgr.create_key(req1, "op").await.is_ok());
        assert!(mgr.create_key(req2, "op").await.is_ok());
    }

    // -----------------------------------------------------------------------
    // Validate
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn validate_key_succeeds_for_valid_key() {
        let mgr = ApiKeyManager::new();
        let req = ApiKeyCreateRequest {
            name: "valid-key".into(),
            tenant_id: "tenant-v".into(),
            policies: Some(vec!["read".into(), "write".into()]),
            path_prefixes: Some(vec!["secret/data/".into()]),
            expires_in_seconds: None,
            rate_limit_per_minute: Some(120),
            is_superuser: false,
            mfa_required: false,
        };
        let create_resp = mgr.create_key(req, "op").await.unwrap();

        let validation = mgr.validate_key(&create_resp.key).await.unwrap();
        assert_eq!(validation.tenant_id, "tenant-v");
        assert_eq!(validation.policies, vec!["read", "write"]);
        assert_eq!(validation.path_prefixes, vec!["secret/data/"]);
        assert_eq!(validation.rate_limit_per_minute, 120);
    }

    #[tokio::test]
    async fn validate_key_rejects_unknown_key() {
        let mgr = ApiKeyManager::new();
        let err = mgr
            .validate_key("wslv_unknownkeyunknownkeyunknownkey1234")
            .await
            .unwrap_err();
        assert!(matches!(err, ApiKeyError::KeyNotFound));
    }

    #[tokio::test]
    async fn validate_key_rejects_revoked_key() {
        let mgr = ApiKeyManager::new();
        let req = ApiKeyCreateRequest {
            name: "revoke-me".into(),
            tenant_id: "tenant-r".into(),
            policies: None,
            path_prefixes: None,
            expires_in_seconds: None,
            rate_limit_per_minute: None,
            is_superuser: false,
            mfa_required: false,
        };
        let resp = mgr.create_key(req, "op").await.unwrap();
        mgr.revoke_key(resp.id, "tenant-r").await.unwrap();

        let err = mgr.validate_key(&resp.key).await.unwrap_err();
        assert!(matches!(err, ApiKeyError::KeyRevoked));
    }

    #[tokio::test]
    async fn validate_key_rejects_expired_key() {
        let mgr = ApiKeyManager::new();
        let req = ApiKeyCreateRequest {
            name: "expire-me".into(),
            tenant_id: "tenant-e".into(),
            policies: None,
            path_prefixes: None,
            // Negative TTL: the key is created already-expired.
            expires_in_seconds: Some(-1),
            rate_limit_per_minute: None,
            is_superuser: false,
            mfa_required: false,
        };
        let resp = mgr.create_key(req, "op").await.unwrap();

        let err = mgr.validate_key(&resp.key).await.unwrap_err();
        assert!(matches!(err, ApiKeyError::KeyExpired));
    }

    #[tokio::test]
    async fn validate_key_rejects_invalid_format() {
        let mgr = ApiKeyManager::new();
        let err = mgr.validate_key("not-a-wslv-key").await.unwrap_err();
        assert!(matches!(err, ApiKeyError::InvalidKeyFormat));
    }

    // -----------------------------------------------------------------------
    // Revoke
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn revoke_key_cross_tenant_is_rejected() {
        let mgr = ApiKeyManager::new();
        let req = ApiKeyCreateRequest {
            name: "cross-tenant-key".into(),
            tenant_id: "tenant-owner".into(),
            policies: None,
            path_prefixes: None,
            expires_in_seconds: None,
            rate_limit_per_minute: None,
            is_superuser: false,
            mfa_required: false,
        };
        let resp = mgr.create_key(req, "op").await.unwrap();

        // Attempt to revoke with wrong tenant id.
        let err = mgr
            .revoke_key(resp.id, "tenant-attacker")
            .await
            .unwrap_err();
        assert!(matches!(err, ApiKeyError::KeyNotFound));
    }

    // -----------------------------------------------------------------------
    // List
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn list_keys_excludes_revoked_and_other_tenants() {
        let mgr = ApiKeyManager::new();

        // Create two keys for tenant-a, one for tenant-b.
        for name in ["key-1", "key-2"] {
            let req = ApiKeyCreateRequest {
                name: name.into(),
                tenant_id: "tenant-a".into(),
                policies: None,
                path_prefixes: None,
                expires_in_seconds: None,
                rate_limit_per_minute: None,
                is_superuser: false,
                mfa_required: false,
            };
            mgr.create_key(req, "op").await.unwrap();
        }
        let req_b = ApiKeyCreateRequest {
            name: "key-b".into(),
            tenant_id: "tenant-b".into(),
            policies: None,
            path_prefixes: None,
            expires_in_seconds: None,
            rate_limit_per_minute: None,
            is_superuser: false,
            mfa_required: false,
        };
        let resp_b = mgr.create_key(req_b, "op").await.unwrap();

        // Revoke one tenant-a key.
        let all_a = mgr.list_keys("tenant-a").await.unwrap();
        mgr.revoke_key(all_a[0].id, "tenant-a").await.unwrap();

        let active_a = mgr.list_keys("tenant-a").await.unwrap();
        assert_eq!(
            active_a.len(),
            1,
            "only 1 active key should remain for tenant-a"
        );

        let active_b = mgr.list_keys("tenant-b").await.unwrap();
        assert_eq!(active_b.len(), 1);
        assert_eq!(active_b[0].id, resp_b.id);
    }

    #[tokio::test]
    async fn list_keys_does_not_expose_key_hash() {
        let mgr = ApiKeyManager::new();
        let req = ApiKeyCreateRequest {
            name: "hash-guard-key".into(),
            tenant_id: "tenant-hg".into(),
            policies: None,
            path_prefixes: None,
            expires_in_seconds: None,
            rate_limit_per_minute: None,
            is_superuser: false,
            mfa_required: false,
        };
        mgr.create_key(req, "op").await.unwrap();

        let keys = mgr.list_keys("tenant-hg").await.unwrap();
        assert_eq!(keys.len(), 1);
        assert!(
            keys[0].key_hash.is_empty(),
            "list_keys must not expose the SHA-256 hash"
        );
    }

    // -----------------------------------------------------------------------
    // Rotate
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn rotate_key_issues_new_key_and_revokes_old() {
        let mgr = ApiKeyManager::new();
        let req = ApiKeyCreateRequest {
            name: "rotate-me".into(),
            tenant_id: "tenant-rot".into(),
            policies: Some(vec!["admin".into()]),
            path_prefixes: Some(vec!["secret/".into()]),
            expires_in_seconds: None,
            rate_limit_per_minute: Some(30),
            is_superuser: false,
            mfa_required: false,
        };
        let old_resp = mgr.create_key(req, "op").await.unwrap();
        let old_id = old_resp.id;

        let new_resp = mgr.rotate_key(old_id, "tenant-rot").await.unwrap();

        // New key should differ from the old one.
        assert_ne!(new_resp.id, old_id);
        assert_ne!(new_resp.key, old_resp.key);

        // New key inherits the same configuration.
        assert_eq!(new_resp.name, "rotate-me");
        assert_eq!(new_resp.policies, vec!["admin"]);
        assert_eq!(new_resp.path_prefixes, vec!["secret/"]);

        // Old key should now be revoked.
        let err = mgr.validate_key(&old_resp.key).await.unwrap_err();
        assert!(matches!(err, ApiKeyError::KeyRevoked));

        // New key should be valid.
        let validation = mgr.validate_key(&new_resp.key).await.unwrap();
        assert_eq!(validation.tenant_id, "tenant-rot");
    }

    // -----------------------------------------------------------------------
    // HTTP integration tests
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn http_create_api_key_returns_201() {
        let app = make_app();
        let body = serde_json::json!({
            "name": "http-test-key",
            "tenant_id": "http-tenant",
            "policies": ["read"]
        });
        let req = Request::builder()
            .method("POST")
            .uri("/v1/api-keys")
            .header("content-type", "application/json")
            .header(ADMIN_TOKEN_HEADER, TEST_ADMIN_TOKEN)
            .body(Body::from(serde_json::to_string(&body).unwrap()))
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::CREATED);
    }

    #[tokio::test]
    async fn http_list_api_keys_requires_tenant_header() {
        let app = make_app();
        let req = Request::builder()
            .method("GET")
            .uri("/v1/api-keys")
            .header(ADMIN_TOKEN_HEADER, TEST_ADMIN_TOKEN)
            .body(Body::empty())
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn http_auth_api_key_returns_jwt() {
        let state = make_state();
        // Pre-create a key directly via the manager.
        let req = ApiKeyCreateRequest {
            name: "auth-test-key".into(),
            tenant_id: "auth-tenant".into(),
            policies: Some(vec!["read".into()]),
            path_prefixes: None,
            expires_in_seconds: None,
            rate_limit_per_minute: None,
            is_superuser: false,
            mfa_required: false,
        };
        let create_resp = state.manager.create_key(req, "op").await.unwrap();

        let app = router(state, make_admin_auth());
        let body = serde_json::json!({ "api_key": create_resp.key });
        let req = Request::builder()
            .method("POST")
            .uri("/v1/auth/api-key")
            .header("content-type", "application/json")
            .body(Body::from(serde_json::to_string(&body).unwrap()))
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
    }

    // -----------------------------------------------------------------------
    // Administrative authentication on the management routes
    // -----------------------------------------------------------------------

    /// Body helper: creates a key-creation request for `tenant`.
    fn create_body(name: &str, tenant: &str) -> String {
        serde_json::to_string(&serde_json::json!({
            "name": name,
            "tenant_id": tenant,
            "policies": ["read"],
        }))
        .unwrap()
    }

    /// A platform administrator is not a superuser.
    ///
    /// `is_superuser` came straight off the request body with no check, so any
    /// caller who could reach key management could grant themselves
    /// cross-tenant access to every secret in the deployment. Reproduced
    /// against a running instance before this guard existed: three superuser
    /// keys minted from an ordinary tenant credential.
    #[tokio::test]
    async fn a_non_superuser_cannot_mint_a_superuser_key() {
        let app = make_app();
        let (token, _) = make_token_manager()
            .issue_token(
                "admin-1",
                "tenant-x",
                vec![DEFAULT_ADMIN_POLICY.to_string()],
                3600,
            )
            .unwrap();

        let body = serde_json::to_string(&serde_json::json!({
            "name": "escalate",
            "tenant_id": "tenant-x",
            "policies": ["read"],
            "is_superuser": true,
            "mfa_required": true,
        }))
        .unwrap();

        let req = Request::builder()
            .method("POST")
            .uri("/v1/api-keys")
            .header("content-type", "application/json")
            .header("authorization", format!("Bearer {token}"))
            .body(Body::from(body))
            .unwrap();

        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(
            resp.status(),
            StatusCode::FORBIDDEN,
            "carrying the administrator policy must not confer the ability to \
             mint cross-tenant superuser keys"
        );
    }

    /// The bootstrap token may, because that is how the first one exists.
    #[tokio::test]
    async fn the_bootstrap_token_may_mint_a_superuser_key() {
        let app = make_app();
        let body = serde_json::to_string(&serde_json::json!({
            "name": "first-superuser",
            "tenant_id": "tenant-x",
            "policies": ["root"],
            "is_superuser": true,
            "mfa_required": true,
        }))
        .unwrap();

        let req = Request::builder()
            .method("POST")
            .uri("/v1/api-keys")
            .header("content-type", "application/json")
            .header(ADMIN_TOKEN_HEADER, TEST_ADMIN_TOKEN)
            .body(Body::from(body))
            .unwrap();

        let resp = app.oneshot(req).await.unwrap();
        assert_ne!(
            resp.status(),
            StatusCode::FORBIDDEN,
            "the bootstrap path must remain able to create the first superuser, \
             or a fresh deployment has no way to get one"
        );
    }

    #[tokio::test]
    async fn create_without_any_credential_is_rejected() {
        let app = make_app();
        let req = Request::builder()
            .method("POST")
            .uri("/v1/api-keys")
            .header("content-type", "application/json")
            .body(Body::from(create_body("no-cred", "t")))
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(
            resp.status(),
            StatusCode::UNAUTHORIZED,
            "minting a key must not be possible without an administrator credential"
        );
    }

    #[tokio::test]
    async fn create_with_wrong_bootstrap_token_is_rejected() {
        let app = make_app();
        let req = Request::builder()
            .method("POST")
            .uri("/v1/api-keys")
            .header("content-type", "application/json")
            .header(ADMIN_TOKEN_HEADER, "not-the-token")
            .body(Body::from(create_body("wrong-cred", "t")))
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn create_with_bootstrap_token_prefix_is_rejected() {
        // A truncated token must not authenticate: the comparison is over the
        // whole value, not a prefix.
        let app = make_app();
        let req = Request::builder()
            .method("POST")
            .uri("/v1/api-keys")
            .header("content-type", "application/json")
            .header(
                ADMIN_TOKEN_HEADER,
                &TEST_ADMIN_TOKEN[..TEST_ADMIN_TOKEN.len() - 1],
            )
            .body(Body::from(create_body("prefix-cred", "t")))
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn create_with_jwt_lacking_admin_policy_is_rejected() {
        let app = make_app();
        let (token, _) = make_token_manager()
            .issue_token("user-1", "tenant-x", vec!["read".into()], 3600)
            .unwrap();

        let req = Request::builder()
            .method("POST")
            .uri("/v1/api-keys")
            .header("content-type", "application/json")
            .header("authorization", format!("Bearer {token}"))
            .body(Body::from(create_body("non-admin", "tenant-x")))
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(
            resp.status(),
            StatusCode::FORBIDDEN,
            "a valid token without the admin policy must not mint keys — and the \
             refusal must be 403, not 401. This asserted 401 until the UI was found \
             to treat 401 as 'session is dead' and log the user out, which ejected \
             every non-administrator the moment the dashboard fetched an admin-gated \
             resource on load."
        );
    }

    #[tokio::test]
    async fn create_with_admin_jwt_succeeds() {
        let app = make_app();
        let (token, _) = make_token_manager()
            .issue_token("admin-1", "tenant-x", vec!["admin".into()], 3600)
            .unwrap();

        let req = Request::builder()
            .method("POST")
            .uri("/v1/api-keys")
            .header("content-type", "application/json")
            .header("authorization", format!("Bearer {token}"))
            .body(Body::from(create_body("admin-made", "tenant-x")))
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::CREATED);
    }

    #[tokio::test]
    async fn expired_admin_jwt_is_rejected() {
        let app = make_app();
        let (token, _) = make_token_manager()
            .issue_token("admin-1", "tenant-x", vec!["admin".into()], -1)
            .unwrap();

        let req = Request::builder()
            .method("POST")
            .uri("/v1/api-keys")
            .header("content-type", "application/json")
            .header("authorization", format!("Bearer {token}"))
            .body(Body::from(create_body("expired-admin", "tenant-x")))
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn admin_jwt_cannot_mint_into_another_tenant() {
        let state = make_state();
        let app = router(state.clone(), make_admin_auth());
        let (token, _) = make_token_manager()
            .issue_token("admin-1", "tenant-own", vec!["admin".into()], 3600)
            .unwrap();

        // Ask for a key in "tenant-victim" while holding a "tenant-own" token.
        let req = Request::builder()
            .method("POST")
            .uri("/v1/api-keys")
            .header("content-type", "application/json")
            .header("authorization", format!("Bearer {token}"))
            .body(Body::from(create_body("cross-tenant", "tenant-victim")))
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::CREATED);

        let body = axum::body::to_bytes(resp.into_body(), 64 * 1024)
            .await
            .unwrap();
        let parsed: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(
            parsed["tenant_id"], "tenant-own",
            "the token's tenant must win over the request body"
        );

        // And nothing landed in the tenant the body named.
        assert!(
            state
                .manager
                .list_keys("tenant-victim")
                .await
                .unwrap()
                .is_empty(),
            "no key may be created in a tenant the caller does not hold"
        );
    }

    #[tokio::test]
    async fn created_by_records_the_authenticated_principal() {
        let state = make_state();
        let app = router(state.clone(), make_admin_auth());
        let (token, _) = make_token_manager()
            .issue_token("admin-jane", "tenant-cb", vec!["admin".into()], 3600)
            .unwrap();

        let req = Request::builder()
            .method("POST")
            .uri("/v1/api-keys")
            .header("content-type", "application/json")
            .header("authorization", format!("Bearer {token}"))
            // A forged principal header must not be believed.
            .header("x-principal-id", "somebody-else")
            .body(Body::from(create_body("audit-key", "tenant-cb")))
            .unwrap();
        assert_eq!(
            app.oneshot(req).await.unwrap().status(),
            StatusCode::CREATED
        );

        let keys = state.manager.list_keys("tenant-cb").await.unwrap();
        assert_eq!(keys.len(), 1);
        assert_eq!(
            keys[0].created_by, "admin-jane",
            "created_by must come from the authenticated identity, not a header"
        );
    }

    #[tokio::test]
    async fn revoke_and_rotate_require_admin() {
        for (method, uri) in [
            (
                "DELETE",
                "/v1/api-keys/019f5b59-385c-7f61-b073-8a1ae402cf4c",
            ),
            (
                "POST",
                "/v1/api-keys/019f5b59-385c-7f61-b073-8a1ae402cf4c/rotate",
            ),
        ] {
            let app = make_app();
            let req = Request::builder()
                .method(method)
                .uri(uri)
                .header("x-tenant-id", "t")
                .body(Body::empty())
                .unwrap();
            let resp = app.oneshot(req).await.unwrap();
            assert_eq!(
                resp.status(),
                StatusCode::UNAUTHORIZED,
                "{method} {uri} must require an administrator credential"
            );
        }
    }

    #[tokio::test]
    async fn listing_requires_admin() {
        let app = make_app();
        let req = Request::builder()
            .method("GET")
            .uri("/v1/api-keys")
            .header("x-tenant-id", "t")
            .body(Body::empty())
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn key_exchange_stays_open_without_admin_credential() {
        // /v1/auth/api-key is the login endpoint: its credential is the API key
        // in the body, so the admin gate must not apply to it.
        let state = make_state();
        let created = state
            .manager
            .create_key(
                ApiKeyCreateRequest {
                    name: "login-key".into(),
                    tenant_id: "tenant-login".into(),
                    policies: Some(vec!["read".into()]),
                    path_prefixes: None,
                    expires_in_seconds: None,
                    rate_limit_per_minute: None,
                    is_superuser: false,
                    mfa_required: false,
                },
                "op",
            )
            .await
            .unwrap();

        let app = router(state, make_admin_auth());
        let req = Request::builder()
            .method("POST")
            .uri("/v1/auth/api-key")
            .header("content-type", "application/json")
            .body(Body::from(
                serde_json::json!({ "api_key": created.key }).to_string(),
            ))
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn bootstrap_path_is_unavailable_when_no_token_is_configured() {
        // With VAULT_ADMIN_TOKEN unset there is no bootstrap credential at all,
        // so an X-Admin-Token header must never authenticate.
        let app = router(
            make_state(),
            AdminAuth::new(make_token_manager(), None, "admin"),
        );
        let req = Request::builder()
            .method("POST")
            .uri("/v1/api-keys")
            .header("content-type", "application/json")
            .header(ADMIN_TOKEN_HEADER, "")
            .body(Body::from(create_body("no-bootstrap", "t")))
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn http_auth_invalid_api_key_returns_401() {
        let app = make_app();
        let body = serde_json::json!({ "api_key": "wslv_invalidkeyinvalidkeyinvalidkey00000" });
        let req = Request::builder()
            .method("POST")
            .uri("/v1/auth/api-key")
            .header("content-type", "application/json")
            .body(Body::from(serde_json::to_string(&body).unwrap()))
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        // KeyNotFound maps to 404, which is intentionally opaque to attackers.
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    }

    /// A tenant administrator is not a platform administrator.
    ///
    /// The default required policy used to be `"admin"` — the single most
    /// likely name a tenant gives its own admin policy — and carrying it grants
    /// authority over every tenant in the deployment. Any tenant that created
    /// an `admin` policy for its own users was silently handing them the estate.
    #[tokio::test]
    async fn a_tenants_own_admin_policy_is_not_platform_administration() {
        let tm = TokenManager::new(b"test-secret-that-is-at-least-32-bytes!!");
        let auth = AdminAuth::new(tm.clone(), None, DEFAULT_ADMIN_POLICY);

        // A perfectly ordinary tenant user whose policy happens to be "admin".
        let (token, _) = tm
            .issue_token("user-1", "some-tenant", vec!["admin".into()], 3600)
            .expect("issue");

        let mut headers = HeaderMap::new();
        headers.insert(
            axum::http::header::AUTHORIZATION,
            format!("Bearer {token}").parse().unwrap(),
        );

        assert!(
            matches!(
                auth.authenticate(&headers).await,
                Err(AdminRejection::Forbidden)
            ),
            "a tenant-scoped 'admin' policy must not confer platform administration, \
             and the refusal must be Forbidden — Unauthenticated would make the UI \
             log this perfectly valid session out"
        );
    }

    /// No credential at all is a different answer from the wrong one.
    #[tokio::test]
    async fn a_missing_credential_is_unauthenticated_not_forbidden() {
        let tm = TokenManager::new(b"test-secret-that-is-at-least-32-bytes!!");
        let auth = AdminAuth::new(tm, None, DEFAULT_ADMIN_POLICY);

        assert!(matches!(
            auth.authenticate(&HeaderMap::new()).await,
            Err(AdminRejection::Unauthenticated)
        ));
    }

    /// The namespaced policy does confer it.
    #[tokio::test]
    async fn the_platform_admin_policy_is_accepted() {
        let tm = TokenManager::new(b"test-secret-that-is-at-least-32-bytes!!");
        let auth = AdminAuth::new(tm.clone(), None, DEFAULT_ADMIN_POLICY);

        let (token, _) = tm
            .issue_token(
                "ops-1",
                "some-tenant",
                vec![DEFAULT_ADMIN_POLICY.to_string()],
                3600,
            )
            .expect("issue");

        let mut headers = HeaderMap::new();
        headers.insert(
            axum::http::header::AUTHORIZATION,
            format!("Bearer {token}").parse().unwrap(),
        );

        assert!(auth.authenticate(&headers).await.is_ok());
    }
}
