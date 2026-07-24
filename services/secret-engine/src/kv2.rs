//! HashiCorp Vault **KV v2 compatibility layer**.
//!
//! Presents the wslvault secret engine through the subset of the HashiCorp
//! Vault HTTP API that standard Vault clients speak, so tooling built for Vault
//! works against wslvault unchanged. The immediate driver is the External
//! Secrets Operator (ESO), whose `vault` provider is the standard way to sync
//! secrets into Kubernetes — but the same surface serves the `vault` CLI, the
//! Terraform provider, and anything else written against Vault's KV v2 API.
//!
//! # Why a separate mount
//!
//! The native API at `/v1/secret/data/*` returns wslvault's own shape
//! (`{"data": "<base64 blob>", "version": N, ...}`) and is consumed by the UI,
//! the SDKs and the CLI. Changing it would break all of them, so the
//! Vault-compatible surface lives at its own mount: `/v1/kv/...`.
//!
//! Point ESO at it with `path: kv` in the SecretStore, e.g.
//!
//! ```yaml
//! provider:
//!   vault:
//!     server: "https://vault.workstation.co.uk"
//!     path: "kv"
//!     version: "v2"
//!     auth:
//!       tokenSecretRef: { name: wslvault-token, key: token }
//! ```
//!
//! # Data-model bridge
//!
//! This is the substantive difference between the two systems:
//!
//! | | HashiCorp KV v2 | wslvault native |
//! |---|---|---|
//! | Value at a path | map of key → value | one opaque blob |
//!
//! We bridge by serialising the map to JSON and storing *that* as the blob, so
//! the underlying storage, envelope encryption and versioning are unchanged. A
//! read parses it back into a map.
//!
//! A blob that is **not** a JSON object — e.g. one written through the native
//! API — is surfaced under a single `value` key (UTF-8 if it is valid text,
//! base64 otherwise) rather than erroring, so pre-existing secrets stay
//! readable through this mount.
//!
//! # Authentication
//!
//! [`resolve_identity`] accepts, in order:
//!
//! 1. `X-Tenant-Id` (+ `X-Principal-Id`, `X-Policies`) — the existing internal
//!    contract used by the native handlers.
//! 2. `X-Vault-Tenant-ID` (+ `X-Vault-Principal-ID`, `X-Vault-Policies`) — what
//!    `gateway/lua/auth/token_auth.lua` actually injects on a token-cache hit.
//! 3. `X-Vault-Token` (or `Authorization: Bearer …`) — a wslvault JWT, verified
//!    here with HS256 against the shared `VAULT_JWT_SECRET`. This is what Vault
//!    clients such as ESO send.
//!
//! Tier 3 **fails closed**: if `VAULT_JWT_SECRET` is not configured the token is
//! rejected rather than trusted, because accepting unverified claims would let
//! any caller that can reach this service assert an arbitrary tenant.

use std::collections::HashMap;

use axum::{
    extract::{Path, Query, State},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    routing::get,
    Json, Router,
};
use base64::Engine as _;
use jsonwebtoken::{decode, Algorithm, DecodingKey, Validation};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use tracing::{error, info, instrument};

use crate::grpc::crypto_proto;
use crate::http::AppState;
use crate::path::normalize_and_validate;

/// Environment variable holding the shared HS256 signing secret. Must match the
/// value identity-service issues tokens with, or token auth cannot be verified.
const JWT_SECRET_ENV: &str = "VAULT_JWT_SECRET";

// ─── Vault-shaped errors ─────────────────────────────────────────────────────

/// Vault returns errors as `{"errors": ["..."]}`; clients parse that shape, so
/// this mount must not emit wslvault's native `{"code","message"}` body.
#[derive(Debug, Serialize)]
struct VaultErrorBody {
    errors: Vec<String>,
}

fn vault_error(status: StatusCode, message: impl Into<String>) -> Response {
    (
        status,
        Json(VaultErrorBody {
            errors: vec![message.into()],
        }),
    )
        .into_response()
}

// ─── Identity ────────────────────────────────────────────────────────────────

/// The caller, resolved from headers or a verified token.
#[derive(Debug, Clone)]
pub struct Identity {
    pub tenant_id: String,
    pub principal_id: String,
    pub policies: Vec<String>,
    /// Unix expiry when the caller authenticated with a token. `None` for the
    /// gateway header paths, which carry no token lifetime of their own.
    pub expires_at: Option<i64>,
}

/// Claims issued by identity-service (`services/identity-service/src/token.rs`).
/// Unknown fields (`iss`, `iat`, …) are ignored by serde.
#[derive(Debug, Deserialize)]
struct TokenClaims {
    sub: String,
    tenant_id: String,
    #[serde(default)]
    policies: Vec<String>,
    /// Unix expiry. Surfaced by lookup-self as `expire_time`/`ttl`, which
    /// Vault clients require — ESO rejects a store with "no expiration time
    /// found in response" when it is missing.
    exp: i64,
}

fn header_value<'a>(headers: &'a HeaderMap, name: &str) -> Option<&'a str> {
    headers
        .get(name)
        .and_then(|v| v.to_str().ok())
        .filter(|s| !s.is_empty())
}

fn split_csv(raw: Option<&str>) -> Vec<String> {
    raw.map(|s| {
        s.split(',')
            .map(|p| p.trim().to_string())
            .filter(|p| !p.is_empty())
            .collect()
    })
    .unwrap_or_default()
}

/// Extract a token from `X-Vault-Token` (what Vault clients send) or an
/// `Authorization: Bearer` header.
fn extract_token(headers: &HeaderMap) -> Option<String> {
    if let Some(t) = header_value(headers, "x-vault-token") {
        return Some(t.to_string());
    }
    header_value(headers, "authorization")
        .and_then(|a| {
            a.strip_prefix("Bearer ")
                .or_else(|| a.strip_prefix("bearer "))
        })
        .map(|t| t.trim().to_string())
        .filter(|t| !t.is_empty())
}

/// Verify a wslvault JWT (HS256, shared `VAULT_JWT_SECRET`) and return its claims.
fn verify_token(token: &str) -> Result<TokenClaims, String> {
    let secret = std::env::var(JWT_SECRET_ENV).map_err(|_| {
        format!("{JWT_SECRET_ENV} is not configured; token authentication is unavailable")
    })?;
    if secret.is_empty() {
        return Err(format!(
            "{JWT_SECRET_ENV} is empty; token authentication is unavailable"
        ));
    }
    // Defaults already require and validate `exp`; issuer/audience are not
    // enforced so tokens from any configured identity provider are accepted.
    let validation = Validation::new(Algorithm::HS256);
    decode::<TokenClaims>(
        token,
        &DecodingKey::from_secret(secret.as_bytes()),
        &validation,
    )
    .map(|data| data.claims)
    .map_err(|e| format!("invalid token: {e}"))
}

/// Resolve the calling identity. See the module docs for the precedence order.
///
/// The `Err` variant is an already-rendered `Response` so callers can return it
/// verbatim; `axum::Response` is inherently large, hence the allow (the same
/// convention the gRPC handlers in this workspace use).
#[allow(clippy::result_large_err)]
pub fn resolve_identity(headers: &HeaderMap) -> Result<Identity, Response> {
    // 1. Native internal contract.
    if let Some(tenant) = header_value(headers, "x-tenant-id") {
        return Ok(Identity {
            tenant_id: tenant.to_string(),
            principal_id: header_value(headers, "x-principal-id")
                .unwrap_or("anonymous")
                .to_string(),
            policies: split_csv(header_value(headers, "x-policies")),
            expires_at: None,
        });
    }

    // 2. Headers the gateway injects on a token-cache hit. The gateway writes
    //    the `X-Vault-*` spelling while the native handlers read `x-tenant-id`,
    //    so honouring both keeps gateway-authenticated requests working.
    if let Some(tenant) = header_value(headers, "x-vault-tenant-id") {
        return Ok(Identity {
            tenant_id: tenant.to_string(),
            principal_id: header_value(headers, "x-vault-principal-id")
                .unwrap_or("anonymous")
                .to_string(),
            policies: split_csv(header_value(headers, "x-vault-policies")),
            expires_at: None,
        });
    }

    // 3. A raw token — the path Vault clients (and ESO) take.
    if let Some(token) = extract_token(headers) {
        return match verify_token(&token) {
            Ok(claims) => Ok(Identity {
                tenant_id: claims.tenant_id,
                principal_id: claims.sub,
                policies: claims.policies,
                expires_at: Some(claims.exp),
            }),
            Err(e) => Err(vault_error(StatusCode::FORBIDDEN, e)),
        };
    }

    Err(vault_error(
        StatusCode::FORBIDDEN,
        "missing authentication: supply X-Vault-Token, or X-Tenant-Id when behind the gateway",
    ))
}

// ─── KV v2 wire types ────────────────────────────────────────────────────────

#[derive(Debug, Deserialize)]
pub struct ReadQuery {
    /// KV v2 reads a specific version with `?version=N`; absent means current.
    pub version: Option<u32>,
}

#[derive(Debug, Serialize)]
struct Kv2Metadata {
    created_time: String,
    deletion_time: String,
    destroyed: bool,
    version: u32,
    #[serde(skip_serializing_if = "Option::is_none")]
    custom_metadata: Option<HashMap<String, String>>,
}

#[derive(Debug, Serialize)]
struct Kv2ReadData {
    /// The key → value map. ESO's `dataFrom.extract` consumes exactly this.
    data: Map<String, Value>,
    metadata: Kv2Metadata,
}

#[derive(Debug, Serialize)]
struct Kv2ReadResponse {
    data: Kv2ReadData,
}

#[derive(Debug, Deserialize, Default)]
struct Kv2WriteOptions {
    /// Check-And-Set: write only if the current version matches.
    #[serde(default)]
    cas: Option<u32>,
}

#[derive(Debug, Deserialize)]
struct Kv2WriteRequest {
    data: Map<String, Value>,
    #[serde(default)]
    options: Kv2WriteOptions,
}

#[derive(Debug, Serialize)]
struct Kv2WriteResponse {
    data: Kv2Metadata,
}

// ─── Data-model bridge ───────────────────────────────────────────────────────

/// Interpret a stored blob as a KV v2 key → value map.
///
/// Secrets written through this mount are JSON objects. Anything else (a blob
/// written through the native API) is surfaced under a single `value` key so it
/// remains readable instead of failing the request.
fn plaintext_to_map(plaintext: &[u8]) -> Map<String, Value> {
    if let Ok(Value::Object(map)) = serde_json::from_slice::<Value>(plaintext) {
        return map;
    }
    let mut map = Map::new();
    let fallback = match std::str::from_utf8(plaintext) {
        Ok(s) => Value::String(s.to_string()),
        Err(_) => Value::String(base64::engine::general_purpose::STANDARD.encode(plaintext)),
    };
    map.insert("value".to_string(), fallback);
    map
}

// ─── Crypto helpers ──────────────────────────────────────────────────────────

async fn decrypt(
    state: &AppState,
    tenant_id: &str,
    path: &str,
    dek_id: &str,
    ciphertext: &str,
) -> Result<Vec<u8>, Response> {
    let aad = format!("{}:{}", tenant_id, path).into_bytes();
    let mut client = crypto_proto::crypto_service_client::CryptoServiceClient::connect(
        state.crypto_endpoint.clone(),
    )
    .await
    .map_err(|e| {
        error!(error = %e, "crypto-service connect failed");
        vault_error(
            StatusCode::SERVICE_UNAVAILABLE,
            format!("crypto-service unavailable: {e}"),
        )
    })?;

    // The crypto-service expects "<dek_id>:<ciphertext_b64>".
    let combined = format!("{}:{}", dek_id, ciphertext);
    let resp = client
        .decrypt(crypto_proto::DecryptRequest {
            tenant_id: tenant_id.to_string(),
            ciphertext_b64: combined,
            aad,
        })
        .await
        .map_err(|e| {
            error!(error = %e, "crypto-service decrypt failed");
            vault_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("decryption failed: {e}"),
            )
        })?;
    Ok(resp.into_inner().plaintext)
}

async fn encrypt(
    state: &AppState,
    tenant_id: &str,
    path: &str,
    plaintext: Vec<u8>,
) -> Result<(String, String), Response> {
    let aad = format!("{}:{}", tenant_id, path).into_bytes();
    let mut client = crypto_proto::crypto_service_client::CryptoServiceClient::connect(
        state.crypto_endpoint.clone(),
    )
    .await
    .map_err(|e| {
        error!(error = %e, "crypto-service connect failed");
        vault_error(
            StatusCode::SERVICE_UNAVAILABLE,
            format!("crypto-service unavailable: {e}"),
        )
    })?;

    let resp = client
        .encrypt(crypto_proto::EncryptRequest {
            tenant_id: tenant_id.to_string(),
            plaintext,
            aad,
        })
        .await
        .map_err(|e| {
            error!(error = %e, "crypto-service encrypt failed");
            vault_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("encryption failed: {e}"),
            )
        })?
        .into_inner();
    Ok((resp.ciphertext_b64, resp.dek_id))
}

// ─── Handlers ────────────────────────────────────────────────────────────────

/// `GET /v1/kv/data/*path` — KV v2 read.
#[instrument(skip(state, headers), fields(path, tenant_id))]
async fn read(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(path): Path<String>,
    Query(query): Query<ReadQuery>,
) -> Response {
    let identity = match resolve_identity(&headers) {
        Ok(i) => i,
        Err(r) => return r,
    };
    let normalized = match normalize_and_validate(&path) {
        Ok(p) => p,
        Err(e) => return vault_error(StatusCode::BAD_REQUEST, e.to_string()),
    };

    tracing::Span::current().record("path", normalized.as_str());
    tracing::Span::current().record("tenant_id", identity.tenant_id.as_str());
    info!("kv2 read");

    // Authorize against the same resource name the native handler uses, so a
    // single policy governs both mounts.
    let resource = format!("secret/data/{}", normalized);
    if let Err(e) = state
        .policy_client
        .authorize(
            &identity.tenant_id,
            &identity.principal_id,
            &identity.policies,
            "read",
            &resource,
        )
        .await
    {
        return vault_error(StatusCode::FORBIDDEN, e.to_string());
    }

    let entry = match state
        .store
        .get(&identity.tenant_id, &normalized, query.version)
        .await
    {
        Ok(v) => v,
        // Vault answers 404 for a missing secret; ESO relies on that.
        Err(e) => {
            let status =
                StatusCode::from_u16(e.http_status()).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);
            return vault_error(status, e.to_string());
        }
    };

    let plaintext = match decrypt(
        &state,
        &identity.tenant_id,
        &normalized,
        &entry.dek_id,
        &entry.ciphertext,
    )
    .await
    {
        Ok(p) => p,
        Err(r) => return r,
    };

    let custom_metadata = if entry.custom_metadata.is_empty() {
        None
    } else {
        Some(entry.custom_metadata.clone())
    };

    (
        StatusCode::OK,
        Json(Kv2ReadResponse {
            data: Kv2ReadData {
                data: plaintext_to_map(&plaintext),
                metadata: Kv2Metadata {
                    created_time: entry.created_at.to_rfc3339(),
                    deletion_time: entry.deleted_at.map(|d| d.to_rfc3339()).unwrap_or_default(),
                    destroyed: entry.destroyed,
                    version: entry.version,
                    custom_metadata,
                },
            },
        }),
    )
        .into_response()
}

/// `POST /v1/kv/data/*path` — KV v2 write.
#[instrument(skip(state, headers, body), fields(path, tenant_id))]
async fn write(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(path): Path<String>,
    Json(body): Json<Kv2WriteRequest>,
) -> Response {
    let identity = match resolve_identity(&headers) {
        Ok(i) => i,
        Err(r) => return r,
    };
    let normalized = match normalize_and_validate(&path) {
        Ok(p) => p,
        Err(e) => return vault_error(StatusCode::BAD_REQUEST, e.to_string()),
    };

    tracing::Span::current().record("path", normalized.as_str());
    tracing::Span::current().record("tenant_id", identity.tenant_id.as_str());
    info!("kv2 write");

    if body.data.is_empty() {
        return vault_error(StatusCode::BAD_REQUEST, "data must not be empty");
    }

    let resource = format!("secret/data/{}", normalized);
    if let Err(e) = state
        .policy_client
        .authorize(
            &identity.tenant_id,
            &identity.principal_id,
            &identity.policies,
            "write",
            &resource,
        )
        .await
    {
        return vault_error(StatusCode::FORBIDDEN, e.to_string());
    }

    // The map IS the secret: serialise it to JSON and store that as the blob.
    let plaintext = match serde_json::to_vec(&body.data) {
        Ok(v) => v,
        Err(e) => {
            return vault_error(
                StatusCode::BAD_REQUEST,
                format!("could not serialise data: {e}"),
            )
        }
    };

    let (ciphertext, dek_id) =
        match encrypt(&state, &identity.tenant_id, &normalized, plaintext).await {
            Ok(v) => v,
            Err(r) => return r,
        };

    let (_secret_id, version) = match state
        .store
        .put(
            &identity.tenant_id,
            &normalized,
            ciphertext,
            dek_id,
            body.options.cas,
            HashMap::new(),
            None,
        )
        .await
    {
        Ok(v) => v,
        Err(e) => {
            let status =
                StatusCode::from_u16(e.http_status()).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);
            return vault_error(status, e.to_string());
        }
    };

    (
        StatusCode::OK,
        Json(Kv2WriteResponse {
            data: Kv2Metadata {
                created_time: chrono::Utc::now().to_rfc3339(),
                deletion_time: String::new(),
                destroyed: false,
                version,
                custom_metadata: None,
            },
        }),
    )
        .into_response()
}

/// `GET /v1/auth/token/lookup-self` — Vault clients probe this to validate a
/// token before use. Returns the tenant and policies the token carries.
async fn lookup_self(headers: HeaderMap) -> Response {
    let identity = match resolve_identity(&headers) {
        Ok(i) => i,
        Err(r) => return r,
    };
    let mut data = Map::new();
    data.insert("id".into(), Value::String(String::new()));
    data.insert(
        "display_name".into(),
        Value::String(identity.principal_id.clone()),
    );
    data.insert(
        "policies".into(),
        Value::Array(
            identity
                .policies
                .iter()
                .map(|p| Value::String(p.clone()))
                .collect(),
        ),
    );
    let mut meta = Map::new();
    meta.insert(
        "tenant_id".into(),
        Value::String(identity.tenant_id.clone()),
    );
    data.insert("meta".into(), Value::Object(meta));

    // Vault's own lookup-self returns these, and clients assert on them —
    // External Secrets Operator rejects the store with "could not assert token
    // type" if `type` is absent, so omitting them is not cosmetic. `service`
    // is the right value: wslvault tokens are ordinary (non-batch) tokens.
    data.insert("type".into(), Value::String("service".into()));
    data.insert("accessor".into(), Value::String(String::new()));
    data.insert("path".into(), Value::String("auth/token/lookup-self".into()));
    data.insert("orphan".into(), Value::Bool(true));
    data.insert("renewable".into(), Value::Bool(false));
    data.insert("num_uses".into(), Value::Number(0.into()));
    // Expiry is REQUIRED by clients: ESO refuses a store with "no expiration
    // time found in response" if absent. Derive both from the JWT's `exp`.
    // Header-authenticated callers carry no token lifetime, so fall back to a
    // nominal window rather than claiming the credential never expires.
    let now = chrono::Utc::now().timestamp();
    let exp = identity.expires_at.unwrap_or(now + 86_400);
    let ttl = (exp - now).max(0);
    data.insert("ttl".into(), Value::Number(ttl.into()));
    data.insert("explicit_max_ttl".into(), Value::Number(0.into()));
    if let Some(dt) = chrono::DateTime::from_timestamp(exp, 0) {
        data.insert("expire_time".into(), Value::String(dt.to_rfc3339()));
        data.insert(
            "issue_time".into(),
            Value::String(chrono::Utc::now().to_rfc3339()),
        );
    }

    let mut body = Map::new();
    body.insert("data".into(), Value::Object(data));
    (StatusCode::OK, Json(Value::Object(body))).into_response()
}

/// `GET /v1/sys/health` — Vault-shaped health, unauthenticated like Vault's.
async fn sys_health() -> Response {
    let mut body = Map::new();
    body.insert("initialized".into(), Value::Bool(true));
    body.insert("sealed".into(), Value::Bool(false));
    body.insert("standby".into(), Value::Bool(false));
    body.insert(
        "version".into(),
        Value::String(env!("CARGO_PKG_VERSION").to_string()),
    );
    (StatusCode::OK, Json(Value::Object(body))).into_response()
}

/// Router for the Vault-compatible surface, merged into the main app router.
pub fn routes() -> Router<AppState> {
    Router::new()
        .route("/v1/kv/data/*path", get(read).post(write))
        .route("/v1/auth/token/lookup-self", get(lookup_self))
        .route("/v1/sys/health", get(sys_health))
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::{HeaderName, HeaderValue};

    fn headers(pairs: &[(&str, &str)]) -> HeaderMap {
        let mut h = HeaderMap::new();
        for (k, v) in pairs {
            // Build an owned HeaderName: the &str keys here are not 'static,
            // which `HeaderMap::insert` would otherwise require.
            h.insert(
                HeaderName::from_bytes(k.as_bytes()).unwrap(),
                HeaderValue::from_str(v).unwrap(),
            );
        }
        h
    }

    #[test]
    fn json_object_blob_round_trips_as_a_map() {
        let map = plaintext_to_map(br#"{"POSTGRES_HOST":"db","PORT":"5432"}"#);
        assert_eq!(map.get("POSTGRES_HOST").unwrap(), "db");
        assert_eq!(map.get("PORT").unwrap(), "5432");
    }

    #[test]
    fn non_json_blob_falls_back_to_a_value_key() {
        // A blob written through the native API must stay readable here.
        let map = plaintext_to_map(b"not-json");
        assert_eq!(map.get("value").unwrap(), "not-json");
    }

    #[test]
    fn non_utf8_blob_falls_back_to_base64() {
        let map = plaintext_to_map(&[0xff, 0xfe]);
        assert!(map.get("value").unwrap().is_string());
    }

    #[test]
    fn json_array_is_not_treated_as_a_map() {
        // Only a JSON *object* is a KV v2 map; an array is an opaque value.
        let map = plaintext_to_map(b"[1,2,3]");
        assert_eq!(map.get("value").unwrap(), "[1,2,3]");
    }

    #[test]
    fn internal_headers_take_precedence() {
        let id = resolve_identity(&headers(&[
            ("x-tenant-id", "acme"),
            ("x-principal-id", "svc"),
            ("x-policies", "read-db, write-db"),
        ]))
        .expect("should resolve");
        assert_eq!(id.tenant_id, "acme");
        assert_eq!(id.principal_id, "svc");
        assert_eq!(id.policies, vec!["read-db", "write-db"]);
    }

    #[test]
    fn gateway_injected_headers_are_honoured() {
        // The gateway writes the X-Vault-* spelling; it must work too.
        let id = resolve_identity(&headers(&[
            ("x-vault-tenant-id", "acme"),
            ("x-vault-principal-id", "svc"),
        ]))
        .expect("should resolve");
        assert_eq!(id.tenant_id, "acme");
        assert_eq!(id.principal_id, "svc");
    }

    #[test]
    fn missing_auth_is_rejected() {
        assert!(resolve_identity(&HeaderMap::new()).is_err());
    }

    #[test]
    fn token_without_configured_secret_is_rejected_not_trusted() {
        // Fail closed: an unverifiable token must never be believed.
        std::env::remove_var(JWT_SECRET_ENV);
        assert!(verify_token("any.token.here").is_err());
    }

    #[test]
    fn extracts_token_from_either_header() {
        assert_eq!(
            extract_token(&headers(&[("x-vault-token", "abc")])).as_deref(),
            Some("abc")
        );
        assert_eq!(
            extract_token(&headers(&[("authorization", "Bearer xyz")])).as_deref(),
            Some("xyz")
        );
        assert_eq!(extract_token(&HeaderMap::new()), None);
    }
}
