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
//! Delegated wholesale to [`wslvault_core::auth::resolve_identity`], which is the
//! single authentication path shared with the native `/v1/secret/*` handlers.
//! See that module for the precedence order and the fail-closed guarantees.

use std::collections::HashMap;

use axum::{
    extract::{Path, Query, State},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    routing::get,
    Json, Router,
};
use base64::Engine as _;
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use tracing::{error, info, instrument};

use crate::grpc::crypto_proto;
use crate::http::AppState;
use crate::path::normalize_and_validate;
use wslvault_core::auth::Identity;

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

/// Resolve the caller, rendering failures in Vault's `{"errors":[…]}` shape.
///
/// The decision itself lives in [`wslvault_core::auth::resolve_identity`]; this is
/// only the error-shape adapter for this mount.
///
/// The `Err` variant is an already-rendered `Response` so callers can return it
/// verbatim; `axum::Response` is inherently large, hence the allow.
#[allow(clippy::result_large_err)]
pub fn resolve_identity(headers: &HeaderMap) -> Result<Identity, Response> {
    wslvault_core::auth::resolve_identity(headers)
        .map_err(|e| vault_error(StatusCode::FORBIDDEN, e.to_string()))
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
    let mut client =
        crypto_proto::crypto_service_client::CryptoServiceClient::new(state.crypto_channel.clone());

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
    let mut client =
        crypto_proto::crypto_service_client::CryptoServiceClient::new(state.crypto_channel.clone());

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

// ─── Audit ───────────────────────────────────────────────────────────────────

/// Emit an audit event for a KV v2 operation.
///
/// This mount previously emitted NONE. `http.rs` referenced `audit_client` 36
/// times; `kv2.rs` referenced it zero times — so every read, write, delete and
/// destroy through `/v1/kv/data/*` left no record at all. That is the mount the
/// External Secrets Operator, the `vault` CLI and the Terraform provider all
/// use, i.e. very plausibly the highest-volume path in a real deployment.
///
/// The action strings deliberately match the native handlers (`secret.read`,
/// `secret.write`) so a query for "who read this path" returns both mounts.
#[allow(clippy::too_many_arguments)]
async fn audit(
    state: &AppState,
    identity: &Identity,
    action: &str,
    path: &str,
    outcome: &str,
    detail: &str,
    headers: &HeaderMap,
) {
    let client_ip = headers
        .get("x-client-ip")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");

    state
        .audit_client
        .emit(
            &identity.tenant_id,
            &identity.principal_id,
            action,
            path,
            outcome,
            detail,
            r#"{"mount":"kv2"}"#,
            client_ip,
        )
        .await;
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
        audit(
            &state,
            &identity,
            "secret.read",
            &normalized,
            "failure",
            &e.to_string(),
            &headers,
        )
        .await;
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
            audit(
                &state,
                &identity,
                "secret.read",
                &normalized,
                "failure",
                &e.to_string(),
                &headers,
            )
            .await;
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

    audit(
        &state,
        &identity,
        "secret.read",
        &normalized,
        "success",
        "",
        &headers,
    )
    .await;

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
        audit(
            &state,
            &identity,
            "secret.write",
            &normalized,
            "failure",
            &e.to_string(),
            &headers,
        )
        .await;
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
            audit(
                &state,
                &identity,
                "secret.write",
                &normalized,
                "failure",
                &e.to_string(),
                &headers,
            )
            .await;
            let status =
                StatusCode::from_u16(e.http_status()).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);
            return vault_error(status, e.to_string());
        }
    };

    audit(
        &state,
        &identity,
        "secret.write",
        &normalized,
        "success",
        "",
        &headers,
    )
    .await;

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
    data.insert(
        "path".into(),
        Value::String("auth/token/lookup-self".into()),
    );
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
    //! Data-model bridge only. The authentication tests live beside the code
    //! they exercise, in `wslvault_core::auth`.
    use super::*;

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
}
