//! Axum REST route handlers for the transit-engine.
//!
//! All routes are under `/v1/transit/` and operate on named keys scoped to a
//! tenant.  For simplicity the tenant ID is read from the `X-Tenant-Id` header;
//! in production this would come from a validated JWT claim.
//!
//! # Policy enforcement
//! Every handler calls `state.policy_client.authorize(...)` with the
//! appropriate action and resource path before proceeding with any key-store
//! or cryptographic operation.  If the policy-engine denies the request or is
//! unreachable, the handler returns 403 or 503 immediately (fail-closed).
//!
//! # Audit logging
//! Every handler emits a fire-and-forget audit event via `state.audit_client`
//! after completing (success or failure). Audit failures are logged but never
//! block or fail the handler response.

use std::sync::Arc;

use axum::{
    extract::{Path, State},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    Json,
};
use serde::{Deserialize, Serialize};

use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine as _;

use wslvault_core::VaultError;

use crate::audit_client::AuditClient;
use crate::key_store::{KeyAlgorithm, TransitKey, TransitKeyStoreBackend};
use crate::operations::{
    decrypt, ed25519_jwks, ed25519_sign, ed25519_verify, encrypt, hmac_versioned, jwk_kid, rewrap,
    sign_data, verify_data,
};
use crate::policy_client::PolicyClient;

/// Shared application state threaded through axum.
///
/// `key_store` is a type-erased backend so that the handlers are independent
/// of whether keys are persisted in PostgreSQL or kept purely in memory.
/// `Arc` is required because axum clones `State` for every request.
///
/// `policy_client` gates every operation behind an authorization check; if the
/// policy-engine is unreachable the request is denied (fail-closed).
///
/// `audit_client` emits fire-and-forget audit events after each handler
/// completes; failures are logged but never block responses.
#[derive(Clone)]
pub struct AppState {
    pub key_store: Arc<dyn TransitKeyStoreBackend>,
    pub policy_client: PolicyClient,
    pub audit_client: AuditClient,
}

// ---------------------------------------------------------------------------
// Request / Response types

/// One key in a listing. Metadata only — key material never crosses this
/// boundary, which is why it is built from `TransitKeySummary` and not from
/// `TransitKey`.
#[derive(Debug, Serialize, utoipa::ToSchema)]
pub struct TransitKeyView {
    pub name: String,
    #[serde(rename = "type")]
    pub key_type: String,
    pub latest_version: u32,
    pub created_at: String,
}

#[derive(Debug, Serialize, utoipa::ToSchema)]
pub struct ListKeysResponse {
    pub keys: Vec<TransitKeyView>,
}
// ---------------------------------------------------------------------------

#[derive(Deserialize, utoipa::ToSchema)]
pub struct EncryptRequest {
    /// Base64-encoded plaintext to encrypt.
    pub plaintext: String,
}

#[derive(Serialize, utoipa::ToSchema)]
pub struct EncryptResponse {
    pub ciphertext: String,
}

#[derive(Deserialize, utoipa::ToSchema)]
pub struct DecryptRequest {
    /// Versioned ciphertext string as produced by the encrypt endpoint.
    pub ciphertext: String,
}

#[derive(Serialize, utoipa::ToSchema)]
pub struct DecryptResponse {
    /// Base64-encoded plaintext.
    pub plaintext: String,
}

#[derive(Deserialize, utoipa::ToSchema)]
pub struct SignRequest {
    /// Base64-encoded data to sign.
    pub data: String,
    /// Ed25519 keys only: sign with this version instead of the current one.
    #[serde(default)]
    pub key_version: Option<u32>,
}

/// For an AES key, `signature` is a hex HMAC-SHA256 (unchanged behaviour).
/// For an Ed25519 key it is `vault:v{N}:{base64url}`; the part after the last
/// `:` is the raw signature in the encoding a compact JWS uses.
#[derive(Serialize, utoipa::ToSchema)]
pub struct SignResponse {
    pub signature: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub key_version: Option<u32>,
    /// JWK key id of the signing version, matching the public JWKS.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub kid: Option<String>,
    /// JWS `alg` for the signature (`EdDSA`).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub algorithm: Option<String>,
}

/// Body for `POST /v1/transit/keys/:key_name`. Optional: an empty body creates
/// an AES-256-GCM key, as before.
#[derive(Deserialize, Default, utoipa::ToSchema)]
pub struct CreateKeyRequest {
    /// `aes256-gcm` (default) or `ed25519`.
    #[serde(rename = "type", default)]
    pub key_type: Option<String>,
}

#[derive(Deserialize, utoipa::ToSchema)]
pub struct HmacRequest {
    /// Base64-encoded data to MAC.
    pub data: String,
    /// Recompute under this version instead of the current one.
    #[serde(default)]
    pub key_version: Option<u32>,
}

#[derive(Serialize, utoipa::ToSchema)]
pub struct HmacResponse {
    /// `vault:v{N}:{hex HMAC-SHA256}`.
    pub hmac: String,
    pub key_version: u32,
}

#[derive(Deserialize, utoipa::ToSchema)]
pub struct VerifyRequest {
    /// Base64-encoded data to verify.
    pub data: String,
    pub signature: String,
}

#[derive(Serialize, utoipa::ToSchema)]
pub struct VerifyResponse {
    pub valid: bool,
}

#[derive(Deserialize, utoipa::ToSchema)]
pub struct RewrapRequest {
    /// Existing versioned ciphertext to upgrade to the latest key version.
    pub ciphertext: String,
}

#[derive(Serialize, utoipa::ToSchema)]
pub struct RewrapResponse {
    pub ciphertext: String,
}

#[derive(Serialize, utoipa::ToSchema)]
pub struct CreateKeyResponse {
    pub key_name: String,
    pub algorithm: String,
}

#[derive(Serialize, utoipa::ToSchema)]
pub struct RotateKeyResponse {
    pub key_name: String,
    pub new_version: u32,
}

/// Error response body.
#[derive(Serialize)]
struct ErrorResponse {
    error: String,
}

// ---------------------------------------------------------------------------
// OpenAPI document
// ---------------------------------------------------------------------------

/// Collects all transit-engine REST paths and schemas into a single OpenAPI document.
///
/// The `/health` liveness path is excluded as it is registered directly in
/// `main.rs` and carries no authentication requirement.
#[derive(utoipa::OpenApi)]
#[openapi(
    paths(
        encrypt_handler,
        decrypt_handler,
        sign_handler,
        verify_handler,
        rewrap_handler,
        create_key_handler,
        rotate_key_handler,
        list_keys_handler,
        hmac_handler,
        public_keys_handler,
    ),
    components(schemas(
        ListKeysResponse,
        TransitKeyView,
        EncryptRequest,
        EncryptResponse,
        DecryptRequest,
        DecryptResponse,
        SignRequest,
        SignResponse,
        CreateKeyRequest,
        HmacRequest,
        HmacResponse,
        VerifyRequest,
        VerifyResponse,
        RewrapRequest,
        RewrapResponse,
        CreateKeyResponse,
        RotateKeyResponse,
    )),
    tags(
        (name = "transit", description = "Transit encryption-as-a-service operations"),
        (name = "keys", description = "Transit key management"),
    ),
    info(
        title = "Transit Engine API",
        version = "0.1.0",
        description = "WSLVault transit encryption-as-a-service REST API",
    )
)]
pub struct ApiDoc;

// ---------------------------------------------------------------------------
// Helper: resolve the calling identity
// ---------------------------------------------------------------------------

/// Resolve tenant, principal and policies from the caller's signed token.
///
/// This service used to read all three out of `X-Tenant-Id`, `X-Principal-Id`
/// and `X-Policies`, which the browser sends and nothing verified. The proxy
/// that once wrote those headers decoded the JWT *without checking its
/// signature*, and has since been deleted — so transit was simultaneously
/// unreachable in practice and, had anything reached it, willing to encrypt or
/// decrypt under any tenant named by the caller.
///
/// [`wslvault_core::auth::resolve_identity`] is the same verified path
/// secret-engine uses; the header contract survives only behind an explicit
/// `VAULT_TRUST_GATEWAY_HEADERS` opt-in.
#[allow(clippy::result_large_err)]
async fn authenticate(headers: &HeaderMap) -> Result<wslvault_core::auth::Identity, Response> {
    wslvault_core::auth::resolve_identity(headers)
        .await
        .map_err(|e| {
            (
                StatusCode::UNAUTHORIZED,
                Json(ErrorResponse {
                    error: e.to_string(),
                }),
            )
                .into_response()
        })
}

/// Extract the `X-Client-Ip` header, returning an empty string when absent or
/// not valid UTF-8.
fn extract_client_ip(headers: &HeaderMap) -> String {
    headers
        .get("x-client-ip")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_string()
}

/// Convert a VaultError to an appropriate HTTP status + JSON error response.
fn vault_error_response(err: VaultError) -> (StatusCode, Json<ErrorResponse>) {
    let status = match err.http_status() {
        400 => StatusCode::BAD_REQUEST,
        403 => StatusCode::FORBIDDEN,
        404 => StatusCode::NOT_FOUND,
        409 => StatusCode::CONFLICT,
        503 => StatusCode::SERVICE_UNAVAILABLE,
        _ => StatusCode::INTERNAL_SERVER_ERROR,
    };
    (
        status,
        Json(ErrorResponse {
            error: err.to_string(),
        }),
    )
}

// ---------------------------------------------------------------------------
// Route handlers
// ---------------------------------------------------------------------------

/// POST /v1/transit/encrypt/:key_name
///
/// Encrypt base64-encoded plaintext with the named key.
#[utoipa::path(
    post,
    path = "/v1/transit/encrypt/{key_name}",
    params(
        ("key_name" = String, Path, description = "Name of the transit key to use for encryption"),
        ("x-tenant-id" = String, Header, description = "Tenant identifier (required)"),
    ),
    request_body = EncryptRequest,
    responses(
        (status = 200, description = "Plaintext encrypted successfully", body = EncryptResponse),
        (status = 400, description = "Missing header or invalid base64 plaintext"),
        (status = 403, description = "Authorization denied by policy-engine"),
        (status = 404, description = "Key not found"),
        (status = 503, description = "Policy-engine unavailable"),
    ),
    tag = "transit"
)]
pub async fn encrypt_handler(
    State(state): State<AppState>,
    Path(key_name): Path<String>,
    headers: HeaderMap,
    Json(body): Json<EncryptRequest>,
) -> impl IntoResponse {
    let (tenant_id, principal_id, policies) = match authenticate(&headers).await {
        Ok(i) => (i.tenant_id, i.principal_id, i.policies),
        Err(e) => return e,
    };
    let client_ip = extract_client_ip(&headers);

    // Authorize before accessing the key store.
    let resource = format!("transit/encrypt/{}", key_name);
    if let Err(e) = state
        .policy_client
        .authorize(&tenant_id, &principal_id, &policies, "write", &resource)
        .await
    {
        state
            .audit_client
            .emit(
                &tenant_id,
                &principal_id,
                "transit.encrypt",
                &key_name,
                "failure",
                &e.to_string(),
                "",
                &client_ip,
            )
            .await;
        return vault_error_response(e).into_response();
    }

    let plaintext = match BASE64.decode(&body.plaintext) {
        Ok(p) => p,
        Err(_) => {
            state
                .audit_client
                .emit(
                    &tenant_id,
                    &principal_id,
                    "transit.encrypt",
                    &key_name,
                    "failure",
                    "plaintext must be valid base64",
                    "",
                    &client_ip,
                )
                .await;
            return (
                StatusCode::BAD_REQUEST,
                Json(ErrorResponse {
                    error: "plaintext must be valid base64".into(),
                }),
            )
                .into_response();
        }
    };

    let key = match state.key_store.get_key(&tenant_id, &key_name).await {
        Ok(k) => k,
        Err(e) => {
            state
                .audit_client
                .emit(
                    &tenant_id,
                    &principal_id,
                    "transit.encrypt",
                    &key_name,
                    "failure",
                    &e.to_string(),
                    "",
                    &client_ip,
                )
                .await;
            return vault_error_response(e).into_response();
        }
    };

    if let Err(resp) = require_symmetric(
        &state,
        &key,
        &tenant_id,
        &principal_id,
        "transit.encrypt",
        &client_ip,
    )
    .await
    {
        return resp;
    }

    match encrypt(&key, &plaintext) {
        Ok(ciphertext) => {
            state
                .audit_client
                .emit(
                    &tenant_id,
                    &principal_id,
                    "transit.encrypt",
                    &key_name,
                    "success",
                    "",
                    "",
                    &client_ip,
                )
                .await;
            (StatusCode::OK, Json(EncryptResponse { ciphertext })).into_response()
        }
        Err(e) => {
            state
                .audit_client
                .emit(
                    &tenant_id,
                    &principal_id,
                    "transit.encrypt",
                    &key_name,
                    "failure",
                    &e.to_string(),
                    "",
                    &client_ip,
                )
                .await;
            vault_error_response(e).into_response()
        }
    }
}

/// POST /v1/transit/decrypt/:key_name
///
/// Decrypt a versioned ciphertext string produced by the encrypt endpoint.
#[utoipa::path(
    post,
    path = "/v1/transit/decrypt/{key_name}",
    params(
        ("key_name" = String, Path, description = "Name of the transit key to use for decryption"),
        ("x-tenant-id" = String, Header, description = "Tenant identifier (required)"),
    ),
    request_body = DecryptRequest,
    responses(
        (status = 200, description = "Ciphertext decrypted; returns base64-encoded plaintext", body = DecryptResponse),
        (status = 400, description = "Missing header or malformed ciphertext"),
        (status = 403, description = "Authorization denied by policy-engine"),
        (status = 404, description = "Key not found"),
        (status = 503, description = "Policy-engine unavailable"),
    ),
    tag = "transit"
)]
pub async fn decrypt_handler(
    State(state): State<AppState>,
    Path(key_name): Path<String>,
    headers: HeaderMap,
    Json(body): Json<DecryptRequest>,
) -> impl IntoResponse {
    let (tenant_id, principal_id, policies) = match authenticate(&headers).await {
        Ok(i) => (i.tenant_id, i.principal_id, i.policies),
        Err(e) => return e,
    };
    let client_ip = extract_client_ip(&headers);

    // Authorize before accessing the key store.
    let resource = format!("transit/decrypt/{}", key_name);
    if let Err(e) = state
        .policy_client
        .authorize(&tenant_id, &principal_id, &policies, "read", &resource)
        .await
    {
        state
            .audit_client
            .emit(
                &tenant_id,
                &principal_id,
                "transit.decrypt",
                &key_name,
                "failure",
                &e.to_string(),
                "",
                &client_ip,
            )
            .await;
        return vault_error_response(e).into_response();
    }

    let key = match state.key_store.get_key(&tenant_id, &key_name).await {
        Ok(k) => k,
        Err(e) => {
            state
                .audit_client
                .emit(
                    &tenant_id,
                    &principal_id,
                    "transit.decrypt",
                    &key_name,
                    "failure",
                    &e.to_string(),
                    "",
                    &client_ip,
                )
                .await;
            return vault_error_response(e).into_response();
        }
    };

    if let Err(resp) = require_symmetric(
        &state,
        &key,
        &tenant_id,
        &principal_id,
        "transit.decrypt",
        &client_ip,
    )
    .await
    {
        return resp;
    }

    match decrypt(&key, &body.ciphertext) {
        Ok(plaintext_bytes) => {
            let plaintext_b64 = BASE64.encode(&plaintext_bytes);
            state
                .audit_client
                .emit(
                    &tenant_id,
                    &principal_id,
                    "transit.decrypt",
                    &key_name,
                    "success",
                    "",
                    "",
                    &client_ip,
                )
                .await;
            (
                StatusCode::OK,
                Json(DecryptResponse {
                    plaintext: plaintext_b64,
                }),
            )
                .into_response()
        }
        Err(e) => {
            state
                .audit_client
                .emit(
                    &tenant_id,
                    &principal_id,
                    "transit.decrypt",
                    &key_name,
                    "failure",
                    &e.to_string(),
                    "",
                    &client_ip,
                )
                .await;
            vault_error_response(e).into_response()
        }
    }
}

/// POST /v1/transit/sign/:key_name
///
/// Sign base64-encoded data with the named key.
#[utoipa::path(
    post,
    path = "/v1/transit/sign/{key_name}",
    params(
        ("key_name" = String, Path, description = "Name of the signing key"),
        ("x-tenant-id" = String, Header, description = "Tenant identifier (required)"),
    ),
    request_body = SignRequest,
    responses(
        (status = 200, description = "Data signed successfully", body = SignResponse),
        (status = 400, description = "Missing header or invalid base64 data"),
        (status = 403, description = "Authorization denied by policy-engine"),
        (status = 404, description = "Key not found"),
    ),
    tag = "transit"
)]
pub async fn sign_handler(
    State(state): State<AppState>,
    Path(key_name): Path<String>,
    headers: HeaderMap,
    Json(body): Json<SignRequest>,
) -> impl IntoResponse {
    let (tenant_id, principal_id, policies) = match authenticate(&headers).await {
        Ok(i) => (i.tenant_id, i.principal_id, i.policies),
        Err(e) => return e,
    };
    let client_ip = extract_client_ip(&headers);

    // Authorize before accessing the key store.
    let resource = format!("transit/sign/{}", key_name);
    if let Err(e) = state
        .policy_client
        .authorize(&tenant_id, &principal_id, &policies, "write", &resource)
        .await
    {
        state
            .audit_client
            .emit(
                &tenant_id,
                &principal_id,
                "transit.sign",
                &key_name,
                "failure",
                &e.to_string(),
                "",
                &client_ip,
            )
            .await;
        return vault_error_response(e).into_response();
    }

    let data = match BASE64.decode(&body.data) {
        Ok(d) => d,
        Err(_) => {
            state
                .audit_client
                .emit(
                    &tenant_id,
                    &principal_id,
                    "transit.sign",
                    &key_name,
                    "failure",
                    "data must be valid base64",
                    "",
                    &client_ip,
                )
                .await;
            return (
                StatusCode::BAD_REQUEST,
                Json(ErrorResponse {
                    error: "data must be valid base64".into(),
                }),
            )
                .into_response();
        }
    };

    let key = match state.key_store.get_key(&tenant_id, &key_name).await {
        Ok(k) => k,
        Err(e) => {
            state
                .audit_client
                .emit(
                    &tenant_id,
                    &principal_id,
                    "transit.sign",
                    &key_name,
                    "failure",
                    &e.to_string(),
                    "",
                    &client_ip,
                )
                .await;
            return vault_error_response(e).into_response();
        }
    };

    // Ed25519 keys produce a public-key signature anyone can check; AES keys
    // keep the HMAC behaviour this endpoint always had.
    let response = match key.algorithm {
        KeyAlgorithm::Ed25519 => match ed25519_sign(&key, &data, body.key_version) {
            Ok(sig) => SignResponse {
                signature: sig.versioned(),
                key_version: Some(sig.key_version),
                kid: Some(jwk_kid(&key.name, sig.key_version)),
                algorithm: Some("EdDSA".into()),
            },
            Err(e) => {
                state
                    .audit_client
                    .emit(
                        &tenant_id,
                        &principal_id,
                        "transit.sign",
                        &key_name,
                        "failure",
                        &e.to_string(),
                        "",
                        &client_ip,
                    )
                    .await;
                return vault_error_response(e).into_response();
            }
        },
        KeyAlgorithm::Aes256Gcm => SignResponse {
            signature: sign_data(key.current_material(), &data),
            key_version: None,
            kid: None,
            algorithm: None,
        },
    };

    state
        .audit_client
        .emit(
            &tenant_id,
            &principal_id,
            "transit.sign",
            &key_name,
            "success",
            "",
            "",
            &client_ip,
        )
        .await;

    (StatusCode::OK, Json(response)).into_response()
}

/// POST /v1/transit/verify/:key_name
///
/// Verify a signature against base64-encoded data.
#[utoipa::path(
    post,
    path = "/v1/transit/verify/{key_name}",
    params(
        ("key_name" = String, Path, description = "Name of the key used for verification"),
        ("x-tenant-id" = String, Header, description = "Tenant identifier (required)"),
    ),
    request_body = VerifyRequest,
    responses(
        (status = 200, description = "Verification result (valid: true/false)", body = VerifyResponse),
        (status = 400, description = "Missing header or invalid base64 data"),
        (status = 403, description = "Authorization denied by policy-engine"),
        (status = 404, description = "Key not found"),
    ),
    tag = "transit"
)]
pub async fn verify_handler(
    State(state): State<AppState>,
    Path(key_name): Path<String>,
    headers: HeaderMap,
    Json(body): Json<VerifyRequest>,
) -> impl IntoResponse {
    let (tenant_id, principal_id, policies) = match authenticate(&headers).await {
        Ok(i) => (i.tenant_id, i.principal_id, i.policies),
        Err(e) => return e,
    };
    let client_ip = extract_client_ip(&headers);

    // Authorize before accessing the key store.
    let resource = format!("transit/verify/{}", key_name);
    if let Err(e) = state
        .policy_client
        .authorize(&tenant_id, &principal_id, &policies, "read", &resource)
        .await
    {
        state
            .audit_client
            .emit(
                &tenant_id,
                &principal_id,
                "transit.verify",
                &key_name,
                "failure",
                &e.to_string(),
                "",
                &client_ip,
            )
            .await;
        return vault_error_response(e).into_response();
    }

    let data = match BASE64.decode(&body.data) {
        Ok(d) => d,
        Err(_) => {
            state
                .audit_client
                .emit(
                    &tenant_id,
                    &principal_id,
                    "transit.verify",
                    &key_name,
                    "failure",
                    "data must be valid base64",
                    "",
                    &client_ip,
                )
                .await;
            return (
                StatusCode::BAD_REQUEST,
                Json(ErrorResponse {
                    error: "data must be valid base64".into(),
                }),
            )
                .into_response();
        }
    };

    let key = match state.key_store.get_key(&tenant_id, &key_name).await {
        Ok(k) => k,
        Err(e) => {
            state
                .audit_client
                .emit(
                    &tenant_id,
                    &principal_id,
                    "transit.verify",
                    &key_name,
                    "failure",
                    &e.to_string(),
                    "",
                    &client_ip,
                )
                .await;
            return vault_error_response(e).into_response();
        }
    };

    let valid = match key.algorithm {
        KeyAlgorithm::Ed25519 => ed25519_verify(&key, &data, &body.signature),
        KeyAlgorithm::Aes256Gcm => verify_data(key.current_material(), &data, &body.signature),
    };

    state
        .audit_client
        .emit(
            &tenant_id,
            &principal_id,
            "transit.verify",
            &key_name,
            "success",
            "",
            "",
            &client_ip,
        )
        .await;

    (StatusCode::OK, Json(VerifyResponse { valid })).into_response()
}

/// POST /v1/transit/rewrap/:key_name
///
/// Re-encrypt an existing ciphertext under the latest version of the named key.
/// Use this to bring old ciphertexts up to date after a key rotation.
#[utoipa::path(
    post,
    path = "/v1/transit/rewrap/{key_name}",
    params(
        ("key_name" = String, Path, description = "Name of the key to rewrap with"),
        ("x-tenant-id" = String, Header, description = "Tenant identifier (required)"),
    ),
    request_body = RewrapRequest,
    responses(
        (status = 200, description = "Ciphertext rewrapped with latest key version", body = RewrapResponse),
        (status = 400, description = "Missing header or malformed ciphertext"),
        (status = 403, description = "Authorization denied by policy-engine"),
        (status = 404, description = "Key not found"),
    ),
    tag = "transit"
)]
pub async fn rewrap_handler(
    State(state): State<AppState>,
    Path(key_name): Path<String>,
    headers: HeaderMap,
    Json(body): Json<RewrapRequest>,
) -> impl IntoResponse {
    let (tenant_id, principal_id, policies) = match authenticate(&headers).await {
        Ok(i) => (i.tenant_id, i.principal_id, i.policies),
        Err(e) => return e,
    };
    let client_ip = extract_client_ip(&headers);

    // Authorize before accessing the key store.
    let resource = format!("transit/rewrap/{}", key_name);
    if let Err(e) = state
        .policy_client
        .authorize(&tenant_id, &principal_id, &policies, "write", &resource)
        .await
    {
        state
            .audit_client
            .emit(
                &tenant_id,
                &principal_id,
                "transit.rewrap",
                &key_name,
                "failure",
                &e.to_string(),
                "",
                &client_ip,
            )
            .await;
        return vault_error_response(e).into_response();
    }

    let key = match state.key_store.get_key(&tenant_id, &key_name).await {
        Ok(k) => k,
        Err(e) => {
            state
                .audit_client
                .emit(
                    &tenant_id,
                    &principal_id,
                    "transit.rewrap",
                    &key_name,
                    "failure",
                    &e.to_string(),
                    "",
                    &client_ip,
                )
                .await;
            return vault_error_response(e).into_response();
        }
    };

    if let Err(resp) = require_symmetric(
        &state,
        &key,
        &tenant_id,
        &principal_id,
        "transit.rewrap",
        &client_ip,
    )
    .await
    {
        return resp;
    }

    match rewrap(&key, &body.ciphertext) {
        Ok(ciphertext) => {
            state
                .audit_client
                .emit(
                    &tenant_id,
                    &principal_id,
                    "transit.rewrap",
                    &key_name,
                    "success",
                    "",
                    "",
                    &client_ip,
                )
                .await;
            (StatusCode::OK, Json(RewrapResponse { ciphertext })).into_response()
        }
        Err(e) => {
            state
                .audit_client
                .emit(
                    &tenant_id,
                    &principal_id,
                    "transit.rewrap",
                    &key_name,
                    "failure",
                    &e.to_string(),
                    "",
                    &client_ip,
                )
                .await;
            vault_error_response(e).into_response()
        }
    }
}

/// GET /v1/transit/keys — list the calling tenant's keys
///
/// Metadata only. The tenant comes from the verified token, never from a
/// parameter, so there is no shape of this request that lists another tenant.
#[utoipa::path(
    get,
    path = "/v1/transit/keys",
    responses(
        (status = 200, description = "Keys for the calling tenant", body = ListKeysResponse),
        (status = 401, description = "Missing or invalid token"),
        (status = 403, description = "Authorization denied by policy-engine"),
    ),
    tag = "keys"
)]
pub async fn list_keys_handler(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> impl IntoResponse {
    let (tenant_id, principal_id, policies) = match authenticate(&headers).await {
        Ok(i) => (i.tenant_id, i.principal_id, i.policies),
        Err(e) => return e,
    };
    let client_ip = extract_client_ip(&headers);

    if let Err(e) = state
        .policy_client
        .authorize(&tenant_id, &principal_id, &policies, "read", "transit/keys")
        .await
    {
        state
            .audit_client
            .emit(
                &tenant_id,
                &principal_id,
                "transit.key.list",
                "",
                "failure",
                &e.to_string(),
                "",
                &client_ip,
            )
            .await;
        return vault_error_response(e).into_response();
    }

    match state.key_store.list_keys(&tenant_id).await {
        Ok(keys) => (
            StatusCode::OK,
            Json(ListKeysResponse {
                keys: keys
                    .into_iter()
                    .map(|k| TransitKeyView {
                        name: k.name,
                        key_type: k.algorithm.as_str().to_string(),
                        latest_version: k.current_version,
                        created_at: k.created_at.to_rfc3339(),
                    })
                    .collect(),
            }),
        )
            .into_response(),
        Err(e) => vault_error_response(e).into_response(),
    }
}

/// POST /v1/transit/keys/:key_name  — create a new named key
///
/// Creates a new transit key scoped to the tenant. The optional body
/// `{"type": "ed25519"}` creates a signing key; the default is AES-256-GCM.
#[utoipa::path(
    post,
    path = "/v1/transit/keys/{key_name}",
    params(
        ("key_name" = String, Path, description = "Name of the key to create"),
        ("x-tenant-id" = String, Header, description = "Tenant identifier (required)"),
    ),
    request_body(content = CreateKeyRequest, description = "Optional; omit for AES-256-GCM"),
    responses(
        (status = 201, description = "Key created", body = CreateKeyResponse),
        (status = 400, description = "Missing X-Tenant-Id header"),
        (status = 403, description = "Authorization denied by policy-engine"),
        (status = 409, description = "A key with this name already exists"),
    ),
    tag = "keys"
)]
pub async fn create_key_handler(
    State(state): State<AppState>,
    Path(key_name): Path<String>,
    headers: HeaderMap,
    body: axum::body::Bytes,
) -> impl IntoResponse {
    // Parsed by hand rather than with `Option<Json<_>>`: that extractor turns
    // a malformed body into `None`, which would silently create an AES key for
    // a caller who asked for a signing key.
    let request: CreateKeyRequest = if body.iter().all(u8::is_ascii_whitespace) {
        CreateKeyRequest::default()
    } else {
        match serde_json::from_slice(&body) {
            Ok(r) => r,
            Err(e) => {
                return (
                    StatusCode::BAD_REQUEST,
                    Json(ErrorResponse {
                        error: format!("invalid request body: {e}"),
                    }),
                )
                    .into_response()
            }
        }
    };
    let algorithm = match request.key_type.as_deref() {
        None => KeyAlgorithm::Aes256Gcm,
        Some(t) => match KeyAlgorithm::parse(t) {
            Some(a) => a,
            None => {
                return (
                    StatusCode::BAD_REQUEST,
                    Json(ErrorResponse {
                        error: format!("unsupported key type '{t}'; use aes256-gcm or ed25519"),
                    }),
                )
                    .into_response()
            }
        },
    };
    let (tenant_id, principal_id, policies) = match authenticate(&headers).await {
        Ok(i) => (i.tenant_id, i.principal_id, i.policies),
        Err(e) => return e,
    };
    let client_ip = extract_client_ip(&headers);

    // Authorize before creating the key.
    let resource = format!("transit/keys/{}", key_name);
    if let Err(e) = state
        .policy_client
        .authorize(&tenant_id, &principal_id, &policies, "write", &resource)
        .await
    {
        state
            .audit_client
            .emit(
                &tenant_id,
                &principal_id,
                "transit.key.create",
                &key_name,
                "failure",
                &e.to_string(),
                "",
                &client_ip,
            )
            .await;
        return vault_error_response(e).into_response();
    }

    match state
        .key_store
        .create_key(&tenant_id, &key_name, algorithm)
        .await
    {
        Ok(()) => {
            state
                .audit_client
                .emit(
                    &tenant_id,
                    &principal_id,
                    "transit.key.create",
                    &key_name,
                    "success",
                    "",
                    "",
                    &client_ip,
                )
                .await;
            (
                StatusCode::CREATED,
                Json(CreateKeyResponse {
                    key_name,
                    algorithm: algorithm.as_str().into(),
                }),
            )
                .into_response()
        }
        Err(e) => {
            state
                .audit_client
                .emit(
                    &tenant_id,
                    &principal_id,
                    "transit.key.create",
                    &key_name,
                    "failure",
                    &e.to_string(),
                    "",
                    &client_ip,
                )
                .await;
            vault_error_response(e).into_response()
        }
    }
}

/// POST /v1/transit/keys/:key_name/rotate  — add a new key version
///
/// Adds a new version to the named key. New encryptions use the latest version.
/// Existing ciphertexts can be upgraded with the rewrap endpoint.
#[utoipa::path(
    post,
    path = "/v1/transit/keys/{key_name}/rotate",
    params(
        ("key_name" = String, Path, description = "Name of the key to rotate"),
        ("x-tenant-id" = String, Header, description = "Tenant identifier (required)"),
    ),
    responses(
        (status = 200, description = "Key rotated; returns new version number", body = RotateKeyResponse),
        (status = 400, description = "Missing X-Tenant-Id header"),
        (status = 403, description = "Authorization denied by policy-engine"),
        (status = 404, description = "Key not found"),
    ),
    tag = "keys"
)]
pub async fn rotate_key_handler(
    State(state): State<AppState>,
    Path(key_name): Path<String>,
    headers: HeaderMap,
) -> impl IntoResponse {
    let (tenant_id, principal_id, policies) = match authenticate(&headers).await {
        Ok(i) => (i.tenant_id, i.principal_id, i.policies),
        Err(e) => return e,
    };
    let client_ip = extract_client_ip(&headers);

    // Authorize before rotating the key.
    let resource = format!("transit/keys/{}/rotate", key_name);
    if let Err(e) = state
        .policy_client
        .authorize(&tenant_id, &principal_id, &policies, "write", &resource)
        .await
    {
        state
            .audit_client
            .emit(
                &tenant_id,
                &principal_id,
                "transit.key.rotate",
                &key_name,
                "failure",
                &e.to_string(),
                "",
                &client_ip,
            )
            .await;
        return vault_error_response(e).into_response();
    }

    match state.key_store.rotate_key(&tenant_id, &key_name).await {
        Ok(new_version) => {
            state
                .audit_client
                .emit(
                    &tenant_id,
                    &principal_id,
                    "transit.key.rotate",
                    &key_name,
                    "success",
                    "",
                    "",
                    &client_ip,
                )
                .await;
            (
                StatusCode::OK,
                Json(RotateKeyResponse {
                    key_name,
                    new_version,
                }),
            )
                .into_response()
        }
        Err(e) => {
            state
                .audit_client
                .emit(
                    &tenant_id,
                    &principal_id,
                    "transit.key.rotate",
                    &key_name,
                    "failure",
                    &e.to_string(),
                    "",
                    &client_ip,
                )
                .await;
            vault_error_response(e).into_response()
        }
    }
}

/// Refuse a cipher operation on an Ed25519 signing key.
///
/// Without this an Ed25519 seed would be accepted as an AES-256 key: both are
/// 32 bytes, so `encrypt` would "work" and turn a signing key into a cipher
/// key, which removes the separation between the two that the key type exists
/// to provide.
#[allow(clippy::result_large_err)] // same convention as secret-engine's authenticate
async fn require_symmetric(
    state: &AppState,
    key: &TransitKey,
    tenant_id: &str,
    principal_id: &str,
    action: &str,
    client_ip: &str,
) -> Result<(), Response> {
    if key.algorithm.is_symmetric() {
        return Ok(());
    }
    let reason = format!(
        "key '{}' is a {} signing key; it supports sign, verify and public only",
        key.name,
        key.algorithm.as_str()
    );
    state
        .audit_client
        .emit(
            tenant_id,
            principal_id,
            action,
            &key.name,
            "failure",
            &reason,
            "",
            client_ip,
        )
        .await;
    Err((
        StatusCode::BAD_REQUEST,
        Json(ErrorResponse { error: reason }),
    )
        .into_response())
}

/// POST /v1/transit/hmac/:key_name
///
/// HMAC-SHA256 over base64 data with a symmetric key, versioned as
/// `vault:v{N}:{hex}`. Pass `key_version` to recompute a stored MAC after the
/// key has been rotated.
#[utoipa::path(
    post,
    path = "/v1/transit/hmac/{key_name}",
    params(("key_name" = String, Path, description = "Name of an aes256-gcm key")),
    request_body = HmacRequest,
    responses(
        (status = 200, description = "Versioned HMAC", body = HmacResponse),
        (status = 400, description = "Invalid base64 data, or the key is a signing key"),
        (status = 403, description = "Authorization denied by policy-engine"),
        (status = 404, description = "Key or key version not found"),
    ),
    tag = "transit"
)]
pub async fn hmac_handler(
    State(state): State<AppState>,
    Path(key_name): Path<String>,
    headers: HeaderMap,
    Json(body): Json<HmacRequest>,
) -> impl IntoResponse {
    let (tenant_id, principal_id, policies) = match authenticate(&headers).await {
        Ok(i) => (i.tenant_id, i.principal_id, i.policies),
        Err(e) => return e,
    };
    let client_ip = extract_client_ip(&headers);
    let action = "transit.hmac";

    let resource = format!("transit/hmac/{}", key_name);
    if let Err(e) = state
        .policy_client
        .authorize(&tenant_id, &principal_id, &policies, "write", &resource)
        .await
    {
        state
            .audit_client
            .emit(
                &tenant_id,
                &principal_id,
                action,
                &key_name,
                "failure",
                &e.to_string(),
                "",
                &client_ip,
            )
            .await;
        return vault_error_response(e).into_response();
    }

    let Ok(data) = BASE64.decode(&body.data) else {
        return (
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse {
                error: "data must be valid base64".into(),
            }),
        )
            .into_response();
    };

    let key = match state.key_store.get_key(&tenant_id, &key_name).await {
        Ok(k) => k,
        Err(e) => {
            state
                .audit_client
                .emit(
                    &tenant_id,
                    &principal_id,
                    action,
                    &key_name,
                    "failure",
                    &e.to_string(),
                    "",
                    &client_ip,
                )
                .await;
            return vault_error_response(e).into_response();
        }
    };
    if let Err(resp) =
        require_symmetric(&state, &key, &tenant_id, &principal_id, action, &client_ip).await
    {
        return resp;
    }

    match hmac_versioned(&key, &data, body.key_version) {
        Ok((hmac, key_version)) => {
            state
                .audit_client
                .emit(
                    &tenant_id,
                    &principal_id,
                    action,
                    &key_name,
                    "success",
                    "",
                    "",
                    &client_ip,
                )
                .await;
            (StatusCode::OK, Json(HmacResponse { hmac, key_version })).into_response()
        }
        Err(e) => {
            state
                .audit_client
                .emit(
                    &tenant_id,
                    &principal_id,
                    action,
                    &key_name,
                    "failure",
                    &e.to_string(),
                    "",
                    &client_ip,
                )
                .await;
            vault_error_response(e).into_response()
        }
    }
}

/// GET /v1/transit/keys/:key_name/public
///
/// The public keys of every version of an Ed25519 key, as a JWK Set (RFC 7517,
/// OKP per RFC 8037). An identity provider serves this, or a cached copy, as
/// its `jwks_uri`. The private seed never leaves the service; nothing here can
/// be used to sign.
#[utoipa::path(
    get,
    path = "/v1/transit/keys/{key_name}/public",
    params(("key_name" = String, Path, description = "Name of an ed25519 key")),
    responses(
        (status = 200, description = "JWK Set with one entry per key version"),
        (status = 400, description = "The key is not an ed25519 key"),
        (status = 403, description = "Authorization denied by policy-engine"),
        (status = 404, description = "Key not found"),
    ),
    tag = "keys"
)]
pub async fn public_keys_handler(
    State(state): State<AppState>,
    Path(key_name): Path<String>,
    headers: HeaderMap,
) -> impl IntoResponse {
    let (tenant_id, principal_id, policies) = match authenticate(&headers).await {
        Ok(i) => (i.tenant_id, i.principal_id, i.policies),
        Err(e) => return e,
    };

    let resource = format!("transit/keys/{}/public", key_name);
    if let Err(e) = state
        .policy_client
        .authorize(&tenant_id, &principal_id, &policies, "read", &resource)
        .await
    {
        return vault_error_response(e).into_response();
    }

    let key = match state.key_store.get_key(&tenant_id, &key_name).await {
        Ok(k) => k,
        Err(e) => return vault_error_response(e).into_response(),
    };
    if key.algorithm != KeyAlgorithm::Ed25519 {
        return (
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse {
                error: format!(
                    "key '{}' is {}, which has no public key",
                    key.name,
                    key.algorithm.as_str()
                ),
            }),
        )
            .into_response();
    }
    (StatusCode::OK, Json(ed25519_jwks(&key))).into_response()
}
