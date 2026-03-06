//! Axum REST route handlers for the transit-engine.
//!
//! All routes are under `/v1/transit/` and operate on named keys scoped to a
//! tenant.  For simplicity the tenant ID is read from the `X-Tenant-Id` header;
//! in production this would come from a validated JWT claim.

use axum::{
    extract::{Path, State},
    http::{HeaderMap, StatusCode},
    response::IntoResponse,
    Json,
};
use serde::{Deserialize, Serialize};

use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine as _;

use wslvault_core::VaultError;

use crate::key_store::{create_key, get_key, rotate_key, SharedKeyStore};
use crate::operations::{decrypt, encrypt, rewrap, sign_data, verify_data};

/// Shared application state threaded through axum.
#[derive(Clone)]
pub struct AppState {
    pub key_store: SharedKeyStore,
}

// ---------------------------------------------------------------------------
// Request / Response types
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
pub struct EncryptRequest {
    /// Base64-encoded plaintext to encrypt.
    pub plaintext: String,
}

#[derive(Serialize)]
pub struct EncryptResponse {
    pub ciphertext: String,
}

#[derive(Deserialize)]
pub struct DecryptRequest {
    /// Versioned ciphertext string as produced by the encrypt endpoint.
    pub ciphertext: String,
}

#[derive(Serialize)]
pub struct DecryptResponse {
    /// Base64-encoded plaintext.
    pub plaintext: String,
}

#[derive(Deserialize)]
pub struct SignRequest {
    /// Base64-encoded data to sign.
    pub data: String,
}

#[derive(Serialize)]
pub struct SignResponse {
    pub signature: String,
}

#[derive(Deserialize)]
pub struct VerifyRequest {
    /// Base64-encoded data to verify.
    pub data: String,
    pub signature: String,
}

#[derive(Serialize)]
pub struct VerifyResponse {
    pub valid: bool,
}

#[derive(Deserialize)]
pub struct RewrapRequest {
    /// Existing versioned ciphertext to upgrade to the latest key version.
    pub ciphertext: String,
}

#[derive(Serialize)]
pub struct RewrapResponse {
    pub ciphertext: String,
}

#[derive(Serialize)]
pub struct CreateKeyResponse {
    pub key_name: String,
    pub algorithm: String,
}

#[derive(Serialize)]
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
// Helper: extract tenant_id from request headers
// ---------------------------------------------------------------------------

fn extract_tenant_id(headers: &HeaderMap) -> Result<String, (StatusCode, Json<ErrorResponse>)> {
    headers
        .get("x-tenant-id")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string())
        .ok_or_else(|| {
            (
                StatusCode::BAD_REQUEST,
                Json(ErrorResponse {
                    error: "missing X-Tenant-Id header".into(),
                }),
            )
        })
}

/// Convert a VaultError to an appropriate HTTP status + JSON error response.
fn vault_error_response(err: VaultError) -> (StatusCode, Json<ErrorResponse>) {
    let status = match err.http_status() {
        400 => StatusCode::BAD_REQUEST,
        404 => StatusCode::NOT_FOUND,
        409 => StatusCode::CONFLICT,
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
pub async fn encrypt_handler(
    State(state): State<AppState>,
    Path(key_name): Path<String>,
    headers: HeaderMap,
    Json(body): Json<EncryptRequest>,
) -> impl IntoResponse {
    let tenant_id = match extract_tenant_id(&headers) {
        Ok(t) => t,
        Err(e) => return e.into_response(),
    };

    let plaintext = match BASE64.decode(&body.plaintext) {
        Ok(p) => p,
        Err(_) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(ErrorResponse {
                    error: "plaintext must be valid base64".into(),
                }),
            )
                .into_response()
        }
    };

    let key = match get_key(&state.key_store, &tenant_id, &key_name).await {
        Ok(k) => k,
        Err(e) => return vault_error_response(e).into_response(),
    };

    match encrypt(&key, &plaintext) {
        Ok(ciphertext) => (StatusCode::OK, Json(EncryptResponse { ciphertext })).into_response(),
        Err(e) => vault_error_response(e).into_response(),
    }
}

/// POST /v1/transit/decrypt/:key_name
pub async fn decrypt_handler(
    State(state): State<AppState>,
    Path(key_name): Path<String>,
    headers: HeaderMap,
    Json(body): Json<DecryptRequest>,
) -> impl IntoResponse {
    let tenant_id = match extract_tenant_id(&headers) {
        Ok(t) => t,
        Err(e) => return e.into_response(),
    };

    let key = match get_key(&state.key_store, &tenant_id, &key_name).await {
        Ok(k) => k,
        Err(e) => return vault_error_response(e).into_response(),
    };

    match decrypt(&key, &body.ciphertext) {
        Ok(plaintext_bytes) => {
            let plaintext_b64 = BASE64.encode(&plaintext_bytes);
            (StatusCode::OK, Json(DecryptResponse { plaintext: plaintext_b64 })).into_response()
        }
        Err(e) => vault_error_response(e).into_response(),
    }
}

/// POST /v1/transit/sign/:key_name
pub async fn sign_handler(
    State(state): State<AppState>,
    Path(key_name): Path<String>,
    headers: HeaderMap,
    Json(body): Json<SignRequest>,
) -> impl IntoResponse {
    let tenant_id = match extract_tenant_id(&headers) {
        Ok(t) => t,
        Err(e) => return e.into_response(),
    };

    let data = match BASE64.decode(&body.data) {
        Ok(d) => d,
        Err(_) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(ErrorResponse {
                    error: "data must be valid base64".into(),
                }),
            )
                .into_response()
        }
    };

    let key = match get_key(&state.key_store, &tenant_id, &key_name).await {
        Ok(k) => k,
        Err(e) => return vault_error_response(e).into_response(),
    };

    let signature = sign_data(key.current_material(), &data);
    (StatusCode::OK, Json(SignResponse { signature })).into_response()
}

/// POST /v1/transit/verify/:key_name
pub async fn verify_handler(
    State(state): State<AppState>,
    Path(key_name): Path<String>,
    headers: HeaderMap,
    Json(body): Json<VerifyRequest>,
) -> impl IntoResponse {
    let tenant_id = match extract_tenant_id(&headers) {
        Ok(t) => t,
        Err(e) => return e.into_response(),
    };

    let data = match BASE64.decode(&body.data) {
        Ok(d) => d,
        Err(_) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(ErrorResponse {
                    error: "data must be valid base64".into(),
                }),
            )
                .into_response()
        }
    };

    let key = match get_key(&state.key_store, &tenant_id, &key_name).await {
        Ok(k) => k,
        Err(e) => return vault_error_response(e).into_response(),
    };

    let valid = verify_data(key.current_material(), &data, &body.signature);
    (StatusCode::OK, Json(VerifyResponse { valid })).into_response()
}

/// POST /v1/transit/rewrap/:key_name
pub async fn rewrap_handler(
    State(state): State<AppState>,
    Path(key_name): Path<String>,
    headers: HeaderMap,
    Json(body): Json<RewrapRequest>,
) -> impl IntoResponse {
    let tenant_id = match extract_tenant_id(&headers) {
        Ok(t) => t,
        Err(e) => return e.into_response(),
    };

    let key = match get_key(&state.key_store, &tenant_id, &key_name).await {
        Ok(k) => k,
        Err(e) => return vault_error_response(e).into_response(),
    };

    match rewrap(&key, &body.ciphertext) {
        Ok(ciphertext) => (StatusCode::OK, Json(RewrapResponse { ciphertext })).into_response(),
        Err(e) => vault_error_response(e).into_response(),
    }
}

/// POST /v1/transit/keys/:key_name  — create a new named key
pub async fn create_key_handler(
    State(state): State<AppState>,
    Path(key_name): Path<String>,
    headers: HeaderMap,
) -> impl IntoResponse {
    let tenant_id = match extract_tenant_id(&headers) {
        Ok(t) => t,
        Err(e) => return e.into_response(),
    };

    match create_key(&state.key_store, &tenant_id, &key_name).await {
        Ok(()) => (
            StatusCode::CREATED,
            Json(CreateKeyResponse {
                key_name,
                algorithm: "aes256-gcm".into(),
            }),
        )
            .into_response(),
        Err(e) => vault_error_response(e).into_response(),
    }
}

/// POST /v1/transit/keys/:key_name/rotate  — add a new key version
pub async fn rotate_key_handler(
    State(state): State<AppState>,
    Path(key_name): Path<String>,
    headers: HeaderMap,
) -> impl IntoResponse {
    let tenant_id = match extract_tenant_id(&headers) {
        Ok(t) => t,
        Err(e) => return e.into_response(),
    };

    match rotate_key(&state.key_store, &tenant_id, &key_name).await {
        Ok(new_version) => (
            StatusCode::OK,
            Json(RotateKeyResponse {
                key_name,
                new_version,
            }),
        )
            .into_response(),
        Err(e) => vault_error_response(e).into_response(),
    }
}
