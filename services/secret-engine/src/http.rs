//! REST API layer for the secret engine using axum.
//!
//! All endpoints mirror the gRPC service surface and speak JSON. The REST API
//! is intended for human operators and tooling that cannot use gRPC directly.
//!
//! # Endpoints
//! | Method | Path                           | Action          |
//! |--------|-------------------------------|-----------------|
//! | GET    | /v1/secret/data/*path         | GetSecret       |
//! | POST   | /v1/secret/data/*path         | PutSecret       |
//! | POST   | /v1/secret/delete/*path       | DeleteSecret    |
//! | POST   | /v1/secret/destroy/*path      | DestroySecret   |
//! | GET    | /v1/secret/metadata/*path     | GetMetadata     |
//! | GET    | /v1/secret/list               | ListSecrets     |
//!
//! All endpoints require a `X-Tenant-Id` header to scope the operation.

use std::sync::Arc;

use axum::{
    extract::{Path, Query, Request, State},
    http::{HeaderMap, StatusCode},
    middleware::Next,
    response::{IntoResponse, Response},
    routing::{get, post},
    Json, Router,
};
use serde::{Deserialize, Serialize};
use tracing::{error, info, instrument};

use crate::audit_client::AuditClient;
use crate::grpc::crypto_proto;
use crate::kv_store::SecretStoreBackend;
use crate::lease_client::LeaseClient;
use crate::path::normalize_and_validate;
use crate::policy_client::PolicyClient;

use wslvault_core::metrics::collector::{SECRETS_MANAGED, SECRET_OPERATIONS_TOTAL};
use wslvault_core::VaultError;

// ─── Shared app state ────────────────────────────────────────────────────────

/// State shared across all HTTP handlers.
///
/// `store` is `Arc<dyn SecretStoreBackend>` so the HTTP layer is independent
/// of the specific storage backend (in-memory or PostgreSQL).
/// `audit_client` is used to emit fire-and-forget audit events after every
/// handler completes; failures are logged but never block responses.
/// `policy_client` gates every operation behind an authorization check;
/// if the policy-engine is unreachable the request is denied (fail-closed).
/// `lease_client` is used to optionally attach TTL-based leases to secret
/// reads; if the lease-manager is unreachable the read still succeeds
/// (degraded mode — no lease is attached).
#[derive(Clone)]
pub struct AppState {
    pub store: Arc<dyn SecretStoreBackend>,
    /// Lazily-connected channel to the crypto-service.
    ///
    /// Was a URL that every handler dialled afresh, so each encrypt or decrypt
    /// paid for a TCP plus HTTP/2 handshake before doing any work.
    pub crypto_channel: tonic::transport::Channel,
    pub audit_client: AuditClient,
    pub policy_client: PolicyClient,
    pub lease_client: LeaseClient,
}

// ─── Error helpers ────────────────────────────────────────────────────────────

/// JSON-serializable error body returned on every error response.
#[derive(Debug, Serialize)]
struct ApiError {
    code: &'static str,
    message: String,
}

/// Convert a `VaultError` to an HTTP response with the appropriate status code.
fn vault_err_to_response(err: VaultError) -> Response {
    let status =
        StatusCode::from_u16(err.http_status()).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);
    let body = ApiError {
        code: err.code(),
        message: err.to_string(),
    };
    (status, Json(body)).into_response()
}

/// Extract the `X-Client-Ip` header from the request, returning an empty
/// string when the header is absent or not valid UTF-8.
fn extract_client_ip(headers: &HeaderMap) -> String {
    headers
        .get("x-client-ip")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_string()
}

/// Reject unauthenticated requests **before** any extractor runs.
///
/// Handler-level authentication is not sufficient on its own. Axum runs every
/// extractor in the handler signature first, so a request with a malformed body
/// was answered `422 Unprocessable Entity` — with the expected schema — without
/// ever reaching the handler's own auth check. That both leaks the request shape
/// to an anonymous caller and makes the guarantee depend on each handler
/// remembering to ask.
///
/// As a layer it holds for every route on the router, including any added
/// later, and it runs before body parsing.
async fn require_authenticated(request: Request, next: Next) -> Response {
    if let Err(reason) = wslvault_core::auth::resolve_identity(request.headers()) {
        // The KV v2 mount speaks Vault's error shape; Vault clients (notably
        // the External Secrets Operator) parse it. The native mount speaks
        // this service's own.
        let path = request.uri().path();
        return if path.starts_with("/v1/kv/") {
            (
                StatusCode::UNAUTHORIZED,
                Json(serde_json::json!({ "errors": [reason.to_string()] })),
            )
                .into_response()
        } else {
            (
                StatusCode::UNAUTHORIZED,
                Json(ApiError {
                    code: "unauthenticated",
                    message: reason.to_string(),
                }),
            )
                .into_response()
        };
    }
    next.run(request).await
}

/// Authenticate the caller and return their verified identity.
///
/// This replaces the previous `extract_tenant_id` / `extract_principal_id` /
/// `extract_policies` trio, which read `X-Tenant-Id`, `X-Principal-Id` and
/// `X-Policies` straight off the request. Those headers are attacker-controlled:
/// any caller who could reach this service could name a tenant and a policy set
/// and be believed, which meant reading or writing any tenant's secrets with no
/// credential at all. The gateway that was supposed to overwrite them does not
/// scrub them, is not configured by the Helm chart, and is not deployed in the
/// live regions.
///
/// Identity now comes from [`wslvault_core::auth::resolve_identity`] — the same
/// verified path the KV v2 mount uses — so a tenant and its policies can only
/// come from a signed token, or from the gateway contract when an operator has
/// explicitly opted in via `VAULT_TRUST_GATEWAY_HEADERS`.
#[allow(clippy::result_large_err)]
fn authenticate(headers: &HeaderMap) -> Result<wslvault_core::auth::Identity, Response> {
    wslvault_core::auth::resolve_identity(headers).map_err(|e| {
        (
            StatusCode::UNAUTHORIZED,
            Json(ApiError {
                code: "unauthenticated",
                message: e.to_string(),
            }),
        )
            .into_response()
    })
}

// ─── Request / response bodies ────────────────────────────────────────────────

#[derive(Debug, Deserialize, utoipa::ToSchema)]
pub struct PutSecretBody {
    /// Base64-encoded plaintext data to store.
    pub data: String,
    /// Optional check-and-set version. If provided, the write only succeeds when
    /// the current version matches this value.
    pub cas: Option<u32>,
    #[serde(default)]
    pub metadata: std::collections::HashMap<String, String>,
}

#[derive(Debug, Serialize, utoipa::ToSchema)]
pub struct PutSecretResponseBody {
    pub secret_id: String,
    pub version: u32,
}

#[derive(Debug, Serialize, utoipa::ToSchema)]
pub struct GetSecretResponseBody {
    /// Base64-encoded decrypted secret data.
    pub data: String,
    pub version: u32,
    pub created_at: String,
    pub metadata: std::collections::HashMap<String, String>,
    /// Opaque lease identifier assigned by the lease-manager.
    /// `None` when the lease-manager is unavailable (degraded mode) or
    /// when no TTL was requested.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub lease_id: Option<String>,
    /// TTL in seconds for the issued lease, when `lease_id` is `Some`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub lease_duration: Option<i64>,
}

#[derive(Debug, Deserialize, utoipa::ToSchema)]
pub struct DeleteVersionsBody {
    #[serde(default)]
    pub versions: Vec<u32>,
}

#[derive(Debug, Serialize, utoipa::ToSchema)]
pub struct DeleteResponseBody {
    pub count: u32,
}

#[derive(Debug, Serialize, utoipa::ToSchema)]
pub struct MetadataResponseBody {
    pub secret_id: String,
    pub path: String,
    pub engine: String,
    pub current_version: u32,
    pub max_versions: u32,
    pub cas_required: bool,
    pub created_at: String,
    pub updated_at: String,
}

#[derive(Debug, Serialize, utoipa::ToSchema)]
pub struct ListResponseBody {
    pub paths: Vec<String>,
}

#[derive(Debug, Deserialize, utoipa::IntoParams)]
pub struct ListQuery {
    /// Optional path prefix to restrict the listing.
    pub prefix: Option<String>,
}

#[derive(Debug, Deserialize, utoipa::IntoParams)]
pub struct VersionQuery {
    /// Specific version number to retrieve. Omit to get the current version.
    pub version: Option<u32>,
}

// ─── OpenAPI document ─────────────────────────────────────────────────────────

/// Collects all secret-engine REST paths and schemas into a single OpenAPI document.
///
/// Health probe paths (`/healthz`, `/readyz`) are intentionally excluded here
/// because they are registered on the router in `server.rs` rather than inside
/// `build_router`.  They carry no secrets and do not require authentication.
#[derive(utoipa::OpenApi)]
#[openapi(
    paths(
        get_secret,
        put_secret,
        delete_secret,
        destroy_secret,
        get_metadata,
        list_secrets,
    ),
    components(schemas(
        GetSecretResponseBody,
        PutSecretBody,
        PutSecretResponseBody,
        DeleteVersionsBody,
        DeleteResponseBody,
        MetadataResponseBody,
        ListResponseBody,
    )),
    tags(
        (name = "secrets", description = "KV secret CRUD operations"),
    ),
    info(
        title = "Secret Engine API",
        version = "0.1.0",
        description = "WSLVault KV secret engine REST API",
    )
)]
pub struct ApiDoc;

// ─── Handlers ─────────────────────────────────────────────────────────────────

/// GET /v1/secret/data/*path
///
/// Retrieve a secret and decrypt it. An optional `?version=N` query parameter
/// selects a specific version; omit it to get the current version.
#[utoipa::path(
    get,
    path = "/v1/secret/data/{path}",
    params(
        ("path" = String, Path, description = "Secret path (e.g. myapp/database)"),
        VersionQuery,
        ("x-tenant-id" = String, Header, description = "Tenant identifier (required)"),
    ),
    responses(
        (status = 200, description = "Secret retrieved and decrypted", body = GetSecretResponseBody),
        (status = 400, description = "Missing or invalid X-Tenant-Id header"),
        (status = 403, description = "Authorization denied by policy-engine"),
        (status = 404, description = "Secret path not found"),
        (status = 503, description = "Crypto-service or policy-engine unavailable"),
    ),
    tag = "secrets"
)]
#[instrument(skip(state, headers), fields(path, tenant_id))]
pub async fn get_secret(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(path): Path<String>,
    Query(query): Query<VersionQuery>,
) -> Response {
    let wslvault_core::auth::Identity {
        tenant_id,
        principal_id,
        policies,
        ..
    } = match authenticate(&headers) {
        Ok(i) => i,
        Err(r) => return r,
    };
    let client_ip = extract_client_ip(&headers);

    let normalized_path = match normalize_and_validate(&path) {
        Ok(p) => p,
        Err(e) => return vault_err_to_response(e),
    };

    tracing::Span::current().record("path", &normalized_path.as_str());
    tracing::Span::current().record("tenant_id", &tenant_id.as_str());
    info!("http get_secret");

    // Authorize the read operation before touching the store.
    let resource = format!("secret/data/{}", normalized_path);
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
                "secret.read",
                &normalized_path,
                "failure",
                &e.to_string(),
                "",
                &client_ip,
            )
            .await;
        return vault_err_to_response(e);
    }

    let ver_entry = match state
        .store
        .get(&tenant_id, &normalized_path, query.version)
        .await
    {
        Ok(v) => v,
        Err(e) => {
            state
                .audit_client
                .emit(
                    &tenant_id,
                    &principal_id,
                    "secret.read",
                    &normalized_path,
                    "failure",
                    &e.to_string(),
                    "",
                    &client_ip,
                )
                .await;
            return vault_err_to_response(e);
        }
    };

    // Decrypt the stored ciphertext via the crypto-service.
    let aad = format!("{}:{}", tenant_id, normalized_path).into_bytes();

    let mut crypto_client = match Ok::<_, tonic::transport::Error>(
        crypto_proto::crypto_service_client::CryptoServiceClient::new(state.crypto_channel.clone()),
    ) {
        Ok(c) => c,
        Err(e) => {
            error!(error = %e, "crypto-service connect failed");
            state
                .audit_client
                .emit(
                    &tenant_id,
                    &principal_id,
                    "secret.read",
                    &normalized_path,
                    "failure",
                    &format!("crypto-service unavailable: {}", e),
                    "",
                    &client_ip,
                )
                .await;
            return (
                StatusCode::SERVICE_UNAVAILABLE,
                Json(ApiError {
                    code: "service_unavailable",
                    message: format!("crypto-service unavailable: {}", e),
                }),
            )
                .into_response();
        }
    };

    // Crypto-service expects "<dek_id>:<ciphertext_b64>" in the ciphertext_b64 field
    let combined_ciphertext = format!("{}:{}", ver_entry.dek_id, ver_entry.ciphertext);

    let decrypt_resp = match crypto_client
        .decrypt(crypto_proto::DecryptRequest {
            tenant_id: tenant_id.clone(),
            ciphertext_b64: combined_ciphertext,
            aad,
        })
        .await
    {
        Ok(r) => r.into_inner(),
        Err(e) => {
            error!(error = %e, "crypto-service decrypt failed");
            state
                .audit_client
                .emit(
                    &tenant_id,
                    &principal_id,
                    "secret.read",
                    &normalized_path,
                    "failure",
                    &format!("decryption failed: {}", e),
                    "",
                    &client_ip,
                )
                .await;
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ApiError {
                    code: "decryption_failed",
                    message: format!("decryption failed: {}", e),
                }),
            )
                .into_response();
        }
    };

    let data_b64 = base64_encode(&decrypt_resp.plaintext);

    SECRET_OPERATIONS_TOTAL
        .with_label_values(&["read", &tenant_id, "success"])
        .inc();

    // Attempt to create a TTL-based lease for this secret read.
    // This is best-effort — if the lease-manager is unavailable the read still
    // succeeds and `lease_info` will be `None` (degraded mode).
    let default_ttl_seconds: i64 = 3600;
    let lease_info = state
        .lease_client
        .create_lease_for_read(&tenant_id, &normalized_path, default_ttl_seconds)
        .await;

    state
        .audit_client
        .emit(
            &tenant_id,
            &principal_id,
            "secret.read",
            &normalized_path,
            "success",
            "",
            "",
            &client_ip,
        )
        .await;

    let (lease_id, lease_duration) = match lease_info {
        Some(info) => (Some(info.lease_id), Some(info.ttl_seconds)),
        None => (None, None),
    };

    (
        StatusCode::OK,
        Json(GetSecretResponseBody {
            data: data_b64,
            version: ver_entry.version,
            created_at: ver_entry.created_at.to_rfc3339(),
            metadata: ver_entry.custom_metadata,
            lease_id,
            lease_duration,
        }),
    )
        .into_response()
}

/// POST /v1/secret/data/*path
///
/// Write a new secret version. The request body must include `data` as a
/// base64-encoded string. An optional `cas` field enables optimistic locking.
#[utoipa::path(
    post,
    path = "/v1/secret/data/{path}",
    params(
        ("path" = String, Path, description = "Secret path (e.g. myapp/database)"),
        ("x-tenant-id" = String, Header, description = "Tenant identifier (required)"),
    ),
    request_body = PutSecretBody,
    responses(
        (status = 200, description = "Secret version written", body = PutSecretResponseBody),
        (status = 400, description = "Missing or invalid header, or invalid base64 data"),
        (status = 403, description = "Authorization denied by policy-engine"),
        (status = 409, description = "CAS version mismatch"),
        (status = 503, description = "Crypto-service or policy-engine unavailable"),
    ),
    tag = "secrets"
)]
#[instrument(skip(state, headers, body), fields(path, tenant_id))]
pub async fn put_secret(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(path): Path<String>,
    Json(body): Json<PutSecretBody>,
) -> Response {
    let wslvault_core::auth::Identity {
        tenant_id,
        principal_id,
        policies,
        ..
    } = match authenticate(&headers) {
        Ok(i) => i,
        Err(r) => return r,
    };
    let client_ip = extract_client_ip(&headers);

    let normalized_path = match normalize_and_validate(&path) {
        Ok(p) => p,
        Err(e) => return vault_err_to_response(e),
    };

    tracing::Span::current().record("path", &normalized_path.as_str());
    tracing::Span::current().record("tenant_id", &tenant_id.as_str());
    info!("http put_secret");

    // Authorize the write operation before touching the crypto-service or store.
    let resource = format!("secret/data/{}", normalized_path);
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
                "secret.write",
                &normalized_path,
                "failure",
                &e.to_string(),
                "",
                &client_ip,
            )
            .await;
        return vault_err_to_response(e);
    }

    // Decode the caller-supplied base64 plaintext.
    let plaintext = match base64_decode(&body.data) {
        Ok(b) => b,
        Err(_) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(ApiError {
                    code: "validation_error",
                    message: "data field must be valid base64".into(),
                }),
            )
                .into_response();
        }
    };

    if plaintext.is_empty() {
        return (
            StatusCode::BAD_REQUEST,
            Json(ApiError {
                code: "validation_error",
                message: "data must not be empty".into(),
            }),
        )
            .into_response();
    }

    let aad = format!("{}:{}", tenant_id, normalized_path).into_bytes();

    let mut crypto_client = match Ok::<_, tonic::transport::Error>(
        crypto_proto::crypto_service_client::CryptoServiceClient::new(state.crypto_channel.clone()),
    ) {
        Ok(c) => c,
        Err(e) => {
            error!(error = %e, "crypto-service connect failed");
            state
                .audit_client
                .emit(
                    &tenant_id,
                    &principal_id,
                    "secret.write",
                    &normalized_path,
                    "failure",
                    &format!("crypto-service unavailable: {}", e),
                    "",
                    &client_ip,
                )
                .await;
            return (
                StatusCode::SERVICE_UNAVAILABLE,
                Json(ApiError {
                    code: "service_unavailable",
                    message: format!("crypto-service unavailable: {}", e),
                }),
            )
                .into_response();
        }
    };

    let encrypt_resp = match crypto_client
        .encrypt(crypto_proto::EncryptRequest {
            tenant_id: tenant_id.clone(),
            plaintext,
            aad,
        })
        .await
    {
        Ok(r) => r.into_inner(),
        Err(e) => {
            error!(error = %e, "crypto-service encrypt failed");
            state
                .audit_client
                .emit(
                    &tenant_id,
                    &principal_id,
                    "secret.write",
                    &normalized_path,
                    "failure",
                    &format!("encryption failed: {}", e),
                    "",
                    &client_ip,
                )
                .await;
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ApiError {
                    code: "encryption_failed",
                    message: format!("encryption failed: {}", e),
                }),
            )
                .into_response();
        }
    };

    let (secret_id, version) = match state
        .store
        .put(
            &tenant_id,
            &normalized_path,
            encrypt_resp.ciphertext_b64,
            encrypt_resp.dek_id,
            body.cas,
            body.metadata,
            None,
        )
        .await
    {
        Ok(r) => r,
        Err(e) => {
            state
                .audit_client
                .emit(
                    &tenant_id,
                    &principal_id,
                    "secret.write",
                    &normalized_path,
                    "failure",
                    &e.to_string(),
                    "",
                    &client_ip,
                )
                .await;
            return vault_err_to_response(e);
        }
    };

    SECRET_OPERATIONS_TOTAL
        .with_label_values(&["write", &tenant_id, "success"])
        .inc();
    SECRETS_MANAGED
        .with_label_values(&[tenant_id.as_str(), "kv-v2"])
        .inc();

    state
        .audit_client
        .emit(
            &tenant_id,
            &principal_id,
            "secret.write",
            &normalized_path,
            "success",
            "",
            "",
            &client_ip,
        )
        .await;

    (
        StatusCode::OK,
        Json(PutSecretResponseBody { secret_id, version }),
    )
        .into_response()
}

/// POST /v1/secret/delete/*path
///
/// Soft-delete secret versions. Pass a JSON body with an optional `versions`
/// array; omit the field to delete the current version.
#[utoipa::path(
    post,
    path = "/v1/secret/delete/{path}",
    params(
        ("path" = String, Path, description = "Secret path to soft-delete"),
        ("x-tenant-id" = String, Header, description = "Tenant identifier (required)"),
    ),
    request_body = DeleteVersionsBody,
    responses(
        (status = 200, description = "Versions soft-deleted", body = DeleteResponseBody),
        (status = 400, description = "Missing X-Tenant-Id header"),
        (status = 403, description = "Authorization denied by policy-engine"),
        (status = 404, description = "Secret path not found"),
    ),
    tag = "secrets"
)]
#[instrument(skip(state, headers, body), fields(path, tenant_id))]
pub async fn delete_secret(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(path): Path<String>,
    Json(body): Json<DeleteVersionsBody>,
) -> Response {
    let wslvault_core::auth::Identity {
        tenant_id,
        principal_id,
        policies,
        ..
    } = match authenticate(&headers) {
        Ok(i) => i,
        Err(r) => return r,
    };
    let client_ip = extract_client_ip(&headers);

    let normalized_path = match normalize_and_validate(&path) {
        Ok(p) => p,
        Err(e) => return vault_err_to_response(e),
    };

    tracing::Span::current().record("path", &normalized_path.as_str());
    tracing::Span::current().record("tenant_id", &tenant_id.as_str());
    info!("http delete_secret");

    // Authorize the delete operation before touching the store.
    let resource = format!("secret/data/{}", normalized_path);
    if let Err(e) = state
        .policy_client
        .authorize(&tenant_id, &principal_id, &policies, "delete", &resource)
        .await
    {
        state
            .audit_client
            .emit(
                &tenant_id,
                &principal_id,
                "secret.delete",
                &normalized_path,
                "failure",
                &e.to_string(),
                "",
                &client_ip,
            )
            .await;
        return vault_err_to_response(e);
    }

    let count = match state
        .store
        .soft_delete(&tenant_id, &normalized_path, &body.versions)
        .await
    {
        Ok(c) => c,
        Err(e) => {
            state
                .audit_client
                .emit(
                    &tenant_id,
                    &principal_id,
                    "secret.delete",
                    &normalized_path,
                    "failure",
                    &e.to_string(),
                    "",
                    &client_ip,
                )
                .await;
            return vault_err_to_response(e);
        }
    };

    SECRET_OPERATIONS_TOTAL
        .with_label_values(&["delete", &tenant_id, "success"])
        .inc();

    state
        .audit_client
        .emit(
            &tenant_id,
            &principal_id,
            "secret.delete",
            &normalized_path,
            "success",
            "",
            "",
            &client_ip,
        )
        .await;

    (StatusCode::OK, Json(DeleteResponseBody { count })).into_response()
}

/// POST /v1/secret/destroy/*path
///
/// Permanently destroy secret versions. This is irreversible — the ciphertext
/// is zeroed and data cannot be recovered.
#[utoipa::path(
    post,
    path = "/v1/secret/destroy/{path}",
    params(
        ("path" = String, Path, description = "Secret path to permanently destroy"),
        ("x-tenant-id" = String, Header, description = "Tenant identifier (required)"),
    ),
    request_body = DeleteVersionsBody,
    responses(
        (status = 200, description = "Versions permanently destroyed", body = DeleteResponseBody),
        (status = 400, description = "Missing X-Tenant-Id header"),
        (status = 403, description = "Authorization denied by policy-engine"),
        (status = 404, description = "Secret path not found"),
    ),
    tag = "secrets"
)]
#[instrument(skip(state, headers, body), fields(path, tenant_id))]
pub async fn destroy_secret(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(path): Path<String>,
    Json(body): Json<DeleteVersionsBody>,
) -> Response {
    let wslvault_core::auth::Identity {
        tenant_id,
        principal_id,
        policies,
        ..
    } = match authenticate(&headers) {
        Ok(i) => i,
        Err(r) => return r,
    };
    let client_ip = extract_client_ip(&headers);

    let normalized_path = match normalize_and_validate(&path) {
        Ok(p) => p,
        Err(e) => return vault_err_to_response(e),
    };

    tracing::Span::current().record("path", &normalized_path.as_str());
    tracing::Span::current().record("tenant_id", &tenant_id.as_str());
    info!("http destroy_secret");

    // Authorize the destroy operation before touching the store.
    let resource = format!("secret/data/{}", normalized_path);
    if let Err(e) = state
        .policy_client
        .authorize(&tenant_id, &principal_id, &policies, "delete", &resource)
        .await
    {
        state
            .audit_client
            .emit(
                &tenant_id,
                &principal_id,
                "secret.destroy",
                &normalized_path,
                "failure",
                &e.to_string(),
                "",
                &client_ip,
            )
            .await;
        return vault_err_to_response(e);
    }

    let count = match state
        .store
        .destroy(&tenant_id, &normalized_path, &body.versions)
        .await
    {
        Ok(c) => c,
        Err(e) => {
            state
                .audit_client
                .emit(
                    &tenant_id,
                    &principal_id,
                    "secret.destroy",
                    &normalized_path,
                    "failure",
                    &e.to_string(),
                    "",
                    &client_ip,
                )
                .await;
            return vault_err_to_response(e);
        }
    };

    SECRET_OPERATIONS_TOTAL
        .with_label_values(&["destroy", &tenant_id, "success"])
        .inc();

    state
        .audit_client
        .emit(
            &tenant_id,
            &principal_id,
            "secret.destroy",
            &normalized_path,
            "success",
            "",
            "",
            &client_ip,
        )
        .await;

    (StatusCode::OK, Json(DeleteResponseBody { count })).into_response()
}

/// GET /v1/secret/metadata/*path
///
/// Return metadata for a secret path without decrypting any version data.
#[utoipa::path(
    get,
    path = "/v1/secret/metadata/{path}",
    params(
        ("path" = String, Path, description = "Secret path to retrieve metadata for"),
        ("x-tenant-id" = String, Header, description = "Tenant identifier (required)"),
    ),
    responses(
        (status = 200, description = "Secret metadata retrieved", body = MetadataResponseBody),
        (status = 400, description = "Missing X-Tenant-Id header"),
        (status = 403, description = "Authorization denied by policy-engine"),
        (status = 404, description = "Secret path not found"),
    ),
    tag = "secrets"
)]
#[instrument(skip(state, headers), fields(path, tenant_id))]
pub async fn get_metadata(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(path): Path<String>,
) -> Response {
    let wslvault_core::auth::Identity {
        tenant_id,
        principal_id,
        policies,
        ..
    } = match authenticate(&headers) {
        Ok(i) => i,
        Err(r) => return r,
    };
    let client_ip = extract_client_ip(&headers);

    let normalized_path = match normalize_and_validate(&path) {
        Ok(p) => p,
        Err(e) => return vault_err_to_response(e),
    };

    tracing::Span::current().record("path", &normalized_path.as_str());
    tracing::Span::current().record("tenant_id", &tenant_id.as_str());
    info!("http get_metadata");

    // Authorize the metadata read before touching the store.
    let resource = format!("secret/metadata/{}", normalized_path);
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
                "secret.metadata.read",
                &normalized_path,
                "failure",
                &e.to_string(),
                "",
                &client_ip,
            )
            .await;
        return vault_err_to_response(e);
    }

    let entry = match state.store.get_metadata(&tenant_id, &normalized_path).await {
        Ok(e) => e,
        Err(e) => {
            state
                .audit_client
                .emit(
                    &tenant_id,
                    &principal_id,
                    "secret.metadata.read",
                    &normalized_path,
                    "failure",
                    &e.to_string(),
                    "",
                    &client_ip,
                )
                .await;
            return vault_err_to_response(e);
        }
    };

    state
        .audit_client
        .emit(
            &tenant_id,
            &principal_id,
            "secret.metadata.read",
            &normalized_path,
            "success",
            "",
            "",
            &client_ip,
        )
        .await;

    (
        StatusCode::OK,
        Json(MetadataResponseBody {
            current_version: entry.current_version_number(),
            secret_id: entry.secret_id,
            path: entry.path,
            engine: "kv-v2".to_string(),
            max_versions: entry.max_versions,
            cas_required: entry.cas_required,
            created_at: entry.created_at.to_rfc3339(),
            updated_at: entry.updated_at.to_rfc3339(),
        }),
    )
        .into_response()
}

/// GET /v1/secret/list
///
/// List all secret paths under an optional prefix. Supply `?prefix=foo/bar`
/// to restrict the listing.
#[utoipa::path(
    get,
    path = "/v1/secret/list",
    params(
        ListQuery,
        ("x-tenant-id" = String, Header, description = "Tenant identifier (required)"),
    ),
    responses(
        (status = 200, description = "List of secret paths", body = ListResponseBody),
        (status = 400, description = "Missing X-Tenant-Id header or invalid prefix"),
        (status = 403, description = "Authorization denied by policy-engine"),
    ),
    tag = "secrets"
)]
#[instrument(skip(state, headers), fields(tenant_id, prefix))]
pub async fn list_secrets(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(query): Query<ListQuery>,
) -> Response {
    let wslvault_core::auth::Identity {
        tenant_id,
        principal_id,
        policies,
        ..
    } = match authenticate(&headers) {
        Ok(i) => i,
        Err(r) => return r,
    };
    let client_ip = extract_client_ip(&headers);

    let prefix = match query.prefix {
        Some(ref p) if !p.is_empty() => match normalize_and_validate(p) {
            Ok(normalized) => normalized,
            Err(e) => return vault_err_to_response(e),
        },
        _ => String::new(),
    };

    tracing::Span::current().record("tenant_id", &tenant_id.as_str());
    tracing::Span::current().record("prefix", &prefix.as_str());
    info!("http list_secrets");

    // Authorize the list operation before touching the store.
    if let Err(e) = state
        .policy_client
        .authorize(&tenant_id, &principal_id, &policies, "list", "secret/list")
        .await
    {
        state
            .audit_client
            .emit(
                &tenant_id,
                &principal_id,
                "secret.list",
                &prefix,
                "failure",
                &e.to_string(),
                "",
                &client_ip,
            )
            .await;
        return vault_err_to_response(e);
    }

    let mut paths = state.store.list(&tenant_id, &prefix).await;
    paths.sort();

    state
        .audit_client
        .emit(
            &tenant_id,
            &principal_id,
            "secret.list",
            &prefix,
            "success",
            "",
            "",
            &client_ip,
        )
        .await;

    (StatusCode::OK, Json(ListResponseBody { paths })).into_response()
}

// ─── Lifecycle request/response bodies ───────────────────────────────────────

#[derive(Debug, Deserialize)]
pub struct InitiateRotationBody {
    /// Base64-encoded plaintext for the new (pending) version.
    pub data: String,
    #[serde(default)]
    pub webhook_url: Option<String>,
    /// Rotation confirmation timeout in seconds (default 86400 = 24 h).
    #[serde(default)]
    pub timeout_secs: Option<i32>,
}

#[derive(Debug, Serialize)]
pub struct InitiateRotationResponse {
    pub rotation_id: String,
    pub new_version: u32,
}

#[derive(Debug, Deserialize)]
pub struct ConfirmRotationBody {
    pub rotation_id: String,
}

#[derive(Debug, Serialize)]
pub struct ConfirmRotationResponse {
    pub old_version: u32,
    pub new_version: u32,
    pub grace_ends_at: String,
}

#[derive(Debug, Deserialize)]
pub struct RollbackBody {
    pub target_version: u32,
}

#[derive(Debug, Serialize)]
pub struct RollbackResponse {
    pub new_version: u32,
}

#[derive(Debug, Serialize)]
pub struct VersionMetaItem {
    pub version: u32,
    pub status: String,
    pub created_by: Option<String>,
    pub created_at: String,
    pub deleted_at: Option<String>,
    pub deprecated_at: Option<String>,
    pub revoked_at: Option<String>,
    pub destroyed: bool,
}

#[derive(Debug, Serialize)]
pub struct ListVersionsResponse {
    pub versions: Vec<VersionMetaItem>,
}

// ─── Lifecycle handlers ───────────────────────────────────────────────────────

/// POST /v1/secret/rotate/*path
///
/// Initiate a two-phase rotation. Encrypts the supplied plaintext and stores
/// it as a `pending` version. Returns `rotation_id` and `new_version`.
/// The calling application must later confirm via POST /v1/secret/confirm/*path.
#[instrument(skip(state, headers, body), fields(path, tenant_id))]
pub async fn initiate_rotation(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(path): Path<String>,
    Json(body): Json<InitiateRotationBody>,
) -> Response {
    let wslvault_core::auth::Identity {
        tenant_id,
        principal_id,
        policies,
        ..
    } = match authenticate(&headers) {
        Ok(i) => i,
        Err(r) => return r,
    };
    let client_ip = extract_client_ip(&headers);

    let normalized_path = match normalize_and_validate(&path) {
        Ok(p) => p,
        Err(e) => return vault_err_to_response(e),
    };

    tracing::Span::current().record("path", &normalized_path.as_str());
    tracing::Span::current().record("tenant_id", &tenant_id.as_str());
    info!("http initiate_rotation");

    let resource = format!("secret/data/{}", normalized_path);
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
                "secret.rotation.initiate",
                &normalized_path,
                "failure",
                &e.to_string(),
                "",
                &client_ip,
            )
            .await;
        return vault_err_to_response(e);
    }

    let plaintext = match base64_decode(&body.data) {
        Ok(b) => b,
        Err(_) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(ApiError {
                    code: "validation_error",
                    message: "data field must be valid base64".into(),
                }),
            )
                .into_response();
        }
    };

    let aad = format!("{}:{}", tenant_id, normalized_path).into_bytes();
    let mut crypto_client = match Ok::<_, tonic::transport::Error>(
        crypto_proto::crypto_service_client::CryptoServiceClient::new(state.crypto_channel.clone()),
    ) {
        Ok(c) => c,
        Err(e) => {
            error!(error = %e, "crypto-service connect failed");
            return (
                StatusCode::SERVICE_UNAVAILABLE,
                Json(ApiError {
                    code: "service_unavailable",
                    message: format!("crypto-service unavailable: {}", e),
                }),
            )
                .into_response();
        }
    };

    let encrypt_resp = match crypto_client
        .encrypt(crypto_proto::EncryptRequest {
            tenant_id: tenant_id.clone(),
            plaintext,
            aad,
        })
        .await
    {
        Ok(r) => r.into_inner(),
        Err(e) => {
            error!(error = %e, "crypto-service encrypt failed");
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ApiError {
                    code: "encryption_failed",
                    message: format!("encryption failed: {}", e),
                }),
            )
                .into_response();
        }
    };

    let (rotation_id, new_version) = match state
        .store
        .initiate_rotation(
            &tenant_id,
            &normalized_path,
            encrypt_resp.ciphertext_b64,
            encrypt_resp.dek_id,
            &principal_id,
            body.webhook_url.as_deref(),
            body.timeout_secs,
        )
        .await
    {
        Ok(r) => r,
        Err(e) => {
            state
                .audit_client
                .emit(
                    &tenant_id,
                    &principal_id,
                    "secret.rotation.initiate",
                    &normalized_path,
                    "failure",
                    &e.to_string(),
                    "",
                    &client_ip,
                )
                .await;
            return vault_err_to_response(e);
        }
    };

    state
        .audit_client
        .emit(
            &tenant_id,
            &principal_id,
            "secret.rotation.initiate",
            &normalized_path,
            "success",
            &rotation_id,
            "",
            &client_ip,
        )
        .await;

    (
        StatusCode::OK,
        Json(InitiateRotationResponse {
            rotation_id,
            new_version,
        }),
    )
        .into_response()
}

/// POST /v1/secret/confirm/*path
///
/// Confirm a pending rotation: activates the new version and deprecates the old.
/// The `rotation_id` returned by initiate_rotation must be included in the body.
#[instrument(skip(state, headers, body), fields(path, tenant_id))]
pub async fn confirm_rotation(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(path): Path<String>,
    Json(body): Json<ConfirmRotationBody>,
) -> Response {
    let wslvault_core::auth::Identity {
        tenant_id,
        principal_id,
        policies,
        ..
    } = match authenticate(&headers) {
        Ok(i) => i,
        Err(r) => return r,
    };
    let client_ip = extract_client_ip(&headers);

    let normalized_path = match normalize_and_validate(&path) {
        Ok(p) => p,
        Err(e) => return vault_err_to_response(e),
    };

    let resource = format!("secret/data/{}", normalized_path);
    if let Err(e) = state
        .policy_client
        .authorize(&tenant_id, &principal_id, &policies, "write", &resource)
        .await
    {
        return vault_err_to_response(e);
    }

    let (old_version, new_version, grace_ends_at) = match state
        .store
        .confirm_rotation(&body.rotation_id, &principal_id)
        .await
    {
        Ok(r) => r,
        Err(e) => {
            state
                .audit_client
                .emit(
                    &tenant_id,
                    &principal_id,
                    "secret.rotation.confirm",
                    &normalized_path,
                    "failure",
                    &e.to_string(),
                    "",
                    &client_ip,
                )
                .await;
            return vault_err_to_response(e);
        }
    };

    state
        .audit_client
        .emit(
            &tenant_id,
            &principal_id,
            "secret.rotation.confirm",
            &normalized_path,
            "success",
            &body.rotation_id,
            "",
            &client_ip,
        )
        .await;

    (
        StatusCode::OK,
        Json(ConfirmRotationResponse {
            old_version,
            new_version,
            grace_ends_at: grace_ends_at.to_rfc3339(),
        }),
    )
        .into_response()
}

/// POST /v1/secret/rollback/*path
///
/// Roll back to a specific previous version (power_admin only). Creates a new
/// version row with the same ciphertext as the target version, preserving audit trail.
#[instrument(skip(state, headers, body), fields(path, tenant_id))]
pub async fn rollback_secret(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(path): Path<String>,
    Json(body): Json<RollbackBody>,
) -> Response {
    let wslvault_core::auth::Identity {
        tenant_id,
        principal_id,
        policies,
        ..
    } = match authenticate(&headers) {
        Ok(i) => i,
        Err(r) => return r,
    };
    let client_ip = extract_client_ip(&headers);

    let normalized_path = match normalize_and_validate(&path) {
        Ok(p) => p,
        Err(e) => return vault_err_to_response(e),
    };

    // Rollback requires power_admin policy.
    let resource = format!("secret/data/{}", normalized_path);
    if let Err(e) = state
        .policy_client
        .authorize(&tenant_id, &principal_id, &policies, "rollback", &resource)
        .await
    {
        state
            .audit_client
            .emit(
                &tenant_id,
                &principal_id,
                "secret.rollback",
                &normalized_path,
                "failure",
                &e.to_string(),
                "",
                &client_ip,
            )
            .await;
        return vault_err_to_response(e);
    }

    let new_version = match state
        .store
        .rollback(
            &tenant_id,
            &normalized_path,
            body.target_version,
            &principal_id,
        )
        .await
    {
        Ok(v) => v,
        Err(e) => {
            state
                .audit_client
                .emit(
                    &tenant_id,
                    &principal_id,
                    "secret.rollback",
                    &normalized_path,
                    "failure",
                    &e.to_string(),
                    "",
                    &client_ip,
                )
                .await;
            return vault_err_to_response(e);
        }
    };

    state
        .audit_client
        .emit(
            &tenant_id,
            &principal_id,
            "secret.rollback",
            &normalized_path,
            "success",
            &format!("target={} new={}", body.target_version, new_version),
            "",
            &client_ip,
        )
        .await;

    (StatusCode::OK, Json(RollbackResponse { new_version })).into_response()
}

/// GET /v1/secret/versions/*path
///
/// List version metadata for a secret (no ciphertext). Admin and power_admin
/// can see all versions; developer-level callers receive only the current version.
#[instrument(skip(state, headers), fields(path, tenant_id))]
pub async fn list_versions(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(path): Path<String>,
) -> Response {
    let wslvault_core::auth::Identity {
        tenant_id,
        principal_id,
        policies,
        ..
    } = match authenticate(&headers) {
        Ok(i) => i,
        Err(r) => return r,
    };
    let client_ip = extract_client_ip(&headers);

    let normalized_path = match normalize_and_validate(&path) {
        Ok(p) => p,
        Err(e) => return vault_err_to_response(e),
    };

    let resource = format!("secret/metadata/{}", normalized_path);
    if let Err(e) = state
        .policy_client
        .authorize(&tenant_id, &principal_id, &policies, "read", &resource)
        .await
    {
        return vault_err_to_response(e);
    }

    let versions = match state
        .store
        .list_versions(&tenant_id, &normalized_path)
        .await
    {
        Ok(v) => v,
        Err(e) => {
            state
                .audit_client
                .emit(
                    &tenant_id,
                    &principal_id,
                    "secret.versions.list",
                    &normalized_path,
                    "failure",
                    &e.to_string(),
                    "",
                    &client_ip,
                )
                .await;
            return vault_err_to_response(e);
        }
    };

    state
        .audit_client
        .emit(
            &tenant_id,
            &principal_id,
            "secret.versions.list",
            &normalized_path,
            "success",
            "",
            "",
            &client_ip,
        )
        .await;

    let items = versions
        .into_iter()
        .map(|v| VersionMetaItem {
            version: v.version,
            status: v.status.as_str().to_string(),
            created_by: v.created_by,
            created_at: v.created_at.to_rfc3339(),
            deleted_at: v.deleted_at.map(|t| t.to_rfc3339()),
            deprecated_at: v.deprecated_at.map(|t| t.to_rfc3339()),
            revoked_at: v.revoked_at.map(|t| t.to_rfc3339()),
            destroyed: v.destroyed,
        })
        .collect();

    (
        StatusCode::OK,
        Json(ListVersionsResponse { versions: items }),
    )
        .into_response()
}

// ─── Router factory ───────────────────────────────────────────────────────────

/// Build the axum `Router` for the REST API.
///
/// Mounts the Swagger UI at `/swagger-ui` (JSON schema at
/// `/api-docs/openapi.json`) so operators can explore and test the API
/// interactively without external tooling.
///
/// Pass the router into the axum `Server` alongside the health router.
pub fn build_router(
    store: Arc<dyn SecretStoreBackend>,
    crypto_endpoint: String,
    audit_client: AuditClient,
    policy_client: PolicyClient,
    lease_client: LeaseClient,
) -> Router {
    use utoipa::OpenApi as _;
    use utoipa_swagger_ui::SwaggerUi;

    let app_state = AppState {
        store,
        crypto_channel: wslvault_core::grpc_channel::lazy_channel(&crypto_endpoint)
            .unwrap_or_else(|e| panic!("crypto-service endpoint is unusable: {e}")),
        audit_client,
        policy_client,
        lease_client,
    };

    Router::new()
        .route("/v1/secret/data/*path", get(get_secret).post(put_secret))
        .route("/v1/secret/delete/*path", post(delete_secret))
        .route("/v1/secret/destroy/*path", post(destroy_secret))
        .route("/v1/secret/metadata/*path", get(get_metadata))
        .route("/v1/secret/list", get(list_secrets))
        .route("/v1/secret/rotate/*path", post(initiate_rotation))
        .route("/v1/secret/confirm/*path", post(confirm_rotation))
        .route("/v1/secret/rollback/*path", post(rollback_secret))
        .route("/v1/secret/versions/*path", get(list_versions))
        // HashiCorp Vault KV v2-compatible surface (mount: /v1/kv/...), so
        // Vault clients — notably the External Secrets Operator — work against
        // wslvault unchanged. Merged here, INSIDE the gateway-auth layer below,
        // so it inherits exactly the same origin protection as the native API.
        .merge(crate::kv2::routes())
        .with_state(app_state)
        // Authentication first: no request reaches a handler — or even a body
        // extractor — without a resolvable identity.
        .layer(axum::middleware::from_fn(require_authenticated))
        // Defence in depth on top of that. Note this check is DISABLED when
        // VAULT_GATEWAY_SECRET is unset, which is the case in every
        // chart-rendered deployment today, so it must never be the only guard.
        .layer(axum::middleware::from_fn_with_state(
            wslvault_core::middleware::GatewayAuth::from_env(),
            wslvault_core::middleware::require_gateway_auth,
        ))
        .merge(SwaggerUi::new("/swagger-ui").url("/api-docs/openapi.json", ApiDoc::openapi()))
}

// ─── Base64 helpers ───────────────────────────────────────────────────────────

/// Encode bytes to a standard base64 string.
///
/// Uses the standard (padded) alphabet from base64 v0.22.
fn base64_encode(data: &[u8]) -> String {
    use base64::Engine as _;
    base64::engine::general_purpose::STANDARD.encode(data)
}

/// Decode a standard base64 string to bytes.
fn base64_decode(s: &str) -> Result<Vec<u8>, base64::DecodeError> {
    use base64::Engine as _;
    base64::engine::general_purpose::STANDARD.decode(s)
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
// ENV_LOCK is deliberately held across `.await`: it serialises mutation of the
// process-wide VAULT_TRUST_GATEWAY_HEADERS var for the whole body of each test,
// which is exactly the window the awaited request reads it in. An async mutex
// would not help — these tests must exclude each other, not yield. Same
// reasoning and same allow as crypto-service/src/root_key.rs.
#[allow(clippy::await_holding_lock)]
mod auth_tests {
    //! Router-level proof that the native `/v1/secret/*` mount cannot be
    //! reached without a credential.
    //!
    //! These exercise the real router — the same `build_router` the binary
    //! serves — rather than the extractor in isolation, because the defect
    //! being pinned was precisely that the router had no authenticating layer
    //! and each handler trusted whatever headers arrived.

    use super::*;
    use crate::audit_client::AuditClient;
    use crate::kv_store::KvStore;
    use crate::lease_client::LeaseClient;
    use axum::body::Body;
    use axum::http::Request;
    use tower::ServiceExt;

    /// `VAULT_TRUST_GATEWAY_HEADERS` is process-global; serialise the tests
    /// that depend on its value.
    static ENV_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    fn test_router() -> Router {
        build_router(
            KvStore::new(),
            "http://127.0.0.1:1".to_string(),
            AuditClient::new("http://127.0.0.1:1".to_string()),
            PolicyClient::new("http://127.0.0.1:1".to_string()),
            LeaseClient::new("http://127.0.0.1:1".to_string()),
        )
    }

    async fn status_for(req: Request<Body>) -> StatusCode {
        test_router()
            .oneshot(req)
            .await
            .expect("router should respond")
            .status()
    }

    fn get(uri: &str, headers: &[(&str, &str)]) -> Request<Body> {
        let mut b = Request::builder().uri(uri).method("GET");
        for (k, v) in headers {
            b = b.header(*k, *v);
        }
        b.body(Body::empty()).unwrap()
    }

    /// The exploit this whole change exists to close: no credential at all,
    /// just an asserted tenant and an asserted policy set.
    #[tokio::test]
    async fn forged_identity_headers_are_rejected() {
        let _g = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        std::env::remove_var("VAULT_TRUST_GATEWAY_HEADERS");

        let status = status_for(get(
            "/v1/secret/data/prod/db",
            &[("x-tenant-id", "victim-tenant"), ("x-policies", "admin")],
        ))
        .await;

        assert_eq!(
            status,
            StatusCode::UNAUTHORIZED,
            "asserting a tenant and a policy set must not authenticate"
        );
    }

    /// The `X-Vault-*` spelling is the same assertion in different clothes.
    #[tokio::test]
    async fn forged_vault_spelling_headers_are_rejected() {
        let _g = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        std::env::remove_var("VAULT_TRUST_GATEWAY_HEADERS");

        let status = status_for(get(
            "/v1/secret/data/prod/db",
            &[
                ("x-vault-tenant-id", "victim-tenant"),
                ("x-vault-policies", "admin"),
            ],
        ))
        .await;

        assert_eq!(status, StatusCode::UNAUTHORIZED);
    }

    /// No headers at all is likewise 401, not 400 "missing header".
    #[tokio::test]
    async fn unauthenticated_request_is_rejected() {
        let _g = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        std::env::remove_var("VAULT_TRUST_GATEWAY_HEADERS");

        assert_eq!(
            status_for(get("/v1/secret/data/prod/db", &[])).await,
            StatusCode::UNAUTHORIZED
        );
    }

    /// Every mutating route is covered too — a write or a destroy must not be
    /// reachable on forged headers either.
    #[tokio::test]
    async fn every_native_route_requires_authentication() {
        let _g = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        std::env::remove_var("VAULT_TRUST_GATEWAY_HEADERS");

        let forged = [("x-tenant-id", "victim"), ("x-policies", "admin")];

        for (method, uri) in [
            ("GET", "/v1/secret/data/a/b"),
            ("POST", "/v1/secret/data/a/b"),
            ("POST", "/v1/secret/delete/a/b"),
            ("POST", "/v1/secret/destroy/a/b"),
            ("GET", "/v1/secret/metadata/a/b"),
            ("GET", "/v1/secret/list"),
            ("POST", "/v1/secret/rotate/a/b"),
            ("POST", "/v1/secret/confirm/a/b"),
            ("POST", "/v1/secret/rollback/a/b"),
            ("GET", "/v1/secret/versions/a/b"),
        ] {
            let mut b = Request::builder().uri(uri).method(method);
            for (k, v) in forged {
                b = b.header(k, v);
            }
            // Mutating routes parse a JSON body; send a valid empty object so a
            // 401 cannot be confused with a 400/415 from body rejection.
            let req = b
                .header("content-type", "application/json")
                .body(Body::from("{}"))
                .unwrap();

            assert_eq!(
                status_for(req).await,
                StatusCode::UNAUTHORIZED,
                "{method} {uri} must reject forged identity headers"
            );
        }
    }

    /// The gateway contract still works when an operator explicitly opts in,
    /// so this change does not silently break a correctly-fronted deployment.
    #[tokio::test]
    async fn gateway_contract_still_works_when_enabled() {
        let _g = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        std::env::set_var("VAULT_TRUST_GATEWAY_HEADERS", "true");

        let status = status_for(get(
            "/v1/secret/data/prod/db",
            &[("x-tenant-id", "acme"), ("x-policies", "reader")],
        ))
        .await;

        std::env::remove_var("VAULT_TRUST_GATEWAY_HEADERS");

        assert_ne!(
            status,
            StatusCode::UNAUTHORIZED,
            "with the flag on, the gateway header contract must still authenticate"
        );
    }
}
