//! Axum REST route handlers for the PKI engine.
//!
//! All routes are under `/v1/pki/` and are scoped to a tenant via the
//! `X-Tenant-Id` header.  CA private key material is encrypted at rest via
//! `key_protect::RootKek`; keys are never returned in API responses.
//!
//! # Blocking operations
//!
//! Certificate generation (rcgen) is synchronous CPU work.  All calls to the
//! `ca` module are wrapped in `tokio::task::spawn_blocking` so they do not
//! stall the async executor.

use std::net::IpAddr;
use std::sync::Arc;

use axum::{
    extract::{Path, State},
    http::{HeaderMap, StatusCode},
    response::IntoResponse,
    Json,
};
use chrono::Utc;
use serde::{Deserialize, Serialize};
use uuid::Uuid;
use zeroize::Zeroizing;

use crate::ca;
use crate::error::PkiError;
use crate::key_protect::RootKek;
use crate::store::PkiStore;
use crate::types::{IssuedCert, KeyType, KeyUsage, PkiRole, TenantCa};

// ---------------------------------------------------------------------------
// Shared application state
// ---------------------------------------------------------------------------

/// State shared across all axum handlers.
///
/// `store` is type-erased so handlers are agnostic of the concrete backend
/// (in-memory vs PostgreSQL).  `kek` is the service-level root KEK used to
/// encrypt/decrypt CA private keys; it is loaded once at startup.
#[derive(Clone)]
pub struct AppState {
    pub store: Arc<dyn PkiStore>,
    pub kek: Arc<RootKek>,
}

// ---------------------------------------------------------------------------
// Error response helper
// ---------------------------------------------------------------------------

#[derive(Serialize)]
struct ErrorBody {
    error: String,
}

fn pki_error_response(err: PkiError) -> (StatusCode, Json<ErrorBody>) {
    let status = match err.http_status() {
        400 => StatusCode::BAD_REQUEST,
        404 => StatusCode::NOT_FOUND,
        409 => StatusCode::CONFLICT,
        _ => StatusCode::INTERNAL_SERVER_ERROR,
    };
    (
        status,
        Json(ErrorBody {
            error: err.to_string(),
        }),
    )
}

// ---------------------------------------------------------------------------
// Header extraction
// ---------------------------------------------------------------------------

fn extract_tenant_id(headers: &HeaderMap) -> Result<String, (StatusCode, Json<ErrorBody>)> {
    headers
        .get("x-tenant-id")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string())
        .ok_or_else(|| {
            (
                StatusCode::BAD_REQUEST,
                Json(ErrorBody {
                    error: "missing X-Tenant-Id header".into(),
                }),
            )
        })
}

// ---------------------------------------------------------------------------
// Request / Response types
// ---------------------------------------------------------------------------

/// POST /v1/pki/ca/generate
#[derive(Deserialize, utoipa::ToSchema)]
pub struct GenerateCaRequest {
    /// Subject Common Name of the root CA, e.g. `"Acme Root CA"`.
    pub common_name: String,
    /// Validity period in seconds (default: 3 years = 94_608_000).
    pub ttl_seconds: Option<i64>,
    /// Key type: `"ecdsa-p256"` (default), `"rsa-2048"`, or `"rsa-4096"`.
    pub key_type: Option<String>,
}

#[derive(Serialize, utoipa::ToSchema)]
pub struct GenerateCaResponse {
    pub cert_pem: String,
    pub serial: String,
}

/// GET /v1/pki/ca
#[derive(Serialize, utoipa::ToSchema)]
pub struct GetCaResponse {
    pub cert_pem: String,
}

/// POST /v1/pki/ca/import
#[derive(Deserialize, utoipa::ToSchema)]
pub struct ImportCaRequest {
    /// PEM-encoded CA certificate.
    pub cert_pem: String,
    /// PEM-encoded CA private key.
    pub key_pem: String,
}

/// POST/GET /v1/pki/roles/:name — role creation/update request body.
#[derive(Deserialize, utoipa::ToSchema)]
pub struct UpsertRoleRequest {
    pub allowed_domains: Vec<String>,
    #[serde(default)]
    pub allow_subdomains: bool,
    #[serde(default)]
    pub allow_bare_domains: bool,
    /// Maximum TTL in seconds (default: 86_400 = 1 day).
    pub max_ttl_seconds: Option<i64>,
    /// Key type for issued leaf certs (default: `"ecdsa-p256"`).
    pub key_type: Option<String>,
    /// Extended key usage strings: `"server_auth"`, `"client_auth"`, `"code_signing"`, etc.
    #[serde(default)]
    pub key_usages: Vec<String>,
    #[serde(default)]
    pub allow_ip_sans: bool,
}

#[derive(Serialize, utoipa::ToSchema)]
pub struct RoleResponse {
    pub name: String,
    pub allowed_domains: Vec<String>,
    pub allow_subdomains: bool,
    pub allow_bare_domains: bool,
    pub max_ttl_seconds: i64,
    pub key_type: String,
    pub allow_ip_sans: bool,
}

impl From<PkiRole> for RoleResponse {
    fn from(r: PkiRole) -> Self {
        RoleResponse {
            name: r.name,
            allowed_domains: r.allowed_domains,
            allow_subdomains: r.allow_subdomains,
            allow_bare_domains: r.allow_bare_domains,
            max_ttl_seconds: r.max_ttl_seconds,
            key_type: r.key_type.to_string(),
            allow_ip_sans: r.allow_ip_sans,
        }
    }
}

/// POST /v1/pki/issue/:role_name
#[derive(Deserialize, utoipa::ToSchema)]
pub struct IssueRequest {
    pub common_name: String,
    #[serde(default)]
    pub alt_names: Vec<String>,
    /// IP address SANs as strings, e.g. `["10.0.0.1"]` (only accepted when the role allows them).
    #[serde(default)]
    pub ip_sans: Vec<String>,
    pub ttl_seconds: Option<i64>,
}

#[derive(Serialize, utoipa::ToSchema)]
pub struct IssueResponse {
    pub certificate: String,
    pub private_key: String,
    pub ca_chain: String,
    pub serial: String,
    pub expiration: String,
}

/// POST /v1/pki/sign/:role_name
#[derive(Deserialize, utoipa::ToSchema)]
pub struct SignCsrRequest {
    /// PEM-encoded certificate signing request.
    pub csr: String,
    pub ttl_seconds: Option<i64>,
}

#[derive(Serialize, utoipa::ToSchema)]
pub struct SignCsrResponse {
    pub certificate: String,
    pub ca_chain: String,
    pub serial: String,
    pub expiration: String,
}

/// POST /v1/pki/revoke
#[derive(Deserialize, utoipa::ToSchema)]
pub struct RevokeRequest {
    /// Hex-encoded certificate serial number.
    pub serial: String,
}

#[derive(Serialize, utoipa::ToSchema)]
pub struct RevokeResponse {
    pub revocation_time: String,
}

// ---------------------------------------------------------------------------
// OpenAPI document
// ---------------------------------------------------------------------------

#[derive(utoipa::OpenApi)]
#[openapi(
    paths(
        generate_ca_handler,
        get_ca_handler,
        import_ca_handler,
        upsert_role_handler,
        get_role_handler,
        delete_role_handler,
        issue_handler,
        sign_csr_handler,
        revoke_handler,
        crl_handler,
    ),
    components(schemas(
        GenerateCaRequest,
        GenerateCaResponse,
        GetCaResponse,
        ImportCaRequest,
        UpsertRoleRequest,
        RoleResponse,
        IssueRequest,
        IssueResponse,
        SignCsrRequest,
        SignCsrResponse,
        RevokeRequest,
        RevokeResponse,
    )),
    tags(
        (name = "pki-ca", description = "CA management"),
        (name = "pki-roles", description = "Role management"),
        (name = "pki-issue", description = "Certificate issuance"),
        (name = "pki-revoke", description = "Revocation and CRL"),
    ),
    info(
        title = "PKI Engine API",
        version = "0.1.0",
        description = "WSLVault internal certificate authority REST API",
    )
)]
pub struct ApiDoc;

// ---------------------------------------------------------------------------
// CA handlers
// ---------------------------------------------------------------------------

/// POST /v1/pki/ca/generate — generate a self-signed root CA for this tenant.
#[utoipa::path(
    post,
    path = "/v1/pki/ca/generate",
    params(("x-tenant-id" = String, Header, description = "Tenant identifier")),
    request_body = GenerateCaRequest,
    responses(
        (status = 201, body = GenerateCaResponse),
        (status = 400, description = "Missing header or invalid key type"),
        (status = 409, description = "CA already exists for this tenant"),
    ),
    tag = "pki-ca"
)]
pub async fn generate_ca_handler(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(body): Json<GenerateCaRequest>,
) -> impl IntoResponse {
    let tenant_id = match extract_tenant_id(&headers) {
        Ok(t) => t,
        Err(e) => return e.into_response(),
    };

    let key_type: KeyType = body
        .key_type
        .as_deref()
        .unwrap_or("ecdsa-p256")
        .parse()
        .unwrap_or_default();

    let ttl = body.ttl_seconds.unwrap_or(94_608_000); // 3 years
    let common_name = body.common_name.clone();

    // Certificate generation is CPU-bound; run it on the blocking thread pool.
    let ca_output = match tokio::task::spawn_blocking(move || {
        ca::generate_ca(&common_name, ttl, &key_type)
    })
    .await
    {
        Ok(Ok(o)) => o,
        Ok(Err(e)) => return pki_error_response(e).into_response(),
        Err(join_err) => {
            return pki_error_response(PkiError::CertGenerationFailed {
                reason: format!("spawn_blocking panic: {join_err}"),
            })
            .into_response()
        }
    };

    // Encrypt the CA private key at rest.
    let encrypted_key = match state.kek.encrypt_ca_key(&tenant_id, &ca_output.key_pem) {
        Ok(e) => e,
        Err(e) => return pki_error_response(e).into_response(),
    };

    let record = TenantCa {
        tenant_id: tenant_id.clone(),
        cert_pem: ca_output.cert_pem.clone(),
        encrypted_key_b64: encrypted_key,
        key_version: state.kek.version,
        created_at: Utc::now(),
    };

    match state.store.create_ca(record).await {
        Ok(()) => (
            StatusCode::CREATED,
            Json(GenerateCaResponse {
                cert_pem: ca_output.cert_pem,
                serial: ca_output.serial,
            }),
        )
            .into_response(),
        Err(e) => pki_error_response(e).into_response(),
    }
}

/// GET /v1/pki/ca — return the tenant CA certificate (PEM).
#[utoipa::path(
    get,
    path = "/v1/pki/ca",
    params(("x-tenant-id" = String, Header, description = "Tenant identifier")),
    responses(
        (status = 200, body = GetCaResponse),
        (status = 404, description = "No CA configured"),
    ),
    tag = "pki-ca"
)]
pub async fn get_ca_handler(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> impl IntoResponse {
    let tenant_id = match extract_tenant_id(&headers) {
        Ok(t) => t,
        Err(e) => return e.into_response(),
    };

    match state.store.get_ca(&tenant_id).await {
        Ok(ca) => (StatusCode::OK, Json(GetCaResponse { cert_pem: ca.cert_pem })).into_response(),
        Err(e) => pki_error_response(e).into_response(),
    }
}

/// POST /v1/pki/ca/import — import an existing CA cert + key.
#[utoipa::path(
    post,
    path = "/v1/pki/ca/import",
    params(("x-tenant-id" = String, Header, description = "Tenant identifier")),
    request_body = ImportCaRequest,
    responses(
        (status = 200, body = GetCaResponse),
        (status = 400, description = "Invalid PEM or key type"),
    ),
    tag = "pki-ca"
)]
pub async fn import_ca_handler(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(body): Json<ImportCaRequest>,
) -> impl IntoResponse {
    let tenant_id = match extract_tenant_id(&headers) {
        Ok(t) => t,
        Err(e) => return e.into_response(),
    };

    // Validate that the PEM parses — reject obviously wrong input early.
    if ::pem::parse(&body.cert_pem).is_err() {
        return pki_error_response(PkiError::InvalidCsr {
            reason: "cert_pem is not valid PEM".into(),
        })
        .into_response();
    }

    let encrypted_key = {
        let key_pem_zeroized = Zeroizing::new(body.key_pem.clone());
        match state
            .kek
            .encrypt_ca_key(&tenant_id, &key_pem_zeroized)
        {
            Ok(e) => e,
            Err(e) => return pki_error_response(e).into_response(),
        }
    };

    let record = TenantCa {
        tenant_id: tenant_id.clone(),
        cert_pem: body.cert_pem.clone(),
        encrypted_key_b64: encrypted_key,
        key_version: state.kek.version,
        created_at: Utc::now(),
    };

    match state.store.upsert_ca(record).await {
        Ok(()) => (
            StatusCode::OK,
            Json(GetCaResponse {
                cert_pem: body.cert_pem,
            }),
        )
            .into_response(),
        Err(e) => pki_error_response(e).into_response(),
    }
}

// ---------------------------------------------------------------------------
// Role handlers
// ---------------------------------------------------------------------------

/// POST /v1/pki/roles/:name — create or update a role.
#[utoipa::path(
    post,
    path = "/v1/pki/roles/{name}",
    params(
        ("name" = String, Path, description = "Role name"),
        ("x-tenant-id" = String, Header, description = "Tenant identifier"),
    ),
    request_body = UpsertRoleRequest,
    responses(
        (status = 200, body = RoleResponse),
        (status = 400, description = "Invalid request"),
    ),
    tag = "pki-roles"
)]
pub async fn upsert_role_handler(
    State(state): State<AppState>,
    Path(name): Path<String>,
    headers: HeaderMap,
    Json(body): Json<UpsertRoleRequest>,
) -> impl IntoResponse {
    let tenant_id = match extract_tenant_id(&headers) {
        Ok(t) => t,
        Err(e) => return e.into_response(),
    };

    let key_type: KeyType = body
        .key_type
        .as_deref()
        .unwrap_or("ecdsa-p256")
        .parse()
        .unwrap_or_default();

    // Parse key_usages from strings — unrecognised strings are silently dropped.
    let key_usages: Vec<KeyUsage> = body
        .key_usages
        .iter()
        .filter_map(|s| serde_json::from_value(serde_json::Value::String(s.clone())).ok())
        .collect();

    let now = Utc::now();
    let role = PkiRole {
        tenant_id: tenant_id.clone(),
        name: name.clone(),
        allowed_domains: body.allowed_domains,
        allow_subdomains: body.allow_subdomains,
        allow_bare_domains: body.allow_bare_domains,
        max_ttl_seconds: body.max_ttl_seconds.unwrap_or(86_400),
        key_type,
        key_usages,
        allow_ip_sans: body.allow_ip_sans,
        created_at: now,
        updated_at: now,
    };

    match state.store.upsert_role(role.clone()).await {
        Ok(()) => (StatusCode::OK, Json(RoleResponse::from(role))).into_response(),
        Err(e) => pki_error_response(e).into_response(),
    }
}

/// GET /v1/pki/roles/:name
#[utoipa::path(
    get,
    path = "/v1/pki/roles/{name}",
    params(
        ("name" = String, Path, description = "Role name"),
        ("x-tenant-id" = String, Header, description = "Tenant identifier"),
    ),
    responses(
        (status = 200, body = RoleResponse),
        (status = 404, description = "Role not found"),
    ),
    tag = "pki-roles"
)]
pub async fn get_role_handler(
    State(state): State<AppState>,
    Path(name): Path<String>,
    headers: HeaderMap,
) -> impl IntoResponse {
    let tenant_id = match extract_tenant_id(&headers) {
        Ok(t) => t,
        Err(e) => return e.into_response(),
    };

    match state.store.get_role(&tenant_id, &name).await {
        Ok(role) => (StatusCode::OK, Json(RoleResponse::from(role))).into_response(),
        Err(e) => pki_error_response(e).into_response(),
    }
}

/// DELETE /v1/pki/roles/:name
#[utoipa::path(
    delete,
    path = "/v1/pki/roles/{name}",
    params(
        ("name" = String, Path, description = "Role name"),
        ("x-tenant-id" = String, Header, description = "Tenant identifier"),
    ),
    responses(
        (status = 204, description = "Role deleted"),
        (status = 404, description = "Role not found"),
    ),
    tag = "pki-roles"
)]
pub async fn delete_role_handler(
    State(state): State<AppState>,
    Path(name): Path<String>,
    headers: HeaderMap,
) -> impl IntoResponse {
    let tenant_id = match extract_tenant_id(&headers) {
        Ok(t) => t,
        Err(e) => return e.into_response(),
    };

    match state.store.delete_role(&tenant_id, &name).await {
        Ok(()) => StatusCode::NO_CONTENT.into_response(),
        Err(e) => pki_error_response(e).into_response(),
    }
}

// ---------------------------------------------------------------------------
// Issuance handlers
// ---------------------------------------------------------------------------

/// POST /v1/pki/issue/:role_name — issue a leaf certificate.
#[utoipa::path(
    post,
    path = "/v1/pki/issue/{role_name}",
    params(
        ("role_name" = String, Path, description = "Role name"),
        ("x-tenant-id" = String, Header, description = "Tenant identifier"),
    ),
    request_body = IssueRequest,
    responses(
        (status = 200, body = IssueResponse),
        (status = 400, description = "Role constraint violated or invalid params"),
        (status = 404, description = "Role or CA not found"),
    ),
    tag = "pki-issue"
)]
pub async fn issue_handler(
    State(state): State<AppState>,
    Path(role_name): Path<String>,
    headers: HeaderMap,
    Json(body): Json<IssueRequest>,
) -> impl IntoResponse {
    let tenant_id = match extract_tenant_id(&headers) {
        Ok(t) => t,
        Err(e) => return e.into_response(),
    };

    // Fetch CA and role concurrently to minimise latency.
    let (ca_result, role_result) = tokio::join!(
        state.store.get_ca(&tenant_id),
        state.store.get_role(&tenant_id, &role_name),
    );

    let tenant_ca = match ca_result {
        Ok(c) => c,
        Err(e) => return pki_error_response(e).into_response(),
    };
    let role = match role_result {
        Ok(r) => r,
        Err(e) => return pki_error_response(e).into_response(),
    };

    // Decrypt CA private key.
    let ca_key_bytes = match state.kek.decrypt_ca_key(&tenant_id, &tenant_ca.encrypted_key_b64) {
        Ok(b) => b,
        Err(e) => return pki_error_response(e).into_response(),
    };
    let ca_key_pem = match std::str::from_utf8(&ca_key_bytes) {
        Ok(s) => Zeroizing::new(s.to_string()),
        Err(_) => {
            return pki_error_response(PkiError::KeyEncryptionError {
                reason: "CA key is not valid UTF-8".into(),
            })
            .into_response()
        }
    };

    // Parse ip_sans from string representations to IpAddr.
    let ip_sans: Vec<IpAddr> = body
        .ip_sans
        .iter()
        .filter_map(|s| s.parse::<IpAddr>().ok())
        .collect();

    let ca_cert_pem = tenant_ca.cert_pem.clone();
    let ttl = body.ttl_seconds.unwrap_or(0);
    let common_name = body.common_name.clone();
    let alt_names = body.alt_names.clone();

    let issue_result = tokio::task::spawn_blocking(move || {
        ca::issue_leaf(
            &ca_cert_pem,
            &ca_key_pem,
            &role,
            &common_name,
            &alt_names,
            &ip_sans,
            ttl,
        )
    })
    .await;

    let out = match issue_result {
        Ok(Ok(o)) => o,
        Ok(Err(e)) => return pki_error_response(e).into_response(),
        Err(je) => {
            return pki_error_response(PkiError::CertGenerationFailed {
                reason: format!("spawn_blocking panic: {je}"),
            })
            .into_response()
        }
    };

    // Record issued cert.
    let cert_record = IssuedCert {
        id: Uuid::now_v7().to_string(),
        tenant_id: tenant_id.clone(),
        role_name: role_name.clone(),
        serial: out.serial.clone(),
        common_name: body.common_name.clone(),
        not_after: out.not_after,
        revoked_at: None,
        created_at: Utc::now(),
    };

    if let Err(e) = state.store.record_cert(cert_record).await {
        tracing::error!(error = %e, "failed to record issued certificate");
    }

    (
        StatusCode::OK,
        Json(IssueResponse {
            certificate: out.cert_pem,
            private_key: out.private_key_pem.as_str().to_string(),
            ca_chain: out.ca_chain_pem,
            serial: out.serial,
            expiration: out.not_after.to_rfc3339(),
        }),
    )
        .into_response()
}

/// POST /v1/pki/sign/:role_name — sign a CSR.
#[utoipa::path(
    post,
    path = "/v1/pki/sign/{role_name}",
    params(
        ("role_name" = String, Path, description = "Role name"),
        ("x-tenant-id" = String, Header, description = "Tenant identifier"),
    ),
    request_body = SignCsrRequest,
    responses(
        (status = 200, body = SignCsrResponse),
        (status = 400, description = "Invalid CSR or role constraint violated"),
        (status = 404, description = "Role or CA not found"),
    ),
    tag = "pki-issue"
)]
pub async fn sign_csr_handler(
    State(state): State<AppState>,
    Path(role_name): Path<String>,
    headers: HeaderMap,
    Json(body): Json<SignCsrRequest>,
) -> impl IntoResponse {
    let tenant_id = match extract_tenant_id(&headers) {
        Ok(t) => t,
        Err(e) => return e.into_response(),
    };

    let (ca_result, role_result) = tokio::join!(
        state.store.get_ca(&tenant_id),
        state.store.get_role(&tenant_id, &role_name),
    );

    let tenant_ca = match ca_result {
        Ok(c) => c,
        Err(e) => return pki_error_response(e).into_response(),
    };
    let role = match role_result {
        Ok(r) => r,
        Err(e) => return pki_error_response(e).into_response(),
    };

    let ca_key_bytes = match state.kek.decrypt_ca_key(&tenant_id, &tenant_ca.encrypted_key_b64) {
        Ok(b) => b,
        Err(e) => return pki_error_response(e).into_response(),
    };
    let ca_key_pem = match std::str::from_utf8(&ca_key_bytes) {
        Ok(s) => Zeroizing::new(s.to_string()),
        Err(_) => {
            return pki_error_response(PkiError::KeyEncryptionError {
                reason: "CA key is not valid UTF-8".into(),
            })
            .into_response()
        }
    };

    let ca_cert_pem = tenant_ca.cert_pem.clone();
    let csr_pem = body.csr.clone();
    let ttl = body.ttl_seconds.unwrap_or(0);

    let sign_result = tokio::task::spawn_blocking(move || {
        ca::sign_csr(&ca_cert_pem, &ca_key_pem, &role, &csr_pem, ttl)
    })
    .await;

    let out = match sign_result {
        Ok(Ok(o)) => o,
        Ok(Err(e)) => return pki_error_response(e).into_response(),
        Err(je) => {
            return pki_error_response(PkiError::CertGenerationFailed {
                reason: format!("spawn_blocking panic: {je}"),
            })
            .into_response()
        }
    };

    // Extract CN from the CSR to record in the cert store.
    let cn = extract_cn_from_cert_pem(&out.cert_pem);

    let cert_record = IssuedCert {
        id: Uuid::now_v7().to_string(),
        tenant_id: tenant_id.clone(),
        role_name: role_name.clone(),
        serial: out.serial.clone(),
        common_name: cn,
        not_after: out.not_after,
        revoked_at: None,
        created_at: Utc::now(),
    };

    if let Err(e) = state.store.record_cert(cert_record).await {
        tracing::error!(error = %e, "failed to record CSR-signed certificate");
    }

    (
        StatusCode::OK,
        Json(SignCsrResponse {
            certificate: out.cert_pem,
            ca_chain: out.ca_chain_pem,
            serial: out.serial,
            expiration: out.not_after.to_rfc3339(),
        }),
    )
        .into_response()
}

// ---------------------------------------------------------------------------
// Revocation handlers
// ---------------------------------------------------------------------------

/// POST /v1/pki/revoke — revoke a certificate by serial.
#[utoipa::path(
    post,
    path = "/v1/pki/revoke",
    params(("x-tenant-id" = String, Header, description = "Tenant identifier")),
    request_body = RevokeRequest,
    responses(
        (status = 200, body = RevokeResponse),
        (status = 404, description = "Certificate serial not found"),
        (status = 409, description = "Already revoked"),
    ),
    tag = "pki-revoke"
)]
pub async fn revoke_handler(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(body): Json<RevokeRequest>,
) -> impl IntoResponse {
    let tenant_id = match extract_tenant_id(&headers) {
        Ok(t) => t,
        Err(e) => return e.into_response(),
    };

    match state.store.revoke_cert(&tenant_id, &body.serial).await {
        Ok(()) => {
            let now = Utc::now();
            (
                StatusCode::OK,
                Json(RevokeResponse {
                    revocation_time: now.to_rfc3339(),
                }),
            )
                .into_response()
        }
        Err(e) => pki_error_response(e).into_response(),
    }
}

/// GET /v1/pki/crl — return the current CRL in PEM format.
///
/// The CRL is generated on-demand from the revocation records in the store and
/// signed with the tenant CA key.
#[utoipa::path(
    get,
    path = "/v1/pki/crl",
    params(("x-tenant-id" = String, Header, description = "Tenant identifier")),
    responses(
        (status = 200, description = "PEM-encoded CRL"),
        (status = 404, description = "CA not configured"),
    ),
    tag = "pki-revoke"
)]
pub async fn crl_handler(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> impl IntoResponse {
    let tenant_id = match extract_tenant_id(&headers) {
        Ok(t) => t,
        Err(e) => return e.into_response(),
    };

    let (ca_result, revoked_result) = tokio::join!(
        state.store.get_ca(&tenant_id),
        state.store.list_revoked_certs(&tenant_id),
    );

    let tenant_ca = match ca_result {
        Ok(c) => c,
        Err(e) => return pki_error_response(e).into_response(),
    };
    let revoked_certs = match revoked_result {
        Ok(r) => r,
        Err(e) => return pki_error_response(e).into_response(),
    };

    let ca_key_bytes = match state.kek.decrypt_ca_key(&tenant_id, &tenant_ca.encrypted_key_b64) {
        Ok(b) => b,
        Err(e) => return pki_error_response(e).into_response(),
    };
    let ca_key_pem = match std::str::from_utf8(&ca_key_bytes) {
        Ok(s) => Zeroizing::new(s.to_string()),
        Err(_) => {
            return pki_error_response(PkiError::KeyEncryptionError {
                reason: "CA key is not valid UTF-8".into(),
            })
            .into_response()
        }
    };

    let ca_cert_pem = tenant_ca.cert_pem.clone();

    // Collect (serial_hex, revoked_at) pairs.
    let revoked_entries: Vec<(String, chrono::DateTime<Utc>)> = revoked_certs
        .into_iter()
        .filter_map(|c| c.revoked_at.map(|at| (c.serial, at)))
        .collect();

    let crl_result = tokio::task::spawn_blocking(move || {
        ca::build_crl_pem(&ca_cert_pem, &ca_key_pem, &revoked_entries)
    })
    .await;

    match crl_result {
        Ok(Ok(crl_pem)) => (
            StatusCode::OK,
            [(axum::http::header::CONTENT_TYPE, "application/x-pem-file")],
            crl_pem,
        )
            .into_response(),
        Ok(Err(e)) => pki_error_response(e).into_response(),
        Err(je) => pki_error_response(PkiError::CertGenerationFailed {
            reason: format!("CRL generation panic: {je}"),
        })
        .into_response(),
    }
}

// ---------------------------------------------------------------------------
// Private helper
// ---------------------------------------------------------------------------

/// Best-effort extraction of the Common Name from a PEM certificate, used for
/// recording the CN in the cert store after a CSR-based issuance.  Returns an
/// empty string if the cert cannot be parsed.
fn extract_cn_from_cert_pem(cert_pem: &str) -> String {
    use x509_parser::prelude::*;

    let der_bytes = match ::pem::parse(cert_pem) {
        Ok(p) => p.into_contents(),
        Err(_) => return String::new(),
    };

    // Parse the DER bytes, keeping both the cert and the owned bytes alive
    // in the same scope so borrow checker is satisfied.
    let cn = match X509Certificate::from_der(&der_bytes) {
        Ok((_, cert)) => cert
            .subject()
            .iter_common_name()
            .next()
            .and_then(|a| a.as_str().ok())
            .unwrap_or("")
            .to_string(),
        Err(_) => String::new(),
    };

    cn
}
