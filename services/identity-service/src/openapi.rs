//! OpenAPI document for the identity-service HTTP API.
//!
//! Collects annotated paths from `health`, `tenant_handlers`, and `api_keys`
//! into a single `ApiDoc` struct that can be served via Swagger UI.
//!
//! SCIM endpoints follow the RFC 7644 specification and are intentionally
//! excluded from this document; they are documented separately.

use crate::api_keys::{
    ApiKeyAuthRequest, ApiKeyAuthResponse, ApiKeyCreateRequest, ApiKeyCreateResponse,
    ApiKeyMetadataResponse,
};
use crate::health::HealthResponse;
use crate::tenant_handlers::{CreateTenantRequest, TenantResponse};

/// Combined OpenAPI 3.x document for all identity-service REST endpoints.
///
/// Excludes:
/// - SCIM 2.0 provisioning endpoints (`/scim/v2/...`): follow RFC 7644 and
///   are documented via the SCIM specification rather than this doc.
#[derive(utoipa::OpenApi)]
#[openapi(
    paths(
        // Health probes
        crate::health::liveness,
        crate::health::readiness,
        // Tenant CRUD
        crate::tenant_handlers::create_tenant,
        crate::tenant_handlers::list_tenants,
        crate::tenant_handlers::get_tenant,
        crate::tenant_handlers::delete_tenant,
        // API key management
        crate::api_keys::handle_create_api_key,
        crate::api_keys::handle_list_api_keys,
        crate::api_keys::handle_revoke_api_key,
        crate::api_keys::handle_rotate_api_key,
        // API key authentication
        crate::api_keys::handle_auth_api_key,
    ),
    components(schemas(
        HealthResponse,
        CreateTenantRequest,
        TenantResponse,
        ApiKeyCreateRequest,
        ApiKeyCreateResponse,
        ApiKeyMetadataResponse,
        ApiKeyAuthRequest,
        ApiKeyAuthResponse,
    )),
    tags(
        (name = "health", description = "Liveness and readiness probes"),
        (name = "tenants", description = "Tenant lifecycle management"),
        (name = "api-keys", description = "API key lifecycle management"),
        (name = "auth", description = "Authentication: exchange credentials for JWTs"),
    ),
    info(
        title = "Identity Service API",
        version = "0.1.0",
        description = "WSLVault identity service REST API (tenants, API keys, authentication)",
    )
)]
pub struct ApiDoc;
