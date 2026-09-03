//! HTTP handlers for tenant CRUD operations.
//!
//! Exposes four REST endpoints under `/v1/tenants`:
//!
//! | Method   | Path                | Description         |
//! |----------|---------------------|---------------------|
//! | POST     | /v1/tenants         | Create a new tenant |
//! | GET      | /v1/tenants         | List all tenants    |
//! | GET      | /v1/tenants/:id     | Get a single tenant |
//! | DELETE   | /v1/tenants/:id     | Soft-delete tenant  |
//!
//! When the `DATABASE_URL` environment variable is set at startup the
//! handlers delegate to `wslvault_storage::tenant_store` for persistence.
//! Otherwise they fall back to an in-memory store so the service can be
//! developed and tested without a live database.

use std::{
    collections::HashMap,
    sync::{Arc, RwLock},
};

use axum::{
    extract::{Path, State},
    http::StatusCode,
    response::IntoResponse,
    routing::{get, post},
    Json, Router,
};
use chrono::Utc;
use serde::{Deserialize, Serialize};
use tracing::{error, info};
use uuid::Uuid;
use wslvault_core::{
    types::tenant::{Tenant, TenantId, TenantTier},
    VaultError,
};
use wslvault_storage::pool::DbPool;

// ---------------------------------------------------------------------------
// Shared application state
// ---------------------------------------------------------------------------

/// Selects between the PostgreSQL-backed store and the in-memory fallback.
///
/// Constructed once at startup and cloned cheaply into each request handler
/// via axum's `State` extractor.
#[derive(Clone)]
pub struct TenantStoreState {
    inner: TenantStoreInner,
}

/// Policy every new tenant starts with, granting its own members full control
/// of its own secrets — and nothing else.
///
/// Without it a tenant is born unusable. Keys issued by invitation carry
/// `["default"]`, and a policy name that resolves to nothing grants nothing:
/// the holder signs in successfully and is then refused on every request,
/// including listing their own secrets. That is what shipped first, and it
/// looked like a permissions bug rather than a missing row.
///
/// Scoped to `secret/**` deliberately. It does not grant policy management,
/// key management or anything cross-tenant — those are separate decisions an
/// operator makes deliberately, not defaults a tenant inherits by existing.
const DEFAULT_TENANT_POLICY: &str = "default";

/// Create the tenant's baseline policy.
///
/// Failure is logged, not propagated: the tenant row is already committed by
/// the time this runs, and failing the request would report "tenant not
/// created" for a tenant that exists — sending an operator to create it twice.
/// The tenant is recoverable (the policy can be written by hand); a phantom
/// duplicate is messier.
async fn seed_default_policy(pool: &wslvault_storage::pool::DbPool, tenant_id: &Uuid) {
    let document = serde_json::json!({
        "name": DEFAULT_TENANT_POLICY,
        "rules": [{
            // `secret/**` covers both shapes the engine checks: `secret/list`
            // and `secret/data/<path>`.
            "paths": ["secret/**"],
            "capabilities": ["read", "write", "list", "delete"],
        }],
    });

    match wslvault_storage::policy_store::put_policy(
        pool,
        tenant_id,
        DEFAULT_TENANT_POLICY,
        &document,
    )
    .await
    {
        Ok(_) => info!(tenant_id = %tenant_id, "seeded the tenant's default policy"),
        Err(e) => error!(
            error = %e,
            tenant_id = %tenant_id,
            "could not seed the default policy — members of this tenant will be \
             refused on every request until one is created"
        ),
    }
}

#[derive(Clone)]
enum TenantStoreInner {
    /// Live PostgreSQL pool (present when DATABASE_URL is configured).
    Database(DbPool),
    /// In-memory fallback keyed by tenant UUID.
    Memory(Arc<RwLock<HashMap<Uuid, Tenant>>>),
}

impl TenantStoreState {
    /// Constructs state from the environment.
    ///
    /// Returns a `Database` variant backed by a live PostgreSQL pool when
    /// `DATABASE_URL` is set; otherwise falls back to an empty in-memory store
    /// and logs a warning. Fails only if `DATABASE_URL` is set but the pool
    /// cannot be established.
    pub async fn from_env() -> Result<Self, VaultError> {
        match std::env::var("DATABASE_URL") {
            Ok(url) if !url.is_empty() => {
                let pool = sqlx::postgres::PgPoolOptions::new()
                    .max_connections(5)
                    .connect(&url)
                    .await
                    .map_err(|e| VaultError::Database {
                        reason: format!("tenant store pool: {e}"),
                    })?;
                tracing::info!("tenant store: using PostgreSQL backend");
                Ok(Self {
                    inner: TenantStoreInner::Database(DbPool::from_pool(pool)),
                })
            }
            _ => {
                tracing::warn!(
                    "DATABASE_URL not set; tenant store using in-memory fallback (data is not persisted)"
                );
                Ok(Self {
                    inner: TenantStoreInner::Memory(Arc::new(RwLock::new(HashMap::new()))),
                })
            }
        }
    }

    /// Insert a tenant into whichever backend is active.
    async fn create(&self, tenant: Tenant) -> Result<(), VaultError> {
        match &self.inner {
            TenantStoreInner::Database(pool) => {
                wslvault_storage::tenant_store::create_tenant(pool, &tenant).await?;
                seed_default_policy(pool, tenant.id.as_uuid()).await;
                Ok(())
            }
            TenantStoreInner::Memory(map) => {
                let mut guard = map.write().map_err(|e| VaultError::Internal {
                    reason: format!("in-memory store lock poisoned: {e}"),
                })?;
                let uuid = *tenant.id.as_uuid();
                if guard.contains_key(&uuid) {
                    return Err(VaultError::ValidationError {
                        field: "id".into(),
                        reason: format!("tenant '{}' already exists", uuid),
                    });
                }
                guard.insert(uuid, tenant);
                Ok(())
            }
        }
    }

    /// Retrieve one tenant by ID.
    async fn get(&self, tenant_id: &TenantId) -> Result<Tenant, VaultError> {
        match &self.inner {
            TenantStoreInner::Database(pool) => {
                wslvault_storage::tenant_store::get_tenant(pool, tenant_id).await
            }
            TenantStoreInner::Memory(map) => {
                let guard = map.read().map_err(|e| VaultError::Internal {
                    reason: format!("in-memory store lock poisoned: {e}"),
                })?;
                guard
                    .get(tenant_id.as_uuid())
                    .cloned()
                    .ok_or_else(|| VaultError::TenantNotFound {
                        tenant_id: tenant_id.to_string(),
                    })
            }
        }
    }

    /// Return all active (non-deleted) tenants.
    async fn list(&self) -> Result<Vec<Tenant>, VaultError> {
        match &self.inner {
            TenantStoreInner::Database(pool) => {
                wslvault_storage::tenant_store::list_tenants(pool).await
            }
            TenantStoreInner::Memory(map) => {
                let guard = map.read().map_err(|e| VaultError::Internal {
                    reason: format!("in-memory store lock poisoned: {e}"),
                })?;
                let mut tenants: Vec<Tenant> = guard
                    .values()
                    .filter(|t| t.deleted_at.is_none())
                    .cloned()
                    .collect();
                // Return deterministic ordering by slug for testability.
                tenants.sort_by(|a, b| a.slug.cmp(&b.slug));
                Ok(tenants)
            }
        }
    }

    /// Soft-delete a tenant by setting `deleted_at`.
    async fn soft_delete(&self, tenant_id: &TenantId) -> Result<(), VaultError> {
        match &self.inner {
            TenantStoreInner::Database(pool) => {
                wslvault_storage::tenant_store::soft_delete_tenant(pool, tenant_id).await
            }
            TenantStoreInner::Memory(map) => {
                let mut guard = map.write().map_err(|e| VaultError::Internal {
                    reason: format!("in-memory store lock poisoned: {e}"),
                })?;
                let tenant = guard.get_mut(tenant_id.as_uuid()).ok_or_else(|| {
                    VaultError::TenantNotFound {
                        tenant_id: tenant_id.to_string(),
                    }
                })?;
                if tenant.deleted_at.is_some() {
                    return Err(VaultError::TenantNotFound {
                        tenant_id: tenant_id.to_string(),
                    });
                }
                tenant.deleted_at = Some(Utc::now());
                Ok(())
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Wire types (HTTP request / response bodies)
// ---------------------------------------------------------------------------

/// Request body for `POST /v1/tenants`.
#[derive(Debug, Deserialize, utoipa::ToSchema)]
pub struct CreateTenantRequest {
    /// URL-safe short name, globally unique (e.g. "acme-corp").
    pub slug: String,
    /// Human-readable display name shown in the UI.
    pub display_name: String,
    /// Isolation tier: "shared" | "dedicated" | "sovereign".
    pub tier: Option<String>,
    /// ID of the tenant's root key-encryption key in the crypto-service.
    pub root_key_id: String,
}

/// Response body returned for single-tenant operations.
#[derive(Debug, Serialize, utoipa::ToSchema)]
pub struct TenantResponse {
    pub id: String,
    pub slug: String,
    pub display_name: String,
    pub tier: String,
    pub root_key_id: String,
    pub created_at: String,
    pub updated_at: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub deleted_at: Option<String>,
}

impl From<&Tenant> for TenantResponse {
    fn from(t: &Tenant) -> Self {
        let tier_str = match t.tier {
            TenantTier::Shared => "shared",
            TenantTier::Dedicated => "dedicated",
            TenantTier::Sovereign => "sovereign",
        };
        Self {
            id: t.id.to_string(),
            slug: t.slug.clone(),
            display_name: t.display_name.clone(),
            tier: tier_str.to_string(),
            root_key_id: t.root_key_id.clone(),
            created_at: t.created_at.to_rfc3339(),
            updated_at: t.updated_at.to_rfc3339(),
            deleted_at: t.deleted_at.map(|dt| dt.to_rfc3339()),
        }
    }
}

// ---------------------------------------------------------------------------
// Validation helpers
// ---------------------------------------------------------------------------

/// Returns `Err` if `slug` contains characters outside [a-z0-9-].
fn validate_slug(slug: &str) -> Result<(), String> {
    if slug.is_empty() {
        return Err("slug must not be empty".into());
    }
    if !slug
        .chars()
        .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-')
    {
        return Err("slug must contain only lowercase letters, digits, and hyphens".into());
    }
    Ok(())
}

/// Parse a tier string from the request body, defaulting to `Shared`.
fn parse_tier(tier_opt: Option<&str>) -> Result<TenantTier, String> {
    match tier_opt {
        None | Some("shared") => Ok(TenantTier::Shared),
        Some("dedicated") => Ok(TenantTier::Dedicated),
        Some("sovereign") => Ok(TenantTier::Sovereign),
        Some(other) => Err(format!(
            "unknown tier '{}'; must be one of: shared, dedicated, sovereign",
            other
        )),
    }
}

/// Map a `VaultError` to an appropriate HTTP status code.
fn vault_error_status(err: &VaultError) -> StatusCode {
    match err {
        VaultError::TenantNotFound { .. } => StatusCode::NOT_FOUND,
        VaultError::ValidationError { .. } => StatusCode::UNPROCESSABLE_ENTITY,
        _ => StatusCode::INTERNAL_SERVER_ERROR,
    }
}

// ---------------------------------------------------------------------------
// Handlers
// ---------------------------------------------------------------------------

/// POST /v1/tenants — create a new tenant.
///
/// The generated `TenantId` uses UUIDv7 so it embeds a monotonic timestamp,
/// enabling time-ordered range scans without a separate `created_at` index.
#[utoipa::path(
    post,
    path = "/v1/tenants",
    request_body = CreateTenantRequest,
    responses(
        (status = 201, description = "Tenant created", body = TenantResponse),
        (status = 422, description = "Invalid slug, display_name, root_key_id, or tier"),
        (status = 500, description = "Internal error (e.g. duplicate ID in store)"),
    ),
    tag = "tenants"
)]
pub async fn create_tenant(
    State(store): State<TenantStoreState>,
    Json(payload): Json<CreateTenantRequest>,
) -> impl IntoResponse {
    if let Err(msg) = validate_slug(&payload.slug) {
        return (
            StatusCode::UNPROCESSABLE_ENTITY,
            Json(serde_json::json!({
                "code": "invalid_slug",
                "message": msg,
            })),
        )
            .into_response();
    }

    if payload.display_name.trim().is_empty() {
        return (
            StatusCode::UNPROCESSABLE_ENTITY,
            Json(serde_json::json!({
                "code": "invalid_display_name",
                "message": "display_name must not be blank",
            })),
        )
            .into_response();
    }

    if payload.root_key_id.trim().is_empty() {
        return (
            StatusCode::UNPROCESSABLE_ENTITY,
            Json(serde_json::json!({
                "code": "invalid_root_key_id",
                "message": "root_key_id must not be blank",
            })),
        )
            .into_response();
    }

    let tier = match parse_tier(payload.tier.as_deref()) {
        Ok(t) => t,
        Err(msg) => {
            return (
                StatusCode::UNPROCESSABLE_ENTITY,
                Json(serde_json::json!({
                    "code": "invalid_tier",
                    "message": msg,
                })),
            )
                .into_response()
        }
    };

    let now = Utc::now();
    let tenant = Tenant {
        id: TenantId::new(),
        slug: payload.slug,
        display_name: payload.display_name,
        tier,
        root_key_id: payload.root_key_id,
        created_at: now,
        updated_at: now,
        deleted_at: None,
    };

    match store.create(tenant.clone()).await {
        Ok(()) => {
            tracing::info!(
                tenant_id = %tenant.id,
                slug = %tenant.slug,
                "tenant created"
            );
            (StatusCode::CREATED, Json(TenantResponse::from(&tenant))).into_response()
        }
        Err(err) => {
            tracing::warn!(error = %err, "failed to create tenant");
            (
                vault_error_status(&err),
                Json(serde_json::json!({
                    "code": "create_failed",
                    "message": err.to_string(),
                })),
            )
                .into_response()
        }
    }
}

/// GET /v1/tenants — list all active tenants.
#[utoipa::path(
    get,
    path = "/v1/tenants",
    responses(
        (status = 200, description = "List of active (non-deleted) tenants", body = Vec<TenantResponse>),
        (status = 500, description = "Internal store error"),
    ),
    tag = "tenants"
)]
pub async fn list_tenants(State(store): State<TenantStoreState>) -> impl IntoResponse {
    match store.list().await {
        Ok(tenants) => {
            let body: Vec<TenantResponse> = tenants.iter().map(TenantResponse::from).collect();
            (StatusCode::OK, Json(body)).into_response()
        }
        Err(err) => {
            tracing::error!(error = %err, "failed to list tenants");
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({
                    "code": "list_failed",
                    "message": err.to_string(),
                })),
            )
                .into_response()
        }
    }
}

/// GET /v1/tenants/:id — get a single tenant by UUID.
#[utoipa::path(
    get,
    path = "/v1/tenants/{id}",
    params(
        ("id" = String, Path, description = "Tenant UUID"),
    ),
    responses(
        (status = 200, description = "Tenant found", body = TenantResponse),
        (status = 400, description = "Invalid UUID format"),
        (status = 404, description = "Tenant not found"),
        (status = 500, description = "Internal store error"),
    ),
    tag = "tenants"
)]
pub async fn get_tenant(
    State(store): State<TenantStoreState>,
    Path(id_str): Path<String>,
) -> impl IntoResponse {
    let tenant_id: TenantId = match id_str.parse() {
        Ok(t) => t,
        Err(_) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({
                    "code": "invalid_id",
                    "message": "tenant id must be a valid UUID",
                })),
            )
                .into_response()
        }
    };

    match store.get(&tenant_id).await {
        Ok(tenant) => (StatusCode::OK, Json(TenantResponse::from(&tenant))).into_response(),
        Err(VaultError::TenantNotFound { .. }) => (
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({
                "code": "not_found",
                "message": format!("tenant '{}' not found", id_str),
            })),
        )
            .into_response(),
        Err(err) => {
            tracing::error!(error = %err, tenant_id = %id_str, "failed to get tenant");
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({
                    "code": "get_failed",
                    "message": err.to_string(),
                })),
            )
                .into_response()
        }
    }
}

/// DELETE /v1/tenants/:id — soft-delete a tenant.
///
/// Uses a soft-delete pattern: sets `deleted_at` on the record rather than
/// removing the row.  This preserves audit history and allows recovery in
/// case of accidental deletion.  A hard-delete path can be added later.
#[utoipa::path(
    delete,
    path = "/v1/tenants/{id}",
    params(
        ("id" = String, Path, description = "Tenant UUID to soft-delete"),
    ),
    responses(
        (status = 204, description = "Tenant soft-deleted"),
        (status = 400, description = "Invalid UUID format"),
        (status = 404, description = "Tenant not found or already deleted"),
        (status = 500, description = "Internal store error"),
    ),
    tag = "tenants"
)]
pub async fn delete_tenant(
    State(store): State<TenantStoreState>,
    Path(id_str): Path<String>,
) -> impl IntoResponse {
    let tenant_id: TenantId = match id_str.parse() {
        Ok(t) => t,
        Err(_) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({
                    "code": "invalid_id",
                    "message": "tenant id must be a valid UUID",
                })),
            )
                .into_response()
        }
    };

    match store.soft_delete(&tenant_id).await {
        Ok(()) => {
            tracing::info!(tenant_id = %id_str, "tenant soft-deleted");
            StatusCode::NO_CONTENT.into_response()
        }
        Err(VaultError::TenantNotFound { .. }) => (
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({
                "code": "not_found",
                "message": format!("tenant '{}' not found", id_str),
            })),
        )
            .into_response(),
        Err(err) => {
            tracing::error!(error = %err, tenant_id = %id_str, "failed to delete tenant");
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({
                    "code": "delete_failed",
                    "message": err.to_string(),
                })),
            )
                .into_response()
        }
    }
}

// ---------------------------------------------------------------------------
// Router
// ---------------------------------------------------------------------------

/// Builds an `axum::Router` containing the tenant CRUD routes.
///
/// Mount at application startup alongside the health router:
/// ```no_run
/// let app = health::router().merge(tenant_handlers::router(store));
/// ```
/// Tenant CRUD, behind the administrator gate.
///
/// These routes had no guard at all. `GET /v1/tenants` returned every tenant in
/// the deployment — id, slug, display name, tier and `root_key_id` — to anyone
/// who could reach the port, and `POST` created one, and `DELETE` removed one.
/// The vault-ui pod proxies `/api/identity/*`, so all three were reachable from
/// wherever the UI is published.
///
/// Managing tenants is a platform operation, not a tenant one: listing them is
/// inherently cross-tenant, and creating one is how the platform grows. So they
/// require an administrator — the `VAULT_ADMIN_TOKEN` bootstrap credential, a
/// token carrying the administrator policy, or a superuser token.
pub fn router(store: TenantStoreState, admin_auth: crate::api_keys::AdminAuth) -> Router {
    Router::new()
        .route("/v1/tenants", post(create_tenant).get(list_tenants))
        .route("/v1/tenants/:id", get(get_tenant).delete(delete_tenant))
        .with_state(store)
        .layer(axum::middleware::from_fn_with_state(
            admin_auth,
            crate::api_keys::require_admin,
        ))
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
    use tower::ServiceExt; // for `oneshot`

    /// Admin gate with a known bootstrap token, so the tests exercise the
    /// guard rather than bypassing it.
    fn test_admin() -> crate::api_keys::AdminAuth {
        crate::api_keys::AdminAuth::new(
            crate::token::TokenManager::new(b"test-secret-that-is-at-least-32-bytes!!"),
            Some(b"test-admin-token".to_vec()),
            "admin",
        )
    }

    fn memory_store() -> TenantStoreState {
        TenantStoreState {
            inner: TenantStoreInner::Memory(Arc::new(RwLock::new(HashMap::new()))),
        }
    }

    fn sample_tenant(slug: &str) -> Tenant {
        let now = Utc::now();
        Tenant {
            id: TenantId::new(),
            slug: slug.to_string(),
            display_name: format!("{slug} Corp"),
            tier: TenantTier::Shared,
            root_key_id: "kek-001".to_string(),
            created_at: now,
            updated_at: now,
            deleted_at: None,
        }
    }

    #[test]
    fn validate_slug_accepts_valid_slugs() {
        assert!(validate_slug("acme-corp").is_ok());
        assert!(validate_slug("tenant123").is_ok());
        assert!(validate_slug("a").is_ok());
    }

    #[test]
    fn validate_slug_rejects_invalid_slugs() {
        assert!(validate_slug("").is_err());
        assert!(validate_slug("Uppercase").is_err());
        assert!(validate_slug("spaces not allowed").is_err());
        assert!(validate_slug("underscore_not_allowed").is_err());
    }

    #[test]
    fn parse_tier_defaults_to_shared() {
        assert!(matches!(parse_tier(None), Ok(TenantTier::Shared)));
        assert!(matches!(parse_tier(Some("shared")), Ok(TenantTier::Shared)));
    }

    #[test]
    fn parse_tier_rejects_unknown() {
        assert!(parse_tier(Some("premium")).is_err());
    }

    #[tokio::test]
    async fn memory_store_create_and_get() {
        let store = memory_store();
        let tenant = sample_tenant("acme");
        let tenant_id = tenant.id.clone();
        store.create(tenant).await.unwrap();
        let fetched = store.get(&tenant_id).await.unwrap();
        assert_eq!(fetched.slug, "acme");
    }

    #[tokio::test]
    async fn memory_store_list_excludes_deleted() {
        let store = memory_store();
        let t1 = sample_tenant("alpha");
        let t2 = sample_tenant("beta");
        let t2_id = t2.id.clone();
        store.create(t1).await.unwrap();
        store.create(t2).await.unwrap();
        store.soft_delete(&t2_id).await.unwrap();
        let active = store.list().await.unwrap();
        assert_eq!(active.len(), 1);
        assert_eq!(active[0].slug, "alpha");
    }

    #[tokio::test]
    async fn memory_store_soft_delete_idempotency() {
        let store = memory_store();
        let tenant = sample_tenant("gamma");
        let id = tenant.id.clone();
        store.create(tenant).await.unwrap();
        store.soft_delete(&id).await.unwrap();
        // Second delete should return TenantNotFound because the tenant is
        // already marked deleted.
        let result = store.soft_delete(&id).await;
        assert!(matches!(result, Err(VaultError::TenantNotFound { .. })));
    }

    #[tokio::test]
    async fn http_create_tenant_returns_201() {
        let app = router(memory_store(), test_admin());
        let body = serde_json::json!({
            "slug": "test-tenant",
            "display_name": "Test Tenant",
            "tier": "shared",
            "root_key_id": "kek-test"
        });
        let req = Request::builder()
            .method("POST")
            .uri("/v1/tenants")
            .header("content-type", "application/json")
            .header("X-Admin-Token", "test-admin-token")
            .body(Body::from(serde_json::to_string(&body).unwrap()))
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::CREATED);
    }

    #[tokio::test]
    async fn http_create_tenant_invalid_slug_returns_422() {
        let app = router(memory_store(), test_admin());
        let body = serde_json::json!({
            "slug": "INVALID SLUG",
            "display_name": "Bad",
            "root_key_id": "kek-test"
        });
        let req = Request::builder()
            .method("POST")
            .uri("/v1/tenants")
            .header("content-type", "application/json")
            .header("X-Admin-Token", "test-admin-token")
            .body(Body::from(serde_json::to_string(&body).unwrap()))
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::UNPROCESSABLE_ENTITY);
    }

    #[tokio::test]
    async fn http_get_nonexistent_tenant_returns_404() {
        let app = router(memory_store(), test_admin());
        let fake_id = Uuid::now_v7();
        let req = Request::builder()
            .method("GET")
            .uri(format!("/v1/tenants/{fake_id}"))
            .header("X-Admin-Token", "test-admin-token")
            .body(Body::empty())
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn http_delete_tenant_returns_204() {
        let store = memory_store();
        let tenant = sample_tenant("to-delete");
        let tenant_id = tenant.id.clone();
        store.create(tenant).await.unwrap();

        let app = router(store, test_admin());
        let req = Request::builder()
            .method("DELETE")
            .uri(format!("/v1/tenants/{tenant_id}"))
            .header("X-Admin-Token", "test-admin-token")
            .body(Body::empty())
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::NO_CONTENT);
    }

    /// The routes had no guard at all: `GET /v1/tenants` returned every tenant
    /// in the deployment — including each one's `root_key_id` — to anyone who
    /// could reach the port, and POST/DELETE were equally open. The vault-ui
    /// pod proxies `/api/identity/*`, so all of it was reachable from wherever
    /// the UI is published.
    #[tokio::test]
    async fn tenant_routes_require_an_administrator() {
        for (method, uri) in [
            ("GET", "/v1/tenants"),
            ("POST", "/v1/tenants"),
            ("GET", "/v1/tenants/00000000-0000-0000-0000-000000000000"),
            ("DELETE", "/v1/tenants/00000000-0000-0000-0000-000000000000"),
        ] {
            let app = router(memory_store(), test_admin());
            let req = Request::builder()
                .method(method)
                .uri(uri)
                .header("content-type", "application/json")
                .body(Body::from("{}"))
                .unwrap();
            let resp = app.oneshot(req).await.unwrap();
            assert_eq!(
                resp.status(),
                StatusCode::UNAUTHORIZED,
                "{method} {uri} must not be reachable without an administrator credential"
            );
        }
    }

    /// A wrong bootstrap token is no better than none.
    #[tokio::test]
    async fn a_wrong_admin_token_is_rejected() {
        let app = router(memory_store(), test_admin());
        let req = Request::builder()
            .method("GET")
            .uri("/v1/tenants")
            .header("X-Admin-Token", "not-the-right-token")
            .body(Body::empty())
            .unwrap();
        assert_eq!(
            app.oneshot(req).await.unwrap().status(),
            StatusCode::UNAUTHORIZED
        );
    }
}
