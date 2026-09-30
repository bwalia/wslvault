//! REST HTTP API for the policy-engine.
//!
//! Exposes CRUD endpoints for policy documents and an authorization check,
//! all using the same in-memory or Postgres backend as the gRPC service.
//!
//! # Routes
//!
//! | Method   | Path                       | Description                         |
//! |----------|----------------------------|-------------------------------------|
//! | GET      | /health                    | Liveness probe                      |
//! | GET      | /v1/policies               | List all policies for a tenant      |
//! | POST     | /v1/policies               | Create / replace a policy           |
//! | GET      | /v1/policies/:name         | Get a single policy by name         |
//! | PUT      | /v1/policies/:name         | Upsert a policy by name             |
//! | DELETE   | /v1/policies/:name         | Delete a policy                     |
//! | POST     | /v1/policies/authorize     | Evaluate a single authorization     |
//!
//! # Authentication
//!
//! Every policy route resolves the caller through
//! [`wslvault_core::auth::resolve_identity`] and operates on **that** caller's
//! tenant. The tenant is never taken from a request header. Any member may
//! read the tenant's policies; creating, replacing or deleting one requires
//! the tenant's `root` or `admin` policy, or platform administration (see
//! [`may_manage_policies`]).
//!
//! It used to be: `tenant_id()` read `X-Tenant-Id` straight off the request and
//! the routes were guarded only by `require_gateway_auth`, which is disabled
//! whenever `VAULT_GATEWAY_SECRET` is unset — as it is in every chart-rendered
//! deployment. Anyone who could reach this port could therefore read, rewrite
//! or delete any tenant's policies without a credential.

use std::sync::Arc;

use axum::extract::{Path, State};
use axum::http::{HeaderMap, HeaderValue, Method, StatusCode};
use axum::response::IntoResponse;
use axum::routing::{get, post};
use axum::{Json, Router};
use serde::{Deserialize, Serialize};
use tower_http::cors::CorsLayer;
use wslvault_core::middleware::{require_gateway_auth, GatewayAuth};

use crate::evaluator::CompiledPolicies;
use crate::model::{Capability, PolicyDocument, PolicyRule};
use crate::store::PolicyStoreBackend;

// ---------------------------------------------------------------------------
// Shared state
// ---------------------------------------------------------------------------

#[derive(Clone)]
pub struct AppState {
    pub store: Arc<dyn PolicyStoreBackend>,
    pub compiled: Arc<tokio::sync::RwLock<CompiledPolicies>>,
}

// ---------------------------------------------------------------------------
// Request / response types
// ---------------------------------------------------------------------------

#[derive(Debug, Serialize, Deserialize)]
pub struct PolicyRuleDto {
    pub paths: Vec<String>,
    pub capabilities: Vec<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct PolicyDocumentDto {
    pub name: String,
    pub rules: Vec<PolicyRuleDto>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct AuthorizeRequest {
    pub principal_id: String,
    /// Policy names held by the caller, exactly as the gRPC `Authorize` RPC
    /// takes them. Required: without it this endpoint has no way to know what
    /// the principal is entitled to, and its previous behaviour was to assume
    /// everything in the tenant.
    #[serde(default)]
    pub policies: Vec<String>,
    pub action: String,
    pub resource: String,
}

#[derive(Debug, Serialize)]
pub struct AuthorizeResponse {
    pub allowed: bool,
    pub reason: String,
}

#[derive(Debug, Serialize)]
#[allow(dead_code)] // Handlers emit inline JSON; kept as the documented error shape.
pub struct ErrorResponse {
    pub message: String,
}

// ---------------------------------------------------------------------------
// Domain ↔ DTO conversion helpers
// ---------------------------------------------------------------------------

fn doc_to_dto(doc: PolicyDocument) -> PolicyDocumentDto {
    PolicyDocumentDto {
        name: doc.name,
        rules: doc
            .rules
            .into_iter()
            .map(|r| PolicyRuleDto {
                paths: r.paths,
                capabilities: r
                    .capabilities
                    .into_iter()
                    .map(|c| format!("{c:?}").to_lowercase())
                    .collect(),
            })
            .collect(),
    }
}

fn dto_to_doc(dto: PolicyDocumentDto) -> Result<PolicyDocument, String> {
    let mut rules = Vec::new();
    for r in dto.rules {
        let mut caps = std::collections::HashSet::new();
        for c in &r.capabilities {
            match c.to_lowercase().as_str() {
                "read" => {
                    caps.insert(Capability::Read);
                }
                "write" => {
                    caps.insert(Capability::Write);
                }
                "delete" => {
                    caps.insert(Capability::Delete);
                }
                "list" => {
                    caps.insert(Capability::List);
                }
                "create" => {
                    caps.insert(Capability::Create);
                }
                "update" => {
                    caps.insert(Capability::Update);
                }
                "deny" => {
                    caps.insert(Capability::Deny);
                }
                other => return Err(format!("unknown capability: {other}")),
            }
        }
        rules.push(PolicyRule {
            paths: r.paths,
            capabilities: caps,
        });
    }
    Ok(PolicyDocument {
        name: dto.name,
        rules,
    })
}

/// Authenticate the caller and return the tenant they may operate on.
///
/// The `Err` variant is an already-rendered response, so handlers return it
/// verbatim.
#[allow(clippy::result_large_err)]
async fn caller_tenant(headers: &HeaderMap) -> Result<String, axum::response::Response> {
    wslvault_core::auth::resolve_identity(headers)
        .await
        .map(|id| id.tenant_id)
        .map_err(|e| {
            (
                StatusCode::UNAUTHORIZED,
                Json(serde_json::json!({ "message": e.to_string() })),
            )
                .into_response()
        })
}

/// Policy names that make a caller an administrator of its **own** tenant.
///
/// Every policy route acts only on the caller's tenant, so a tenant's `admin`
/// here reaches that tenant and no other — unlike identity-service's key
/// management, which crosses tenants and so demands the platform policy. These
/// are the same names the console uses to decide who sees the Policies page.
const TENANT_ADMIN_POLICIES: &[&str] = &["root", "admin"];

/// Whether this caller may change its tenant's policies.
///
/// A policy is the tenant's permission system: writing one is granting
/// permissions. Membership alone used to be enough, so a caller holding only
/// `default` could rewrite `default` to grant itself everything in the tenant,
/// or delete the policies constraining others.
fn may_manage_policies(identity: &wslvault_core::auth::Identity) -> bool {
    wslvault_core::auth::is_platform_admin(identity)
        || identity
            .policies
            .iter()
            .any(|p| TENANT_ADMIN_POLICIES.contains(&p.as_str()))
}

/// Resolve the caller, and require that it may manage policies. Returns the
/// tenant to act on: always the caller's own.
async fn admin_caller_tenant(headers: &HeaderMap) -> Result<String, axum::response::Response> {
    let identity = wslvault_core::auth::resolve_identity(headers)
        .await
        .map_err(|e| {
            (
                StatusCode::UNAUTHORIZED,
                Json(serde_json::json!({ "message": e.to_string() })),
            )
                .into_response()
        })?;
    if !may_manage_policies(&identity) {
        tracing::warn!(
            tenant_id = %identity.tenant_id,
            principal_id = %identity.principal_id,
            "denied: policy change by a caller without an administrator policy"
        );
        return Err((
            StatusCode::FORBIDDEN,
            Json(serde_json::json!({
                "code": "admin_policy_required",
                "message": "changing policies requires the tenant's root or admin policy, or platform administration"
            })),
        )
            .into_response());
    }
    Ok(identity.tenant_id)
}

// ---------------------------------------------------------------------------
// Handlers
// ---------------------------------------------------------------------------

async fn health_handler() -> impl IntoResponse {
    (
        StatusCode::OK,
        Json(serde_json::json!({ "status": "ok", "service": "policy-engine" })),
    )
}

/// GET /v1/policies
async fn list_policies(State(state): State<AppState>, headers: HeaderMap) -> impl IntoResponse {
    let tid = match caller_tenant(&headers).await {
        Ok(t) => t,
        Err(r) => return r,
    };
    let docs = state.store.get_all_for_tenant(&tid).await;
    let dtos: Vec<_> = docs.into_iter().map(doc_to_dto).collect();
    (StatusCode::OK, Json(dtos)).into_response()
}

/// POST /v1/policies
async fn create_policy(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(body): Json<PolicyDocumentDto>,
) -> impl IntoResponse {
    let tid = match admin_caller_tenant(&headers).await {
        Ok(t) => t,
        Err(r) => return r,
    };
    let doc = match dto_to_doc(body) {
        Ok(d) => d,
        Err(e) => {
            return (
                StatusCode::UNPROCESSABLE_ENTITY,
                Json(serde_json::json!({ "message": e })),
            )
                .into_response()
        }
    };
    state.store.put_policy(&tid, doc.clone()).await;
    {
        let mut guard = state.compiled.write().await;
        guard.upsert(tid.clone(), doc.name.clone(), doc.rules.clone());
    }
    (StatusCode::CREATED, Json(doc_to_dto(doc))).into_response()
}

/// GET /v1/policies/:name
async fn get_policy(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(name): Path<String>,
) -> impl IntoResponse {
    let tid = match caller_tenant(&headers).await {
        Ok(t) => t,
        Err(r) => return r,
    };
    match state.store.get_policy(&tid, &name).await {
        Some(doc) => (StatusCode::OK, Json(doc_to_dto(doc))).into_response(),
        None => (
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({ "message": "policy not found" })),
        )
            .into_response(),
    }
}

/// PUT /v1/policies/:name
async fn upsert_policy(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(name): Path<String>,
    Json(mut body): Json<PolicyDocumentDto>,
) -> impl IntoResponse {
    let tid = match admin_caller_tenant(&headers).await {
        Ok(t) => t,
        Err(r) => return r,
    };
    body.name = name; // path name wins
    let doc = match dto_to_doc(body) {
        Ok(d) => d,
        Err(e) => {
            return (
                StatusCode::UNPROCESSABLE_ENTITY,
                Json(serde_json::json!({ "message": e })),
            )
                .into_response()
        }
    };
    state.store.put_policy(&tid, doc.clone()).await;
    {
        let mut guard = state.compiled.write().await;
        guard.upsert(tid.clone(), doc.name.clone(), doc.rules.clone());
    }
    (StatusCode::OK, Json(doc_to_dto(doc))).into_response()
}

/// DELETE /v1/policies/:name
async fn delete_policy(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(name): Path<String>,
) -> impl IntoResponse {
    let tid = match admin_caller_tenant(&headers).await {
        Ok(t) => t,
        Err(r) => return r,
    };
    match state.store.delete_policy(&tid, &name).await {
        Some(_) => {
            // Drop it from the live snapshot too. Without this the deleted
            // policy keeps granting access until the next background
            // recompilation tick.
            let mut guard = state.compiled.write().await;
            guard.remove(&tid, &name);
            StatusCode::NO_CONTENT.into_response()
        }
        None => (
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({ "message": "policy not found" })),
        )
            .into_response(),
    }
}

/// POST /v1/policies/authorize
async fn authorize(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(body): Json<AuthorizeRequest>,
) -> impl IntoResponse {
    let tid = match caller_tenant(&headers).await {
        Ok(t) => t,
        Err(r) => return r,
    };

    let compiled = state.compiled.read().await;
    let action = body.action.clone();
    let resource = body.resource.clone();

    // Evaluate the caller's OWN policies, scoped to their tenant.
    //
    // This previously loaded every policy in the tenant and evaluated the
    // caller against the union of all of them, ignoring `principal_id`
    // entirely: if any policy anywhere in the tenant granted an action, every
    // principal in that tenant had it. The gRPC path never had this bug, and
    // this endpoint now takes the same input it does.
    let decision = crate::evaluator::evaluate(&compiled, &tid, &body.policies, &action, &resource);
    let (allowed, reason) = match decision {
        crate::model::PolicyDecision::Allow => (true, "allowed".to_string()),
        crate::model::PolicyDecision::Deny { reason } => (false, reason),
    };

    (StatusCode::OK, Json(AuthorizeResponse { allowed, reason })).into_response()
}

// ---------------------------------------------------------------------------
// Router
// ---------------------------------------------------------------------------

/// Build the Axum `Router` for the policy HTTP API.
///
/// Policy routes are protected by gateway-origin authentication so that only
/// requests proxied through the WSLVault gateway (which carry the shared
/// `X-Gateway-Auth` secret) are honored — a caller reaching this port directly
/// cannot forge an `X-Tenant-Id`. The `/health` probe is intentionally left
/// unauthenticated so orchestrators can reach it.
pub fn api_router(state: AppState) -> Router {
    // CORS origins are scoped to an explicit allowlist from
    // `VAULT_CORS_ALLOWED_ORIGINS` (comma-separated). Absent/empty means no
    // cross-origin access is granted, replacing the previous wildcard.
    let allowed_origins: Vec<HeaderValue> = std::env::var("VAULT_CORS_ALLOWED_ORIGINS")
        .ok()
        .map(|raw| {
            raw.split(',')
                .map(str::trim)
                .filter(|s| !s.is_empty())
                .filter_map(|o| o.parse::<HeaderValue>().ok())
                .collect()
        })
        .unwrap_or_default();

    let cors = CorsLayer::new()
        .allow_methods([
            Method::GET,
            Method::POST,
            Method::PUT,
            Method::DELETE,
            Method::OPTIONS,
        ])
        .allow_headers([
            axum::http::header::CONTENT_TYPE,
            axum::http::header::AUTHORIZATION,
        ])
        .allow_origin(allowed_origins);

    let policy_routes = Router::new()
        .route("/v1/policies", get(list_policies).post(create_policy))
        .route(
            "/v1/policies/:name",
            get(get_policy).put(upsert_policy).delete(delete_policy),
        )
        .route("/v1/policies/authorize", post(authorize))
        .layer(axum::middleware::from_fn_with_state(
            GatewayAuth::from_env(),
            require_gateway_auth,
        ));

    Router::new()
        .route("/health", get(health_handler))
        .merge(policy_routes)
        .layer(cors)
        .with_state(state)
}

#[cfg(test)]
mod tests {
    //! Who may change a tenant's policies.
    //!
    //! Policies are the tenant's permission system, so rewriting one is
    //! granting permissions. A member holding only `default` could rewrite
    //! `default` itself and hand themselves everything; these tests pin that
    //! shut, and pin that ordinary members can still read.

    use super::*;
    use crate::evaluator::CompiledPolicies;
    use crate::store::PolicyStore;
    use axum::body::Body;
    use axum::http::Request;
    use tower::ServiceExt;

    const SECRET: &str = "policy-engine-test-secret-at-least-32-bytes!!";
    const TENANT: &str = "tenant-a";

    fn env() {
        // Every test sets the same values, so parallel tests cannot disagree.
        std::env::set_var(wslvault_core::auth::JWT_SECRET_ENV, SECRET);
        std::env::remove_var(wslvault_core::auth::TRUST_GATEWAY_HEADERS_ENV);
        std::env::remove_var("VAULT_GATEWAY_SECRET");
        std::env::remove_var(wslvault_core::auth::ADMIN_POLICY_ENV);
    }

    fn token(policies: &[&str], superuser: bool) -> String {
        use jsonwebtoken::{encode, Algorithm, EncodingKey, Header};
        let claims = serde_json::json!({
            "sub": "someone",
            "tenant_id": TENANT,
            "policies": policies,
            "superuser": superuser,
            "exp": chrono::Utc::now().timestamp() + 600,
        });
        encode(
            &Header::new(Algorithm::HS256),
            &claims,
            &EncodingKey::from_secret(SECRET.as_bytes()),
        )
        .expect("encode test token")
    }

    fn state() -> AppState {
        AppState {
            store: Arc::new(PolicyStore::new()),
            compiled: Arc::new(tokio::sync::RwLock::new(CompiledPolicies::new())),
        }
    }

    async fn call(
        state: &AppState,
        method: &str,
        uri: &str,
        bearer: Option<&str>,
        body: Option<serde_json::Value>,
    ) -> StatusCode {
        env();
        let mut req = Request::builder().method(method).uri(uri);
        if let Some(t) = bearer {
            req = req.header("authorization", format!("Bearer {t}"));
        }
        let req = match body {
            Some(b) => req
                .header("content-type", "application/json")
                .body(Body::from(b.to_string()))
                .unwrap(),
            None => req.body(Body::empty()).unwrap(),
        };
        api_router(state.clone())
            .oneshot(req)
            .await
            .expect("route")
            .status()
    }

    fn everything(name: &str) -> serde_json::Value {
        serde_json::json!({
            "name": name,
            "rules": [{ "paths": ["secret/**"], "capabilities": ["read", "write", "list", "delete"] }]
        })
    }

    async fn seed(state: &AppState, name: &str, paths: &[&str]) {
        let dto: PolicyDocumentDto = serde_json::from_value(serde_json::json!({
            "name": name,
            "rules": [{ "paths": paths, "capabilities": ["read"] }]
        }))
        .unwrap();
        state
            .store
            .put_policy(TENANT, dto_to_doc(dto).unwrap())
            .await;
    }

    async fn paths_of(state: &AppState, name: &str) -> Option<Vec<String>> {
        let doc = state.store.get_policy(TENANT, name).await?;
        let dto = doc_to_dto(doc);
        Some(dto.rules.into_iter().flat_map(|r| r.paths).collect())
    }

    // --- the escalation ---------------------------------------------------

    /// The hole: a `default`-only member rewrote `default` to grant itself
    /// everything in the tenant.
    #[tokio::test]
    async fn a_member_cannot_rewrite_default_to_grant_itself_everything() {
        let s = state();
        seed(&s, "default", &["secret/public/*"]).await;
        let member = token(&["default"], false);

        let status = call(
            &s,
            "PUT",
            "/v1/policies/default",
            Some(&member),
            Some(everything("default")),
        )
        .await;

        assert_eq!(status, StatusCode::FORBIDDEN);
        assert_eq!(
            paths_of(&s, "default").await,
            Some(vec!["secret/public/*".to_string()])
        );
    }

    #[tokio::test]
    async fn a_member_cannot_create_a_policy() {
        let s = state();
        let member = token(&["default"], false);
        let status = call(
            &s,
            "POST",
            "/v1/policies",
            Some(&member),
            Some(everything("mine")),
        )
        .await;
        assert_eq!(status, StatusCode::FORBIDDEN);
        assert_eq!(paths_of(&s, "mine").await, None);
    }

    #[tokio::test]
    async fn a_member_cannot_delete_a_policy() {
        let s = state();
        seed(&s, "guard", &["secret/x"]).await;
        let member = token(&["default"], false);
        let status = call(&s, "DELETE", "/v1/policies/guard", Some(&member), None).await;
        assert_eq!(status, StatusCode::FORBIDDEN);
        assert!(paths_of(&s, "guard").await.is_some(), "policy must survive");
    }

    // --- who may ------------------------------------------------------------

    #[tokio::test]
    async fn a_tenant_admin_manages_the_tenants_policies() {
        let s = state();
        let admin = token(&["admin"], false);
        assert_eq!(
            call(
                &s,
                "POST",
                "/v1/policies",
                Some(&admin),
                Some(everything("ops"))
            )
            .await,
            StatusCode::CREATED
        );
        assert_eq!(
            call(
                &s,
                "PUT",
                "/v1/policies/ops",
                Some(&admin),
                Some(everything("ops"))
            )
            .await,
            StatusCode::OK
        );
        assert_eq!(
            call(&s, "DELETE", "/v1/policies/ops", Some(&admin), None).await,
            StatusCode::NO_CONTENT
        );
    }

    #[tokio::test]
    async fn root_manages_the_tenants_policies() {
        let s = state();
        let root = token(&["root"], false);
        assert_eq!(
            call(
                &s,
                "POST",
                "/v1/policies",
                Some(&root),
                Some(everything("ops"))
            )
            .await,
            StatusCode::CREATED
        );
    }

    #[tokio::test]
    async fn a_platform_admin_manages_policies() {
        let s = state();
        let platform = token(&[wslvault_core::auth::DEFAULT_ADMIN_POLICY], false);
        assert_eq!(
            call(
                &s,
                "POST",
                "/v1/policies",
                Some(&platform),
                Some(everything("ops"))
            )
            .await,
            StatusCode::CREATED
        );
    }

    #[tokio::test]
    async fn a_superuser_manages_policies_without_the_policy_name() {
        let s = state();
        let su = token(&[], true);
        assert_eq!(
            call(
                &s,
                "POST",
                "/v1/policies",
                Some(&su),
                Some(everything("ops"))
            )
            .await,
            StatusCode::CREATED
        );
    }

    // --- unchanged ----------------------------------------------------------

    /// Reading stays open to members: the console and SDKs list policies, and
    /// seeing a rule is not holding it.
    #[tokio::test]
    async fn a_member_can_still_read_policies() {
        let s = state();
        seed(&s, "default", &["secret/public/*"]).await;
        let member = token(&["default"], false);
        assert_eq!(
            call(&s, "GET", "/v1/policies", Some(&member), None).await,
            StatusCode::OK
        );
        assert_eq!(
            call(&s, "GET", "/v1/policies/default", Some(&member), None).await,
            StatusCode::OK
        );
    }

    #[tokio::test]
    async fn no_credential_is_still_unauthorized() {
        let s = state();
        assert_eq!(
            call(&s, "POST", "/v1/policies", None, Some(everything("x"))).await,
            StatusCode::UNAUTHORIZED
        );
        assert_eq!(
            call(&s, "GET", "/v1/policies", None, None).await,
            StatusCode::UNAUTHORIZED
        );
    }
}
