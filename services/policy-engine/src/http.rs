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
//! All policy routes require an `X-Tenant-Id` header.

use std::sync::Arc;

use axum::extract::{Path, State};
use axum::http::{HeaderMap, HeaderValue, Method, StatusCode};
use axum::response::IntoResponse;
use axum::routing::{delete, get, post, put};
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
    pub action: String,
    pub resource: String,
}

#[derive(Debug, Serialize)]
pub struct AuthorizeResponse {
    pub allowed: bool,
    pub reason: String,
}

#[derive(Debug, Serialize)]
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
                "read" => { caps.insert(Capability::Read); }
                "write" => { caps.insert(Capability::Write); }
                "delete" => { caps.insert(Capability::Delete); }
                "list" => { caps.insert(Capability::List); }
                "create" => { caps.insert(Capability::Create); }
                "update" => { caps.insert(Capability::Update); }
                "deny" => { caps.insert(Capability::Deny); }
                other => return Err(format!("unknown capability: {other}")),
            }
        }
        rules.push(PolicyRule { paths: r.paths, capabilities: caps });
    }
    Ok(PolicyDocument { name: dto.name, rules })
}

fn tenant_id(headers: &HeaderMap) -> Option<String> {
    headers
        .get("x-tenant-id")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string())
}

// ---------------------------------------------------------------------------
// Handlers
// ---------------------------------------------------------------------------

async fn health_handler() -> impl IntoResponse {
    (StatusCode::OK, Json(serde_json::json!({ "status": "ok", "service": "policy-engine" })))
}

/// GET /v1/policies
async fn list_policies(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> impl IntoResponse {
    let Some(tid) = tenant_id(&headers) else {
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({ "message": "X-Tenant-Id header is required" })),
        ).into_response();
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
    let Some(tid) = tenant_id(&headers) else {
        return (StatusCode::BAD_REQUEST, Json(serde_json::json!({ "message": "X-Tenant-Id header is required" }))).into_response();
    };
    let doc = match dto_to_doc(body) {
        Ok(d) => d,
        Err(e) => return (StatusCode::UNPROCESSABLE_ENTITY, Json(serde_json::json!({ "message": e }))).into_response(),
    };
    state.store.put_policy(&tid, doc.clone()).await;
    {
        let mut guard = state.compiled.write().await;
        guard.upsert(doc.name.clone(), doc.rules.clone());
    }
    (StatusCode::CREATED, Json(doc_to_dto(doc))).into_response()
}

/// GET /v1/policies/:name
async fn get_policy(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(name): Path<String>,
) -> impl IntoResponse {
    let Some(tid) = tenant_id(&headers) else {
        return (StatusCode::BAD_REQUEST, Json(serde_json::json!({ "message": "X-Tenant-Id header is required" }))).into_response();
    };
    match state.store.get_policy(&tid, &name).await {
        Some(doc) => (StatusCode::OK, Json(doc_to_dto(doc))).into_response(),
        None => (StatusCode::NOT_FOUND, Json(serde_json::json!({ "message": "policy not found" }))).into_response(),
    }
}

/// PUT /v1/policies/:name
async fn upsert_policy(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(name): Path<String>,
    Json(mut body): Json<PolicyDocumentDto>,
) -> impl IntoResponse {
    let Some(tid) = tenant_id(&headers) else {
        return (StatusCode::BAD_REQUEST, Json(serde_json::json!({ "message": "X-Tenant-Id header is required" }))).into_response();
    };
    body.name = name; // path name wins
    let doc = match dto_to_doc(body) {
        Ok(d) => d,
        Err(e) => return (StatusCode::UNPROCESSABLE_ENTITY, Json(serde_json::json!({ "message": e }))).into_response(),
    };
    state.store.put_policy(&tid, doc.clone()).await;
    {
        let mut guard = state.compiled.write().await;
        guard.upsert(doc.name.clone(), doc.rules.clone());
    }
    (StatusCode::OK, Json(doc_to_dto(doc))).into_response()
}

/// DELETE /v1/policies/:name
async fn delete_policy(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(name): Path<String>,
) -> impl IntoResponse {
    let Some(tid) = tenant_id(&headers) else {
        return (StatusCode::BAD_REQUEST, Json(serde_json::json!({ "message": "X-Tenant-Id header is required" }))).into_response();
    };
    match state.store.delete_policy(&tid, &name).await {
        Some(_) => StatusCode::NO_CONTENT.into_response(),
        None => (StatusCode::NOT_FOUND, Json(serde_json::json!({ "message": "policy not found" }))).into_response(),
    }
}

/// POST /v1/policies/authorize
async fn authorize(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(body): Json<AuthorizeRequest>,
) -> impl IntoResponse {
    let Some(tid) = tenant_id(&headers) else {
        return (StatusCode::BAD_REQUEST, Json(serde_json::json!({ "message": "X-Tenant-Id header is required" }))).into_response();
    };

    let compiled = state.compiled.read().await;
    let action = body.action.clone();
    let resource = body.resource.clone();

    // Collect policy names for this principal by loading all tenant policies
    let docs = state.store.get_all_for_tenant(&tid).await;
    let policy_names: Vec<String> = docs.iter().map(|d| d.name.clone()).collect();

    let decision = crate::evaluator::evaluate(&compiled, &policy_names, &action, &resource);
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
        .allow_methods([Method::GET, Method::POST, Method::PUT, Method::DELETE, Method::OPTIONS])
        .allow_headers([
            axum::http::header::CONTENT_TYPE,
            axum::http::header::AUTHORIZATION,
        ])
        .allow_origin(allowed_origins);

    let policy_routes = Router::new()
        .route("/v1/policies", get(list_policies).post(create_policy))
        .route("/v1/policies/:name", get(get_policy).put(upsert_policy).delete(delete_policy))
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
