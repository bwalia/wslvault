//! REST surface for lease list/get/renew/revoke.
//!
//! Create is gRPC-only (identity and future engines). Every handler authenticates
//! via [`wslvault_core::auth::resolve_identity`] and scopes queries to that
//! tenant, unless a superuser names another via `act_as_tenant`.

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
use tracing::error;

use crate::identity_client::IdentityClient;
use crate::store::{LeaseId, LeaseRecord, LeaseStoreBackend};
use wslvault_core::auth::{self, Identity};

#[derive(Clone)]
pub struct AppState {
    pub store: Arc<dyn LeaseStoreBackend>,
    pub identity: Option<IdentityClient>,
}

#[derive(Debug, Serialize)]
struct ApiError {
    code: &'static str,
    message: String,
}

fn json_error(status: StatusCode, code: &'static str, message: impl Into<String>) -> Response {
    (
        status,
        Json(ApiError {
            code,
            message: message.into(),
        }),
    )
        .into_response()
}

async fn require_authenticated(request: Request, next: Next) -> Response {
    if let Err(reason) = auth::resolve_identity(request.headers()).await {
        return json_error(
            StatusCode::UNAUTHORIZED,
            "unauthenticated",
            reason.to_string(),
        );
    }
    next.run(request).await
}

async fn authenticate(headers: &HeaderMap) -> Result<Identity, Response> {
    auth::resolve_identity(headers)
        .await
        .map_err(|e| json_error(StatusCode::UNAUTHORIZED, "unauthenticated", e.to_string()))
}

fn tenant_for(identity: &Identity, headers: &HeaderMap) -> String {
    auth::act_as_tenant(identity, headers).0
}

#[derive(Debug, Serialize)]
struct LeaseBody {
    id: String,
    tenant_id: String,
    target_type: String,
    target_label: String,
    state: String,
    ttl_seconds: i64,
    max_ttl_seconds: i64,
    renewable: bool,
    issued_at: String,
    expires_at: String,
    revoked_at: Option<String>,
    remaining_seconds: i64,
}

impl From<&LeaseRecord> for LeaseBody {
    fn from(r: &LeaseRecord) -> Self {
        Self {
            id: r.id.to_string(),
            tenant_id: r.tenant_id.clone(),
            target_type: r.target_type.clone(),
            target_label: r.target_label(),
            state: r.state.as_str().to_string(),
            ttl_seconds: r.ttl_seconds,
            max_ttl_seconds: r.max_ttl_seconds,
            renewable: r.renewable,
            issued_at: r.issued_at.to_rfc3339(),
            expires_at: r.expires_at.to_rfc3339(),
            revoked_at: r.revoked_at.map(|t| t.to_rfc3339()),
            remaining_seconds: r.remaining_seconds(),
        }
    }
}

#[derive(Debug, Serialize)]
struct ListBody {
    leases: Vec<LeaseBody>,
}

#[derive(Debug, Deserialize)]
struct ListQuery {
    state: Option<String>,
}

#[derive(Debug, Deserialize)]
struct RenewBody {
    increment_seconds: Option<i64>,
}

#[derive(Debug, Serialize)]
struct RenewResponse {
    id: String,
    ttl_seconds: i64,
    expires_at: String,
}

fn parse_lease_id(id: &str) -> Result<LeaseId, Response> {
    id.parse::<LeaseId>().map_err(|_| {
        json_error(
            StatusCode::BAD_REQUEST,
            "invalid_argument",
            "invalid lease id",
        )
    })
}

/// Visible to this tenant (or 404, including cross-tenant, so we do not leak).
async fn load_for_tenant(
    store: &Arc<dyn LeaseStoreBackend>,
    lease_id: &LeaseId,
    tenant_id: &str,
) -> Result<LeaseRecord, Response> {
    match store.get_lease(lease_id).await {
        Some(r) if r.tenant_id == tenant_id => Ok(r),
        Some(_) | None => Err(json_error(
            StatusCode::NOT_FOUND,
            "not_found",
            "lease not found",
        )),
    }
}

async fn list_leases(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(query): Query<ListQuery>,
) -> Response {
    let identity = match authenticate(&headers).await {
        Ok(i) => i,
        Err(r) => return r,
    };
    let tenant_id = tenant_for(&identity, &headers);
    let filter = query
        .state
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty() && *s != "all");

    let records = state.store.list_leases(&tenant_id, filter).await;
    let leases = records.iter().map(LeaseBody::from).collect();
    (StatusCode::OK, Json(ListBody { leases })).into_response()
}

async fn get_lease(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> Response {
    let identity = match authenticate(&headers).await {
        Ok(i) => i,
        Err(r) => return r,
    };
    let tenant_id = tenant_for(&identity, &headers);
    let lease_id = match parse_lease_id(&id) {
        Ok(v) => v,
        Err(r) => return r,
    };
    match load_for_tenant(&state.store, &lease_id, &tenant_id).await {
        Ok(r) => (StatusCode::OK, Json(LeaseBody::from(&r))).into_response(),
        Err(r) => r,
    }
}

async fn renew_lease(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<String>,
    body: Result<Json<RenewBody>, axum::extract::rejection::JsonRejection>,
) -> Response {
    let identity = match authenticate(&headers).await {
        Ok(i) => i,
        Err(r) => return r,
    };
    let tenant_id = tenant_for(&identity, &headers);
    let lease_id = match parse_lease_id(&id) {
        Ok(v) => v,
        Err(r) => return r,
    };
    if let Err(r) = load_for_tenant(&state.store, &lease_id, &tenant_id).await {
        return r;
    }

    let increment = body
        .ok()
        .and_then(|Json(b)| b.increment_seconds)
        .unwrap_or(3600);
    if increment <= 0 {
        return json_error(
            StatusCode::BAD_REQUEST,
            "invalid_argument",
            "increment_seconds must be positive",
        );
    }

    match state.store.renew_lease(&lease_id, increment).await {
        Ok(updated) => (
            StatusCode::OK,
            Json(RenewResponse {
                id: updated.id.to_string(),
                ttl_seconds: updated.ttl_seconds,
                expires_at: updated.expires_at.to_rfc3339(),
            }),
        )
            .into_response(),
        Err(e) => json_error(StatusCode::BAD_REQUEST, "failed_precondition", e),
    }
}

async fn revoke_lease(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> Response {
    let identity = match authenticate(&headers).await {
        Ok(i) => i,
        Err(r) => return r,
    };
    let tenant_id = tenant_for(&identity, &headers);
    let lease_id = match parse_lease_id(&id) {
        Ok(v) => v,
        Err(r) => return r,
    };
    let record = match load_for_tenant(&state.store, &lease_id, &tenant_id).await {
        Ok(r) => r,
        Err(r) => return r,
    };

    if record.state.as_str() != "revoked" {
        if let Some((hash, principal_id, expires_at)) = record.token_revocation() {
            match &state.identity {
                Some(client) => {
                    if let Err(e) = client
                        .revoke_token_by_hash(&hash, &record.tenant_id, &principal_id, expires_at)
                        .await
                    {
                        return json_error(StatusCode::SERVICE_UNAVAILABLE, "unavailable", e);
                    }
                }
                None => {
                    error!(
                        lease_id = %lease_id,
                        "IDENTITY_SERVICE_GRPC unset; token lease row will be revoked but the JWT stays live until exp"
                    );
                }
            }
        }

        if let Err(e) = state.store.revoke_lease(&lease_id).await {
            if e.contains("not found") {
                return json_error(StatusCode::NOT_FOUND, "not_found", "lease not found");
            }
            return json_error(StatusCode::INTERNAL_SERVER_ERROR, "internal", e);
        }
    }

    StatusCode::NO_CONTENT.into_response()
}

/// Routes for `/v1/leases`. Mount next to `/health` (which stays unauthenticated).
pub fn router(store: Arc<dyn LeaseStoreBackend>, identity: Option<IdentityClient>) -> Router {
    let state = AppState { store, identity };
    Router::new()
        .route("/v1/leases", get(list_leases))
        .route("/v1/leases/", get(list_leases))
        .route("/v1/leases/:id", get(get_lease))
        .route("/v1/leases/:id/renew", post(renew_lease))
        .route("/v1/leases/:id/revoke", post(revoke_lease))
        .layer(axum::middleware::from_fn(require_authenticated))
        .with_state(state)
}
