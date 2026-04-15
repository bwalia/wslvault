//! HTTP handlers for per-tenant quota management.
//!
//! | Method | Path                 | Description                |
//! |--------|----------------------|----------------------------|
//! | GET    | /v1/quotas           | List all tenant quotas     |
//! | GET    | /v1/quotas/:id       | Get quota for one tenant   |
//! | PATCH  | /v1/quotas/:id       | Update quota limits        |

use axum::{
    extract::{Path, State},
    http::StatusCode,
    response::IntoResponse,
    routing::get,
    Json, Router,
};
use serde::{Deserialize, Serialize};
use uuid::Uuid;
use wslvault_storage::pool::DbPool;
use wslvault_storage::quota_store::{self, TenantQuotaRow};

// ---------------------------------------------------------------------------
// State
// ---------------------------------------------------------------------------

/// Shared state for quota handlers.
#[derive(Clone)]
pub struct QuotaState {
    pub pool: Option<DbPool>,
}

// ---------------------------------------------------------------------------
// Wire types
// ---------------------------------------------------------------------------

/// JSON representation of a tenant quota record.
#[derive(Debug, Serialize, utoipa::ToSchema)]
pub struct QuotaResponse {
    pub tenant_id: String,
    pub max_secrets: i32,
    pub max_secret_versions: i32,
    pub max_secret_size_bytes: i32,
    pub max_transit_keys: i32,
    pub read_rate_limit: i32,
    pub write_rate_limit: i32,
    pub max_storage_bytes: i64,
    pub current_storage_bytes: i64,
    pub current_secret_count: i32,
    pub current_transit_key_count: i32,
    pub tier: String,
    pub created_at: String,
    pub updated_at: String,
}

impl From<&TenantQuotaRow> for QuotaResponse {
    fn from(r: &TenantQuotaRow) -> Self {
        Self {
            tenant_id: r.tenant_id.to_string(),
            max_secrets: r.max_secrets,
            max_secret_versions: r.max_secret_versions,
            max_secret_size_bytes: r.max_secret_size_bytes,
            max_transit_keys: r.max_transit_keys,
            read_rate_limit: r.read_rate_limit,
            write_rate_limit: r.write_rate_limit,
            max_storage_bytes: r.max_storage_bytes,
            current_storage_bytes: r.current_storage_bytes,
            current_secret_count: r.current_secret_count,
            current_transit_key_count: r.current_transit_key_count,
            tier: r.tier.clone(),
            created_at: r.created_at.to_rfc3339(),
            updated_at: r.updated_at.to_rfc3339(),
        }
    }
}

/// Request body for `PATCH /v1/quotas/:id`.
#[derive(Debug, Deserialize, utoipa::ToSchema)]
pub struct UpdateQuotaRequest {
    pub max_secrets: Option<i32>,
    pub max_secret_versions: Option<i32>,
    pub max_secret_size_bytes: Option<i32>,
    pub max_transit_keys: Option<i32>,
    pub read_rate_limit: Option<i32>,
    pub write_rate_limit: Option<i32>,
    pub max_storage_bytes: Option<i64>,
    pub tier: Option<String>,
}

// ---------------------------------------------------------------------------
// Handlers
// ---------------------------------------------------------------------------

/// GET /v1/quotas — list quotas for all active tenants.
#[utoipa::path(
    get,
    path = "/v1/quotas",
    responses(
        (status = 200, description = "Quota list", body = Vec<QuotaResponse>),
        (status = 503, description = "Database not configured"),
    ),
    tag = "quotas"
)]
pub async fn list_quotas(State(state): State<QuotaState>) -> impl IntoResponse {
    let Some(ref pool) = state.pool else {
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(serde_json::json!({
                "code": "no_database",
                "message": "quota management requires DATABASE_URL",
            })),
        )
            .into_response();
    };

    match quota_store::list_quotas(pool).await {
        Ok(rows) => {
            let body: Vec<QuotaResponse> = rows.iter().map(QuotaResponse::from).collect();
            (StatusCode::OK, Json(body)).into_response()
        }
        Err(e) => {
            tracing::error!(error = %e, "failed to list quotas");
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({
                    "code": "list_failed",
                    "message": e.to_string(),
                })),
            )
                .into_response()
        }
    }
}

/// GET /v1/quotas/:id — get quota for a specific tenant.
#[utoipa::path(
    get,
    path = "/v1/quotas/{id}",
    params(
        ("id" = String, Path, description = "Tenant UUID"),
    ),
    responses(
        (status = 200, description = "Quota found", body = QuotaResponse),
        (status = 400, description = "Invalid UUID"),
        (status = 404, description = "Quota not found"),
        (status = 503, description = "Database not configured"),
    ),
    tag = "quotas"
)]
pub async fn get_quota(
    State(state): State<QuotaState>,
    Path(id_str): Path<String>,
) -> impl IntoResponse {
    let Some(ref pool) = state.pool else {
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(serde_json::json!({
                "code": "no_database",
                "message": "quota management requires DATABASE_URL",
            })),
        )
            .into_response();
    };

    let tenant_id: Uuid = match id_str.parse() {
        Ok(u) => u,
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

    match quota_store::get_quota(pool, tenant_id).await {
        Ok(row) => (StatusCode::OK, Json(QuotaResponse::from(&row))).into_response(),
        Err(quota_store::QuotaStoreError::NotFound { .. }) => (
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({
                "code": "not_found",
                "message": format!("quota not found for tenant '{id_str}'"),
            })),
        )
            .into_response(),
        Err(e) => {
            tracing::error!(error = %e, tenant_id = %id_str, "failed to get quota");
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({
                    "code": "get_failed",
                    "message": e.to_string(),
                })),
            )
                .into_response()
        }
    }
}

/// PATCH /v1/quotas/:id — update quota limits for a tenant.
#[utoipa::path(
    patch,
    path = "/v1/quotas/{id}",
    params(
        ("id" = String, Path, description = "Tenant UUID"),
    ),
    request_body = UpdateQuotaRequest,
    responses(
        (status = 200, description = "Quota updated", body = QuotaResponse),
        (status = 400, description = "Invalid UUID or payload"),
        (status = 404, description = "Quota not found"),
        (status = 503, description = "Database not configured"),
    ),
    tag = "quotas"
)]
pub async fn update_quota(
    State(state): State<QuotaState>,
    Path(id_str): Path<String>,
    Json(payload): Json<UpdateQuotaRequest>,
) -> impl IntoResponse {
    let Some(ref pool) = state.pool else {
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(serde_json::json!({
                "code": "no_database",
                "message": "quota management requires DATABASE_URL",
            })),
        )
            .into_response();
    };

    let tenant_id: Uuid = match id_str.parse() {
        Ok(u) => u,
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

    // Validate tier if provided.
    if let Some(ref tier) = payload.tier {
        if !matches!(tier.as_str(), "shared" | "dedicated" | "sovereign") {
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({
                    "code": "invalid_tier",
                    "message": format!("unknown tier '{tier}'; must be shared, dedicated, or sovereign"),
                })),
            )
                .into_response();
        }
    }

    let update = quota_store::QuotaUpdate {
        max_secrets: payload.max_secrets,
        max_secret_versions: payload.max_secret_versions,
        max_secret_size_bytes: payload.max_secret_size_bytes,
        max_transit_keys: payload.max_transit_keys,
        read_rate_limit: payload.read_rate_limit,
        write_rate_limit: payload.write_rate_limit,
        max_storage_bytes: payload.max_storage_bytes,
        tier: payload.tier,
    };

    match quota_store::update_quota(pool, tenant_id, &update).await {
        Ok(row) => {
            tracing::info!(
                tenant_id = %id_str,
                "tenant quota updated"
            );
            (StatusCode::OK, Json(QuotaResponse::from(&row))).into_response()
        }
        Err(quota_store::QuotaStoreError::NotFound { .. }) => (
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({
                "code": "not_found",
                "message": format!("quota not found for tenant '{id_str}'"),
            })),
        )
            .into_response(),
        Err(e) => {
            tracing::error!(error = %e, tenant_id = %id_str, "failed to update quota");
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({
                    "code": "update_failed",
                    "message": e.to_string(),
                })),
            )
                .into_response()
        }
    }
}

// ---------------------------------------------------------------------------
// Router
// ---------------------------------------------------------------------------

/// Builds an `axum::Router` with quota management routes.
pub fn router(state: QuotaState) -> Router {
    Router::new()
        .route("/v1/quotas", get(list_quotas))
        .route(
            "/v1/quotas/:id",
            get(get_quota).patch(update_quota),
        )
        .with_state(state)
}
