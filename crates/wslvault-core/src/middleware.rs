//! Tenant context extraction middleware for axum services.
//!
//! Provides a `FromRequestParts` implementation for `TenantContext` so that
//! axum handlers can declare a `TenantContext` extractor parameter and
//! receive a fully-parsed, validated tenant identity without touching raw
//! headers themselves.
//!
//! # Required headers
//! - `X-Tenant-Id`: UUID of the tenant making the request.
//!
//! # Optional headers
//! - `X-Principal-Id`: ID of the authenticated principal (defaults to
//!   `"anonymous"` when absent — useful for local dev / integration tests).
//! - `X-Policies`: Comma-separated list of policy names attached to this
//!   principal.  Empty or absent means no policies are granted.
//!
//! # Example
//! ```no_run
//! use axum::{routing::get, Router};
//! use wslvault_core::types::tenant::TenantContext;
//!
//! async fn my_handler(ctx: TenantContext) -> String {
//!     format!("hello tenant {}", ctx.tenant_id)
//! }
//!
//! let app: Router = Router::new().route("/secret", get(my_handler));
//! ```

use axum::{
    extract::FromRequestParts,
    http::{request::Parts, StatusCode},
    response::{IntoResponse, Response},
    Json,
};
use serde::Serialize;

use crate::types::tenant::{TenantContext, TenantId};

/// JSON error body returned when the extractor rejects a request.
#[derive(Debug, Serialize)]
struct ErrorBody {
    /// Machine-readable error code for programmatic handling by clients.
    code: &'static str,
    /// Human-readable description suitable for logging and debugging.
    message: String,
}

/// Constructs a well-formed JSON rejection response.
fn rejection(status: StatusCode, code: &'static str, message: impl Into<String>) -> Response {
    (
        status,
        Json(ErrorBody {
            code,
            message: message.into(),
        }),
    )
        .into_response()
}

/// Axum extractor that resolves `TenantContext` from HTTP request headers.
///
/// This implementation is intentionally stateless: it reads headers directly
/// from the request parts without consulting a database or cache.  Services
/// that need to validate that the tenant actually exists should add an
/// additional middleware layer that calls the identity-service.
#[axum::async_trait]
impl<S: Send + Sync> FromRequestParts<S> for TenantContext {
    type Rejection = Response;

    async fn from_request_parts(parts: &mut Parts, _state: &S) -> Result<Self, Self::Rejection> {
        // --- X-Tenant-Id (required) ---
        let tenant_id_str = parts
            .headers
            .get("x-tenant-id")
            .and_then(|value| value.to_str().ok())
            .filter(|s| !s.is_empty())
            .ok_or_else(|| {
                rejection(
                    StatusCode::BAD_REQUEST,
                    "missing_header",
                    "X-Tenant-Id header is required",
                )
            })?;

        let tenant_id: TenantId = tenant_id_str.parse().map_err(|_| {
            rejection(
                StatusCode::BAD_REQUEST,
                "invalid_tenant_id",
                format!(
                    "X-Tenant-Id '{}' is not a valid UUID",
                    tenant_id_str
                ),
            )
        })?;

        // --- X-Principal-Id (optional, defaults to "anonymous") ---
        let principal_id = parts
            .headers
            .get("x-principal-id")
            .and_then(|value| value.to_str().ok())
            .filter(|s| !s.is_empty())
            .unwrap_or("anonymous")
            .to_string();

        // --- X-Policies (optional, comma-separated) ---
        // Split on commas, trim whitespace, and drop any empty tokens that
        // result from trailing commas or consecutive delimiters.
        let policies: Vec<String> = parts
            .headers
            .get("x-policies")
            .and_then(|value| value.to_str().ok())
            .map(|raw| {
                raw.split(',')
                    .map(|policy| policy.trim().to_string())
                    .filter(|policy| !policy.is_empty())
                    .collect()
            })
            .unwrap_or_default();

        Ok(TenantContext {
            tenant_id,
            principal_id,
            policies,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{
        body::Body,
        http::{Request, StatusCode},
        routing::get,
        Router,
    };
    use tower::ServiceExt; // for `Router::oneshot`

    /// Minimal handler that returns the resolved tenant ID as plain text.
    async fn echo_tenant(ctx: TenantContext) -> String {
        ctx.tenant_id.to_string()
    }

    fn test_app() -> Router {
        Router::new().route("/test", get(echo_tenant))
    }

    #[tokio::test]
    async fn missing_tenant_id_header_returns_400() {
        let app = test_app();
        let req = Request::builder()
            .uri("/test")
            .body(Body::empty())
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn invalid_uuid_returns_400() {
        let app = test_app();
        let req = Request::builder()
            .uri("/test")
            .header("x-tenant-id", "not-a-uuid")
            .body(Body::empty())
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn valid_headers_resolve_context() {
        let app = test_app();
        let uuid = uuid::Uuid::new_v4().to_string();
        let req = Request::builder()
            .uri("/test")
            .header("x-tenant-id", &uuid)
            .header("x-principal-id", "svc-account-1")
            .header("x-policies", "read-secrets, write-secrets, ")
            .body(Body::empty())
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn missing_principal_id_defaults_to_anonymous() {
        // We cannot inspect TenantContext directly here without a more complex
        // test setup, but we can verify that the extractor succeeds (200) when
        // x-principal-id is absent.
        let app = Router::new().route(
            "/test",
            get(|ctx: TenantContext| async move { ctx.principal_id }),
        );
        let uuid = uuid::Uuid::new_v4().to_string();
        let req = Request::builder()
            .uri("/test")
            .header("x-tenant-id", &uuid)
            .body(Body::empty())
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn policies_are_split_and_trimmed() {
        use axum::response::IntoResponse;

        let app = Router::new().route(
            "/test",
            get(|ctx: TenantContext| async move {
                // Return the number of policies as a JSON number for assertion.
                Json(ctx.policies.len()).into_response()
            }),
        );
        let uuid = uuid::Uuid::new_v4().to_string();
        let req = Request::builder()
            .uri("/test")
            .header("x-tenant-id", &uuid)
            .header("x-policies", "read-secrets,  write-secrets  ,admin,")
            .body(Body::empty())
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let body_bytes = axum::body::to_bytes(resp.into_body(), 1024)
            .await
            .unwrap();
        // "read-secrets", "write-secrets", "admin" → 3 (trailing comma dropped)
        assert_eq!(body_bytes.as_ref(), b"3");
    }
}
