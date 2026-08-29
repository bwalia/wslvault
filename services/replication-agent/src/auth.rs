//! Shared-secret authentication for the peer-facing replication API.
//!
//! `/v1/replication/events` serves the raw outbox stream to whoever asks. That
//! stream is not innocuous: `secret_upsert` payloads carry ciphertext and DEK
//! identifiers, `policy_update` carries the full RBAC policy document in
//! cleartext, and `tenant_update` carries the tenant roster with its
//! `root_key_id`. Regions peer over the public internet — there is no
//! pod-network path between edge PoPs — so these routes are reachable from
//! anywhere the peer can reach, and they must not be open.
//!
//! Peers authenticate with a bearer token shared across the mesh (the same
//! material every region already has to hold in common). The comparison is
//! constant-time so a token cannot be recovered byte-by-byte through timing.
//!
//! Fail-closed: with no token configured the replication routes refuse every
//! request rather than serving the outbox unauthenticated.

use axum::extract::Request;
use axum::http::StatusCode;
use axum::middleware::Next;
use axum::response::Response;
use subtle::ConstantTimeEq;
use tracing::warn;

/// The token peers must present, or `None` when replication is unauthenticated
/// and therefore disabled.
#[derive(Clone)]
pub struct PeerToken(pub Option<String>);

/// Reject any request to the replication API that does not carry the shared
/// peer token as `Authorization: Bearer <token>`.
pub async fn require_peer_token(
    axum::extract::State(token): axum::extract::State<PeerToken>,
    request: Request,
    next: Next,
) -> Result<Response, StatusCode> {
    let Some(expected) = token.0.as_deref() else {
        warn!(
            "rejecting replication request: REPLICATION_PEER_TOKEN is not set, \
             so the peer API is disabled"
        );
        return Err(StatusCode::SERVICE_UNAVAILABLE);
    };

    let presented = request
        .headers()
        .get(axum::http::header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))
        .unwrap_or_default();

    // ct_eq is only constant-time across equal lengths; comparing the lengths
    // first leaks the token length, which is not sensitive, and avoids a
    // trivially non-constant-time slice comparison.
    let matches: bool =
        presented.len() == expected.len() && presented.as_bytes().ct_eq(expected.as_bytes()).into();

    if !matches {
        return Err(StatusCode::UNAUTHORIZED);
    }

    Ok(next.run(request).await)
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::Body;
    use axum::routing::get;
    use axum::Router;
    use tower::ServiceExt;

    fn app(token: Option<&str>) -> Router {
        let state = PeerToken(token.map(str::to_string));
        Router::new()
            .route("/v1/replication/events", get(|| async { "events" }))
            .layer(axum::middleware::from_fn_with_state(
                state.clone(),
                require_peer_token,
            ))
            .with_state(())
    }

    async fn call(app: Router, header: Option<&str>) -> StatusCode {
        let mut req = Request::builder().uri("/v1/replication/events");
        if let Some(h) = header {
            req = req.header(axum::http::header::AUTHORIZATION, h);
        }
        app.oneshot(req.body(Body::empty()).unwrap())
            .await
            .unwrap()
            .status()
    }

    #[tokio::test]
    async fn correct_token_is_accepted() {
        assert_eq!(
            call(app(Some("s3cret")), Some("Bearer s3cret")).await,
            StatusCode::OK
        );
    }

    #[tokio::test]
    async fn wrong_token_is_rejected() {
        assert_eq!(
            call(app(Some("s3cret")), Some("Bearer wrong")).await,
            StatusCode::UNAUTHORIZED
        );
    }

    #[tokio::test]
    async fn missing_header_is_rejected() {
        assert_eq!(
            call(app(Some("s3cret")), None).await,
            StatusCode::UNAUTHORIZED
        );
    }

    #[tokio::test]
    async fn same_length_wrong_token_is_rejected() {
        assert_eq!(
            call(app(Some("s3cret")), Some("Bearer s3creT")).await,
            StatusCode::UNAUTHORIZED
        );
    }

    #[tokio::test]
    async fn unconfigured_token_disables_the_api() {
        assert_eq!(
            call(app(None), Some("Bearer anything")).await,
            StatusCode::SERVICE_UNAVAILABLE
        );
    }
}
