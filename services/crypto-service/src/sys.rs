//! The `sys/` seal API: initialize, unseal, seal, and report status.
//!
//! Mirrors the HashiCorp Vault endpoints operators already know, so existing
//! runbooks and muscle memory carry over:
//!
//! | Method | Path                    | Purpose                                  |
//! |--------|-------------------------|------------------------------------------|
//! | GET    | `/v1/sys/seal-status`   | Is it sealed, and how far along is unseal |
//! | POST   | `/v1/sys/init`          | Generate the root key and issue shares    |
//! | POST   | `/v1/sys/unseal`        | Submit one unseal share                   |
//! | POST   | `/v1/sys/seal`          | Drop the root key from memory             |
//!
//! # Why these are unauthenticated
//!
//! They have to be. A sealed vault cannot validate a token — token validation
//! needs key material, and key material is exactly what is locked away. Vault
//! has the same property.
//!
//! What protects them is that they are useless without the shares:
//!
//! * `unseal` needs a threshold of shares to do anything, and a share that does
//!   not belong to this vault is rejected outright.
//! * `init` refuses to run against an initialized vault, so it cannot be used
//!   to replace a live root key.
//! * `seal` is the exception — it needs no secret and is destructive to
//!   availability, so it requires `X-Vault-Token` matching the operator token
//!   when one is configured.
//!
//! These endpoints must not be exposed to the public internet. They belong
//! behind the same perimeter as any other operator surface.

use std::sync::Arc;

use axum::extract::State;
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use serde::{Deserialize, Serialize};
use subtle::ConstantTimeEq;
use tracing::{error, info, warn};

use wslvault_core::seal::Seal;
use wslvault_storage::pool::DbPool;

use crate::kek_store::KekStore;

/// Environment variable holding the token required to call `POST /v1/sys/seal`.
///
/// Unset means sealing is unauthenticated, which is logged at startup — an
/// operator should know if anyone who can reach the port can take the vault
/// offline.
const OPERATOR_TOKEN_ENV: &str = "VAULT_OPERATOR_TOKEN";

#[derive(Clone)]
pub struct SysState {
    pub seal: Seal,
    pub pool: Option<DbPool>,
    pub kek_store: KekStore,
}

#[derive(Debug, Deserialize)]
pub struct InitRequest {
    /// Total shares to issue. Defaults to Vault's 5.
    #[serde(default = "default_shares")]
    pub secret_shares: u8,
    /// Shares required to unseal. Defaults to Vault's 3.
    #[serde(default = "default_threshold")]
    pub secret_threshold: u8,
}

fn default_shares() -> u8 {
    5
}
fn default_threshold() -> u8 {
    3
}

#[derive(Debug, Serialize)]
pub struct InitResponse {
    /// The unseal shares, base64. Returned exactly once — the vault cannot
    /// reproduce them, which is what makes them worth protecting.
    pub keys_base64: Vec<String>,
    pub secret_threshold: u8,
    /// Deliberately prominent: an operator who does not act on this loses the
    /// vault the first time it restarts.
    pub warning: String,
}

#[derive(Debug, Deserialize)]
pub struct UnsealRequest {
    /// One share. Vault names this field `key`.
    pub key: String,
}

fn err(status: StatusCode, message: impl Into<String>) -> Response {
    (
        status,
        Json(serde_json::json!({ "errors": [message.into()] })),
    )
        .into_response()
}

/// `GET /v1/sys/seal-status`
async fn seal_status(State(state): State<Arc<SysState>>) -> Response {
    (StatusCode::OK, Json(state.seal.status().await)).into_response()
}

/// `POST /v1/sys/init`
async fn init(State(state): State<Arc<SysState>>, body: Option<Json<InitRequest>>) -> Response {
    let req = body.map(|Json(b)| b).unwrap_or(InitRequest {
        secret_shares: default_shares(),
        secret_threshold: default_threshold(),
    });

    // Without somewhere to persist the sealed root key, initialising would
    // produce shares that open nothing after a restart.
    let Some(pool) = state.pool.as_ref() else {
        return err(
            StatusCode::PRECONDITION_FAILED,
            "cannot initialize without DATABASE_URL: the sealed root key has nowhere to live",
        );
    };

    let (result, material) = match state
        .seal
        .init(req.secret_shares, req.secret_threshold)
        .await
    {
        Ok(v) => v,
        Err(e) => return err(StatusCode::BAD_REQUEST, e.to_string()),
    };

    // Persist before returning the shares. If this fails the operator must not
    // be handed shares for a root key that was never stored.
    if let Err(e) = wslvault_storage::seal_store::save_initial(pool, &material).await {
        error!(error = %e, "failed to persist seal configuration");
        state.seal.seal().await;
        return err(
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("seal configuration could not be stored, vault is NOT initialized: {e}"),
        );
    }

    info!(
        shares = req.secret_shares,
        threshold = req.secret_threshold,
        "vault initialized; unseal shares issued once and not recoverable"
    );

    (
        StatusCode::OK,
        Json(InitResponse {
            keys_base64: result.shares,
            secret_threshold: result.threshold,
            warning: "These shares are shown once and cannot be recovered. Distribute them to \
                      separate holders and store them apart from this vault and from each other. \
                      Losing more than (shares - threshold) of them makes every secret in this \
                      vault permanently unreadable."
                .to_string(),
        }),
    )
        .into_response()
}

/// `POST /v1/sys/unseal`
async fn unseal(State(state): State<Arc<SysState>>, Json(req): Json<UnsealRequest>) -> Response {
    let was_sealed = !state.seal.is_unsealed().await;

    let status = match state.seal.unseal(&req.key).await {
        Ok(s) => s,
        Err(e) => return err(StatusCode::BAD_REQUEST, e.to_string()),
    };

    // Crossing from sealed to unsealed is the moment the key caches can be
    // populated — before this there was nothing the service could decrypt.
    if was_sealed && !status.sealed {
        info!("vault unsealed; warm-loading keys");
        if let Err(e) = state.kek_store.load_from_db().await {
            error!(error = %e, "failed to warm-load keys after unseal");
            // Not fatal: lazy hydration fetches keys on demand. Say so rather
            // than reporting a clean unseal and degrading silently.
            return (
                StatusCode::OK,
                Json(serde_json::json!({
                    "sealed": status.sealed,
                    "initialized": status.initialized,
                    "threshold": status.threshold,
                    "shares": status.shares,
                    "progress": status.progress,
                    "warning": format!(
                        "unsealed, but key warm-load failed ({e}); keys will be loaded on demand"
                    ),
                })),
            )
                .into_response();
        }
    }

    (StatusCode::OK, Json(status)).into_response()
}

/// `POST /v1/sys/seal`
async fn seal(State(state): State<Arc<SysState>>, headers: HeaderMap) -> Response {
    if let Ok(expected) = std::env::var(OPERATOR_TOKEN_ENV) {
        if !expected.is_empty() {
            let presented = headers
                .get("x-vault-token")
                .and_then(|v| v.to_str().ok())
                .unwrap_or_default();
            let ok = presented.len() == expected.len()
                && bool::from(presented.as_bytes().ct_eq(expected.as_bytes()));
            if !ok {
                return err(StatusCode::FORBIDDEN, "operator token required to seal");
            }
        }
    }

    state.seal.seal().await;
    warn!("vault SEALED by operator request; crypto operations will fail until unsealed");
    (StatusCode::OK, Json(state.seal.status().await)).into_response()
}

pub fn router(state: Arc<SysState>) -> Router {
    if std::env::var(OPERATOR_TOKEN_ENV)
        .unwrap_or_default()
        .is_empty()
    {
        warn!(
            "{OPERATOR_TOKEN_ENV} is not set — anyone who can reach this port can seal the vault"
        );
    }

    Router::new()
        .route("/v1/sys/seal-status", get(seal_status))
        .route("/v1/sys/init", post(init))
        .route("/v1/sys/unseal", post(unseal))
        .route("/v1/sys/seal", post(seal))
        .with_state(state)
}
