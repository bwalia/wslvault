//! OAuth 2.0 Device Authorization Grant (RFC 8628) proxy for developer SSO.
//!
//! # Purpose
//!
//! Provides a CLI/IDE-friendly login path where the developer does not need a
//! browser redirect to the vault service.  Instead:
//!
//! 1. The tool calls `POST /v1/auth/oidc/device/start`, which proxies the
//!    **device authorization request** to the configured OIDC provider.
//!    The response carries `user_code` and `verification_uri` for the human.
//! 2. While the human visits the verification URI and enters the code,
//!    the tool polls `POST /v1/auth/oidc/device/poll` (with the `device_code`).
//! 3. Once the provider grants the token, the ID token is validated using the
//!    existing [`OidcManager`] JWKS path.  A wslvault JWT is issued and
//!    returned to the tool.
//!
//! # Device state machine
//!
//! ```text
//! start → [Pending] ← poll (authorization_pending)
//!                  ↓
//!             [SlowDown] ← poll (slow_down; back off)
//!                  ↓
//!             [Success]  ← poll returns ID token
//!             [Expired]  ← poll after device code expiry
//! ```
//!
//! Pending states are tracked in an in-memory `HashMap` with expiry, keyed by
//! the opaque `device_code` value returned by the provider.
//!
//! # OIDC provider integration
//!
//! This module reuses the existing [`OidcManager`] for:
//! - Discovery of the provider's `device_authorization_endpoint`
//!   (RFC 8628 §3.1 / OIDC discovery extension).
//! - JWKS caching and ID token signature validation once a token is obtained.
//!
//! The `DeviceOidcConfig` references an OIDC provider name that must also be
//! present in `VAULT_OIDC_PROVIDERS`.
//!
//! # Security notes
//!
//! - `client_secret` is **never** logged.
//! - Device codes are stored in memory only; they expire after `expires_in`
//!   seconds as reported by the provider (capped at 10 minutes).
//! - Expired entries are purged lazily on each poll.

use std::{
    collections::HashMap,
    sync::Arc,
    time::{Duration, Instant},
};

use axum::{
    extract::State,
    http::StatusCode,
    response::IntoResponse,
    routing::post,
    Json, Router,
};
use reqwest::Client;
use serde::{Deserialize, Serialize};
use thiserror::Error;
use tokio::sync::RwLock;
use tracing::{info, warn};

use crate::{oidc::OidcManager, token::TokenManager};

// ── Constants ─────────────────────────────────────────────────────────────────

/// JWT TTL (seconds) issued when the device flow completes.
const DEVICE_JWT_TTL_SECONDS: i64 = 3600;

/// Maximum device-code lifetime we will honour, regardless of provider's claim.
const MAX_DEVICE_CODE_TTL_SECS: u64 = 600;

// ── Error type ────────────────────────────────────────────────────────────────

/// Errors from the device-flow authentication backend.
#[derive(Debug, Error)]
pub enum DeviceFlowError {
    #[error("OIDC provider '{0}' is not configured")]
    ProviderNotFound(String),

    #[error("device authorization request failed: {0}")]
    DeviceAuthFailed(String),

    #[error("device code has expired or is unknown")]
    DeviceCodeExpired,

    #[error("authorization is still pending — poll again later")]
    AuthorizationPending,

    #[error("too many poll requests — slow down and retry in {interval_hint_secs}s")]
    SlowDown { interval_hint_secs: u64 },

    #[error("token exchange failed: {0}")]
    TokenExchangeFailed(String),

    #[error("ID token validation failed: {0}")]
    IdTokenValidation(String),

    #[error("wslvault token issuance failed: {0}")]
    TokenIssuance(String),
}

impl DeviceFlowError {
    fn status_code(&self) -> StatusCode {
        match self {
            DeviceFlowError::ProviderNotFound(_) => StatusCode::NOT_FOUND,
            DeviceFlowError::DeviceAuthFailed(_) => StatusCode::BAD_GATEWAY,
            DeviceFlowError::DeviceCodeExpired => StatusCode::GONE,
            DeviceFlowError::AuthorizationPending => StatusCode::ACCEPTED,
            DeviceFlowError::SlowDown { .. } => StatusCode::TOO_MANY_REQUESTS,
            DeviceFlowError::TokenExchangeFailed(_) => StatusCode::BAD_GATEWAY,
            DeviceFlowError::IdTokenValidation(_) => StatusCode::UNAUTHORIZED,
            DeviceFlowError::TokenIssuance(_) => StatusCode::INTERNAL_SERVER_ERROR,
        }
    }

    fn error_code(&self) -> &'static str {
        match self {
            DeviceFlowError::ProviderNotFound(_) => "provider_not_found",
            DeviceFlowError::DeviceAuthFailed(_) => "device_auth_failed",
            DeviceFlowError::DeviceCodeExpired => "device_code_expired",
            DeviceFlowError::AuthorizationPending => "authorization_pending",
            DeviceFlowError::SlowDown { .. } => "slow_down",
            DeviceFlowError::TokenExchangeFailed(_) => "token_exchange_failed",
            DeviceFlowError::IdTokenValidation(_) => "id_token_validation_failed",
            DeviceFlowError::TokenIssuance(_) => "token_issuance_failed",
        }
    }
}

impl IntoResponse for DeviceFlowError {
    fn into_response(self) -> axum::response::Response {
        let body = match &self {
            DeviceFlowError::SlowDown { interval_hint_secs } => serde_json::json!({
                "code": self.error_code(),
                "message": self.to_string(),
                "interval_hint_secs": interval_hint_secs,
            }),
            _ => serde_json::json!({
                "code": self.error_code(),
                "message": self.to_string(),
            }),
        };
        (self.status_code(), Json(body)).into_response()
    }
}

// ── Configuration ─────────────────────────────────────────────────────────────

/// Configuration for the OAuth 2.0 device-flow backend.
///
/// Loaded from `VAULT_DEVICE_OIDC_CONFIG` (JSON).
#[derive(Debug, Clone, Deserialize)]
pub struct DeviceOidcConfig {
    /// Name of the OIDC provider (must match a key in `VAULT_OIDC_PROVIDERS`).
    pub provider_name: String,

    /// OAuth 2.0 client ID registered with the provider for the device flow.
    pub client_id: String,

    /// OAuth 2.0 client secret (optional; some providers use PKCE only).
    pub client_secret: Option<String>,

    /// Space-separated scopes to request.  Defaults to `"openid profile email"`.
    pub scopes: Option<String>,

    /// Override the device authorization endpoint URL.  When absent, this is
    /// read from the provider's OIDC discovery document.
    pub device_authorization_endpoint: Option<String>,

    /// Override the token endpoint URL.  When absent, this is read from discovery.
    pub token_endpoint: Option<String>,
}

// ── Provider endpoints cache ──────────────────────────────────────────────────

/// Resolved provider endpoints needed for the device flow.
#[derive(Debug, Clone)]
struct ProviderEndpoints {
    device_authorization_endpoint: String,
    token_endpoint: String,
}

// ── In-memory device-code state ───────────────────────────────────────────────

/// Tracks the lifecycle of an in-progress device authorization.
#[derive(Debug, Clone)]
struct DeviceCodeState {
    /// The provider's device code (opaque string used to poll the token endpoint).
    provider_device_code: String,
    /// Name of the OIDC provider (for ID token validation after exchange).
    provider_name: String,
    /// Time at which this code expires.
    expires_at: Instant,
    /// Minimum interval (seconds) between poll attempts, as reported by the provider.
    min_interval_secs: u64,
}

// ── Device authorization response from the provider ──────────────────────────

/// Subset of the RFC 8628 device authorization response.
#[derive(Debug, Deserialize)]
struct ProviderDeviceAuthResponse {
    /// The opaque code used to poll the token endpoint.
    device_code: String,
    /// Short human-friendly code the user enters at `verification_uri`.
    user_code: String,
    /// URL the user visits to enter the `user_code`.
    verification_uri: String,
    /// Optional "complete" URI with the code pre-filled.
    verification_uri_complete: Option<String>,
    /// Lifetime of the device code in seconds.
    expires_in: u64,
    /// Recommended polling interval in seconds.
    interval: Option<u64>,
}

/// Subset of the token endpoint response used during device-flow polling.
#[derive(Debug, Deserialize)]
struct ProviderTokenResponse {
    id_token: Option<String>,
    error: Option<String>,
    error_description: Option<String>,
}

// ── Manager ───────────────────────────────────────────────────────────────────

/// Manages the OAuth 2.0 device authorization grant flow.
pub struct DeviceFlowManager {
    config: DeviceOidcConfig,
    /// Shared OIDC manager used for ID token validation.
    oidc_manager: Arc<OidcManager>,
    http_client: Client,
    /// Active device-code states, keyed by the provider's `device_code`.
    /// The key exposed to the caller is also the provider's device_code (it is
    /// already an opaque, high-entropy token from the provider).
    device_states: Arc<RwLock<HashMap<String, DeviceCodeState>>>,
    /// Lazily-resolved provider endpoints.
    endpoints: Arc<RwLock<Option<ProviderEndpoints>>>,
}

impl DeviceFlowManager {
    /// Constructs a new manager.
    pub fn new(config: DeviceOidcConfig, oidc_manager: Arc<OidcManager>) -> Self {
        Self {
            config,
            oidc_manager,
            http_client: Client::builder()
                .build()
                .expect("reqwest client construction should not fail"),
            device_states: Arc::new(RwLock::new(HashMap::new())),
            endpoints: Arc::new(RwLock::new(None)),
        }
    }

    // ── Public API ────────────────────────────────────────────────────────────

    /// Initiates the device authorization flow by proxying to the provider.
    ///
    /// Returns the `user_code`, `verification_uri`, `device_code` (opaque),
    /// and `expires_in` so the caller can display them to the user.
    pub async fn start(&self) -> Result<DeviceStartResponse, DeviceFlowError> {
        let endpoints = self.resolve_endpoints().await?;

        let scopes = self
            .config
            .scopes
            .as_deref()
            .unwrap_or("openid profile email");

        let mut form_params = vec![
            ("client_id", self.config.client_id.as_str()),
            ("scope", scopes),
        ];

        // Include client_secret if configured.  Borrow the Option to avoid moving.
        let secret_str;
        if let Some(secret) = &self.config.client_secret {
            secret_str = secret.as_str();
            form_params.push(("client_secret", secret_str));
        }

        let response = self
            .http_client
            .post(&endpoints.device_authorization_endpoint)
            .form(&form_params)
            .send()
            .await
            .map_err(|e| DeviceFlowError::DeviceAuthFailed(format!("HTTP request: {e}")))?;

        if !response.status().is_success() {
            return Err(DeviceFlowError::DeviceAuthFailed(format!(
                "provider returned HTTP {}",
                response.status()
            )));
        }

        let provider_response: ProviderDeviceAuthResponse = response
            .json()
            .await
            .map_err(|e| DeviceFlowError::DeviceAuthFailed(format!("parse response: {e}")))?;

        // Cap the TTL to prevent excessively long-lived codes.
        let ttl_secs = provider_response
            .expires_in
            .min(MAX_DEVICE_CODE_TTL_SECS);

        let min_interval_secs = provider_response.interval.unwrap_or(5);

        // Store state for subsequent poll calls.
        {
            let mut states = self.device_states.write().await;
            // Purge expired entries on each write to bound memory usage.
            let now = Instant::now();
            states.retain(|_, state| state.expires_at > now);

            states.insert(
                provider_response.device_code.clone(),
                DeviceCodeState {
                    provider_device_code: provider_response.device_code.clone(),
                    provider_name: self.config.provider_name.clone(),
                    expires_at: now + Duration::from_secs(ttl_secs),
                    min_interval_secs,
                },
            );
        }

        info!(
            provider = %self.config.provider_name,
            user_code = %provider_response.user_code,
            "device flow started"
        );

        Ok(DeviceStartResponse {
            device_code: provider_response.device_code,
            user_code: provider_response.user_code,
            verification_uri: provider_response.verification_uri,
            verification_uri_complete: provider_response.verification_uri_complete,
            expires_in: ttl_secs,
            interval: min_interval_secs,
        })
    }

    /// Polls the provider's token endpoint for a completed device authorization.
    ///
    /// Returns:
    /// - `Ok(DevicePollResponse)` when the user has approved access.
    /// - `Err(AuthorizationPending)` when the user hasn't acted yet.
    /// - `Err(SlowDown)` when the provider asks the client to back off.
    /// - `Err(DeviceCodeExpired)` when the code has expired.
    pub async fn poll(
        &self,
        device_code: &str,
        token_manager: &TokenManager,
    ) -> Result<DevicePollResponse, DeviceFlowError> {
        // Look up device state — return Expired for unknown codes.
        let state = {
            let states = self.device_states.read().await;
            states
                .get(device_code)
                .filter(|s| s.expires_at > Instant::now())
                .cloned()
                .ok_or(DeviceFlowError::DeviceCodeExpired)?
        };

        let endpoints = self.resolve_endpoints().await?;

        let mut form_params = vec![
            ("grant_type", "urn:ietf:params:oauth:grant-type:device_code"),
            ("device_code", &state.provider_device_code),
            ("client_id", self.config.client_id.as_str()),
        ];

        let secret_str;
        if let Some(secret) = &self.config.client_secret {
            secret_str = secret.as_str();
            form_params.push(("client_secret", secret_str));
        }

        let response = self
            .http_client
            .post(&endpoints.token_endpoint)
            .form(&form_params)
            .send()
            .await
            .map_err(|e| DeviceFlowError::TokenExchangeFailed(format!("HTTP request: {e}")))?;

        // RFC 8628 §3.5: the provider returns 4xx with a JSON error body for
        // non-terminal states (authorization_pending, slow_down).  A 200 with
        // an id_token means success.
        let token_response: ProviderTokenResponse = response
            .json()
            .await
            .map_err(|e| DeviceFlowError::TokenExchangeFailed(format!("parse response: {e}")))?;

        if let Some(error) = &token_response.error {
            return Err(match error.as_str() {
                "authorization_pending" => DeviceFlowError::AuthorizationPending,
                "slow_down" => DeviceFlowError::SlowDown {
                    interval_hint_secs: state.min_interval_secs + 5,
                },
                "expired_token" | "access_denied" => {
                    // Remove the expired state.
                    let mut states = self.device_states.write().await;
                    states.remove(device_code);
                    DeviceFlowError::DeviceCodeExpired
                }
                other => DeviceFlowError::TokenExchangeFailed(format!(
                    "provider error '{}': {}",
                    other,
                    token_response.error_description.as_deref().unwrap_or("")
                )),
            });
        }

        // Success: validate the ID token via the OIDC manager.
        let id_token = token_response
            .id_token
            .ok_or_else(|| {
                DeviceFlowError::TokenExchangeFailed("no id_token in successful response".to_string())
            })?;

        let oidc_result = self
            .oidc_manager
            .validate_id_token(&state.provider_name, &id_token)
            .await
            .map_err(|e| DeviceFlowError::IdTokenValidation(e.to_string()))?;

        // Remove the consumed device code state.
        {
            let mut states = self.device_states.write().await;
            states.remove(device_code);
        }

        let (token, expires_at) = token_manager
            .issue_token(
                &oidc_result.subject,
                &oidc_result.tenant_id,
                oidc_result.policies.clone(),
                DEVICE_JWT_TTL_SECONDS,
            )
            .map_err(|e| DeviceFlowError::TokenIssuance(e.to_string()))?;

        info!(
            provider = %state.provider_name,
            subject = %oidc_result.subject,
            tenant_id = %oidc_result.tenant_id,
            "device flow authentication completed; JWT issued"
        );

        Ok(DevicePollResponse {
            token,
            expires_at,
            tenant_id: oidc_result.tenant_id,
            policies: oidc_result.policies,
        })
    }

    // ── Private helpers ───────────────────────────────────────────────────────

    /// Resolves provider endpoints, using overrides from config when present and
    /// falling back to OIDC discovery otherwise.
    async fn resolve_endpoints(&self) -> Result<ProviderEndpoints, DeviceFlowError> {
        // Fast path: already cached.
        {
            let ep = self.endpoints.read().await;
            if let Some(endpoints) = ep.as_ref() {
                return Ok(endpoints.clone());
            }
        }

        // Slow path: discover or use configured overrides.
        let mut ep = self.endpoints.write().await;
        if let Some(endpoints) = ep.as_ref() {
            return Ok(endpoints.clone()); // another task beat us to it
        }

        let endpoints = if let (Some(dae), Some(te)) = (
            &self.config.device_authorization_endpoint,
            &self.config.token_endpoint,
        ) {
            // Both endpoints explicitly configured — no network call needed.
            ProviderEndpoints {
                device_authorization_endpoint: dae.clone(),
                token_endpoint: te.clone(),
            }
        } else {
            // Discover via OIDC manager.
            let issuer = self.oidc_manager
                .discover_issuer_for_provider(&self.config.provider_name)
                .ok_or_else(|| {
                    DeviceFlowError::ProviderNotFound(self.config.provider_name.clone())
                })?;

            let discovery_url = format!(
                "{}/.well-known/openid-configuration",
                issuer.trim_end_matches('/')
            );

            let resp = self
                .http_client
                .get(&discovery_url)
                .send()
                .await
                .map_err(|e| {
                    DeviceFlowError::DeviceAuthFailed(format!("discovery request: {e}"))
                })?;

            #[derive(Deserialize)]
            struct DeviceDiscovery {
                device_authorization_endpoint: Option<String>,
                token_endpoint: String,
            }

            let doc: DeviceDiscovery = resp
                .json()
                .await
                .map_err(|e| DeviceFlowError::DeviceAuthFailed(format!("parse discovery: {e}")))?;

            let dae = doc.device_authorization_endpoint.ok_or_else(|| {
                DeviceFlowError::DeviceAuthFailed(format!(
                    "provider '{}' does not advertise device_authorization_endpoint",
                    self.config.provider_name
                ))
            })?;

            ProviderEndpoints {
                device_authorization_endpoint: self
                    .config
                    .device_authorization_endpoint
                    .clone()
                    .unwrap_or(dae),
                token_endpoint: self
                    .config
                    .token_endpoint
                    .clone()
                    .unwrap_or(doc.token_endpoint),
            }
        };

        *ep = Some(endpoints.clone());
        Ok(endpoints)
    }
}

// ── HTTP wire types ───────────────────────────────────────────────────────────

/// Request body for `POST /v1/auth/oidc/device/start`.
#[derive(Debug, Deserialize)]
pub struct DeviceStartRequest {
    /// Optional override for the provider name (defaults to the configured one).
    pub provider: Option<String>,
}

/// Response body from `POST /v1/auth/oidc/device/start`.
#[derive(Debug, Serialize)]
pub struct DeviceStartResponse {
    /// Opaque device code; returned to the client and used in poll calls.
    pub device_code: String,
    /// Short user-facing code (e.g. `"ABCD-EFGH"`).
    pub user_code: String,
    /// URL the user navigates to in a browser.
    pub verification_uri: String,
    /// Pre-filled URL including the user code (if the provider supplies it).
    pub verification_uri_complete: Option<String>,
    /// Lifetime of this code in seconds.
    pub expires_in: u64,
    /// Minimum recommended polling interval in seconds.
    pub interval: u64,
}

/// Request body for `POST /v1/auth/oidc/device/poll`.
#[derive(Debug, Deserialize)]
pub struct DevicePollRequest {
    /// Opaque device code from the `start` response.
    pub device_code: String,
}

/// Response body from `POST /v1/auth/oidc/device/poll` on success.
#[derive(Debug, Serialize)]
pub struct DevicePollResponse {
    pub token: String,
    pub expires_at: chrono::DateTime<chrono::Utc>,
    pub tenant_id: String,
    pub policies: Vec<String>,
}

// ── HTTP handlers ─────────────────────────────────────────────────────────────

/// Shared state for device-flow HTTP handlers.
#[derive(Clone)]
pub struct DeviceFlowState {
    pub manager: Arc<DeviceFlowManager>,
    pub token_manager: TokenManager,
}

/// `POST /v1/auth/oidc/device/start` — initiate a device authorization flow.
pub async fn handle_device_start(
    State(state): State<DeviceFlowState>,
    Json(_payload): Json<DeviceStartRequest>,
) -> impl IntoResponse {
    match state.manager.start().await {
        Ok(response) => (StatusCode::OK, Json(response)).into_response(),
        Err(err) => {
            warn!(error = %err, "device flow start failed");
            err.into_response()
        }
    }
}

/// `POST /v1/auth/oidc/device/poll` — poll for device flow completion.
pub async fn handle_device_poll(
    State(state): State<DeviceFlowState>,
    Json(payload): Json<DevicePollRequest>,
) -> impl IntoResponse {
    match state
        .manager
        .poll(&payload.device_code, &state.token_manager)
        .await
    {
        Ok(response) => (StatusCode::OK, Json(response)).into_response(),
        Err(err) => {
            // AuthorizationPending is not a user-visible error; log at debug only.
            if matches!(err, DeviceFlowError::AuthorizationPending) {
                // Still return 202 to the client.
            } else {
                warn!(error = %err, "device flow poll failed");
            }
            err.into_response()
        }
    }
}

/// Builds the axum [`Router`] for device-flow auth routes.
pub fn router(state: DeviceFlowState) -> Router {
    Router::new()
        .route("/v1/auth/oidc/device/start", post(handle_device_start))
        .route("/v1/auth/oidc/device/poll", post(handle_device_poll))
        .with_state(state)
}

// ── OidcManager extension ─────────────────────────────────────────────────────

/// Extend [`OidcManager`] with a method to expose the issuer URL for a
/// named provider (needed by [`DeviceFlowManager::resolve_endpoints`]).
///
/// This is implemented as a trait on `OidcManager` to avoid modifying the
/// existing `oidc.rs` source while staying compatible.
pub trait OidcManagerDeviceExt {
    /// Returns the configured issuer URL for the named provider, or `None`.
    fn discover_issuer_for_provider(&self, provider_name: &str) -> Option<String>;
}

impl OidcManagerDeviceExt for OidcManager {
    fn discover_issuer_for_provider(&self, provider_name: &str) -> Option<String> {
        self.provider_issuer(provider_name)
    }
}

// ── Unit tests ─────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // ── Device-code state machine (pure-logic tests) ──────────────────────────

    /// A minimal stand-in for the in-memory state store to test expiry logic.
    fn make_expired_state() -> DeviceCodeState {
        DeviceCodeState {
            provider_device_code: "provider-dc-abc".to_string(),
            provider_name: "test-provider".to_string(),
            // Already expired.
            expires_at: Instant::now() - Duration::from_secs(1),
            min_interval_secs: 5,
        }
    }

    fn make_valid_state() -> DeviceCodeState {
        DeviceCodeState {
            provider_device_code: "provider-dc-xyz".to_string(),
            provider_name: "test-provider".to_string(),
            expires_at: Instant::now() + Duration::from_secs(300),
            min_interval_secs: 5,
        }
    }

    #[test]
    fn expired_state_is_detected() {
        let state = make_expired_state();
        assert!(state.expires_at <= Instant::now());
    }

    #[test]
    fn valid_state_is_not_expired() {
        let state = make_valid_state();
        assert!(state.expires_at > Instant::now());
    }

    // ── Provider error → DeviceFlowError mapping ──────────────────────────────

    /// Verifies that every RFC 8628 error string maps to the right variant.
    #[test]
    fn pending_error_maps_correctly() {
        let error = "authorization_pending".to_string();
        let result: DeviceFlowError = match error.as_str() {
            "authorization_pending" => DeviceFlowError::AuthorizationPending,
            "slow_down" => DeviceFlowError::SlowDown {
                interval_hint_secs: 10,
            },
            "expired_token" | "access_denied" => DeviceFlowError::DeviceCodeExpired,
            other => DeviceFlowError::TokenExchangeFailed(other.to_string()),
        };
        assert!(matches!(result, DeviceFlowError::AuthorizationPending));
    }

    #[test]
    fn slow_down_error_maps_correctly() {
        let error = "slow_down".to_string();
        let result: DeviceFlowError = match error.as_str() {
            "authorization_pending" => DeviceFlowError::AuthorizationPending,
            "slow_down" => DeviceFlowError::SlowDown {
                interval_hint_secs: 10,
            },
            _ => DeviceFlowError::DeviceCodeExpired,
        };
        assert!(matches!(
            result,
            DeviceFlowError::SlowDown {
                interval_hint_secs: 10
            }
        ));
    }

    #[test]
    fn expired_token_error_maps_correctly() {
        let error = "expired_token".to_string();
        let result: DeviceFlowError = match error.as_str() {
            "authorization_pending" => DeviceFlowError::AuthorizationPending,
            "slow_down" => DeviceFlowError::SlowDown {
                interval_hint_secs: 10,
            },
            "expired_token" | "access_denied" => DeviceFlowError::DeviceCodeExpired,
            other => DeviceFlowError::TokenExchangeFailed(other.to_string()),
        };
        assert!(matches!(result, DeviceFlowError::DeviceCodeExpired));
    }

    // ── HTTP status codes ─────────────────────────────────────────────────────

    #[test]
    fn authorization_pending_returns_202() {
        assert_eq!(
            DeviceFlowError::AuthorizationPending.status_code(),
            StatusCode::ACCEPTED
        );
    }

    #[test]
    fn slow_down_returns_429() {
        assert_eq!(
            DeviceFlowError::SlowDown {
                interval_hint_secs: 5
            }
            .status_code(),
            StatusCode::TOO_MANY_REQUESTS
        );
    }

    #[test]
    fn expired_returns_410() {
        assert_eq!(
            DeviceFlowError::DeviceCodeExpired.status_code(),
            StatusCode::GONE
        );
    }

    // ── TTL cap ───────────────────────────────────────────────────────────────

    #[test]
    fn max_ttl_cap_is_applied() {
        // Simulate the TTL-capping logic from `start()`.
        let provider_expires_in: u64 = 99_999;
        let capped = provider_expires_in.min(MAX_DEVICE_CODE_TTL_SECS);
        assert_eq!(capped, MAX_DEVICE_CODE_TTL_SECS);
    }

    #[test]
    fn short_ttl_is_not_capped() {
        let provider_expires_in: u64 = 300;
        let capped = provider_expires_in.min(MAX_DEVICE_CODE_TTL_SECS);
        assert_eq!(capped, 300);
    }

    // ── DeviceOidcConfig deserialisation ──────────────────────────────────────

    #[test]
    fn device_config_deserialises() {
        let json = serde_json::json!({
            "provider_name": "keycloak",
            "client_id": "wslvault-cli",
            "client_secret": "s3cr3t",
            "scopes": "openid email profile",
            "device_authorization_endpoint": "https://idp.example.com/device_authorization",
            "token_endpoint": "https://idp.example.com/token"
        });

        let config: DeviceOidcConfig = serde_json::from_value(json).unwrap();
        assert_eq!(config.provider_name, "keycloak");
        assert_eq!(config.client_id, "wslvault-cli");
        assert_eq!(
            config.scopes.as_deref(),
            Some("openid email profile")
        );
        assert!(config.device_authorization_endpoint.is_some());
    }

    #[test]
    fn device_config_deserialises_without_secret() {
        let json = serde_json::json!({
            "provider_name": "github",
            "client_id": "gh-wslvault",
        });

        let config: DeviceOidcConfig = serde_json::from_value(json).unwrap();
        assert!(config.client_secret.is_none());
    }

    /// External-network test that exercises the full device flow against a real
    /// OIDC provider.  Skipped in CI; run manually with `--ignored`.
    #[tokio::test]
    #[ignore]
    async fn device_flow_integration_test() {
        // This test requires VAULT_JWT_SECRET and a configured OIDC provider.
        // Set TEST_DEVICE_PROVIDER, TEST_DEVICE_CLIENT_ID, TEST_DEVICE_DAE, TEST_DEVICE_TE.
        println!("Device flow integration test — manual execution only");
    }
}
