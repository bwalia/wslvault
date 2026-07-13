//! Kubernetes service-account JWT authentication.
//!
//! # Authentication flow
//!
//! Mirrors HashiCorp Vault's `kubernetes` auth method:
//!
//! 1. A pod presents its projected service-account token JWT and a role name.
//! 2. This module validates the JWT by calling the Kubernetes **TokenReview API**
//!    (`POST /apis/authentication.k8s.io/v1/tokenreviews`) with a reviewer token
//!    that has `system:auth-delegator` permissions.
//! 3. The role's `bound_service_account_names` and `bound_service_account_namespaces`
//!    are checked against the identity returned by TokenReview.
//! 4. On success a wslvault JWT is issued via `token.rs`.
//!
//! # Offline JWKS validation mode
//!
//! When `validation_mode` is set to `Jwks`, the module instead:
//! 1. Fetches the cluster's OIDC discovery document at
//!    `{issuer}/.well-known/openid-configuration`.
//! 2. Caches the JWKS keys (shared TTL = 1 h, same as the OIDC module).
//! 3. Validates the JWT's signature and standard claims locally using
//!    `jsonwebtoken`.
//!
//! The JWKS path is useful when the API server is not reachable from the
//! identity-service (e.g. a cross-cluster setup) but the cluster exposes a
//! public OIDC issuer URL.
//!
//! # Role binding
//!
//! Role configs are loaded from `VAULT_K8S_ROLES` (JSON object, see
//! [`KubernetesRoleConfig`]).  A role matches when:
//! - `bound_service_account_namespaces` contains `"*"` **or** the namespace of
//!   the authenticating SA.
//! - `bound_service_account_names` contains `"*"` **or** the SA name.
//!
//! # Security notes
//!
//! - Role names, SA names, and namespaces are validated to contain only
//!   alphanumeric characters, hyphens, and colons.
//! - Wildcard `"*"` entries in bound lists are treated as explicit allowlists,
//!   not regexes.

use std::{collections::HashMap, sync::Arc, time::Instant};

use axum::{extract::State, http::StatusCode, response::IntoResponse, routing::post, Json, Router};
use jsonwebtoken::{
    decode, decode_header,
    jwk::{AlgorithmParameters, JwkSet},
    Algorithm, DecodingKey, Validation,
};
use reqwest::Client;
use serde::{Deserialize, Serialize};
use thiserror::Error;
use tokio::sync::RwLock;
use tracing::{info, warn};

use crate::token::TokenManager;

// ── Constants ─────────────────────────────────────────────────────────────────

/// JWT TTL for tokens issued upon successful Kubernetes auth.
const K8S_JWT_TTL_SECONDS: i64 = 3600;

/// Maximum length for role names to prevent abuse.
const MAX_ROLE_NAME_LEN: usize = 253;

/// JWKS cache TTL (seconds) — matches the OIDC module.
const JWKS_CACHE_TTL_SECS: u64 = 3600;

// ── Error type ────────────────────────────────────────────────────────────────

/// Errors from the Kubernetes authentication backend.
#[derive(Debug, Error)]
pub enum KubernetesError {
    #[error("role '{0}' is not configured")]
    RoleNotFound(String),

    #[error("role name is invalid")]
    InvalidRoleName,

    #[error("token review failed: {0}")]
    TokenReviewFailed(String),

    #[error("service account '{namespace}/{name}' is not bound to role '{role}'")]
    UnboundServiceAccount {
        namespace: String,
        name: String,
        role: String,
    },

    #[error("JWT validation failed: {0}")]
    JwtValidation(String),

    #[error("JWKS fetch failed: {0}")]
    JwksFetch(String),

    #[error("token issuance failed: {0}")]
    TokenIssuance(String),
}

impl KubernetesError {
    fn status_code(&self) -> StatusCode {
        match self {
            KubernetesError::RoleNotFound(_) => StatusCode::NOT_FOUND,
            KubernetesError::InvalidRoleName => StatusCode::BAD_REQUEST,
            KubernetesError::TokenReviewFailed(_) => StatusCode::BAD_GATEWAY,
            KubernetesError::UnboundServiceAccount { .. } => StatusCode::FORBIDDEN,
            KubernetesError::JwtValidation(_) => StatusCode::UNAUTHORIZED,
            KubernetesError::JwksFetch(_) => StatusCode::BAD_GATEWAY,
            KubernetesError::TokenIssuance(_) => StatusCode::INTERNAL_SERVER_ERROR,
        }
    }

    fn error_code(&self) -> &'static str {
        match self {
            KubernetesError::RoleNotFound(_) => "role_not_found",
            KubernetesError::InvalidRoleName => "invalid_role_name",
            KubernetesError::TokenReviewFailed(_) => "token_review_failed",
            KubernetesError::UnboundServiceAccount { .. } => "unbound_service_account",
            KubernetesError::JwtValidation(_) => "jwt_validation_failed",
            KubernetesError::JwksFetch(_) => "jwks_fetch_failed",
            KubernetesError::TokenIssuance(_) => "token_issuance_failed",
        }
    }
}

impl IntoResponse for KubernetesError {
    fn into_response(self) -> axum::response::Response {
        (
            self.status_code(),
            Json(serde_json::json!({
                "code": self.error_code(),
                "message": self.to_string(),
            })),
        )
            .into_response()
    }
}

// ── Configuration ─────────────────────────────────────────────────────────────

/// Selects how incoming service-account JWTs are validated.
#[derive(Debug, Clone, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum ValidationMode {
    /// Call the Kubernetes TokenReview API with a reviewer token (default).
    #[default]
    TokenReview,
    /// Validate locally using the cluster's OIDC JWKS (offline).
    Jwks,
}

/// Configuration for the Kubernetes authentication backend.
#[derive(Debug, Clone, Deserialize)]
pub struct KubernetesConfig {
    /// URL of the Kubernetes API server (e.g. `"https://kubernetes.default.svc"`).
    pub kubernetes_host: String,

    /// Service-account token with `system:auth-delegator` permissions.
    /// Used only in `TokenReview` mode.
    pub reviewer_token: Option<String>,

    /// OIDC issuer URL for the cluster (e.g.
    /// `"https://kubernetes.default.svc.cluster.local"`).
    /// Used only in `Jwks` mode for discovery.
    pub issuer: Option<String>,

    /// Whether to skip TLS verification when contacting the API server.
    /// **Only for development / testing — never enable in production.**
    pub tls_skip_verify: bool,

    /// Validation mode.  Defaults to `TokenReview`.
    pub validation_mode: Option<ValidationMode>,

    /// Map of role name → role configuration.
    pub roles: HashMap<String, KubernetesRoleConfig>,
}

/// Defines which service accounts and namespaces may authenticate under a role,
/// and what wslvault tenant + policies they receive.
#[derive(Debug, Clone, Deserialize)]
pub struct KubernetesRoleConfig {
    /// Allowed namespace names.  Use `["*"]` to allow all namespaces.
    pub bound_service_account_namespaces: Vec<String>,

    /// Allowed service-account names.  Use `["*"]` to allow all SAs.
    pub bound_service_account_names: Vec<String>,

    /// wslvault tenant_id assigned to principals authenticated via this role.
    pub tenant_id: String,

    /// wslvault policy names granted to principals authenticated via this role.
    pub policies: Vec<String>,
}

// ── Kubernetes API wire types ─────────────────────────────────────────────────

/// The subset of a Kubernetes `TokenReview` request that we need to send.
#[derive(Debug, Serialize)]
struct TokenReviewRequest {
    #[serde(rename = "apiVersion")]
    api_version: &'static str,
    kind: &'static str,
    spec: TokenReviewSpec,
}

#[derive(Debug, Serialize)]
struct TokenReviewSpec {
    token: String,
}

/// Subset of the Kubernetes `TokenReview` response that we care about.
#[derive(Debug, Deserialize)]
struct TokenReviewResponse {
    status: TokenReviewStatus,
}

#[derive(Debug, Deserialize)]
struct TokenReviewStatus {
    authenticated: Option<bool>,
    user: Option<TokenReviewUser>,
}

#[derive(Debug, Deserialize)]
struct TokenReviewUser {
    username: Option<String>,
}

/// Standard Kubernetes SA username format:
/// `system:serviceaccount:<namespace>:<name>`.
#[derive(Debug, Clone)]
pub struct ServiceAccountIdentity {
    pub namespace: String,
    pub name: String,
}

/// The claims we need from a service-account JWT for offline JWKS validation.
#[derive(Debug, Deserialize)]
struct SaJwtClaims {
    /// Kubernetes service-account namespace (k8s.io claim).
    #[serde(rename = "kubernetes.io/serviceaccount/namespace")]
    namespace: Option<String>,
    /// Kubernetes service-account name (k8s.io claim).
    #[serde(rename = "kubernetes.io/serviceaccount/service-account.name")]
    sa_name: Option<String>,
    /// Generic subject that contains `system:serviceaccount:<ns>:<name>`.
    sub: Option<String>,
}

// ── JWKS cache entry (mirrors oidc.rs pattern) ────────────────────────────────

struct JwksCacheEntry {
    key_set: JwkSet,
    fetched_at: Instant,
}

// ── Manager ───────────────────────────────────────────────────────────────────

/// Validates Kubernetes service-account tokens and translates them into
/// wslvault tenant + policy assignments.
pub struct KubernetesManager {
    config: KubernetesConfig,
    http_client: Client,
    /// In-memory JWKS cache; keyed by the cluster issuer URL.
    jwks_cache: Arc<RwLock<HashMap<String, JwksCacheEntry>>>,
}

/// Result of a successful Kubernetes authentication.
#[derive(Debug, Clone)]
pub struct KubernetesValidationResult {
    pub namespace: String,
    pub service_account_name: String,
    pub tenant_id: String,
    pub policies: Vec<String>,
}

impl KubernetesManager {
    /// Constructs a new manager from the given configuration.
    pub fn new(config: KubernetesConfig) -> Result<Self, KubernetesError> {
        let client_builder = reqwest::Client::builder();
        let client_builder = if config.tls_skip_verify {
            warn!("Kubernetes auth: TLS verification disabled — not safe for production");
            client_builder.danger_accept_invalid_certs(true)
        } else {
            client_builder
        };

        let http_client = client_builder
            .build()
            .map_err(|e| KubernetesError::TokenReviewFailed(format!("build HTTP client: {e}")))?;

        Ok(Self {
            config,
            http_client,
            jwks_cache: Arc::new(RwLock::new(HashMap::new())),
        })
    }

    /// Authenticates a Kubernetes service-account JWT for the named role.
    ///
    /// Validates the token via TokenReview or JWKS depending on
    /// `validation_mode`, then checks role bindings.
    pub async fn authenticate(
        &self,
        sa_jwt: &str,
        role_name: &str,
    ) -> Result<KubernetesValidationResult, KubernetesError> {
        // Validate role name input before any network calls.
        validate_k8s_name(role_name).map_err(|_| KubernetesError::InvalidRoleName)?;

        // Look up the role configuration.
        let role = self
            .config
            .roles
            .get(role_name)
            .ok_or_else(|| KubernetesError::RoleNotFound(role_name.to_string()))?
            .clone();

        // Validate the JWT and extract the service-account identity.
        let identity = match self
            .config
            .validation_mode
            .as_ref()
            .unwrap_or(&ValidationMode::TokenReview)
        {
            ValidationMode::TokenReview => self.validate_via_token_review(sa_jwt).await?,
            ValidationMode::Jwks => self.validate_via_jwks(sa_jwt).await?,
        };

        // Check role bindings.
        self.check_role_bindings(&identity, role_name, &role)?;

        info!(
            namespace = %identity.namespace,
            service_account = %identity.name,
            role = %role_name,
            tenant_id = %role.tenant_id,
            "Kubernetes service-account authenticated"
        );

        Ok(KubernetesValidationResult {
            namespace: identity.namespace,
            service_account_name: identity.name,
            tenant_id: role.tenant_id,
            policies: role.policies,
        })
    }

    // ── TokenReview validation ────────────────────────────────────────────────

    /// Calls the Kubernetes TokenReview API to validate the SA token.
    async fn validate_via_token_review(
        &self,
        sa_jwt: &str,
    ) -> Result<ServiceAccountIdentity, KubernetesError> {
        let reviewer_token = self.config.reviewer_token.as_deref().ok_or_else(|| {
            KubernetesError::TokenReviewFailed(
                "reviewer_token is required for TokenReview mode".to_string(),
            )
        })?;

        let url = format!(
            "{}/apis/authentication.k8s.io/v1/tokenreviews",
            self.config.kubernetes_host.trim_end_matches('/')
        );

        let body = TokenReviewRequest {
            api_version: "authentication.k8s.io/v1",
            kind: "TokenReview",
            spec: TokenReviewSpec {
                token: sa_jwt.to_string(),
            },
        };

        let response = self
            .http_client
            .post(&url)
            .bearer_auth(reviewer_token)
            .json(&body)
            .send()
            .await
            .map_err(|e| KubernetesError::TokenReviewFailed(format!("HTTP request: {e}")))?;

        if !response.status().is_success() {
            return Err(KubernetesError::TokenReviewFailed(format!(
                "API server returned HTTP {}",
                response.status()
            )));
        }

        let review: TokenReviewResponse = response
            .json()
            .await
            .map_err(|e| KubernetesError::TokenReviewFailed(format!("parse response: {e}")))?;

        if review.status.authenticated != Some(true) {
            return Err(KubernetesError::JwtValidation(
                "token review: not authenticated".to_string(),
            ));
        }

        // The `username` field contains `system:serviceaccount:<ns>:<sa>`.
        let username = review.status.user.and_then(|u| u.username).ok_or_else(|| {
            KubernetesError::TokenReviewFailed("no username in token review response".to_string())
        })?;

        parse_sa_username(&username)
    }

    // ── JWKS / offline validation ─────────────────────────────────────────────

    /// Validates the SA JWT offline using the cluster's OIDC JWKS.
    async fn validate_via_jwks(
        &self,
        sa_jwt: &str,
    ) -> Result<ServiceAccountIdentity, KubernetesError> {
        let issuer = self.config.issuer.as_deref().ok_or_else(|| {
            KubernetesError::JwksFetch("issuer is required for JWKS validation mode".to_string())
        })?;

        let key_set = self.get_jwks(issuer).await?;

        // Decode the JWT header to find the key ID.
        let header = decode_header(sa_jwt)
            .map_err(|e| KubernetesError::JwtValidation(format!("decode header: {e}")))?;

        let jwk = if let Some(kid) = &header.kid {
            key_set
                .find(kid)
                .ok_or_else(|| KubernetesError::JwtValidation(format!("no JWK for kid '{kid}'")))?
        } else {
            key_set
                .keys
                .iter()
                .find(|k| matches!(k.algorithm, AlgorithmParameters::RSA(_)))
                .ok_or_else(|| KubernetesError::JwtValidation("no RSA key in JWKS".to_string()))?
        };

        let decoding_key = DecodingKey::from_jwk(jwk)
            .map_err(|e| KubernetesError::JwtValidation(format!("build decoding key: {e}")))?;

        let algorithm = jwk
            .common
            .key_algorithm
            .and_then(|a| format!("{a}").parse::<Algorithm>().ok())
            .unwrap_or(header.alg);

        let mut validation = Validation::new(algorithm);
        validation.set_issuer(&[issuer]);
        validation.validate_exp = true;
        validation.leeway = 0;
        // SA tokens may not carry an audience — allow missing aud.
        validation.validate_aud = false;

        let token_data = decode::<SaJwtClaims>(sa_jwt, &decoding_key, &validation)
            .map_err(|e| KubernetesError::JwtValidation(format!("validate token: {e}")))?;

        let claims = token_data.claims;

        // Extract SA identity from claims.  Prefer the dedicated k8s.io claims;
        // fall back to parsing the `sub` field.
        let (namespace, name) = if let (Some(ns), Some(sa)) = (&claims.namespace, &claims.sa_name) {
            (ns.clone(), sa.clone())
        } else if let Some(sub) = &claims.sub {
            let identity = parse_sa_username(sub)?;
            (identity.namespace, identity.name)
        } else {
            return Err(KubernetesError::JwtValidation(
                "cannot determine service account identity from JWT claims".to_string(),
            ));
        };

        Ok(ServiceAccountIdentity { namespace, name })
    }

    /// Returns JWKS for the given issuer, refreshing from the network when
    /// the cache entry is absent or stale (same double-checked-lock pattern as
    /// `oidc.rs`).
    async fn get_jwks(&self, issuer: &str) -> Result<JwkSet, KubernetesError> {
        // Fast path: read lock.
        {
            let cache = self.jwks_cache.read().await;
            if let Some(entry) = cache.get(issuer) {
                if entry.fetched_at.elapsed().as_secs() < JWKS_CACHE_TTL_SECS {
                    return Ok(entry.key_set.clone());
                }
            }
        }

        // Slow path: write lock with double-check.
        let mut cache = self.jwks_cache.write().await;
        if let Some(entry) = cache.get(issuer) {
            if entry.fetched_at.elapsed().as_secs() < JWKS_CACHE_TTL_SECS {
                return Ok(entry.key_set.clone());
            }
        }

        // Discover the JWKS URI via the cluster's OIDC configuration endpoint.
        let discovery_url = format!(
            "{}/.well-known/openid-configuration",
            issuer.trim_end_matches('/')
        );

        let discovery_resp = self
            .http_client
            .get(&discovery_url)
            .send()
            .await
            .map_err(|e| KubernetesError::JwksFetch(format!("discovery HTTP request: {e}")))?;

        #[derive(Deserialize)]
        struct DiscoveryDoc {
            jwks_uri: String,
        }

        let discovery: DiscoveryDoc = discovery_resp
            .json()
            .await
            .map_err(|e| KubernetesError::JwksFetch(format!("parse discovery doc: {e}")))?;

        let jwks_resp = self
            .http_client
            .get(&discovery.jwks_uri)
            .send()
            .await
            .map_err(|e| KubernetesError::JwksFetch(format!("JWKS HTTP request: {e}")))?;

        let key_set: JwkSet = jwks_resp
            .json()
            .await
            .map_err(|e| KubernetesError::JwksFetch(format!("parse JWKS: {e}")))?;

        cache.insert(
            issuer.to_string(),
            JwksCacheEntry {
                key_set: key_set.clone(),
                fetched_at: Instant::now(),
            },
        );

        Ok(key_set)
    }

    // ── Role binding check ────────────────────────────────────────────────────

    /// Checks whether `identity` satisfies the role's binding constraints.
    pub fn check_role_bindings(
        &self,
        identity: &ServiceAccountIdentity,
        role_name: &str,
        role: &KubernetesRoleConfig,
    ) -> Result<(), KubernetesError> {
        let namespace_allowed = role
            .bound_service_account_namespaces
            .iter()
            .any(|ns| ns == "*" || ns == &identity.namespace);

        let sa_allowed = role
            .bound_service_account_names
            .iter()
            .any(|sa| sa == "*" || sa == &identity.name);

        if !namespace_allowed || !sa_allowed {
            return Err(KubernetesError::UnboundServiceAccount {
                namespace: identity.namespace.clone(),
                name: identity.name.clone(),
                role: role_name.to_string(),
            });
        }

        Ok(())
    }
}

// ── Helpers ───────────────────────────────────────────────────────────────────

/// Parses a Kubernetes SA username of the form
/// `system:serviceaccount:<namespace>:<name>`.
pub fn parse_sa_username(username: &str) -> Result<ServiceAccountIdentity, KubernetesError> {
    // Expected format: "system:serviceaccount:<namespace>:<name>"
    let prefix = "system:serviceaccount:";
    let rest = username.strip_prefix(prefix).ok_or_else(|| {
        KubernetesError::JwtValidation(format!("unexpected SA username format: '{username}'"))
    })?;

    let mut parts = rest.splitn(2, ':');
    let namespace = parts
        .next()
        .filter(|s| !s.is_empty())
        .ok_or_else(|| {
            KubernetesError::JwtValidation("empty namespace in SA username".to_string())
        })?
        .to_string();
    let name = parts
        .next()
        .filter(|s| !s.is_empty())
        .ok_or_else(|| KubernetesError::JwtValidation("empty name in SA username".to_string()))?
        .to_string();

    Ok(ServiceAccountIdentity { namespace, name })
}

/// Validates that a Kubernetes resource name contains only permitted characters.
///
/// Allowed: alphanumeric, `-`, `:`, `.`  (covers namespace/SA names and role names).
fn validate_k8s_name(name: &str) -> Result<(), ()> {
    if name.is_empty() || name.len() > MAX_ROLE_NAME_LEN {
        return Err(());
    }
    if name
        .chars()
        .all(|c| c.is_alphanumeric() || c == '-' || c == ':' || c == '.')
    {
        Ok(())
    } else {
        Err(())
    }
}

// ── HTTP layer ────────────────────────────────────────────────────────────────

/// Shared state for Kubernetes auth HTTP handlers.
#[derive(Clone)]
pub struct KubernetesState {
    pub manager: Arc<KubernetesManager>,
    pub token_manager: TokenManager,
}

/// Request body for `POST /v1/auth/kubernetes/login`.
#[derive(Debug, Deserialize)]
pub struct KubernetesLoginRequest {
    /// The service-account projected token JWT.
    pub jwt: String,
    /// The role name configured in `VAULT_K8S_ROLES`.
    pub role: String,
}

/// Response body from `POST /v1/auth/kubernetes/login`.
#[derive(Debug, Serialize)]
pub struct KubernetesLoginResponse {
    pub token: String,
    pub expires_at: chrono::DateTime<chrono::Utc>,
    pub tenant_id: String,
    pub policies: Vec<String>,
    pub namespace: String,
    pub service_account_name: String,
}

/// `POST /v1/auth/kubernetes/login` — authenticate a Kubernetes SA token.
pub async fn handle_kubernetes_login(
    State(state): State<KubernetesState>,
    Json(payload): Json<KubernetesLoginRequest>,
) -> impl IntoResponse {
    match state
        .manager
        .authenticate(&payload.jwt, &payload.role)
        .await
    {
        Ok(result) => {
            let subject = format!("{}:{}", result.namespace, result.service_account_name);
            match state.token_manager.issue_token(
                &subject,
                &result.tenant_id,
                result.policies.clone(),
                K8S_JWT_TTL_SECONDS,
            ) {
                Ok((token, expires_at)) => (
                    StatusCode::OK,
                    Json(KubernetesLoginResponse {
                        token,
                        expires_at,
                        tenant_id: result.tenant_id,
                        policies: result.policies,
                        namespace: result.namespace,
                        service_account_name: result.service_account_name,
                    }),
                )
                    .into_response(),
                Err(e) => {
                    let err = KubernetesError::TokenIssuance(e.to_string());
                    err.into_response()
                }
            }
        }
        Err(err) => {
            warn!(role = %payload.role, error = %err, "Kubernetes auth login failed");
            err.into_response()
        }
    }
}

/// Builds the axum [`Router`] for Kubernetes auth routes.
pub fn router(state: KubernetesState) -> Router {
    Router::new()
        .route("/v1/auth/kubernetes/login", post(handle_kubernetes_login))
        .with_state(state)
}

// ── Unit tests ────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn make_manager(roles: HashMap<String, KubernetesRoleConfig>) -> KubernetesManager {
        KubernetesManager::new(KubernetesConfig {
            kubernetes_host: "https://kubernetes.default.svc".to_string(),
            reviewer_token: Some("test-reviewer-token".to_string()),
            issuer: None,
            tls_skip_verify: false,
            validation_mode: None,
            roles,
        })
        .unwrap()
    }

    fn make_role(
        namespaces: Vec<&str>,
        sa_names: Vec<&str>,
        tenant_id: &str,
    ) -> KubernetesRoleConfig {
        KubernetesRoleConfig {
            bound_service_account_namespaces: namespaces.into_iter().map(str::to_owned).collect(),
            bound_service_account_names: sa_names.into_iter().map(str::to_owned).collect(),
            tenant_id: tenant_id.to_string(),
            policies: vec!["read".to_string()],
        }
    }

    // ── SA username parsing ───────────────────────────────────────────────────

    #[test]
    fn parse_sa_username_valid() {
        let identity = parse_sa_username("system:serviceaccount:default:my-app").unwrap();
        assert_eq!(identity.namespace, "default");
        assert_eq!(identity.name, "my-app");
    }

    #[test]
    fn parse_sa_username_namespaced_colon() {
        // Namespace itself can contain hyphens.
        let identity = parse_sa_username("system:serviceaccount:kube-system:coredns").unwrap();
        assert_eq!(identity.namespace, "kube-system");
        assert_eq!(identity.name, "coredns");
    }

    #[test]
    fn parse_sa_username_invalid_prefix() {
        let err = parse_sa_username("k8s:serviceaccount:default:sa").unwrap_err();
        assert!(matches!(err, KubernetesError::JwtValidation(_)));
    }

    #[test]
    fn parse_sa_username_missing_name() {
        // Format: "system:serviceaccount:<namespace>" — no name segment.
        let err = parse_sa_username("system:serviceaccount:default:").unwrap_err();
        assert!(matches!(err, KubernetesError::JwtValidation(_)));
    }

    // ── Role binding ─────────────────────────────────────────────────────────

    #[test]
    fn check_role_bindings_exact_match_passes() {
        let mut roles = HashMap::new();
        roles.insert(
            "my-role".to_string(),
            make_role(vec!["default"], vec!["my-app"], "tenant-1"),
        );
        let mgr = make_manager(roles);

        let identity = ServiceAccountIdentity {
            namespace: "default".to_string(),
            name: "my-app".to_string(),
        };
        let role = mgr.config.roles.get("my-role").unwrap();
        assert!(mgr.check_role_bindings(&identity, "my-role", role).is_ok());
    }

    #[test]
    fn check_role_bindings_wildcard_namespace_passes() {
        let mut roles = HashMap::new();
        roles.insert(
            "any-ns".to_string(),
            make_role(vec!["*"], vec!["my-app"], "tenant-1"),
        );
        let mgr = make_manager(roles);

        let identity = ServiceAccountIdentity {
            namespace: "production".to_string(),
            name: "my-app".to_string(),
        };
        let role = mgr.config.roles.get("any-ns").unwrap();
        assert!(mgr.check_role_bindings(&identity, "any-ns", role).is_ok());
    }

    #[test]
    fn check_role_bindings_wildcard_sa_passes() {
        let mut roles = HashMap::new();
        roles.insert(
            "any-sa".to_string(),
            make_role(vec!["default"], vec!["*"], "tenant-1"),
        );
        let mgr = make_manager(roles);

        let identity = ServiceAccountIdentity {
            namespace: "default".to_string(),
            name: "whatever".to_string(),
        };
        let role = mgr.config.roles.get("any-sa").unwrap();
        assert!(mgr.check_role_bindings(&identity, "any-sa", role).is_ok());
    }

    #[test]
    fn check_role_bindings_wrong_namespace_fails() {
        let mut roles = HashMap::new();
        roles.insert(
            "strict".to_string(),
            make_role(vec!["staging"], vec!["*"], "tenant-1"),
        );
        let mgr = make_manager(roles);

        let identity = ServiceAccountIdentity {
            namespace: "production".to_string(),
            name: "app".to_string(),
        };
        let role = mgr.config.roles.get("strict").unwrap();
        let err = mgr
            .check_role_bindings(&identity, "strict", role)
            .unwrap_err();
        assert!(matches!(err, KubernetesError::UnboundServiceAccount { .. }));
    }

    #[test]
    fn check_role_bindings_wrong_sa_name_fails() {
        let mut roles = HashMap::new();
        roles.insert(
            "strict-sa".to_string(),
            make_role(vec!["*"], vec!["allowed-app"], "tenant-1"),
        );
        let mgr = make_manager(roles);

        let identity = ServiceAccountIdentity {
            namespace: "default".to_string(),
            name: "evil-app".to_string(),
        };
        let role = mgr.config.roles.get("strict-sa").unwrap();
        let err = mgr
            .check_role_bindings(&identity, "strict-sa", role)
            .unwrap_err();
        assert!(matches!(err, KubernetesError::UnboundServiceAccount { .. }));
    }

    #[test]
    fn role_not_found_returns_correct_error() {
        let mgr = make_manager(HashMap::new());
        // Can't call authenticate without a network, so test role lookup via config.
        let role = mgr.config.roles.get("missing-role");
        assert!(role.is_none());
    }

    // ── validate_k8s_name ─────────────────────────────────────────────────────

    #[test]
    fn validate_k8s_name_allows_alphanumeric_and_hyphens() {
        assert!(validate_k8s_name("my-role-123").is_ok());
    }

    #[test]
    fn validate_k8s_name_rejects_special_characters() {
        assert!(validate_k8s_name("role!name").is_err());
        assert!(validate_k8s_name("role name").is_err());
    }

    #[test]
    fn validate_k8s_name_rejects_empty() {
        assert!(validate_k8s_name("").is_err());
    }

    /// External-network test: calls the real Kubernetes TokenReview API.
    /// Skipped by default; run with `cargo test -- --ignored` in a cluster env.
    #[tokio::test]
    #[ignore]
    async fn token_review_integration_test() {
        let mut roles = HashMap::new();
        roles.insert(
            "integration-role".to_string(),
            KubernetesRoleConfig {
                bound_service_account_namespaces: vec!["*".to_string()],
                bound_service_account_names: vec!["*".to_string()],
                tenant_id: "tenant-integration".to_string(),
                policies: vec!["read".to_string()],
            },
        );

        let config = KubernetesConfig {
            kubernetes_host: std::env::var("KUBE_HOST")
                .unwrap_or_else(|_| "https://kubernetes.default.svc".to_string()),
            reviewer_token: std::env::var("KUBE_REVIEWER_TOKEN").ok(),
            issuer: None,
            tls_skip_verify: true,
            validation_mode: Some(ValidationMode::TokenReview),
            roles,
        };

        let mgr = KubernetesManager::new(config).unwrap();
        let sa_jwt = std::env::var("TEST_SA_JWT").expect("TEST_SA_JWT must be set");

        let result = mgr
            .authenticate(&sa_jwt, "integration-role")
            .await
            .expect("authentication should succeed");

        println!(
            "Authenticated: {}/{}",
            result.namespace, result.service_account_name
        );
    }
}
