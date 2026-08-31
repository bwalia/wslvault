//! High-level WSLVault client.
//!
//! Provides typed methods for every service API exposed by WSLVault:
//! secrets, transit encryption, policy management, audit queries, lease
//! lifecycle, tenant management, and API key management.
//!
//! ## Retry behaviour
//!
//! Every request is automatically retried on transient HTTP errors (408, 429,
//! 500, 502, 503, 504) using an exponential backoff strategy up to
//! `ClientConfig::max_retries` attempts.  The backoff starts at 100 ms and
//! doubles each attempt, capped at 10 s.

use std::collections::HashMap;
use std::time::Duration;

use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::config::ClientConfig;
use crate::error::VaultClientError;

// ---------------------------------------------------------------------------
// Re-exported domain response types
// ---------------------------------------------------------------------------

/// Response from a secret read operation.
#[derive(Debug, Deserialize)]
pub struct SecretData {
    pub data: HashMap<String, Value>,
    pub version: u32,
    pub created_at: Option<String>,
    pub metadata: Option<HashMap<String, String>>,
}

/// Response from a secret write operation.
#[derive(Debug, Deserialize)]
pub struct WriteResponse {
    pub secret_id: String,
    pub version: u32,
}

/// Response from a secret list operation.
#[derive(Debug, Deserialize)]
pub struct ListResponse {
    pub paths: Vec<String>,
}

// ---------------------------------------------------------------------------
// Policy types
// ---------------------------------------------------------------------------

/// A single rule within a policy document.
#[derive(Debug, Serialize, Deserialize)]
pub struct PolicyRule {
    /// Glob-style path patterns.
    pub paths: Vec<String>,
    /// Capabilities granted for matching paths (e.g. "read", "write").
    pub capabilities: Vec<String>,
}

/// Request body for creating or replacing a policy.
#[derive(Debug, Serialize)]
pub struct PolicyCreateRequest {
    pub name: String,
    pub rules: Vec<PolicyRule>,
}

/// Response body for a single policy.
#[derive(Debug, Deserialize)]
pub struct PolicyResponse {
    pub name: String,
    pub rules: Vec<PolicyRule>,
    pub created_at: Option<String>,
    pub updated_at: Option<String>,
}

/// Response body for listing policies.
#[derive(Debug, Deserialize)]
pub struct PolicyListResponse {
    pub policies: Vec<PolicyResponse>,
}

// ---------------------------------------------------------------------------
// Audit types
// ---------------------------------------------------------------------------

/// Filters for querying audit events.
#[derive(Debug, Default)]
pub struct AuditQueryFilters {
    pub start_time: Option<String>,
    pub end_time: Option<String>,
    pub action_filter: Option<String>,
    pub principal_filter: Option<String>,
    pub limit: Option<u32>,
    pub offset: Option<u32>,
}

/// A single audit event record.
#[derive(Debug, Deserialize)]
pub struct AuditEvent {
    pub id: String,
    pub tenant_id: String,
    pub principal_id: String,
    pub action: String,
    pub resource: String,
    pub outcome: String,
    pub outcome_detail: Option<String>,
    pub client_ip: Option<String>,
    pub timestamp: String,
}

/// Paginated response from an audit query.
#[derive(Debug, Deserialize)]
pub struct AuditQueryResponse {
    pub events: Vec<AuditEvent>,
    pub total: u64,
}

// ---------------------------------------------------------------------------
// Lease types
// ---------------------------------------------------------------------------

/// A lease record returned by the service.
#[derive(Debug, Deserialize)]
pub struct LeaseRecord {
    pub id: String,
    pub tenant_id: String,
    pub target_type: String,
    pub state: String,
    pub ttl_seconds: i64,
    pub max_ttl_seconds: i64,
    pub renewable: bool,
    pub issued_at: String,
    pub expires_at: String,
    pub revoked_at: Option<String>,
}

/// Response from a lease renewal operation.
#[derive(Debug, Deserialize)]
pub struct LeaseRenewResponse {
    pub id: String,
    pub expires_at: String,
    pub ttl_seconds: i64,
}

// ---------------------------------------------------------------------------
// Transit types
// ---------------------------------------------------------------------------

/// Response from a transit encrypt operation.
#[derive(Debug, Deserialize)]
pub struct TransitEncryptResponse {
    pub ciphertext: String,
}

/// Response from a transit decrypt operation.
#[derive(Debug, Deserialize)]
pub struct TransitDecryptResponse {
    /// Base64-encoded plaintext.
    pub plaintext: String,
}

/// Response from a transit sign operation.
#[derive(Debug, Deserialize)]
pub struct TransitSignResponse {
    pub signature: String,
}

/// Response from a transit verify operation.
#[derive(Debug, Deserialize)]
pub struct TransitVerifyResponse {
    pub valid: bool,
}

/// Response from a transit hash operation.
#[derive(Debug, Deserialize)]
pub struct TransitHashResponse {
    pub hash: String,
}

/// Response from a transit HMAC operation.
#[derive(Debug, Deserialize)]
pub struct TransitHmacResponse {
    pub hmac: String,
}

/// Response from creating a transit key.
#[derive(Debug, Deserialize)]
pub struct TransitKeyResponse {
    pub key_name: String,
    pub algorithm: String,
}

/// Response from rotating a transit key.
#[derive(Debug, Deserialize)]
pub struct TransitKeyRotateResponse {
    pub key_name: String,
    pub new_version: u32,
}

// ---------------------------------------------------------------------------
// Tenant types
// ---------------------------------------------------------------------------

/// Request body for creating a new tenant.
#[derive(Debug, Serialize)]
pub struct TenantCreateRequest {
    pub slug: String,
    pub display_name: String,
    pub tier: Option<String>,
    pub root_key_id: String,
}

/// Response body for a single tenant.
#[derive(Debug, Deserialize)]
pub struct TenantResponse {
    pub id: String,
    pub slug: String,
    pub display_name: String,
    pub tier: String,
    pub root_key_id: String,
    pub created_at: String,
    pub updated_at: String,
    pub deleted_at: Option<String>,
}

// ---------------------------------------------------------------------------
// API key types
// ---------------------------------------------------------------------------

/// Request body for creating an API key.
#[derive(Debug, Serialize)]
pub struct ApiKeyCreateRequest {
    pub name: String,
    pub tenant_id: String,
    pub policies: Option<Vec<String>>,
    pub path_prefixes: Option<Vec<String>>,
    /// Seconds until the key expires; `None` means the key never expires.
    pub expires_in_seconds: Option<i64>,
    pub rate_limit_per_minute: Option<i32>,
}

/// Response from creating an API key.  The raw `key` is only present here;
/// it cannot be retrieved after this response.
#[derive(Debug, Deserialize)]
pub struct ApiKeyCreateResponse {
    pub id: String,
    /// The raw API key string.  Store securely — shown once and never again.
    pub key: String,
    pub key_prefix: String,
    pub name: String,
    pub tenant_id: String,
    pub policies: Vec<String>,
    pub path_prefixes: Vec<String>,
    pub expires_at: Option<String>,
    pub created_at: String,
}

/// API key metadata (no raw key or hash).
#[derive(Debug, Deserialize)]
pub struct ApiKeyMetadata {
    pub id: String,
    pub name: String,
    pub tenant_id: String,
    pub key_prefix: String,
    pub policies: Vec<String>,
    pub path_prefixes: Vec<String>,
    pub created_by: String,
    pub created_at: String,
    pub expires_at: Option<String>,
    pub last_used_at: Option<String>,
    pub rate_limit_per_minute: i32,
}

/// Response from authenticating an API key (JWT exchange).
#[derive(Debug, Deserialize)]
pub struct ApiKeyAuthResponse {
    pub token: String,
    pub expires_at: String,
    pub tenant_id: String,
    pub policies: Vec<String>,
}

// ---------------------------------------------------------------------------
// HTTP client helpers
// ---------------------------------------------------------------------------

/// Returns true when the HTTP status code represents a transient error that
/// should be retried with backoff.
/// Whether a transport-level failure is worth another attempt.
///
/// Only connect and timeout failures: those happen before the server has
/// necessarily acted. A failure mid-response could mean the request was
/// applied, and retrying it would duplicate the side effect.
fn is_retryable_transport(err: &VaultClientError) -> bool {
    match err {
        VaultClientError::Http(e) => e.is_connect() || e.is_timeout(),
        _ => false,
    }
}

fn is_retryable_status(status: u16) -> bool {
    matches!(status, 408 | 429 | 500 | 502 | 503 | 504)
}

// ---------------------------------------------------------------------------
// VaultClient
// ---------------------------------------------------------------------------

/// High-level async client for the WSLVault secrets platform.
#[derive(Clone)]
pub struct VaultClient {
    config: ClientConfig,
    http: reqwest::Client,
}

/// Builder for constructing a [`VaultClient`] with configuration.
pub struct VaultClientBuilder {
    config: ClientConfig,
}

impl VaultClient {
    /// Create a new builder for the client.
    pub fn builder() -> VaultClientBuilder {
        VaultClientBuilder {
            config: ClientConfig::default(),
        }
    }

    // -----------------------------------------------------------------------
    // Secrets API
    // -----------------------------------------------------------------------

    /// Read a secret at the given path.
    pub async fn read_secret(&self, path: &str) -> Result<SecretData, VaultClientError> {
        let url = format!("{}/v1/secret/data/{}", self.config.endpoint, path);
        self.get(&url).await
    }

    /// Write a secret at the given path.
    pub async fn write_secret(
        &self,
        path: &str,
        data: Value,
    ) -> Result<WriteResponse, VaultClientError> {
        let url = format!("{}/v1/secret/data/{}", self.config.endpoint, path);
        let body = serde_json::json!({ "data": data });
        self.post(&url, &body).await
    }

    /// List secret paths under the given prefix.
    pub async fn list_secrets(&self, prefix: &str) -> Result<ListResponse, VaultClientError> {
        let url = format!("{}/v1/secret/list?prefix={}", self.config.endpoint, prefix);
        self.get(&url).await
    }

    /// Delete a secret (soft delete of specific versions).
    pub async fn delete_secret(
        &self,
        path: &str,
        versions: &[u32],
    ) -> Result<(), VaultClientError> {
        let url = format!("{}/v1/secret/delete/{}", self.config.endpoint, path);
        let body = serde_json::json!({ "versions": versions });
        self.post_empty(&url, &body).await
    }

    // -----------------------------------------------------------------------
    // Policy API  (HTTP gateway exposes /v1/policies)
    // -----------------------------------------------------------------------

    /// Create or replace a policy for the configured tenant.
    pub async fn create_policy(
        &self,
        req: PolicyCreateRequest,
    ) -> Result<PolicyResponse, VaultClientError> {
        let url = format!("{}/v1/policies", self.config.endpoint);
        let body = serde_json::to_value(&req)
            .map_err(|e| VaultClientError::Serialization(e.to_string()))?;
        self.post(&url, &body).await
    }

    /// Get a policy by name.
    pub async fn get_policy(&self, name: &str) -> Result<PolicyResponse, VaultClientError> {
        let url = format!("{}/v1/policies/{}", self.config.endpoint, name);
        self.get(&url).await
    }

    /// Delete a policy by name.
    pub async fn delete_policy(&self, name: &str) -> Result<(), VaultClientError> {
        let url = format!("{}/v1/policies/{}", self.config.endpoint, name);
        self.delete_empty(&url).await
    }

    /// List all policies for the configured tenant.
    pub async fn list_policies(&self) -> Result<PolicyListResponse, VaultClientError> {
        let url = format!("{}/v1/policies", self.config.endpoint);
        self.get(&url).await
    }

    // -----------------------------------------------------------------------
    // Audit API  (HTTP gateway exposes /v1/audit/events)
    // -----------------------------------------------------------------------

    /// Query audit events with optional filters.
    pub async fn query_audit_events(
        &self,
        filters: AuditQueryFilters,
    ) -> Result<AuditQueryResponse, VaultClientError> {
        let mut params: Vec<(&str, String)> = Vec::new();
        if let Some(ref s) = filters.start_time {
            params.push(("start_time", s.clone()));
        }
        if let Some(ref e) = filters.end_time {
            params.push(("end_time", e.clone()));
        }
        if let Some(ref a) = filters.action_filter {
            params.push(("action", a.clone()));
        }
        if let Some(ref p) = filters.principal_filter {
            params.push(("principal", p.clone()));
        }
        if let Some(limit) = filters.limit {
            params.push(("limit", limit.to_string()));
        }
        if let Some(offset) = filters.offset {
            params.push(("offset", offset.to_string()));
        }

        let query_string = params
            .iter()
            .map(|(k, v)| format!("{}={}", k, v))
            .collect::<Vec<_>>()
            .join("&");

        let url = if query_string.is_empty() {
            format!("{}/v1/audit/events", self.config.endpoint)
        } else {
            format!("{}/v1/audit/events?{}", self.config.endpoint, query_string)
        };

        self.get(&url).await
    }

    // -----------------------------------------------------------------------
    // Lease API  (HTTP gateway exposes /v1/leases)
    // -----------------------------------------------------------------------

    /// Retrieve a lease by its UUID.
    pub async fn get_lease(&self, lease_id: &str) -> Result<LeaseRecord, VaultClientError> {
        let url = format!("{}/v1/leases/{}", self.config.endpoint, lease_id);
        self.get(&url).await
    }

    /// Revoke a lease immediately.
    pub async fn revoke_lease(&self, lease_id: &str) -> Result<(), VaultClientError> {
        let url = format!("{}/v1/leases/{}/revoke", self.config.endpoint, lease_id);
        self.post_empty(&url, &serde_json::json!({})).await
    }

    /// Renew a lease by extending its TTL by `increment_secs` seconds.
    pub async fn renew_lease(
        &self,
        lease_id: &str,
        increment_secs: i64,
    ) -> Result<LeaseRenewResponse, VaultClientError> {
        let url = format!("{}/v1/leases/{}/renew", self.config.endpoint, lease_id);
        let body = serde_json::json!({ "increment_seconds": increment_secs });
        self.post(&url, &body).await
    }

    // -----------------------------------------------------------------------
    // Transit API
    // -----------------------------------------------------------------------

    /// Encrypt plaintext (base64-encoded) using the named transit key.
    pub async fn transit_encrypt(
        &self,
        key_name: &str,
        plaintext: &str,
    ) -> Result<TransitEncryptResponse, VaultClientError> {
        let url = format!("{}/v1/transit/encrypt/{}", self.config.endpoint, key_name);
        let body = serde_json::json!({ "plaintext": plaintext });
        self.post(&url, &body).await
    }

    /// Decrypt a versioned ciphertext using the named transit key.
    pub async fn transit_decrypt(
        &self,
        key_name: &str,
        ciphertext: &str,
    ) -> Result<TransitDecryptResponse, VaultClientError> {
        let url = format!("{}/v1/transit/decrypt/{}", self.config.endpoint, key_name);
        let body = serde_json::json!({ "ciphertext": ciphertext });
        self.post(&url, &body).await
    }

    /// Sign data (base64-encoded) with the named transit key.
    pub async fn transit_sign(
        &self,
        key_name: &str,
        data: &str,
    ) -> Result<TransitSignResponse, VaultClientError> {
        let url = format!("{}/v1/transit/sign/{}", self.config.endpoint, key_name);
        let body = serde_json::json!({ "data": data });
        self.post(&url, &body).await
    }

    /// Verify a signature over data (both base64-encoded) using the named transit key.
    pub async fn transit_verify(
        &self,
        key_name: &str,
        data: &str,
        signature: &str,
    ) -> Result<TransitVerifyResponse, VaultClientError> {
        let url = format!("{}/v1/transit/verify/{}", self.config.endpoint, key_name);
        let body = serde_json::json!({ "data": data, "signature": signature });
        self.post(&url, &body).await
    }

    /// Compute a SHA-256 hash of input data (hex-encoded input).
    pub async fn transit_hash(
        &self,
        key_name: &str,
        input: &str,
    ) -> Result<TransitHashResponse, VaultClientError> {
        let url = format!("{}/v1/transit/hash/{}", self.config.endpoint, key_name);
        let body = serde_json::json!({ "input": input });
        self.post(&url, &body).await
    }

    /// Compute an HMAC over input data using the named transit key.
    pub async fn transit_hmac(
        &self,
        key_name: &str,
        input: &str,
    ) -> Result<TransitHmacResponse, VaultClientError> {
        let url = format!("{}/v1/transit/hmac/{}", self.config.endpoint, key_name);
        let body = serde_json::json!({ "input": input });
        self.post(&url, &body).await
    }

    /// Create a new named transit key.
    ///
    /// Sends `POST /v1/transit/keys/:key_name`.
    pub async fn transit_create_key(
        &self,
        key_name: &str,
    ) -> Result<TransitKeyResponse, VaultClientError> {
        let url = format!("{}/v1/transit/keys/{}", self.config.endpoint, key_name);
        // The service expects a POST with no body for key creation.
        self.post(&url, &serde_json::json!({})).await
    }

    /// Rotate a transit key, adding a new key version.
    ///
    /// Sends `POST /v1/transit/keys/:key_name/rotate`.
    pub async fn transit_rotate_key(
        &self,
        key_name: &str,
    ) -> Result<TransitKeyRotateResponse, VaultClientError> {
        let url = format!(
            "{}/v1/transit/keys/{}/rotate",
            self.config.endpoint, key_name
        );
        self.post(&url, &serde_json::json!({})).await
    }

    // -----------------------------------------------------------------------
    // Tenant management API  (/v1/tenants)
    // -----------------------------------------------------------------------

    /// Create a new tenant.
    pub async fn create_tenant(
        &self,
        req: TenantCreateRequest,
    ) -> Result<TenantResponse, VaultClientError> {
        let url = format!("{}/v1/tenants", self.config.endpoint);
        let body = serde_json::to_value(&req)
            .map_err(|e| VaultClientError::Serialization(e.to_string()))?;
        self.post(&url, &body).await
    }

    /// Get a tenant by its UUID.
    pub async fn get_tenant(&self, tenant_id: &str) -> Result<TenantResponse, VaultClientError> {
        let url = format!("{}/v1/tenants/{}", self.config.endpoint, tenant_id);
        self.get(&url).await
    }

    /// List all active tenants.
    pub async fn list_tenants(&self) -> Result<Vec<TenantResponse>, VaultClientError> {
        let url = format!("{}/v1/tenants", self.config.endpoint);
        self.get(&url).await
    }

    /// Soft-delete a tenant by its UUID.
    pub async fn delete_tenant(&self, tenant_id: &str) -> Result<(), VaultClientError> {
        let url = format!("{}/v1/tenants/{}", self.config.endpoint, tenant_id);
        self.delete_empty(&url).await
    }

    // -----------------------------------------------------------------------
    // API key management  (/v1/api-keys, /v1/auth/api-key)
    // -----------------------------------------------------------------------

    /// Create a new API key.  The returned `key` field is shown only once.
    pub async fn create_api_key(
        &self,
        req: ApiKeyCreateRequest,
    ) -> Result<ApiKeyCreateResponse, VaultClientError> {
        let url = format!("{}/v1/api-keys", self.config.endpoint);
        let body = serde_json::to_value(&req)
            .map_err(|e| VaultClientError::Serialization(e.to_string()))?;
        self.post(&url, &body).await
    }

    /// List active API keys for the configured tenant.
    pub async fn list_api_keys(&self) -> Result<Vec<ApiKeyMetadata>, VaultClientError> {
        let url = format!("{}/v1/api-keys", self.config.endpoint);
        self.get(&url).await
    }

    /// Revoke an API key by its UUID.
    pub async fn revoke_api_key(&self, key_id: &str) -> Result<(), VaultClientError> {
        let url = format!("{}/v1/api-keys/{}", self.config.endpoint, key_id);
        self.delete_empty(&url).await
    }

    /// Rotate an API key: revokes the existing key and returns a replacement
    /// with the same configuration.
    pub async fn rotate_api_key(
        &self,
        key_id: &str,
    ) -> Result<ApiKeyCreateResponse, VaultClientError> {
        let url = format!("{}/v1/api-keys/{}/rotate", self.config.endpoint, key_id);
        self.post(&url, &serde_json::json!({})).await
    }

    /// Exchange a raw API key (`wslv_...`) for a short-lived JWT.
    ///
    /// The returned `token` can be set as the client bearer token using
    /// `VaultClient::builder().token(...)`.
    pub async fn authenticate_api_key(
        &self,
        api_key: &str,
    ) -> Result<ApiKeyAuthResponse, VaultClientError> {
        let url = format!("{}/v1/auth/api-key", self.config.endpoint);
        let body = serde_json::json!({ "api_key": api_key });
        self.post(&url, &body).await
    }

    // -----------------------------------------------------------------------
    // Internal HTTP helpers with retry / backoff
    // -----------------------------------------------------------------------

    /// Build a request with standard auth + tenant headers.
    fn request(&self, method: reqwest::Method, url: &str) -> reqwest::RequestBuilder {
        let mut req = self.http.request(method, url);
        if let Some(ref token) = self.config.token {
            req = req.header("Authorization", format!("Bearer {}", token));
        }
        if let Some(ref tenant_id) = self.config.tenant_id {
            // The service accepts both header names; use the canonical one.
            req = req.header("X-Tenant-Id", tenant_id);
        }
        req
    }

    /// Perform a GET request with retry/backoff, deserialising the JSON body.
    async fn get<T: serde::de::DeserializeOwned>(&self, url: &str) -> Result<T, VaultClientError> {
        self.with_retry(|| async {
            let resp = self.request(reqwest::Method::GET, url).send().await?;
            self.handle_response(resp).await
        })
        .await
    }

    /// Perform a POST request with a JSON body, deserialising the response.
    async fn post<T: serde::de::DeserializeOwned>(
        &self,
        url: &str,
        body: &Value,
    ) -> Result<T, VaultClientError> {
        self.with_retry(|| async {
            let resp = self
                .request(reqwest::Method::POST, url)
                .json(body)
                .send()
                .await?;
            self.handle_response(resp).await
        })
        .await
    }

    /// Perform a POST request where a successful response has no body (e.g.
    /// revoke operations that return 204).
    async fn post_empty(&self, url: &str, body: &Value) -> Result<(), VaultClientError> {
        self.with_retry(|| async {
            let resp = self
                .request(reqwest::Method::POST, url)
                .json(body)
                .send()
                .await?;
            self.handle_empty_response(resp).await
        })
        .await
    }

    /// Perform a DELETE request where a successful response has no body (204).
    async fn delete_empty(&self, url: &str) -> Result<(), VaultClientError> {
        self.with_retry(|| async {
            let resp = self.request(reqwest::Method::DELETE, url).send().await?;
            self.handle_empty_response(resp).await
        })
        .await
    }

    /// Execute a fallible async closure, retrying on transient errors with
    /// exponential backoff.
    ///
    /// Attempts: `1 + config.max_retries`.
    /// Initial delay: 100 ms, doubled per attempt, capped at 10 s.
    async fn with_retry<F, Fut, T>(&self, mut f: F) -> Result<T, VaultClientError>
    where
        F: FnMut() -> Fut,
        Fut: std::future::Future<Output = Result<T, VaultClientError>>,
    {
        let max_attempts = 1 + self.config.max_retries;
        let mut delay_ms: u64 = 100;

        for attempt in 0..max_attempts {
            match f().await {
                Ok(value) => return Ok(value),
                Err(VaultClientError::Api { status, message }) if is_retryable_status(status) => {
                    if attempt + 1 < max_attempts {
                        // Wait before next attempt; ignore the error if the
                        // tokio sleep is interrupted (shouldn't happen in practice).
                        tokio::time::sleep(Duration::from_millis(delay_ms)).await;
                        // Double the delay up to 10 s.
                        delay_ms = (delay_ms * 2).min(10_000);
                        tracing::warn!(
                            attempt = attempt + 1,
                            max_attempts,
                            status,
                            "transient API error, retrying"
                        );
                    } else {
                        return Err(VaultClientError::Api { status, message });
                    }
                }
                // Network-level errors are also retryable.
                //
                // This arm used to open with `let err = f().await;` — a second,
                // immediate execution of the request — and then discard its
                // result with `let _ = err` before looping to run it a third
                // time. For a non-idempotent call that meant duplicate side
                // effects: a flapping connection could write a secret, revoke a
                // lease or issue a certificate up to five times against a
                // three-attempt budget, and a retry that actually SUCCEEDED had
                // its response thrown away.
                //
                // The error from the failed attempt is already in hand; there is
                // nothing to re-run to obtain it.
                Err(err @ VaultClientError::Http(_)) if is_retryable_transport(&err) => {
                    if attempt + 1 == max_attempts {
                        return Err(err);
                    }
                    tokio::time::sleep(Duration::from_millis(delay_ms)).await;
                    delay_ms = (delay_ms * 2).min(10_000);
                    tracing::warn!(
                        attempt = attempt + 1,
                        max_attempts,
                        error = %err,
                        "network error, retrying"
                    );
                }
                Err(other) => return Err(other),
            }
        }

        // Unreachable: loop always returns inside the body.
        unreachable!("retry loop exited without returning a result")
    }

    /// Parse a successful response body as JSON or map HTTP errors to typed errors.
    async fn handle_response<T: serde::de::DeserializeOwned>(
        &self,
        resp: reqwest::Response,
    ) -> Result<T, VaultClientError> {
        let status = resp.status();
        if status.is_success() {
            let body = resp
                .json::<T>()
                .await
                .map_err(|e| VaultClientError::Serialization(e.to_string()))?;
            return Ok(body);
        }

        let status_code = status.as_u16();
        let text = resp.text().await.unwrap_or_default();

        match status_code {
            401 => Err(VaultClientError::Unauthenticated),
            403 => Err(VaultClientError::PermissionDenied(text)),
            404 => Err(VaultClientError::NotFound(text)),
            _ => Err(VaultClientError::Api {
                status: status_code,
                message: text,
            }),
        }
    }

    /// Handle a response that carries no body on success (201 / 204 etc.).
    async fn handle_empty_response(&self, resp: reqwest::Response) -> Result<(), VaultClientError> {
        if resp.status().is_success() {
            return Ok(());
        }

        let status_code = resp.status().as_u16();
        let text = resp.text().await.unwrap_or_default();

        match status_code {
            401 => Err(VaultClientError::Unauthenticated),
            403 => Err(VaultClientError::PermissionDenied(text)),
            404 => Err(VaultClientError::NotFound(text)),
            _ => Err(VaultClientError::Api {
                status: status_code,
                message: text,
            }),
        }
    }
}

// ---------------------------------------------------------------------------
// VaultClientBuilder
// ---------------------------------------------------------------------------

impl VaultClientBuilder {
    /// Set the WSLVault endpoint URL.
    pub fn endpoint(mut self, endpoint: &str) -> Self {
        self.config.endpoint = endpoint.to_string();
        self
    }

    /// Set the authentication token (JWT or API key).
    pub fn token(mut self, token: &str) -> Self {
        self.config.token = Some(token.to_string());
        self
    }

    /// Set the tenant ID header (`X-Tenant-Id`) sent on every request.
    pub fn tenant_id(mut self, tenant_id: &str) -> Self {
        self.config.tenant_id = Some(tenant_id.to_string());
        self
    }

    /// Set the per-request timeout in seconds (default: 30).
    pub fn timeout_secs(mut self, secs: u64) -> Self {
        self.config.timeout_secs = secs;
        self
    }

    /// Set the maximum number of retries for transient HTTP errors (default: 3).
    pub fn max_retries(mut self, retries: u32) -> Self {
        self.config.max_retries = retries;
        self
    }

    /// Build the client.
    pub fn build(self) -> Result<VaultClient, VaultClientError> {
        self.config.validate()?;

        let http = reqwest::Client::builder()
            .timeout(Duration::from_secs(self.config.timeout_secs))
            .build()
            .map_err(|e| VaultClientError::Connection(e.to_string()))?;

        Ok(VaultClient {
            config: self.config,
            http,
        })
    }
}
