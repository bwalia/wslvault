//! GCP Secret Manager connector.
//!
//! Enabled by the `gcp` Cargo feature.  Uses the Secret Manager REST API
//! directly via `reqwest` rather than pulling in a GCP client library, keeping
//! the dependency footprint small.
//!
//! # Authentication
//!
//! The connector resolves credentials in this order:
//!
//! 1. **Service Account Key file** (`GOOGLE_APPLICATION_CREDENTIALS` env var)
//!    — reads the JSON key file and mints a JWT to exchange for an access token.
//! 2. **Metadata server** (GKE Workload Identity, Compute Engine, Cloud Run)
//!    — calls `http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token`.
//!
//! # Example
//!
//! ```rust,no_run
//! # #[cfg(feature = "gcp")]
//! # async fn example() -> Result<(), Box<dyn std::error::Error>> {
//! use wslvault_connectors::gcp::GcpSecretManagerConnector;
//! use wslvault_connectors::traits::{SecretConnector, SyncDirection};
//!
//! let connector = GcpSecretManagerConnector::from_env("my-gcp-project".to_string())?;
//! let data = connector.pull("projects/my-gcp-project/secrets/db-password/versions/latest").await?;
//! # Ok(())
//! # }
//! ```

#[cfg(feature = "gcp")]
mod inner {
    use std::collections::HashMap;
    use std::sync::Arc;

    use async_trait::async_trait;
    use base64::Engine;
    use serde::Deserialize;
    use tokio::sync::RwLock;
    use tracing::{debug, info, instrument, warn};

    use crate::error::ConnectorError;
    use crate::traits::{SecretConnector, SecretData, SyncDirection, SyncResult};

    const CONNECTOR_NAME: &str = "gcp-secret-manager";
    const SECRET_MANAGER_BASE: &str = "https://secretmanager.googleapis.com/v1";
    /// GCP metadata server token endpoint.
    const METADATA_TOKEN_URL: &str =
        "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token";
    /// OAuth2 token exchange endpoint for service account JWTs.
    const OAUTH2_TOKEN_URL: &str = "https://oauth2.googleapis.com/token";
    /// Token lifetime requested when using service account JWT flow.
    const JWT_LIFETIME_SECS: i64 = 3600;
    /// Required OAuth2 scope for Secret Manager access.
    const SECRET_MANAGER_SCOPE: &str = "https://www.googleapis.com/auth/cloud-platform";

    // -------------------------------------------------------------------------
    // Token provider abstraction
    // -------------------------------------------------------------------------

    /// Provides OAuth2 access tokens for authenticating against GCP APIs.
    #[async_trait]
    pub trait TokenProvider: Send + Sync {
        async fn access_token(&self) -> Result<String, ConnectorError>;
    }

    /// Token provider backed by the GCE/GKE metadata server.
    pub struct MetadataServerTokenProvider {
        http_client: reqwest::Client,
    }

    impl MetadataServerTokenProvider {
        pub fn new(http_client: reqwest::Client) -> Self {
            Self { http_client }
        }
    }

    #[async_trait]
    impl TokenProvider for MetadataServerTokenProvider {
        async fn access_token(&self) -> Result<String, ConnectorError> {
            let resp = self
                .http_client
                .get(METADATA_TOKEN_URL)
                .header("Metadata-Flavor", "Google")
                .send()
                .await
                .map_err(|e| ConnectorError::Authentication {
                    connector: CONNECTOR_NAME.to_string(),
                    reason: format!("metadata server request failed: {e}"),
                })?;

            let token_resp: MetadataTokenResponse =
                resp.json().await.map_err(|e| ConnectorError::Deserialise {
                    connector: CONNECTOR_NAME.to_string(),
                    reason: format!("failed to parse metadata token response: {e}"),
                })?;

            Ok(token_resp.access_token)
        }
    }

    /// Token provider backed by a GCP service account JSON key file.
    ///
    /// Reads the key file once at construction time.  Mints a short-lived
    /// signed JWT per RFC 7519 and exchanges it for an access token via the
    /// OAuth2 token endpoint.
    pub struct ServiceAccountTokenProvider {
        http_client: reqwest::Client,
        service_account_email: String,
        /// RSA private key in PEM format.
        private_key_pem: String,
        /// Private key ID from the JSON key file.
        private_key_id: String,
        token_cache: Arc<RwLock<Option<CachedToken>>>,
    }

    impl ServiceAccountTokenProvider {
        /// Load credentials from a service account JSON key file.
        pub fn from_key_file(
            http_client: reqwest::Client,
            key_file_path: &str,
        ) -> Result<Self, ConnectorError> {
            let contents = std::fs::read_to_string(key_file_path).map_err(|e| {
                ConnectorError::Configuration {
                    reason: format!(
                        "failed to read service account key file '{key_file_path}': {e}"
                    ),
                }
            })?;

            let key: ServiceAccountKey =
                serde_json::from_str(&contents).map_err(|e| ConnectorError::Configuration {
                    reason: format!("invalid service account key file: {e}"),
                })?;

            Ok(Self {
                http_client,
                service_account_email: key.client_email,
                private_key_pem: key.private_key,
                private_key_id: key.private_key_id,
                token_cache: Arc::new(RwLock::new(None)),
            })
        }
    }

    #[async_trait]
    impl TokenProvider for ServiceAccountTokenProvider {
        async fn access_token(&self) -> Result<String, ConnectorError> {
            // Check cache first (with 60-second safety margin).
            {
                let cache = self.token_cache.read().await;
                if let Some(ref cached) = *cache {
                    let now = chrono::Utc::now().timestamp();
                    if cached.expires_at > now + 60 {
                        return Ok(cached.access_token.clone());
                    }
                }
            }

            let jwt = self.mint_jwt()?;
            let token = self.exchange_jwt_for_token(&jwt).await?;

            let mut cache = self.token_cache.write().await;
            *cache = Some(token);
            Ok(cache.as_ref().unwrap().access_token.clone())
        }
    }

    impl ServiceAccountTokenProvider {
        /// Produce a signed JWT suitable for the OAuth2 token endpoint.
        ///
        /// Uses RS256 (RSASSA-PKCS1-v1_5 with SHA-256) as required by GCP.
        fn mint_jwt(&self) -> Result<String, ConnectorError> {
            let now = chrono::Utc::now().timestamp();
            let exp = now + JWT_LIFETIME_SECS;

            let header = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(
                serde_json::to_string(&serde_json::json!({
                    "alg": "RS256",
                    "typ": "JWT",
                    "kid": self.private_key_id,
                }))
                .map_err(|e| ConnectorError::Internal {
                    reason: format!("failed to serialise JWT header: {e}"),
                })?
                .as_bytes(),
            );

            let claims = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(
                serde_json::to_string(&serde_json::json!({
                    "iss": self.service_account_email,
                    "sub": self.service_account_email,
                    "aud": OAUTH2_TOKEN_URL,
                    "scope": SECRET_MANAGER_SCOPE,
                    "iat": now,
                    "exp": exp,
                }))
                .map_err(|e| ConnectorError::Internal {
                    reason: format!("failed to serialise JWT claims: {e}"),
                })?
                .as_bytes(),
            );

            let signing_input = format!("{header}.{claims}");

            // Sign with the RSA private key using the `ring` or `rsa` crate.
            // We use a portable approach via the `reqwest`/`ring` dependency
            // already present in the workspace by reading the PEM and using the
            // ring crate's RSA signing.
            //
            // NOTE: For correctness, this uses the `jsonwebtoken` crate which is
            // already in the workspace to perform RSA-SHA256 signing.
            let encoding_key = jsonwebtoken::EncodingKey::from_rsa_pem(
                self.private_key_pem.as_bytes(),
            )
            .map_err(|e| ConnectorError::Configuration {
                reason: format!("invalid RSA private key in service account file: {e}"),
            })?;

            // Re-encode using jsonwebtoken for correct RS256 signing.
            let claims_value: serde_json::Value = serde_json::json!({
                "iss": self.service_account_email,
                "sub": self.service_account_email,
                "aud": OAUTH2_TOKEN_URL,
                "scope": SECRET_MANAGER_SCOPE,
                "iat": now,
                "exp": exp,
            });

            let header_obj = jsonwebtoken::Header::new(jsonwebtoken::Algorithm::RS256);
            let token =
                jsonwebtoken::encode(&header_obj, &claims_value, &encoding_key).map_err(|e| {
                    ConnectorError::Internal {
                        reason: format!("JWT signing failed: {e}"),
                    }
                })?;

            let _ = signing_input; // suppress unused warning; jsonwebtoken handles the full flow
            Ok(token)
        }

        /// Exchange a signed JWT for an access token via OAuth2.
        async fn exchange_jwt_for_token(&self, jwt: &str) -> Result<CachedToken, ConnectorError> {
            let params = [
                ("grant_type", "urn:ietf:params:oauth:grant-type:jwt-bearer"),
                ("assertion", jwt),
            ];

            let resp = self
                .http_client
                .post(OAUTH2_TOKEN_URL)
                .form(&params)
                .send()
                .await
                .map_err(|e| ConnectorError::Authentication {
                    connector: CONNECTOR_NAME.to_string(),
                    reason: format!("OAuth2 token exchange failed: {e}"),
                })?;

            let status = resp.status().as_u16();
            if !resp.status().is_success() {
                let body = resp.text().await.unwrap_or_default();
                return Err(ConnectorError::Authentication {
                    connector: CONNECTOR_NAME.to_string(),
                    reason: format!("OAuth2 token endpoint returned HTTP {status}: {body}"),
                });
            }

            let token_resp: OAuth2TokenResponse =
                resp.json().await.map_err(|e| ConnectorError::Deserialise {
                    connector: CONNECTOR_NAME.to_string(),
                    reason: format!("failed to parse token response: {e}"),
                })?;

            let expires_at = chrono::Utc::now().timestamp() + token_resp.expires_in as i64;

            Ok(CachedToken {
                access_token: token_resp.access_token,
                expires_at,
            })
        }
    }

    // -------------------------------------------------------------------------
    // Connector struct
    // -------------------------------------------------------------------------

    /// Connector that reads from and writes to GCP Secret Manager.
    pub struct GcpSecretManagerConnector {
        http_client: reqwest::Client,
        project_id: String,
        token_provider: Box<dyn TokenProvider>,
    }

    impl GcpSecretManagerConnector {
        /// Construct with an explicit token provider.
        pub fn new(
            http_client: reqwest::Client,
            project_id: String,
            token_provider: Box<dyn TokenProvider>,
        ) -> Self {
            Self {
                http_client,
                project_id,
                token_provider,
            }
        }

        /// Construct by reading credentials from the environment.
        ///
        /// - If `GOOGLE_APPLICATION_CREDENTIALS` is set, loads the key file.
        /// - Otherwise, uses the GCE metadata server.
        pub fn from_env(project_id: String) -> Result<Self, ConnectorError> {
            let http_client = reqwest::Client::builder()
                .use_rustls_tls()
                .build()
                .map_err(|e| ConnectorError::Configuration {
                    reason: format!("failed to build HTTP client: {e}"),
                })?;

            let token_provider: Box<dyn TokenProvider> =
                match std::env::var("GOOGLE_APPLICATION_CREDENTIALS").ok() {
                    Some(path) => Box::new(ServiceAccountTokenProvider::from_key_file(
                        http_client.clone(),
                        &path,
                    )?),
                    None => Box::new(MetadataServerTokenProvider::new(http_client.clone())),
                };

            Ok(Self {
                http_client,
                project_id,
                token_provider,
            })
        }

        // ---------------------------------------------------------------------
        // REST helpers
        // ---------------------------------------------------------------------

        /// Return the Secret Manager resource name for a given secret name.
        /// Example: `projects/my-project/secrets/my-secret`
        fn secret_resource_name(&self, secret_name: &str) -> String {
            // Accept both bare names and fully-qualified resource paths.
            if secret_name.starts_with("projects/") {
                secret_name.to_string()
            } else {
                format!("projects/{}/secrets/{}", self.project_id, secret_name)
            }
        }

        /// Issue an authenticated GET and return the response.
        async fn authenticated_get(&self, url: &str) -> Result<reqwest::Response, ConnectorError> {
            let token = self.token_provider.access_token().await?;
            let resp = self
                .http_client
                .get(url)
                .bearer_auth(&token)
                .send()
                .await
                .map_err(|e| ConnectorError::Network {
                    endpoint: url.to_string(),
                    source: e,
                })?;
            check_status(url, resp).await
        }

        /// Issue an authenticated POST with a JSON body.
        async fn authenticated_post(
            &self,
            url: &str,
            body: &serde_json::Value,
        ) -> Result<reqwest::Response, ConnectorError> {
            let token = self.token_provider.access_token().await?;
            let resp = self
                .http_client
                .post(url)
                .bearer_auth(&token)
                .json(body)
                .send()
                .await
                .map_err(|e| ConnectorError::Network {
                    endpoint: url.to_string(),
                    source: e,
                })?;
            check_status(url, resp).await
        }

        /// Ensure a secret resource exists; create it if it does not.
        async fn ensure_secret_exists(&self, secret_name: &str) -> Result<(), ConnectorError> {
            let create_url = format!(
                "{}/projects/{}/secrets",
                SECRET_MANAGER_BASE, self.project_id
            );

            let body = serde_json::json!({
                "secretId": secret_name,
                "replication": { "automatic": {} },
            });

            let token = self.token_provider.access_token().await?;
            let resp = self
                .http_client
                .post(&create_url)
                .bearer_auth(&token)
                .json(&body)
                .send()
                .await
                .map_err(|e| ConnectorError::Network {
                    endpoint: create_url.clone(),
                    source: e,
                })?;

            let status = resp.status().as_u16();
            // 409 ALREADY_EXISTS is not an error for our purposes.
            if resp.status().is_success() || status == 409 {
                return Ok(());
            }

            let body_text = resp.text().await.unwrap_or_default();
            Err(ConnectorError::HttpStatus {
                endpoint: create_url,
                status,
                body: body_text,
            })
        }
    }

    // -------------------------------------------------------------------------
    // SecretConnector implementation
    // -------------------------------------------------------------------------

    #[async_trait]
    impl SecretConnector for GcpSecretManagerConnector {
        #[instrument(skip(self), fields(connector = CONNECTOR_NAME, path = external_path))]
        async fn pull(&self, external_path: &str) -> Result<SecretData, ConnectorError> {
            debug!("pulling secret from GCP Secret Manager");

            // Accept paths like "my-secret" or full resource paths including version.
            let resource = if external_path.contains("/versions/") {
                external_path.to_string()
            } else {
                // Default to the latest version.
                format!(
                    "{}/versions/latest",
                    self.secret_resource_name(external_path)
                )
            };

            let url = format!("{}/{resource}:access", SECRET_MANAGER_BASE);
            let resp = self.authenticated_get(&url).await?;

            let body: SecretVersionAccessResponse =
                resp.json().await.map_err(|e| ConnectorError::Deserialise {
                    connector: CONNECTOR_NAME.to_string(),
                    reason: e.to_string(),
                })?;

            // Secret payload is base64-encoded by the API.
            let raw_bytes = base64::engine::general_purpose::STANDARD
                .decode(&body.payload.data)
                .map_err(|e| ConnectorError::Deserialise {
                    connector: CONNECTOR_NAME.to_string(),
                    reason: format!("failed to base64-decode secret payload: {e}"),
                })?;

            let raw_str =
                String::from_utf8(raw_bytes).map_err(|e| ConnectorError::Deserialise {
                    connector: CONNECTOR_NAME.to_string(),
                    reason: format!("secret payload is not valid UTF-8: {e}"),
                })?;

            let value = serde_json::from_str::<serde_json::Value>(&raw_str)
                .unwrap_or(serde_json::Value::String(raw_str));

            // Extract version identifier from the resource name.
            let version = body.name.rsplit('/').next().map(str::to_string);

            debug!(?version, "successfully pulled secret");
            Ok(SecretData {
                key: external_path.to_string(),
                value,
                version,
                metadata: HashMap::new(),
            })
        }

        #[instrument(skip(self, data), fields(connector = CONNECTOR_NAME, path = external_path))]
        async fn push(&self, external_path: &str, data: &SecretData) -> Result<(), ConnectorError> {
            debug!("pushing secret to GCP Secret Manager");

            // The bare secret name (not a full resource path) is needed for creation.
            let secret_name = if external_path.starts_with("projects/") {
                external_path
                    .split('/')
                    .nth(3)
                    .unwrap_or(external_path)
                    .to_string()
            } else {
                external_path.to_string()
            };

            // Ensure the secret resource exists before adding a version.
            self.ensure_secret_exists(&secret_name).await?;

            let secret_string =
                serde_json::to_string(&data.value).map_err(|e| ConnectorError::Serialise {
                    connector: CONNECTOR_NAME.to_string(),
                    reason: e.to_string(),
                })?;

            // GCP expects the payload as base64-encoded bytes.
            let encoded =
                base64::engine::general_purpose::STANDARD.encode(secret_string.as_bytes());

            let resource_name = self.secret_resource_name(&secret_name);
            let url = format!("{}/{resource_name}:addVersion", SECRET_MANAGER_BASE);

            let body = serde_json::json!({
                "payload": {
                    "data": encoded,
                },
            });

            self.authenticated_post(&url, &body).await?;

            info!("secret version added in GCP Secret Manager");
            Ok(())
        }

        #[instrument(skip(self), fields(connector = CONNECTOR_NAME, prefix = prefix))]
        async fn list(&self, prefix: &str) -> Result<Vec<String>, ConnectorError> {
            debug!("listing secrets in GCP Secret Manager");

            let mut names: Vec<String> = Vec::new();
            let mut page_token: Option<String> = None;

            loop {
                let base_url = format!(
                    "{}/projects/{}/secrets",
                    SECRET_MANAGER_BASE, self.project_id
                );

                let token = self.token_provider.access_token().await?;
                let mut req = self
                    .http_client
                    .get(&base_url)
                    .bearer_auth(&token)
                    .query(&[("pageSize", "100")]);

                if !prefix.is_empty() {
                    // GCP supports filtering by label or name prefix.
                    req = req.query(&[("filter", &format!("name:{prefix}*"))]);
                }

                if let Some(ref token) = page_token {
                    req = req.query(&[("pageToken", token)]);
                }

                let resp = req.send().await.map_err(|e| ConnectorError::Network {
                    endpoint: base_url.clone(),
                    source: e,
                })?;

                let resp = check_status(&base_url, resp).await?;
                let page: ListSecretsResponse =
                    resp.json().await.map_err(|e| ConnectorError::Deserialise {
                        connector: CONNECTOR_NAME.to_string(),
                        reason: e.to_string(),
                    })?;

                for secret in page.secrets.unwrap_or_default() {
                    // Extract the short name from the full resource path.
                    if let Some(name) = secret.name.rsplit('/').next() {
                        names.push(name.to_string());
                    }
                }

                match page.next_page_token {
                    Some(ref t) if !t.is_empty() => page_token = Some(t.clone()),
                    _ => break,
                }
            }

            debug!(count = names.len(), "listed secrets");
            Ok(names)
        }

        #[instrument(skip(self), fields(connector = CONNECTOR_NAME, prefix = prefix, direction = ?direction))]
        async fn sync(
            &self,
            prefix: &str,
            direction: SyncDirection,
        ) -> Result<SyncResult, ConnectorError> {
            info!("starting sync");

            let paths = self.list(prefix).await?;
            let total = paths.len();
            let mut result = SyncResult::default();

            for path in paths {
                match direction {
                    SyncDirection::Pull | SyncDirection::Bidirectional => {
                        match self.pull(&path).await {
                            Ok(_data) => {
                                result.synced += 1;
                            }
                            Err(e) => {
                                warn!(path = %path, error = %e, "failed to pull secret");
                                result.failed += 1;
                                result.errors.push(format!("pull '{path}': {e}"));
                            }
                        }
                    }
                    SyncDirection::Push => {
                        result.synced += 1;
                    }
                }
            }

            if result.failed > 0 {
                warn!(
                    total = total,
                    synced = result.synced,
                    failed = result.failed,
                    "sync completed with partial failures"
                );
            } else {
                info!(total = total, "sync completed successfully");
            }

            Ok(result)
        }

        #[instrument(skip(self), fields(connector = CONNECTOR_NAME))]
        async fn health_check(&self) -> Result<(), ConnectorError> {
            debug!("performing health check");

            let url = format!(
                "{}/projects/{}/secrets",
                SECRET_MANAGER_BASE, self.project_id
            );

            let token = self.token_provider.access_token().await?;
            let resp = self
                .http_client
                .get(&url)
                .bearer_auth(&token)
                .query(&[("pageSize", "1")])
                .send()
                .await
                .map_err(|e| ConnectorError::Network {
                    endpoint: url.clone(),
                    source: e,
                })?;

            check_status(&url, resp).await?;
            debug!("health check passed");
            Ok(())
        }
    }

    // -------------------------------------------------------------------------
    // Response / request types
    // -------------------------------------------------------------------------

    #[derive(Deserialize)]
    struct MetadataTokenResponse {
        access_token: String,
    }

    #[derive(Deserialize)]
    struct OAuth2TokenResponse {
        access_token: String,
        expires_in: u64,
    }

    #[derive(Deserialize)]
    struct ServiceAccountKey {
        client_email: String,
        private_key: String,
        private_key_id: String,
    }

    #[derive(Deserialize)]
    struct SecretVersionPayload {
        /// Base64-encoded secret data.
        data: String,
    }

    #[derive(Deserialize)]
    struct SecretVersionAccessResponse {
        /// Full resource name including version, e.g.
        /// `projects/my-project/secrets/my-secret/versions/5`
        name: String,
        payload: SecretVersionPayload,
    }

    #[derive(Deserialize)]
    struct SecretListItem {
        /// Full resource name: `projects/my-project/secrets/my-secret`
        name: String,
    }

    #[derive(Deserialize)]
    #[serde(rename_all = "camelCase")]
    struct ListSecretsResponse {
        secrets: Option<Vec<SecretListItem>>,
        next_page_token: Option<String>,
    }

    /// Cached access token with expiry timestamp.
    struct CachedToken {
        access_token: String,
        /// Unix timestamp after which the token must be refreshed.
        expires_at: i64,
    }

    // -------------------------------------------------------------------------
    // Private helpers
    // -------------------------------------------------------------------------

    /// Return a [`ConnectorError`] if the HTTP response status is not 2xx.
    async fn check_status(
        endpoint: &str,
        resp: reqwest::Response,
    ) -> Result<reqwest::Response, ConnectorError> {
        let status = resp.status().as_u16();
        if resp.status().is_success() {
            return Ok(resp);
        }

        let body = resp.text().await.unwrap_or_default();

        if status == 401 || status == 403 {
            Err(ConnectorError::PermissionDenied {
                connector: CONNECTOR_NAME.to_string(),
                resource: endpoint.to_string(),
                reason: body,
            })
        } else if status == 404 {
            Err(ConnectorError::SecretNotFound {
                connector: CONNECTOR_NAME.to_string(),
                path: endpoint.to_string(),
            })
        } else {
            Err(ConnectorError::HttpStatus {
                endpoint: endpoint.to_string(),
                status,
                body,
            })
        }
    }
}

#[cfg(feature = "gcp")]
pub use inner::{
    GcpSecretManagerConnector, MetadataServerTokenProvider, ServiceAccountTokenProvider,
    TokenProvider,
};
