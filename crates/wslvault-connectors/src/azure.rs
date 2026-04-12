//! Azure Key Vault connector.
//!
//! Enabled by the `azure` Cargo feature.  Uses the Azure Key Vault Secrets
//! REST API directly via `reqwest`, avoiding a hard dependency on the Azure
//! SDK crates (which bring in many transitive dependencies and have a rapid
//! release cadence that can cause version conflicts).
//!
//! # Authentication
//!
//! The connector supports two authentication paths:
//!
//! 1. **Managed Identity / Workload Identity** (recommended in Azure-hosted
//!    environments): set `AZURE_CLIENT_ID` and `AZURE_TENANT_ID`.  The
//!    connector calls the IMDS token endpoint automatically.
//!
//! 2. **Client Secret** (CI/CD, local development): set
//!    `AZURE_CLIENT_ID`, `AZURE_TENANT_ID`, and `AZURE_CLIENT_SECRET`.
//!
//! The connector picks the client-secret flow if `AZURE_CLIENT_SECRET` is
//! present; otherwise it falls back to managed identity.
//!
//! # Example
//!
//! ```rust,no_run
//! # #[cfg(feature = "azure")]
//! # async fn example() -> Result<(), Box<dyn std::error::Error>> {
//! use wslvault_connectors::azure::AzureKeyVaultConnector;
//! use wslvault_connectors::traits::SecretConnector;
//!
//! let connector = AzureKeyVaultConnector::from_env(
//!     "https://my-vault.vault.azure.net".to_string(),
//! )?;
//!
//! let secret = connector.pull("database-password").await?;
//! println!("version: {:?}", secret.version);
//! # Ok(())
//! # }
//! ```

#[cfg(feature = "azure")]
mod inner {
    use std::collections::HashMap;
    use std::sync::Arc;

    use async_trait::async_trait;
    use serde::Deserialize;
    use tokio::sync::RwLock;
    use tracing::{debug, info, instrument, warn};

    use crate::error::ConnectorError;
    use crate::traits::{SecretConnector, SecretData, SyncDirection, SyncResult};

    const CONNECTOR_NAME: &str = "azure-key-vault";
    /// Azure Key Vault Secrets API version used in every REST call.
    const API_VERSION: &str = "7.4";
    /// Azure AD OAuth2 token endpoint template.
    const TOKEN_URL_TEMPLATE: &str =
        "https://login.microsoftonline.com/{tenant_id}/oauth2/v2.0/token";
    /// Managed Identity token endpoint (Azure IMDS).
    const IMDS_TOKEN_URL: &str =
        "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://vault.azure.net";

    // -------------------------------------------------------------------------
    // Configuration / credential types
    // -------------------------------------------------------------------------

    /// Which authentication mechanism to use when obtaining an access token.
    #[derive(Clone)]
    enum CredentialSource {
        /// Use the Azure IMDS endpoint (managed identity or workload identity).
        ManagedIdentity { client_id: Option<String> },
        /// Use the client-credentials OAuth2 flow with an explicit secret.
        ClientSecret {
            tenant_id: String,
            client_id: String,
            client_secret: String,
        },
    }

    /// Cached access token with expiry timestamp.
    struct CachedToken {
        access_token: String,
        /// Unix timestamp after which this token must be refreshed.
        expires_at: i64,
    }

    // -------------------------------------------------------------------------
    // Connector struct
    // -------------------------------------------------------------------------

    /// Connector that reads from and writes to Azure Key Vault Secrets.
    pub struct AzureKeyVaultConnector {
        http_client: reqwest::Client,
        vault_url: String,
        credential: CredentialSource,
        /// Cached access token shared across async tasks via interior mutability.
        token_cache: Arc<RwLock<Option<CachedToken>>>,
    }

    impl AzureKeyVaultConnector {
        /// Construct from explicit parameters.
        ///
        /// This constructor is intentionally non-public because `CredentialSource`
        /// is a private type containing sensitive credential material.  External
        /// callers should use [`AzureKeyVaultConnector::from_env`] instead.
        fn new(
            vault_url: String,
            credential: CredentialSource,
        ) -> Result<Self, ConnectorError> {
            let vault_url = vault_url.trim_end_matches('/').to_string();
            let http_client = reqwest::Client::builder()
                .use_rustls_tls()
                .build()
                .map_err(|e| ConnectorError::Configuration {
                    reason: format!("failed to build HTTP client: {e}"),
                })?;

            Ok(Self {
                http_client,
                vault_url,
                credential,
                token_cache: Arc::new(RwLock::new(None)),
            })
        }

        /// Construct from environment variables (see module documentation).
        ///
        /// Required variables: `AZURE_CLIENT_ID`, `AZURE_TENANT_ID`.
        /// Optional: `AZURE_CLIENT_SECRET` — if absent, managed identity is used.
        pub fn from_env(vault_url: String) -> Result<Self, ConnectorError> {
            let client_id = std::env::var("AZURE_CLIENT_ID").ok();
            let tenant_id = std::env::var("AZURE_TENANT_ID").ok();
            let client_secret = std::env::var("AZURE_CLIENT_SECRET").ok();

            let credential = match (tenant_id, client_id.clone(), client_secret) {
                (Some(tenant_id), Some(client_id), Some(client_secret)) => {
                    // Full client-secret flow.
                    CredentialSource::ClientSecret {
                        tenant_id,
                        client_id,
                        client_secret,
                    }
                }
                _ => {
                    // Fall back to managed / workload identity; client_id is optional here.
                    CredentialSource::ManagedIdentity { client_id }
                }
            };

            Self::new(vault_url, credential)
        }

        // ---------------------------------------------------------------------
        // Token acquisition
        // ---------------------------------------------------------------------

        /// Return a valid access token, refreshing the cache if necessary.
        async fn access_token(&self) -> Result<String, ConnectorError> {
            // Fast path: check whether the cached token is still valid (with a
            // 60-second safety margin).
            {
                let cache = self.token_cache.read().await;
                if let Some(ref cached) = *cache {
                    let now = chrono::Utc::now().timestamp();
                    if cached.expires_at > now + 60 {
                        return Ok(cached.access_token.clone());
                    }
                }
            }

            // Slow path: acquire a new token and update the cache.
            let new_token = self.fetch_access_token().await?;

            let mut cache = self.token_cache.write().await;
            *cache = Some(new_token);
            Ok(cache.as_ref().unwrap().access_token.clone())
        }

        /// Fetch a fresh token from the appropriate endpoint.
        async fn fetch_access_token(&self) -> Result<CachedToken, ConnectorError> {
            match &self.credential {
                CredentialSource::ManagedIdentity { client_id } => {
                    self.fetch_managed_identity_token(client_id.as_deref()).await
                }
                CredentialSource::ClientSecret {
                    tenant_id,
                    client_id,
                    client_secret,
                } => {
                    self.fetch_client_secret_token(tenant_id, client_id, client_secret)
                        .await
                }
            }
        }

        /// Acquire a token via the Azure IMDS managed identity endpoint.
        async fn fetch_managed_identity_token(
            &self,
            client_id: Option<&str>,
        ) -> Result<CachedToken, ConnectorError> {
            let mut url = IMDS_TOKEN_URL.to_string();
            if let Some(id) = client_id {
                url.push_str(&format!("&client_id={id}"));
            }

            let resp = self
                .http_client
                .get(&url)
                .header("Metadata", "true")
                .send()
                .await
                .map_err(|e| ConnectorError::Authentication {
                    connector: CONNECTOR_NAME.to_string(),
                    reason: format!("IMDS request failed: {e}"),
                })?;

            parse_token_response(resp).await
        }

        /// Acquire a token via the client-credentials OAuth2 flow.
        async fn fetch_client_secret_token(
            &self,
            tenant_id: &str,
            client_id: &str,
            client_secret: &str,
        ) -> Result<CachedToken, ConnectorError> {
            let token_url = TOKEN_URL_TEMPLATE.replace("{tenant_id}", tenant_id);

            let params = [
                ("grant_type", "client_credentials"),
                ("client_id", client_id),
                ("client_secret", client_secret),
                ("scope", "https://vault.azure.net/.default"),
            ];

            let resp = self
                .http_client
                .post(&token_url)
                .form(&params)
                .send()
                .await
                .map_err(|e| ConnectorError::Authentication {
                    connector: CONNECTOR_NAME.to_string(),
                    reason: format!("token request failed: {e}"),
                })?;

            parse_token_response(resp).await
        }

        // ---------------------------------------------------------------------
        // REST helpers
        // ---------------------------------------------------------------------

        /// Return the base URL for a named secret.
        fn secret_url(&self, secret_name: &str) -> String {
            format!("{}/secrets/{}", self.vault_url, secret_name)
        }

        /// Issue an authenticated GET request and return the raw response body.
        async fn authenticated_get(&self, url: &str) -> Result<reqwest::Response, ConnectorError> {
            let token = self.access_token().await?;
            let resp = self
                .http_client
                .get(url)
                .bearer_auth(&token)
                .query(&[("api-version", API_VERSION)])
                .send()
                .await
                .map_err(|e| ConnectorError::Network {
                    endpoint: url.to_string(),
                    source: e,
                })?;
            check_status(url, resp).await
        }

        /// Issue an authenticated PUT request with a JSON body.
        async fn authenticated_put(
            &self,
            url: &str,
            body: &serde_json::Value,
        ) -> Result<reqwest::Response, ConnectorError> {
            let token = self.access_token().await?;
            let resp = self
                .http_client
                .put(url)
                .bearer_auth(&token)
                .query(&[("api-version", API_VERSION)])
                .json(body)
                .send()
                .await
                .map_err(|e| ConnectorError::Network {
                    endpoint: url.to_string(),
                    source: e,
                })?;
            check_status(url, resp).await
        }
    }

    // -------------------------------------------------------------------------
    // SecretConnector implementation
    // -------------------------------------------------------------------------

    #[async_trait]
    impl SecretConnector for AzureKeyVaultConnector {
        #[instrument(skip(self), fields(connector = CONNECTOR_NAME, path = external_path))]
        async fn pull(&self, external_path: &str) -> Result<SecretData, ConnectorError> {
            debug!("pulling secret from Azure Key Vault");

            let url = self.secret_url(external_path);
            let resp = self.authenticated_get(&url).await?;

            let body: KeyVaultSecretBundle =
                resp.json().await.map_err(|e| ConnectorError::Deserialise {
                    connector: CONNECTOR_NAME.to_string(),
                    reason: e.to_string(),
                })?;

            // Extract version from the secret `id` URI
            // Format: https://<vault>.vault.azure.net/secrets/<name>/<version>
            let version = body
                .id
                .as_deref()
                .and_then(|id| id.rsplit('/').next())
                .map(str::to_string);

            let value = serde_json::from_str::<serde_json::Value>(&body.value)
                .unwrap_or_else(|_| serde_json::Value::String(body.value));

            let metadata: HashMap<String, String> = body
                .tags
                .unwrap_or_default()
                .into_iter()
                .collect();

            debug!(?version, "successfully pulled secret");
            Ok(SecretData {
                key: external_path.to_string(),
                value,
                version,
                metadata,
            })
        }

        #[instrument(skip(self, data), fields(connector = CONNECTOR_NAME, path = external_path))]
        async fn push(
            &self,
            external_path: &str,
            data: &SecretData,
        ) -> Result<(), ConnectorError> {
            debug!("pushing secret to Azure Key Vault");

            let secret_value = serde_json::to_string(&data.value).map_err(|e| {
                ConnectorError::Serialise {
                    connector: CONNECTOR_NAME.to_string(),
                    reason: e.to_string(),
                }
            })?;

            // Azure Key Vault uses a PUT /secrets/<name> to upsert.
            let body = serde_json::json!({
                "value": secret_value,
                "tags": data.metadata,
            });

            let url = self.secret_url(external_path);
            self.authenticated_put(&url, &body).await?;

            info!("secret upserted in Azure Key Vault");
            Ok(())
        }

        #[instrument(skip(self), fields(connector = CONNECTOR_NAME, prefix = prefix))]
        async fn list(&self, prefix: &str) -> Result<Vec<String>, ConnectorError> {
            debug!("listing secrets in Azure Key Vault");

            let mut names: Vec<String> = Vec::new();
            let mut next_link: Option<String> = None;
            // Start with the base secrets list URL; Azure returns nextLink for pagination.
            let initial_url = format!("{}/secrets", self.vault_url);
            let mut current_url = initial_url;

            loop {
                if let Some(ref link) = next_link {
                    current_url = link.clone();
                }

                let token = self.access_token().await?;
                let mut req = self
                    .http_client
                    .get(&current_url)
                    .bearer_auth(&token);

                // Only append api-version if this is not a nextLink (which already contains it).
                if next_link.is_none() {
                    req = req.query(&[("api-version", API_VERSION), ("maxresults", "25")]);
                }

                let resp = req.send().await.map_err(|e| ConnectorError::Network {
                    endpoint: current_url.clone(),
                    source: e,
                })?;

                let resp = check_status(&current_url, resp).await?;
                let page: KeyVaultListResponse =
                    resp.json().await.map_err(|e| ConnectorError::Deserialise {
                        connector: CONNECTOR_NAME.to_string(),
                        reason: e.to_string(),
                    })?;

                for item in page.value {
                    // `id` is the full URI; extract the secret name from it.
                    if let Some(name) = item.id.rsplit('/').nth(1) {
                        if name.starts_with(prefix) {
                            names.push(name.to_string());
                        }
                    }
                }

                match page.next_link {
                    Some(link) => next_link = Some(link),
                    None => break,
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
                        // Push direction is driven externally; listing validates reachability.
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
            // List secrets with maxresults=1 to validate auth and reachability.
            let url = format!("{}/secrets", self.vault_url);
            let token = self.access_token().await?;
            let resp = self
                .http_client
                .get(&url)
                .bearer_auth(&token)
                .query(&[("api-version", API_VERSION), ("maxresults", "1")])
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
    // Response deserialisation types
    // -------------------------------------------------------------------------

    #[derive(Deserialize)]
    struct KeyVaultSecretBundle {
        /// The secret value (plaintext string).
        value: String,
        /// Full URI including version: https://<vault>/secrets/<name>/<version>
        id: Option<String>,
        /// User-defined tags stored as metadata.
        tags: Option<HashMap<String, String>>,
    }

    #[derive(Deserialize)]
    struct KeyVaultListItem {
        /// Full URI: https://<vault>/secrets/<name>/<version>
        id: String,
    }

    #[derive(Deserialize)]
    struct KeyVaultListResponse {
        value: Vec<KeyVaultListItem>,
        #[serde(rename = "nextLink")]
        next_link: Option<String>,
    }

    #[derive(Deserialize)]
    struct TokenResponse {
        access_token: String,
        /// Seconds until expiry, as a string in the IMDS response.
        expires_in: serde_json::Value,
    }

    // -------------------------------------------------------------------------
    // Private helpers
    // -------------------------------------------------------------------------

    /// Raise a [`ConnectorError::HttpStatus`] if the response status is not 2xx.
    async fn check_status(
        endpoint: &str,
        resp: reqwest::Response,
    ) -> Result<reqwest::Response, ConnectorError> {
        let status = resp.status().as_u16();
        if resp.status().is_success() {
            return Ok(resp);
        }

        let body = resp.text().await.unwrap_or_default();

        // Map common Azure status codes to semantic connector errors.
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

    /// Parse a JSON token response (shared between IMDS and client-secret flows).
    async fn parse_token_response(
        resp: reqwest::Response,
    ) -> Result<CachedToken, ConnectorError> {
        let status = resp.status().as_u16();
        if !resp.status().is_success() {
            let body = resp.text().await.unwrap_or_default();
            return Err(ConnectorError::Authentication {
                connector: CONNECTOR_NAME.to_string(),
                reason: format!("token endpoint returned HTTP {status}: {body}"),
            });
        }

        let token_resp: TokenResponse =
            resp.json().await.map_err(|e| ConnectorError::Deserialise {
                connector: CONNECTOR_NAME.to_string(),
                reason: format!("failed to parse token response: {e}"),
            })?;

        // `expires_in` may be a number or a string depending on the endpoint.
        let expires_in_secs: i64 = match &token_resp.expires_in {
            serde_json::Value::Number(n) => n.as_i64().unwrap_or(3600),
            serde_json::Value::String(s) => s.parse().unwrap_or(3600),
            _ => 3600,
        };

        let expires_at = chrono::Utc::now().timestamp() + expires_in_secs;

        Ok(CachedToken {
            access_token: token_resp.access_token,
            expires_at,
        })
    }
}

#[cfg(feature = "azure")]
pub use inner::AzureKeyVaultConnector;
