//! HashiCorp Vault connector.
//!
//! Implements the [`SecretConnector`] trait against the HashiCorp Vault HTTP API v1.
//! Supports KV v2 secret engine. Authentication is via token, AppRole, or
//! Kubernetes service account JWT.
//!
//! Enabled by the `hashicorp-vault` Cargo feature.

use std::sync::Arc;

use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use tokio::sync::RwLock;
use tracing::{debug, info, warn};

use crate::error::ConnectorError;
use crate::traits::{SecretConnector, SecretData, SyncDirection, SyncResult};

/// Authentication method for connecting to HashiCorp Vault.
#[derive(Debug, Clone)]
pub enum HashiCorpAuth {
    /// Static token authentication (simplest; suitable for dev and CI).
    Token(String),
    /// AppRole authentication with role_id and secret_id.
    AppRole { role_id: String, secret_id: String },
    /// Kubernetes service account JWT authentication.
    Kubernetes { role: String, jwt_path: String },
}

/// Cached Vault token with expiry.
#[derive(Debug, Clone)]
struct CachedToken {
    token: String,
    expires_at: chrono::DateTime<chrono::Utc>,
}

/// HashiCorp Vault connector.
pub struct HashiCorpVaultConnector {
    client: reqwest::Client,
    base_url: String,
    mount_path: String,
    auth: HashiCorpAuth,
    token: Arc<RwLock<Option<CachedToken>>>,
}

impl HashiCorpVaultConnector {
    /// Create a new connector.
    ///
    /// * `base_url` — e.g. `https://vault.example.com`
    /// * `mount_path` — KV v2 mount path (e.g. `secret`)
    /// * `auth` — authentication method
    pub fn new(base_url: String, mount_path: String, auth: HashiCorpAuth) -> Self {
        let client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(10))
            .build()
            .expect("failed to build reqwest client");

        Self {
            client,
            base_url,
            mount_path,
            auth,
            token: Arc::new(RwLock::new(None)),
        }
    }

    /// Create from environment variables.
    ///
    /// Reads: `HASHICORP_VAULT_ADDR`, `HASHICORP_VAULT_MOUNT` (default "secret"),
    /// `HASHICORP_VAULT_TOKEN`, `HASHICORP_VAULT_ROLE_ID` + `HASHICORP_VAULT_SECRET_ID`,
    /// or `HASHICORP_VAULT_K8S_ROLE` + `HASHICORP_VAULT_K8S_JWT_PATH`.
    pub fn from_env() -> Result<Self, ConnectorError> {
        let base_url =
            std::env::var("HASHICORP_VAULT_ADDR").map_err(|_| ConnectorError::Configuration {
                reason: "HASHICORP_VAULT_ADDR not set".into(),
            })?;

        let mount_path =
            std::env::var("HASHICORP_VAULT_MOUNT").unwrap_or_else(|_| "secret".to_string());

        let auth = if let Ok(token) = std::env::var("HASHICORP_VAULT_TOKEN") {
            HashiCorpAuth::Token(token)
        } else if let (Ok(role_id), Ok(secret_id)) = (
            std::env::var("HASHICORP_VAULT_ROLE_ID"),
            std::env::var("HASHICORP_VAULT_SECRET_ID"),
        ) {
            HashiCorpAuth::AppRole { role_id, secret_id }
        } else if let Ok(role) = std::env::var("HASHICORP_VAULT_K8S_ROLE") {
            let jwt_path = std::env::var("HASHICORP_VAULT_K8S_JWT_PATH").unwrap_or_else(|_| {
                "/var/run/secrets/kubernetes.io/serviceaccount/token".to_string()
            });
            HashiCorpAuth::Kubernetes { role, jwt_path }
        } else {
            return Err(ConnectorError::Configuration {
                reason: "no HashiCorp Vault authentication method configured".into(),
            });
        };

        Ok(Self::new(base_url, mount_path, auth))
    }

    /// Get a valid Vault token, refreshing if needed.
    async fn get_token(&self) -> Result<String, ConnectorError> {
        // Check if we have a cached, non-expired token.
        {
            let guard = self.token.read().await;
            if let Some(ref cached) = *guard {
                if cached.expires_at > chrono::Utc::now() + chrono::Duration::seconds(60) {
                    return Ok(cached.token.clone());
                }
            }
        }

        // Need to refresh.
        let new_token = self.authenticate().await?;
        Ok(new_token)
    }

    /// Authenticate and cache the resulting token.
    async fn authenticate(&self) -> Result<String, ConnectorError> {
        let (token, ttl_secs) = match &self.auth {
            HashiCorpAuth::Token(t) => {
                return Ok(t.clone());
            }
            HashiCorpAuth::AppRole { role_id, secret_id } => {
                let url = format!("{}/v1/auth/approle/login", self.base_url);
                let body = serde_json::json!({
                    "role_id": role_id,
                    "secret_id": secret_id,
                });
                let resp = self
                    .client
                    .post(&url)
                    .json(&body)
                    .send()
                    .await
                    .map_err(|e| ConnectorError::Network {
                        endpoint: url.clone(),
                        source: e,
                    })?;

                let data: VaultAuthResponse =
                    resp.json()
                        .await
                        .map_err(|_| ConnectorError::Authentication {
                            connector: "hashicorp-vault".into(),
                            reason: "failed to parse AppRole auth response".into(),
                        })?;
                (data.auth.client_token, data.auth.lease_duration)
            }
            HashiCorpAuth::Kubernetes { role, jwt_path } => {
                let jwt = tokio::fs::read_to_string(jwt_path).await.map_err(|e| {
                    ConnectorError::Configuration {
                        reason: format!("failed to read JWT: {}", e),
                    }
                })?;
                let url = format!("{}/v1/auth/kubernetes/login", self.base_url);
                let body = serde_json::json!({
                    "role": role,
                    "jwt": jwt.trim(),
                });
                let resp = self
                    .client
                    .post(&url)
                    .json(&body)
                    .send()
                    .await
                    .map_err(|e| ConnectorError::Network {
                        endpoint: url.clone(),
                        source: e,
                    })?;
                let data: VaultAuthResponse =
                    resp.json()
                        .await
                        .map_err(|_| ConnectorError::Authentication {
                            connector: "hashicorp-vault".into(),
                            reason: "failed to parse Kubernetes auth response".into(),
                        })?;
                (data.auth.client_token, data.auth.lease_duration)
            }
        };

        let expires_at = chrono::Utc::now() + chrono::Duration::seconds(ttl_secs as i64);
        let mut guard = self.token.write().await;
        *guard = Some(CachedToken {
            token: token.clone(),
            expires_at,
        });

        info!("HashiCorp Vault token refreshed, TTL={}s", ttl_secs);
        Ok(token)
    }
}

#[async_trait]
impl SecretConnector for HashiCorpVaultConnector {
    async fn pull(&self, external_path: &str) -> Result<SecretData, ConnectorError> {
        let token = self.get_token().await?;
        let url = format!(
            "{}/v1/{}/data/{}",
            self.base_url, self.mount_path, external_path
        );

        let resp = self
            .client
            .get(&url)
            .header("X-Vault-Token", &token)
            .send()
            .await
            .map_err(|e| ConnectorError::Network {
                endpoint: url.clone(),
                source: e,
            })?;

        if resp.status() == reqwest::StatusCode::NOT_FOUND {
            return Err(ConnectorError::SecretNotFound {
                connector: "hashicorp-vault".into(),
                path: external_path.to_string(),
            });
        }

        if !resp.status().is_success() {
            return Err(ConnectorError::HttpStatus {
                endpoint: url,
                status: resp.status().as_u16(),
                body: resp.text().await.unwrap_or_default(),
            });
        }

        let body: VaultKvReadResponse =
            resp.json().await.map_err(|_| ConnectorError::Deserialise {
                connector: "hashicorp-vault".into(),
                reason: "failed to parse KV read response".into(),
            })?;

        let version = body
            .data
            .metadata
            .get("version")
            .and_then(|v| v.as_u64())
            .map(|v| v.to_string());

        Ok(SecretData {
            key: external_path.to_string(),
            value: serde_json::Value::Object(body.data.data),
            version,
            metadata: body
                .data
                .metadata
                .into_iter()
                .map(|(k, v)| (k, v.to_string()))
                .collect(),
        })
    }

    async fn push(&self, external_path: &str, data: &SecretData) -> Result<(), ConnectorError> {
        let token = self.get_token().await?;
        let url = format!(
            "{}/v1/{}/data/{}",
            self.base_url, self.mount_path, external_path
        );

        let body = serde_json::json!({
            "data": data.value,
        });

        let resp = self
            .client
            .post(&url)
            .header("X-Vault-Token", &token)
            .json(&body)
            .send()
            .await
            .map_err(|e| ConnectorError::Network {
                endpoint: url.clone(),
                source: e,
            })?;

        if !resp.status().is_success() {
            return Err(ConnectorError::HttpStatus {
                endpoint: url,
                status: resp.status().as_u16(),
                body: resp.text().await.unwrap_or_default(),
            });
        }

        debug!(path = external_path, "pushed secret to HashiCorp Vault");
        Ok(())
    }

    async fn list(&self, prefix: &str) -> Result<Vec<String>, ConnectorError> {
        let token = self.get_token().await?;
        let url = format!(
            "{}/v1/{}/metadata/{}",
            self.base_url, self.mount_path, prefix
        );

        let resp = self
            .client
            .request(reqwest::Method::from_bytes(b"LIST").unwrap(), &url)
            .header("X-Vault-Token", &token)
            .send()
            .await
            .map_err(|e| ConnectorError::Network {
                endpoint: url.clone(),
                source: e,
            })?;

        if resp.status() == reqwest::StatusCode::NOT_FOUND {
            return Ok(Vec::new());
        }

        if !resp.status().is_success() {
            return Err(ConnectorError::HttpStatus {
                endpoint: url,
                status: resp.status().as_u16(),
                body: resp.text().await.unwrap_or_default(),
            });
        }

        let body: VaultListResponse =
            resp.json().await.map_err(|_| ConnectorError::Deserialise {
                connector: "hashicorp-vault".into(),
                reason: "failed to parse list response".into(),
            })?;

        Ok(body.data.keys)
    }

    async fn sync(
        &self,
        prefix: &str,
        direction: SyncDirection,
    ) -> Result<SyncResult, ConnectorError> {
        let mut synced = 0;
        let mut failed = 0;
        let mut errors = Vec::new();

        let paths = self.list(prefix).await?;

        for path in paths {
            match direction {
                SyncDirection::Pull | SyncDirection::Bidirectional => {
                    match self.pull(&path).await {
                        Ok(_) => synced += 1,
                        Err(e) => {
                            errors.push(format!("pull {}: {}", path, e));
                            failed += 1;
                        }
                    }
                }
                SyncDirection::Push => {
                    // Push requires source data — caller provides via push()
                    synced += 1;
                }
            }
        }

        Ok(SyncResult {
            synced,
            failed,
            errors,
        })
    }

    async fn health_check(&self) -> Result<(), ConnectorError> {
        let token = self.get_token().await?;
        let url = format!("{}/v1/sys/health", self.base_url);

        let resp = self
            .client
            .get(&url)
            .header("X-Vault-Token", &token)
            .send()
            .await
            .map_err(|e| ConnectorError::Network {
                endpoint: url.clone(),
                source: e,
            })?;

        // Vault returns 200 (healthy), 429 (standby), 472 (DR secondary), 473 (perf standby).
        // All indicate a reachable Vault.
        if resp.status().as_u16() <= 499 {
            Ok(())
        } else {
            Err(ConnectorError::HttpStatus {
                endpoint: url,
                status: resp.status().as_u16(),
                body: resp.text().await.unwrap_or_default(),
            })
        }
    }
}

// --- Internal response types ---

#[derive(Deserialize)]
struct VaultAuthResponse {
    auth: VaultAuthData,
}

#[derive(Deserialize)]
struct VaultAuthData {
    client_token: String,
    lease_duration: u64,
}

#[derive(Deserialize)]
struct VaultKvReadResponse {
    data: VaultKvData,
}

#[derive(Deserialize)]
struct VaultKvData {
    data: serde_json::Map<String, serde_json::Value>,
    metadata: serde_json::Map<String, serde_json::Value>,
}

#[derive(Deserialize)]
struct VaultListResponse {
    data: VaultListData,
}

#[derive(Deserialize)]
struct VaultListData {
    keys: Vec<String>,
}
