//! High-level WSLVault client.

use std::collections::HashMap;
use std::time::Duration;

use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::config::ClientConfig;
use crate::error::VaultClientError;

/// High-level async client for the WSLVault secrets platform.
#[derive(Clone)]
pub struct VaultClient {
    config: ClientConfig,
    http: reqwest::Client,
}

/// Builder for constructing a VaultClient with configuration.
pub struct VaultClientBuilder {
    config: ClientConfig,
}

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

impl VaultClient {
    /// Create a new builder for the client.
    pub fn builder() -> VaultClientBuilder {
        VaultClientBuilder {
            config: ClientConfig::default(),
        }
    }

    /// Read a secret at the given path.
    pub async fn read_secret(&self, path: &str) -> Result<SecretData, VaultClientError> {
        let url = format!("{}/v1/secret/data/{}", self.config.endpoint, path);
        let resp = self.request(reqwest::Method::GET, &url).send().await?;
        self.handle_response(resp).await
    }

    /// Write a secret at the given path.
    pub async fn write_secret(
        &self,
        path: &str,
        data: Value,
    ) -> Result<WriteResponse, VaultClientError> {
        let url = format!("{}/v1/secret/data/{}", self.config.endpoint, path);
        let body = serde_json::json!({ "data": data });
        let resp = self
            .request(reqwest::Method::POST, &url)
            .json(&body)
            .send()
            .await?;
        self.handle_response(resp).await
    }

    /// List secret paths under the given prefix.
    pub async fn list_secrets(&self, prefix: &str) -> Result<ListResponse, VaultClientError> {
        let url = format!(
            "{}/v1/secret/list?prefix={}",
            self.config.endpoint, prefix
        );
        let resp = self.request(reqwest::Method::GET, &url).send().await?;
        self.handle_response(resp).await
    }

    /// Delete a secret (soft delete).
    pub async fn delete_secret(
        &self,
        path: &str,
        versions: &[u32],
    ) -> Result<(), VaultClientError> {
        let url = format!("{}/v1/secret/delete/{}", self.config.endpoint, path);
        let body = serde_json::json!({ "versions": versions });
        let resp = self
            .request(reqwest::Method::POST, &url)
            .json(&body)
            .send()
            .await?;
        if !resp.status().is_success() {
            let status = resp.status().as_u16();
            let text = resp.text().await.unwrap_or_default();
            return Err(VaultClientError::Api {
                status,
                message: text,
            });
        }
        Ok(())
    }

    /// Encrypt data using the transit engine.
    pub async fn transit_encrypt(
        &self,
        key_name: &str,
        plaintext: &str,
    ) -> Result<Value, VaultClientError> {
        let url = format!(
            "{}/v1/transit/encrypt/{}",
            self.config.endpoint, key_name
        );
        let body = serde_json::json!({ "plaintext": plaintext });
        let resp = self
            .request(reqwest::Method::POST, &url)
            .json(&body)
            .send()
            .await?;
        self.handle_response(resp).await
    }

    /// Decrypt data using the transit engine.
    pub async fn transit_decrypt(
        &self,
        key_name: &str,
        ciphertext: &str,
    ) -> Result<Value, VaultClientError> {
        let url = format!(
            "{}/v1/transit/decrypt/{}",
            self.config.endpoint, key_name
        );
        let body = serde_json::json!({ "ciphertext": ciphertext });
        let resp = self
            .request(reqwest::Method::POST, &url)
            .json(&body)
            .send()
            .await?;
        self.handle_response(resp).await
    }

    /// Build a request with common headers.
    fn request(&self, method: reqwest::Method, url: &str) -> reqwest::RequestBuilder {
        let mut req = self.http.request(method, url);
        if let Some(ref token) = self.config.token {
            req = req.header("Authorization", format!("Bearer {}", token));
        }
        if let Some(ref tenant_id) = self.config.tenant_id {
            req = req.header("X-Vault-Tenant-ID", tenant_id);
        }
        req
    }

    /// Parse a response, mapping HTTP errors to client errors.
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
}

impl VaultClientBuilder {
    /// Set the WSLVault endpoint URL.
    pub fn endpoint(mut self, endpoint: &str) -> Self {
        self.config.endpoint = endpoint.to_string();
        self
    }

    /// Set the authentication token.
    pub fn token(mut self, token: &str) -> Self {
        self.config.token = Some(token.to_string());
        self
    }

    /// Set the tenant ID.
    pub fn tenant_id(mut self, tenant_id: &str) -> Self {
        self.config.tenant_id = Some(tenant_id.to_string());
        self
    }

    /// Set the request timeout.
    pub fn timeout_secs(mut self, secs: u64) -> Self {
        self.config.timeout_secs = secs;
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
