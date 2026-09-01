//! MCP Client for communicating with the WSLVault MCP server and REST APIs.
//!
//! Provides both:
//! - Direct MCP tool invocation (via the MCP protocol)
//! - Convenience wrappers that call WSLVault REST APIs directly

use serde::{Deserialize, Serialize};
use tracing::debug;

/// MCP client that communicates with WSLVault services.
#[derive(Clone)]
pub struct McpClient {
    http: reqwest::Client,
    endpoint: String,
    token: Option<String>,
    tenant_id: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ToolDefinition {
    pub name: String,
    pub description: String,
    pub input_schema: serde_json::Value,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ListToolsResponse {
    pub tools: Vec<ToolDefinition>,
}

#[derive(Debug, Serialize)]
struct CallToolRequest {
    name: String,
    arguments: serde_json::Value,
}

#[derive(Debug, Deserialize)]
pub struct CallToolResponse {
    pub content: Vec<ToolContent>,
    #[serde(default)]
    pub is_error: Option<bool>,
}

#[derive(Debug, Deserialize)]
pub struct ToolContent {
    #[serde(rename = "type")]
    /// Part of the MCP wire contract: deserialised from the server's reply
    /// and re-serialised, but never read by the CLI itself.
    #[allow(dead_code)]
    pub content_type: String,
    pub text: String,
}

impl McpClient {
    /// Create a new MCP client.
    pub fn new(
        endpoint: &str,
        token: Option<&str>,
        tenant_id: Option<&str>,
    ) -> anyhow::Result<Self> {
        let http = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(30))
            .build()?;

        Ok(Self {
            http,
            endpoint: endpoint.trim_end_matches('/').to_string(),
            token: token.map(|s| s.to_string()),
            tenant_id: tenant_id.map(|s| s.to_string()),
        })
    }

    /// Build a request with common auth headers.
    fn request(&self, method: reqwest::Method, url: &str) -> reqwest::RequestBuilder {
        let mut req = self.http.request(method, url);
        if let Some(ref token) = self.token {
            req = req.bearer_auth(token);
        }
        if let Some(ref tid) = self.tenant_id {
            req = req.header("X-Vault-Tenant-ID", tid);
        }
        req
    }

    // ── MCP Protocol Methods ────────────────────────────────────────────

    /// List available MCP tools from the server.
    pub async fn list_tools(&self) -> anyhow::Result<ListToolsResponse> {
        let url = format!("{}/v1/mcp/tools", self.endpoint);
        debug!(url, "listing MCP tools");
        let resp = self.request(reqwest::Method::GET, &url).send().await?;
        handle_response(resp).await
    }

    /// Call an MCP tool by name with the given arguments.
    pub async fn call_tool(
        &self,
        name: &str,
        arguments: serde_json::Value,
    ) -> anyhow::Result<serde_json::Value> {
        let url = format!("{}/v1/mcp/tools/call", self.endpoint);
        debug!(url, tool = name, "calling MCP tool");
        let body = CallToolRequest {
            name: name.to_string(),
            arguments,
        };
        let resp = self
            .request(reqwest::Method::POST, &url)
            .json(&body)
            .send()
            .await?;

        let call_resp: CallToolResponse = handle_response(resp).await?;

        if call_resp.is_error == Some(true) {
            let msg = call_resp
                .content
                .first()
                .map(|c| c.text.clone())
                .unwrap_or_else(|| "unknown MCP error".to_string());
            anyhow::bail!("MCP tool error: {}", msg);
        }

        // Try to parse the text content as JSON, fallback to string value
        if let Some(content) = call_resp.content.first() {
            match serde_json::from_str::<serde_json::Value>(&content.text) {
                Ok(val) => Ok(val),
                Err(_) => Ok(serde_json::Value::String(content.text.clone())),
            }
        } else {
            Ok(serde_json::Value::Null)
        }
    }

    // ── Secret REST API Methods ─────────────────────────────────────────

    /// Read a secret directly via the REST API.
    pub async fn get_secret(
        &self,
        path: &str,
        version: Option<u32>,
    ) -> anyhow::Result<serde_json::Value> {
        let mut url = format!("{}/v1/secret/data/{}", self.endpoint, path);
        if let Some(v) = version {
            url.push_str(&format!("?version={}", v));
        }
        debug!(url, "reading secret");
        let resp = self.request(reqwest::Method::GET, &url).send().await?;
        handle_response(resp).await
    }

    /// Write a secret via the REST API.
    pub async fn put_secret(
        &self,
        path: &str,
        data: serde_json::Value,
        cas: Option<u32>,
    ) -> anyhow::Result<serde_json::Value> {
        let url = format!("{}/v1/secret/data/{}", self.endpoint, path);
        let mut body = serde_json::json!({ "data": data });
        if let Some(cas_ver) = cas {
            body["cas"] = serde_json::json!(cas_ver);
        }
        debug!(url, "writing secret");
        let resp = self
            .request(reqwest::Method::POST, &url)
            .json(&body)
            .send()
            .await?;
        handle_response(resp).await
    }

    /// Delete secret versions via the REST API.
    pub async fn delete_secret(
        &self,
        path: &str,
        versions: &[u32],
    ) -> anyhow::Result<serde_json::Value> {
        let url = format!("{}/v1/secret/delete/{}", self.endpoint, path);
        let body = serde_json::json!({ "versions": versions });
        let resp = self
            .request(reqwest::Method::POST, &url)
            .json(&body)
            .send()
            .await?;
        handle_response(resp).await
    }

    /// Destroy secret versions via the REST API.
    pub async fn destroy_secret(
        &self,
        path: &str,
        versions: &[u32],
    ) -> anyhow::Result<serde_json::Value> {
        let url = format!("{}/v1/secret/destroy/{}", self.endpoint, path);
        let body = serde_json::json!({ "versions": versions });
        let resp = self
            .request(reqwest::Method::POST, &url)
            .json(&body)
            .send()
            .await?;
        handle_response(resp).await
    }

    /// List secrets via the REST API.
    pub async fn list_secrets(&self, prefix: &str) -> anyhow::Result<serde_json::Value> {
        let url = format!("{}/v1/secret/list?prefix={}", self.endpoint, prefix);
        debug!(url, "listing secrets");
        let resp = self.request(reqwest::Method::GET, &url).send().await?;
        handle_response(resp).await
    }

    // ── Transit REST API Methods ────────────────────────────────────────

    pub async fn transit_encrypt(
        &self,
        key_name: &str,
        plaintext: &str,
    ) -> anyhow::Result<serde_json::Value> {
        let url = format!("{}/v1/transit/encrypt/{}", self.endpoint, key_name);
        let body = serde_json::json!({ "plaintext": plaintext });
        let resp = self
            .request(reqwest::Method::POST, &url)
            .json(&body)
            .send()
            .await?;
        handle_response(resp).await
    }

    pub async fn transit_decrypt(
        &self,
        key_name: &str,
        ciphertext: &str,
    ) -> anyhow::Result<serde_json::Value> {
        let url = format!("{}/v1/transit/decrypt/{}", self.endpoint, key_name);
        let body = serde_json::json!({ "ciphertext": ciphertext });
        let resp = self
            .request(reqwest::Method::POST, &url)
            .json(&body)
            .send()
            .await?;
        handle_response(resp).await
    }

    pub async fn transit_sign(
        &self,
        key_name: &str,
        data: &str,
    ) -> anyhow::Result<serde_json::Value> {
        let url = format!("{}/v1/transit/sign/{}", self.endpoint, key_name);
        let body = serde_json::json!({ "data": data });
        let resp = self
            .request(reqwest::Method::POST, &url)
            .json(&body)
            .send()
            .await?;
        handle_response(resp).await
    }

    pub async fn transit_verify(
        &self,
        key_name: &str,
        data: &str,
        signature: &str,
    ) -> anyhow::Result<serde_json::Value> {
        let url = format!("{}/v1/transit/verify/{}", self.endpoint, key_name);
        let body = serde_json::json!({ "data": data, "signature": signature });
        let resp = self
            .request(reqwest::Method::POST, &url)
            .json(&body)
            .send()
            .await?;
        handle_response(resp).await
    }

    pub async fn transit_create_key(&self, key_name: &str) -> anyhow::Result<serde_json::Value> {
        let url = format!("{}/v1/transit/keys/{}", self.endpoint, key_name);
        let resp = self.request(reqwest::Method::POST, &url).send().await?;
        handle_response(resp).await
    }

    pub async fn transit_rotate_key(&self, key_name: &str) -> anyhow::Result<serde_json::Value> {
        let url = format!("{}/v1/transit/keys/{}/rotate", self.endpoint, key_name);
        let resp = self.request(reqwest::Method::POST, &url).send().await?;
        handle_response(resp).await
    }
}

/// Handle an HTTP response, mapping non-success statuses to errors.
async fn handle_response<T: serde::de::DeserializeOwned>(
    resp: reqwest::Response,
) -> anyhow::Result<T> {
    let status = resp.status();
    if !status.is_success() {
        let body = resp.text().await.unwrap_or_default();
        anyhow::bail!("API error ({}): {}", status.as_u16(), body);
    }
    let body = resp.json::<T>().await?;
    Ok(body)
}
