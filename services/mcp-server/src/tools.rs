//! MCP Tool definitions and dispatch for WSLVault.
//!
//! Each tool maps to a WSLVault operation and is exposed via the MCP protocol
//! so that AI agents can securely interact with the secrets platform.

use axum::{extract::State, Json};
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::AppState;

/// MCP Tool schema as described in the protocol.
#[derive(Debug, Serialize)]
pub struct ToolDefinition {
    pub name: String,
    pub description: String,
    pub input_schema: Value,
}

/// Response for the list_tools endpoint.
#[derive(Serialize)]
pub struct ListToolsResponse {
    pub tools: Vec<ToolDefinition>,
}

/// Request body for calling an MCP tool.
#[derive(Deserialize)]
pub struct CallToolRequest {
    pub name: String,
    pub arguments: Value,
}

/// Result of an MCP tool invocation.
#[derive(Serialize)]
pub struct CallToolResponse {
    pub content: Vec<ToolContent>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub is_error: Option<bool>,
}

#[derive(Serialize)]
pub struct ToolContent {
    #[serde(rename = "type")]
    pub content_type: String,
    pub text: String,
}

/// List all available MCP tools.
pub async fn list_tools() -> Json<ListToolsResponse> {
    Json(ListToolsResponse {
        tools: vec![
            ToolDefinition {
                name: "read_secret".into(),
                description: "Read a secret from WSLVault by path".into(),
                input_schema: serde_json::json!({
                    "type": "object",
                    "properties": {
                        "path": {
                            "type": "string",
                            "description": "The secret path (e.g. 'prod/database/password')"
                        },
                        "tenant_id": {
                            "type": "string",
                            "description": "Tenant ID for multi-tenant isolation"
                        },
                        "version": {
                            "type": "integer",
                            "description": "Optional version number; omit for latest"
                        }
                    },
                    "required": ["path", "tenant_id"]
                }),
            },
            ToolDefinition {
                name: "write_secret".into(),
                description: "Write a secret to WSLVault at the given path".into(),
                input_schema: serde_json::json!({
                    "type": "object",
                    "properties": {
                        "path": {
                            "type": "string",
                            "description": "The secret path"
                        },
                        "tenant_id": {
                            "type": "string",
                            "description": "Tenant ID"
                        },
                        "data": {
                            "type": "object",
                            "description": "Key-value pairs to store as the secret"
                        }
                    },
                    "required": ["path", "tenant_id", "data"]
                }),
            },
            ToolDefinition {
                name: "list_secrets".into(),
                description: "List secret paths under a given prefix".into(),
                input_schema: serde_json::json!({
                    "type": "object",
                    "properties": {
                        "prefix": {
                            "type": "string",
                            "description": "Path prefix to list under"
                        },
                        "tenant_id": {
                            "type": "string",
                            "description": "Tenant ID"
                        }
                    },
                    "required": ["prefix", "tenant_id"]
                }),
            },
            ToolDefinition {
                name: "encrypt_data".into(),
                description: "Encrypt data using a named transit key".into(),
                input_schema: serde_json::json!({
                    "type": "object",
                    "properties": {
                        "key_name": {
                            "type": "string",
                            "description": "Name of the transit encryption key"
                        },
                        "plaintext": {
                            "type": "string",
                            "description": "Base64-encoded plaintext to encrypt"
                        },
                        "tenant_id": {
                            "type": "string",
                            "description": "Tenant ID"
                        }
                    },
                    "required": ["key_name", "plaintext", "tenant_id"]
                }),
            },
            ToolDefinition {
                name: "decrypt_data".into(),
                description: "Decrypt data using a named transit key".into(),
                input_schema: serde_json::json!({
                    "type": "object",
                    "properties": {
                        "key_name": {
                            "type": "string",
                            "description": "Name of the transit encryption key"
                        },
                        "ciphertext": {
                            "type": "string",
                            "description": "Ciphertext to decrypt (as returned by encrypt_data)"
                        },
                        "tenant_id": {
                            "type": "string",
                            "description": "Tenant ID"
                        }
                    },
                    "required": ["key_name", "ciphertext", "tenant_id"]
                }),
            },
        ],
    })
}

/// Dispatch an MCP tool call to the appropriate handler.
pub async fn call_tool(
    State(state): State<AppState>,
    Json(req): Json<CallToolRequest>,
) -> Json<CallToolResponse> {
    let result = match req.name.as_str() {
        "read_secret" => handle_read_secret(&state, req.arguments).await,
        "write_secret" => handle_write_secret(&state, req.arguments).await,
        "list_secrets" => handle_list_secrets(&state, req.arguments).await,
        "encrypt_data" => handle_encrypt(&state, req.arguments).await,
        "decrypt_data" => handle_decrypt(&state, req.arguments).await,
        _ => Err(format!("unknown tool: {}", req.name)),
    };

    match result {
        Ok(text) => Json(CallToolResponse {
            content: vec![ToolContent {
                content_type: "text".into(),
                text,
            }],
            is_error: None,
        }),
        Err(err) => Json(CallToolResponse {
            content: vec![ToolContent {
                content_type: "text".into(),
                text: err,
            }],
            is_error: Some(true),
        }),
    }
}

async fn handle_read_secret(state: &AppState, args: Value) -> Result<String, String> {
    let path = args["path"].as_str().ok_or("missing 'path' argument")?;
    let tenant_id = args["tenant_id"]
        .as_str()
        .ok_or("missing 'tenant_id' argument")?;

    let url = format!("{}/v1/secret/data/{}", state.secret_engine_url, path);

    let client = reqwest::Client::new();
    let resp = client
        .get(&url)
        .header("X-Vault-Tenant-ID", tenant_id)
        .send()
        .await
        .map_err(|e| format!("request failed: {}", e))?;

    let status = resp.status();
    let body = resp
        .text()
        .await
        .map_err(|e| format!("failed to read response: {}", e))?;

    if !status.is_success() {
        return Err(format!("secret-engine returned {}: {}", status, body));
    }

    Ok(body)
}

async fn handle_write_secret(state: &AppState, args: Value) -> Result<String, String> {
    let path = args["path"].as_str().ok_or("missing 'path' argument")?;
    let tenant_id = args["tenant_id"]
        .as_str()
        .ok_or("missing 'tenant_id' argument")?;
    let data = &args["data"];

    let url = format!("{}/v1/secret/data/{}", state.secret_engine_url, path);

    let client = reqwest::Client::new();
    let resp = client
        .post(&url)
        .header("X-Vault-Tenant-ID", tenant_id)
        .json(&serde_json::json!({ "data": data }))
        .send()
        .await
        .map_err(|e| format!("request failed: {}", e))?;

    let status = resp.status();
    let body = resp
        .text()
        .await
        .map_err(|e| format!("failed to read response: {}", e))?;

    if !status.is_success() {
        return Err(format!("secret-engine returned {}: {}", status, body));
    }

    Ok(body)
}

async fn handle_list_secrets(state: &AppState, args: Value) -> Result<String, String> {
    let prefix = args["prefix"].as_str().unwrap_or("");
    let tenant_id = args["tenant_id"]
        .as_str()
        .ok_or("missing 'tenant_id' argument")?;

    let url = format!(
        "{}/v1/secret/list?prefix={}",
        state.secret_engine_url, prefix
    );

    let client = reqwest::Client::new();
    let resp = client
        .get(&url)
        .header("X-Vault-Tenant-ID", tenant_id)
        .send()
        .await
        .map_err(|e| format!("request failed: {}", e))?;

    let body = resp
        .text()
        .await
        .map_err(|e| format!("failed to read response: {}", e))?;

    Ok(body)
}

async fn handle_encrypt(state: &AppState, args: Value) -> Result<String, String> {
    let key_name = args["key_name"]
        .as_str()
        .ok_or("missing 'key_name' argument")?;
    let plaintext = args["plaintext"]
        .as_str()
        .ok_or("missing 'plaintext' argument")?;

    let url = format!(
        "{}/v1/transit/encrypt/{}",
        state.transit_engine_url, key_name
    );

    let client = reqwest::Client::new();
    let resp = client
        .post(&url)
        .json(&serde_json::json!({ "plaintext": plaintext }))
        .send()
        .await
        .map_err(|e| format!("request failed: {}", e))?;

    let body = resp
        .text()
        .await
        .map_err(|e| format!("failed to read response: {}", e))?;

    Ok(body)
}

async fn handle_decrypt(state: &AppState, args: Value) -> Result<String, String> {
    let key_name = args["key_name"]
        .as_str()
        .ok_or("missing 'key_name' argument")?;
    let ciphertext = args["ciphertext"]
        .as_str()
        .ok_or("missing 'ciphertext' argument")?;

    let url = format!(
        "{}/v1/transit/decrypt/{}",
        state.transit_engine_url, key_name
    );

    let client = reqwest::Client::new();
    let resp = client
        .post(&url)
        .json(&serde_json::json!({ "ciphertext": ciphertext }))
        .send()
        .await
        .map_err(|e| format!("request failed: {}", e))?;

    let body = resp
        .text()
        .await
        .map_err(|e| format!("failed to read response: {}", e))?;

    Ok(body)
}
