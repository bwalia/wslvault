//! MCP Tool definitions and dispatch for WSLVault.
//!
//! Each tool maps to a WSLVault operation and is exposed via the MCP protocol
//! so that AI agents can securely interact with the secrets platform.
//!
//! ## Audit trail
//!
//! After every tool call (success or failure) an audit event is fired
//! asynchronously to the audit-service. The spawn is fire-and-forget so it
//! never blocks the MCP response.

use axum::{extract::State, Json};
use chrono::Utc;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use tracing::{error, warn};

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

/// Payload posted to the audit service after each tool call.
#[derive(Serialize)]
struct AuditEvent {
    event_type: String,
    tool_name: String,
    tenant_id: String,
    success: bool,
    timestamp: String,
}

/// Fire an audit event to the audit service asynchronously.
///
/// This is intentionally fire-and-forget — a failure here must never
/// propagate back to the caller or block the MCP response.
fn fire_audit_event(
    audit_url: String,
    tool_name: String,
    tenant_id: String,
    success: bool,
) {
    tokio::spawn(async move {
        let event = AuditEvent {
            event_type: "mcp_tool_call".into(),
            tool_name: tool_name.clone(),
            tenant_id,
            success,
            timestamp: Utc::now().to_rfc3339(),
        };

        let client = reqwest::Client::new();
        let url = format!("{}/v1/audit/events", audit_url);
        match client.post(&url).json(&event).send().await {
            Ok(resp) if !resp.status().is_success() => {
                warn!(
                    tool = %tool_name,
                    status = %resp.status(),
                    "audit service returned non-success status"
                );
            }
            Err(err) => {
                error!(tool = %tool_name, error = %err, "failed to send audit event");
            }
            Ok(_) => {}
        }
    });
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
            ToolDefinition {
                name: "delete_secret".into(),
                description: "Delete all versions of a secret at the given path".into(),
                input_schema: serde_json::json!({
                    "type": "object",
                    "properties": {
                        "path": {
                            "type": "string",
                            "description": "The secret path to delete"
                        },
                        "tenant_id": {
                            "type": "string",
                            "description": "Tenant ID"
                        }
                    },
                    "required": ["path", "tenant_id"]
                }),
            },
            ToolDefinition {
                name: "destroy_secret_version".into(),
                description: "Permanently destroy a specific version of a secret".into(),
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
                        "version": {
                            "type": "integer",
                            "description": "The secret version number to permanently destroy"
                        }
                    },
                    "required": ["path", "tenant_id", "version"]
                }),
            },
            ToolDefinition {
                name: "rotate_transit_key".into(),
                description: "Rotate a named transit encryption key to a new version".into(),
                input_schema: serde_json::json!({
                    "type": "object",
                    "properties": {
                        "key_name": {
                            "type": "string",
                            "description": "Name of the transit key to rotate"
                        },
                        "tenant_id": {
                            "type": "string",
                            "description": "Tenant ID"
                        }
                    },
                    "required": ["key_name", "tenant_id"]
                }),
            },
            ToolDefinition {
                name: "list_leases".into(),
                description: "List all active leases for a tenant".into(),
                input_schema: serde_json::json!({
                    "type": "object",
                    "properties": {
                        "tenant_id": {
                            "type": "string",
                            "description": "Tenant ID"
                        }
                    },
                    "required": ["tenant_id"]
                }),
            },
            ToolDefinition {
                name: "revoke_lease".into(),
                description: "Revoke a specific lease by lease ID".into(),
                input_schema: serde_json::json!({
                    "type": "object",
                    "properties": {
                        "lease_id": {
                            "type": "string",
                            "description": "The lease ID to revoke"
                        },
                        "tenant_id": {
                            "type": "string",
                            "description": "Tenant ID"
                        }
                    },
                    "required": ["lease_id", "tenant_id"]
                }),
            },
        ],
    })
}

/// Dispatch an MCP tool call to the appropriate handler, then fire an async
/// audit event regardless of whether the call succeeded or failed.
pub async fn call_tool(
    State(state): State<AppState>,
    Json(req): Json<CallToolRequest>,
) -> Json<CallToolResponse> {
    // Capture tenant_id before moving req.arguments into the handler.
    let tenant_id = req
        .arguments
        .get("tenant_id")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_owned();

    let result = match req.name.as_str() {
        "read_secret" => handle_read_secret(&state, req.arguments).await,
        "write_secret" => handle_write_secret(&state, req.arguments).await,
        "list_secrets" => handle_list_secrets(&state, req.arguments).await,
        "encrypt_data" => handle_encrypt(&state, req.arguments).await,
        "decrypt_data" => handle_decrypt(&state, req.arguments).await,
        "delete_secret" => handle_delete_secret(&state, req.arguments).await,
        "destroy_secret_version" => handle_destroy_secret_version(&state, req.arguments).await,
        "rotate_transit_key" => handle_rotate_transit_key(&state, req.arguments).await,
        "list_leases" => handle_list_leases(&state, req.arguments).await,
        "revoke_lease" => handle_revoke_lease(&state, req.arguments).await,
        _ => Err(format!("unknown tool: {}", req.name)),
    };

    // Fire audit event asynchronously; do not block or propagate errors.
    fire_audit_event(
        state.audit_engine_url.clone(),
        req.name.clone(),
        tenant_id,
        result.is_ok(),
    );

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

// ---------------------------------------------------------------------------
// Existing tool handlers
// ---------------------------------------------------------------------------

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

// ---------------------------------------------------------------------------
// New tool handlers
// ---------------------------------------------------------------------------

/// DELETE `/v1/secret/data/{path}` — removes all versions of a secret.
async fn handle_delete_secret(state: &AppState, args: Value) -> Result<String, String> {
    let path = args["path"].as_str().ok_or("missing 'path' argument")?;
    let tenant_id = args["tenant_id"]
        .as_str()
        .ok_or("missing 'tenant_id' argument")?;

    let url = format!("{}/v1/secret/data/{}", state.secret_engine_url, path);

    let client = reqwest::Client::new();
    let resp = client
        .delete(&url)
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

    Ok(if body.is_empty() {
        "secret deleted".into()
    } else {
        body
    })
}

/// POST `/v1/secret/destroy/{path}` with `{"versions":[N]}` — permanently
/// destroys the underlying data for a specific secret version.
async fn handle_destroy_secret_version(state: &AppState, args: Value) -> Result<String, String> {
    let path = args["path"].as_str().ok_or("missing 'path' argument")?;
    let tenant_id = args["tenant_id"]
        .as_str()
        .ok_or("missing 'tenant_id' argument")?;
    let version = args["version"]
        .as_i64()
        .ok_or("missing or invalid 'version' argument (must be an integer)")?;

    let url = format!("{}/v1/secret/destroy/{}", state.secret_engine_url, path);

    let client = reqwest::Client::new();
    let resp = client
        .post(&url)
        .header("X-Vault-Tenant-ID", tenant_id)
        .json(&serde_json::json!({ "versions": [version] }))
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

    Ok(if body.is_empty() {
        format!("version {} destroyed", version)
    } else {
        body
    })
}

/// POST `/v1/transit/keys/{key_name}/rotate` — advances the key to a new
/// cryptographic version; existing ciphertext remains decryptable.
async fn handle_rotate_transit_key(state: &AppState, args: Value) -> Result<String, String> {
    let key_name = args["key_name"]
        .as_str()
        .ok_or("missing 'key_name' argument")?;
    let tenant_id = args["tenant_id"]
        .as_str()
        .ok_or("missing 'tenant_id' argument")?;

    let url = format!(
        "{}/v1/transit/keys/{}/rotate",
        state.transit_engine_url, key_name
    );

    let client = reqwest::Client::new();
    let resp = client
        .post(&url)
        .header("X-Vault-Tenant-ID", tenant_id)
        // Body is empty for a rotate request
        .send()
        .await
        .map_err(|e| format!("request failed: {}", e))?;

    let status = resp.status();
    let body = resp
        .text()
        .await
        .map_err(|e| format!("failed to read response: {}", e))?;

    if !status.is_success() {
        return Err(format!("transit-engine returned {}: {}", status, body));
    }

    Ok(if body.is_empty() {
        format!("key '{}' rotated", key_name)
    } else {
        body
    })
}

/// GET `/v1/leases?tenant_id={tenant_id}` — returns all active leases for
/// the specified tenant.
async fn handle_list_leases(state: &AppState, args: Value) -> Result<String, String> {
    let tenant_id = args["tenant_id"]
        .as_str()
        .ok_or("missing 'tenant_id' argument")?;

    let url = format!(
        "{}/v1/leases?tenant_id={}",
        state.secret_engine_url, tenant_id
    );

    let client = reqwest::Client::new();
    let resp = client
        .get(&url)
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

/// DELETE `/v1/leases/{lease_id}` — revokes the named lease immediately,
/// invalidating any associated credentials or tokens.
async fn handle_revoke_lease(state: &AppState, args: Value) -> Result<String, String> {
    let lease_id = args["lease_id"]
        .as_str()
        .ok_or("missing 'lease_id' argument")?;
    let tenant_id = args["tenant_id"]
        .as_str()
        .ok_or("missing 'tenant_id' argument")?;

    let url = format!("{}/v1/leases/{}", state.secret_engine_url, lease_id);

    let client = reqwest::Client::new();
    let resp = client
        .delete(&url)
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

    Ok(if body.is_empty() {
        format!("lease '{}' revoked", lease_id)
    } else {
        body
    })
}
