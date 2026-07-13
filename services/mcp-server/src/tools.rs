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
use reqwest::RequestBuilder;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use tracing::{error, warn};

use crate::AppState;

/// Identity context forwarded from the caller (gateway / UI middleware or
/// environment) on every inbound request.
///
/// **HTTP transport:** populated by reading the `X-Policies` and
/// `X-Principal-Id` headers injected by the gateway after JWT validation.
///
/// **stdio transport (dev/local use):** populated from the
/// `VAULT_MCP_POLICIES` and `VAULT_MCP_PRINCIPAL_ID` environment variables.
/// In production the HTTP transport behind the gateway is authoritative.
#[derive(Debug, Clone, Default)]
pub struct CallerContext {
    /// Comma-separated policy names that the caller holds, as injected by the
    /// gateway after successful JWT validation.  Forwarded as `X-Policies` to
    /// secret-engine / transit-engine so they can authorise the operation.
    pub policies: Option<String>,
    /// Stable principal identifier (user ID, service account, etc.) for the
    /// authenticated caller.  Forwarded as `X-Principal-Id` to backends.
    pub principal_id: Option<String>,
}

/// Apply the optional caller-context headers (`X-Tenant-Id`, `X-Policies`,
/// `X-Principal-Id`) to a [`RequestBuilder`].
///
/// Only headers whose values are non-empty are attached, so backends never
/// receive empty-valued authorization headers that could confuse them.
fn apply_caller_headers(
    builder: RequestBuilder,
    tenant_id: &str,
    ctx: &CallerContext,
) -> RequestBuilder {
    let mut b = builder.header("X-Tenant-Id", tenant_id);
    if let Some(ref policies) = ctx.policies {
        b = b.header("X-Policies", policies);
    }
    if let Some(ref principal_id) = ctx.principal_id {
        b = b.header("X-Principal-Id", principal_id);
    }
    b
}

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
fn fire_audit_event(audit_url: String, tool_name: String, tenant_id: String, success: bool) {
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

/// Return the canonical list of all tool definitions.
///
/// This is the single source of truth used by both the legacy REST `list_tools`
/// handler and the new JSON-RPC `tools/list` method.  Callers should not
/// duplicate the tool definitions — always derive from this function.
pub fn all_tool_definitions() -> Vec<ToolDefinition> {
    vec![
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
    ]
}

/// Dispatch a tool call by name, returning the MCP response shape.
///
/// This is the central routing function for both the JSON-RPC `tools/call`
/// handler and the legacy REST `call_tool` handler.  It fires an async audit
/// event after every call regardless of outcome.
///
/// `ctx` carries the caller's identity (policies, principal) extracted from
/// the inbound transport and forwarded verbatim to backend services.
pub async fn dispatch_tool(
    state: &AppState,
    tool_name: &str,
    arguments: Value,
    ctx: CallerContext,
) -> CallToolResponse {
    // Extract tenant_id for the audit trail before moving `arguments`.
    let tenant_id = arguments
        .get("tenant_id")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_owned();

    let result = match tool_name {
        "read_secret" => handle_read_secret(state, arguments, &ctx).await,
        "write_secret" => handle_write_secret(state, arguments, &ctx).await,
        "list_secrets" => handle_list_secrets(state, arguments, &ctx).await,
        "encrypt_data" => handle_encrypt(state, arguments, &ctx).await,
        "decrypt_data" => handle_decrypt(state, arguments, &ctx).await,
        "delete_secret" => handle_delete_secret(state, arguments, &ctx).await,
        "destroy_secret_version" => handle_destroy_secret_version(state, arguments, &ctx).await,
        "rotate_transit_key" => handle_rotate_transit_key(state, arguments, &ctx).await,
        "list_leases" => handle_list_leases(state, arguments, &ctx).await,
        "revoke_lease" => handle_revoke_lease(state, arguments, &ctx).await,
        unknown => Err(format!("unknown tool: {unknown}")),
    };

    fire_audit_event(
        state.audit_engine_url.clone(),
        tool_name.to_owned(),
        tenant_id,
        result.is_ok(),
    );

    match result {
        Ok(text) => CallToolResponse {
            content: vec![ToolContent {
                content_type: "text".into(),
                text,
            }],
            is_error: None,
        },
        Err(err) => CallToolResponse {
            content: vec![ToolContent {
                content_type: "text".into(),
                text: err,
            }],
            is_error: Some(true),
        },
    }
}

/// List all available MCP tools (legacy REST handler).
///
/// Delegates to [`all_tool_definitions`] so the tool list is defined in one
/// place and shared with the JSON-RPC `tools/list` method.
pub async fn list_tools() -> Json<ListToolsResponse> {
    Json(ListToolsResponse {
        tools: all_tool_definitions(),
    })
}

/// Legacy REST handler for `POST /v1/mcp/tools/call`.
///
/// Delegates to [`dispatch_tool`] so both the REST and JSON-RPC paths share
/// identical routing and auditing logic.
///
/// `X-Policies` and `X-Principal-Id` are read from the incoming request headers
/// and forwarded to backend services as-is (pass-through from gateway middleware).
pub async fn call_tool(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
    Json(req): Json<CallToolRequest>,
) -> Json<CallToolResponse> {
    let ctx = caller_context_from_headers(&headers);
    Json(dispatch_tool(&state, &req.name, req.arguments, ctx).await)
}

/// Build a [`CallerContext`] from an HTTP request's headers.
///
/// Reads `X-Policies` and `X-Principal-Id` which are injected by the gateway
/// after JWT validation and must be passed through verbatim to backend services.
pub fn caller_context_from_headers(headers: &axum::http::HeaderMap) -> CallerContext {
    CallerContext {
        policies: headers
            .get("x-policies")
            .and_then(|v| v.to_str().ok())
            .filter(|s| !s.is_empty())
            .map(|s| s.to_owned()),
        principal_id: headers
            .get("x-principal-id")
            .and_then(|v| v.to_str().ok())
            .filter(|s| !s.is_empty())
            .map(|s| s.to_owned()),
    }
}

// ---------------------------------------------------------------------------
// Existing tool handlers
// ---------------------------------------------------------------------------

async fn handle_read_secret(
    state: &AppState,
    args: Value,
    ctx: &CallerContext,
) -> Result<String, String> {
    let path = args["path"].as_str().ok_or("missing 'path' argument")?;
    let tenant_id = args["tenant_id"]
        .as_str()
        .ok_or("missing 'tenant_id' argument")?;

    let url = format!("{}/v1/secret/data/{}", state.secret_engine_url, path);

    let client = reqwest::Client::new();
    let resp = apply_caller_headers(client.get(&url), tenant_id, ctx)
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

async fn handle_write_secret(
    state: &AppState,
    args: Value,
    ctx: &CallerContext,
) -> Result<String, String> {
    let path = args["path"].as_str().ok_or("missing 'path' argument")?;
    let tenant_id = args["tenant_id"]
        .as_str()
        .ok_or("missing 'tenant_id' argument")?;
    let data = &args["data"];

    let url = format!("{}/v1/secret/data/{}", state.secret_engine_url, path);

    let client = reqwest::Client::new();
    let resp = apply_caller_headers(client.post(&url), tenant_id, ctx)
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

async fn handle_list_secrets(
    state: &AppState,
    args: Value,
    ctx: &CallerContext,
) -> Result<String, String> {
    let prefix = args["prefix"].as_str().unwrap_or("");
    let tenant_id = args["tenant_id"]
        .as_str()
        .ok_or("missing 'tenant_id' argument")?;

    let url = format!(
        "{}/v1/secret/list?prefix={}",
        state.secret_engine_url, prefix
    );

    let client = reqwest::Client::new();
    let resp = apply_caller_headers(client.get(&url), tenant_id, ctx)
        .send()
        .await
        .map_err(|e| format!("request failed: {}", e))?;

    let body = resp
        .text()
        .await
        .map_err(|e| format!("failed to read response: {}", e))?;

    Ok(body)
}

async fn handle_encrypt(
    state: &AppState,
    args: Value,
    ctx: &CallerContext,
) -> Result<String, String> {
    let key_name = args["key_name"]
        .as_str()
        .ok_or("missing 'key_name' argument")?;
    let plaintext = args["plaintext"]
        .as_str()
        .ok_or("missing 'plaintext' argument")?;
    let tenant_id = args["tenant_id"]
        .as_str()
        .ok_or("missing 'tenant_id' argument")?;

    let url = format!(
        "{}/v1/transit/encrypt/{}",
        state.transit_engine_url, key_name
    );

    let client = reqwest::Client::new();
    let resp = apply_caller_headers(client.post(&url), tenant_id, ctx)
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

async fn handle_decrypt(
    state: &AppState,
    args: Value,
    ctx: &CallerContext,
) -> Result<String, String> {
    let key_name = args["key_name"]
        .as_str()
        .ok_or("missing 'key_name' argument")?;
    let ciphertext = args["ciphertext"]
        .as_str()
        .ok_or("missing 'ciphertext' argument")?;
    let tenant_id = args["tenant_id"]
        .as_str()
        .ok_or("missing 'tenant_id' argument")?;

    let url = format!(
        "{}/v1/transit/decrypt/{}",
        state.transit_engine_url, key_name
    );

    let client = reqwest::Client::new();
    let resp = apply_caller_headers(client.post(&url), tenant_id, ctx)
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
async fn handle_delete_secret(
    state: &AppState,
    args: Value,
    ctx: &CallerContext,
) -> Result<String, String> {
    let path = args["path"].as_str().ok_or("missing 'path' argument")?;
    let tenant_id = args["tenant_id"]
        .as_str()
        .ok_or("missing 'tenant_id' argument")?;

    let url = format!("{}/v1/secret/data/{}", state.secret_engine_url, path);

    let client = reqwest::Client::new();
    let resp = apply_caller_headers(client.delete(&url), tenant_id, ctx)
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
async fn handle_destroy_secret_version(
    state: &AppState,
    args: Value,
    ctx: &CallerContext,
) -> Result<String, String> {
    let path = args["path"].as_str().ok_or("missing 'path' argument")?;
    let tenant_id = args["tenant_id"]
        .as_str()
        .ok_or("missing 'tenant_id' argument")?;
    let version = args["version"]
        .as_i64()
        .ok_or("missing or invalid 'version' argument (must be an integer)")?;

    let url = format!("{}/v1/secret/destroy/{}", state.secret_engine_url, path);

    let client = reqwest::Client::new();
    let resp = apply_caller_headers(client.post(&url), tenant_id, ctx)
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
async fn handle_rotate_transit_key(
    state: &AppState,
    args: Value,
    ctx: &CallerContext,
) -> Result<String, String> {
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
    // Body is empty for a rotate request; only caller-context headers are needed.
    let resp = apply_caller_headers(client.post(&url), tenant_id, ctx)
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
async fn handle_list_leases(
    state: &AppState,
    args: Value,
    ctx: &CallerContext,
) -> Result<String, String> {
    let tenant_id = args["tenant_id"]
        .as_str()
        .ok_or("missing 'tenant_id' argument")?;

    let url = format!(
        "{}/v1/leases?tenant_id={}",
        state.secret_engine_url, tenant_id
    );

    let client = reqwest::Client::new();
    let resp = apply_caller_headers(client.get(&url), tenant_id, ctx)
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
async fn handle_revoke_lease(
    state: &AppState,
    args: Value,
    ctx: &CallerContext,
) -> Result<String, String> {
    let lease_id = args["lease_id"]
        .as_str()
        .ok_or("missing 'lease_id' argument")?;
    let tenant_id = args["tenant_id"]
        .as_str()
        .ok_or("missing 'tenant_id' argument")?;

    let url = format!("{}/v1/leases/{}", state.secret_engine_url, lease_id);

    let client = reqwest::Client::new();
    let resp = apply_caller_headers(client.delete(&url), tenant_id, ctx)
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
