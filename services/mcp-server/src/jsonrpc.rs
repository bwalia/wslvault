//! JSON-RPC 2.0 protocol layer for the MCP server.
//!
//! Implements the Model Context Protocol (MCP) revision 2024-11-05 on top of a
//! JSON-RPC 2.0 envelope.  Supported methods:
//!
//! | Method                       | Spec role         |
//! |------------------------------|-------------------|
//! | `initialize`                 | Capability exchange at connection start |
//! | `notifications/initialized`  | Client acknowledgement (notification — no response) |
//! | `tools/list`                 | Enumerate all WSLVault tools |
//! | `tools/call`                 | Invoke a named tool |
//! | `ping`                       | Keepalive |
//!
//! ## JSON-RPC error codes
//!
//! | Code    | Meaning          | When used |
//! |---------|------------------|-----------|
//! | -32700  | Parse error      | Request body is not valid JSON |
//! | -32600  | Invalid request  | `jsonrpc` field is not `"2.0"` |
//! | -32601  | Method not found | Unknown method name |
//! | -32602  | Invalid params   | Required params field missing or wrong type |
//! | -32603  | Internal error   | Unexpected server-side failure |

use serde::{Deserialize, Serialize};
use serde_json::Value;
use tracing::debug;

use crate::tools::{self, CallerContext};
use crate::AppState;

// ---------------------------------------------------------------------------
// Standard JSON-RPC 2.0 error codes
// ---------------------------------------------------------------------------

/// JSON-RPC 2.0 error code: request body is not valid JSON.
pub const PARSE_ERROR: i32 = -32700;
/// JSON-RPC 2.0 error code: the `jsonrpc` field is not `"2.0"` or another
/// structural violation of the JSON-RPC envelope.
pub const INVALID_REQUEST: i32 = -32600;
/// JSON-RPC 2.0 error code: the method name is not recognised.
/// Part of the spec's error-code set; kept for completeness even where the
/// dispatcher does not currently emit it.
#[allow(dead_code)]
pub const METHOD_NOT_FOUND: i32 = -32601;
/// JSON-RPC 2.0 error code: required parameters are missing or have the wrong type.
pub const INVALID_PARAMS: i32 = -32602;
/// JSON-RPC 2.0 error code: unexpected server-side failure.
#[allow(dead_code)] // Spec-complete error-code set.
pub const INTERNAL_ERROR: i32 = -32603;

// ---------------------------------------------------------------------------
// JSON-RPC 2.0 wire types
// ---------------------------------------------------------------------------

/// An inbound JSON-RPC 2.0 request or notification.
///
/// Notifications are distinguished from requests by the absence or nullness of
/// the `id` field — they must not receive a response.
#[derive(Debug, Deserialize)]
pub struct JsonRpcRequest {
    /// Must be exactly `"2.0"`.
    pub jsonrpc: String,
    /// Present and non-null for requests; absent or null for notifications.
    #[serde(default)]
    pub id: Value,
    /// The method to invoke.
    pub method: String,
    /// Method parameters; defaults to a JSON null if omitted.
    #[serde(default)]
    pub params: Value,
}

/// An outbound JSON-RPC 2.0 response (either a result or an error).
///
/// Exactly one of `result` and `error` will be populated.
#[derive(Debug, Serialize)]
pub struct JsonRpcResponse {
    pub jsonrpc: String,
    /// Echoes the request `id`.  Null when responding to a malformed request
    /// whose id could not be extracted.
    pub id: Value,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub result: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<JsonRpcError>,
}

impl JsonRpcResponse {
    /// Construct a successful response carrying `result`.
    pub fn ok(id: Value, result: Value) -> Self {
        Self {
            jsonrpc: "2.0".into(),
            id,
            result: Some(result),
            error: None,
        }
    }

    /// Construct an error response with `code` and `message`.
    pub fn err(id: Value, code: i32, message: impl Into<String>) -> Self {
        Self {
            jsonrpc: "2.0".into(),
            id,
            result: None,
            error: Some(JsonRpcError {
                code,
                message: message.into(),
                data: None,
            }),
        }
    }
}

/// JSON-RPC 2.0 error object embedded in an error response.
#[derive(Debug, Serialize)]
pub struct JsonRpcError {
    /// Numeric error code (use the constants defined in this module).
    pub code: i32,
    /// Human-readable error description.
    pub message: String,
    /// Optional additional error context; omitted when `None`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub data: Option<Value>,
}

// ---------------------------------------------------------------------------
// MCP tool schema (camelCase field names required by MCP spec 2024-11-05)
// ---------------------------------------------------------------------------

/// MCP tool definition serialised with camelCase fields as required by
/// the MCP `tools/list` response format.
#[derive(Debug, Serialize)]
struct McpTool {
    name: String,
    description: String,
    /// JSON Schema object describing the tool's input parameters.
    /// Serialised as `inputSchema` (camelCase) per MCP spec 2024-11-05 §4.2.1.
    #[serde(rename = "inputSchema")]
    input_schema: Value,
}

// ---------------------------------------------------------------------------
// Public parsing / validation helpers
// ---------------------------------------------------------------------------

/// Parse raw bytes as a JSON-RPC 2.0 request envelope.
///
/// Returns the parsed request on success, or a JSON-RPC `-32700` (parse error)
/// response on failure — ready to be serialised and sent back to the caller.
pub fn parse_request(raw: &[u8]) -> Result<JsonRpcRequest, JsonRpcResponse> {
    serde_json::from_slice::<JsonRpcRequest>(raw).map_err(|err| {
        JsonRpcResponse::err(Value::Null, PARSE_ERROR, format!("parse error: {err}"))
    })
}

/// Validate the structural constraints of a parsed JSON-RPC 2.0 envelope.
///
/// Returns `None` when the request is valid; `Some(error_response)` when it
/// violates the protocol (e.g. `jsonrpc` is not `"2.0"`).
pub fn validate_request(req: &JsonRpcRequest) -> Option<JsonRpcResponse> {
    if req.jsonrpc != "2.0" {
        Some(JsonRpcResponse::err(
            req.id.clone(),
            INVALID_REQUEST,
            r#"jsonrpc field must be "2.0""#,
        ))
    } else {
        None
    }
}

// ---------------------------------------------------------------------------
// Protocol dispatch
// ---------------------------------------------------------------------------

/// Dispatch a validated JSON-RPC request to the appropriate MCP handler.
///
/// Returns `None` for notifications (requests whose `id` is null or absent)
/// because the MCP/JSON-RPC spec prohibits sending a response to a notification.
///
/// `ctx` carries the caller's identity (policies, principal) extracted from
/// the inbound transport and forwarded verbatim to backend services.
pub async fn dispatch(
    req: JsonRpcRequest,
    state: &AppState,
    ctx: CallerContext,
) -> Option<JsonRpcResponse> {
    // A null id marks a notification — never respond to these.
    let is_notification = req.id.is_null();
    let id = req.id.clone();

    let response = match req.method.as_str() {
        "initialize" => handle_initialize(id),

        "notifications/initialized" => {
            // The client sends this after `initialize`; no response is expected.
            debug!("received notifications/initialized — acknowledging without response");
            return None;
        }

        "ping" => {
            // Return an empty object per MCP spec ping/pong semantics.
            JsonRpcResponse::ok(id, serde_json::json!({}))
        }

        "tools/list" => handle_tools_list(id),

        "tools/call" => handle_tools_call(id, &req.params, state, ctx).await,

        unknown_method => {
            // Unknown notifications are silently ignored per JSON-RPC spec §4.
            if is_notification {
                debug!(method = %unknown_method, "ignoring unknown notification");
                return None;
            }
            JsonRpcResponse::err(
                id,
                METHOD_NOT_FOUND,
                format!("method not found: {unknown_method}"),
            )
        }
    };

    // Suppress the response for any non-notification that somehow ended up
    // here with a null id (defensive guard).
    if is_notification {
        None
    } else {
        Some(response)
    }
}

// ---------------------------------------------------------------------------
// Individual MCP method handlers
// ---------------------------------------------------------------------------

/// Handle the `initialize` handshake.
///
/// Returns the server's protocol version and capability set.  The client uses
/// this to verify compatibility before sending any other requests.
fn handle_initialize(id: Value) -> JsonRpcResponse {
    let result = serde_json::json!({
        "protocolVersion": "2024-11-05",
        "capabilities": {
            // Advertise tool support; no resource or prompt capabilities yet.
            "tools": {}
        },
        "serverInfo": {
            "name": "wslvault-mcp-server",
            "version": env!("CARGO_PKG_VERSION")
        }
    });
    JsonRpcResponse::ok(id, result)
}

/// Handle `tools/list`.
///
/// Converts the existing [`tools::ToolDefinition`] slice into the camelCase
/// `McpTool` format required by MCP spec 2024-11-05 §4.2.1.
fn handle_tools_list(id: Value) -> JsonRpcResponse {
    let mcp_tools: Vec<McpTool> = tools::all_tool_definitions()
        .into_iter()
        .map(|def| McpTool {
            name: def.name,
            description: def.description,
            // `input_schema` is already a JSON Schema object; just rename the key.
            input_schema: def.input_schema,
        })
        .collect();

    JsonRpcResponse::ok(id, serde_json::json!({ "tools": mcp_tools }))
}

/// Handle `tools/call`.
///
/// Extracts `params.name` and `params.arguments` from the JSON-RPC params,
/// delegates to [`tools::dispatch_tool`], and wraps the result in the MCP
/// `content` / `isError` shape.
///
/// Tool-level failures (e.g. backend unreachable, unknown tool name) are
/// returned as successful JSON-RPC responses with `isError: true` — this is
/// the MCP convention for distinguishing protocol errors from tool errors.
async fn handle_tools_call(
    id: Value,
    params: &Value,
    state: &AppState,
    ctx: CallerContext,
) -> JsonRpcResponse {
    let tool_name = match params.get("name").and_then(|v| v.as_str()) {
        Some(name) => name.to_owned(),
        None => {
            return JsonRpcResponse::err(
                id,
                INVALID_PARAMS,
                "params.name is required and must be a string",
            );
        }
    };

    // `arguments` is optional; default to an empty object when absent so that
    // tool handlers receive a consistent type.
    let arguments = params
        .get("arguments")
        .cloned()
        .unwrap_or_else(|| serde_json::json!({}));

    let call_response = tools::dispatch_tool(state, &tool_name, arguments, ctx).await;

    // `isError` is explicitly set to false on success so callers don't have to
    // special-case its absence.
    let result = serde_json::json!({
        "content": call_response.content,
        "isError": call_response.is_error.unwrap_or(false)
    });

    JsonRpcResponse::ok(id, result)
}

// ---------------------------------------------------------------------------
// Unit tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    /// Build an AppState whose service URLs point to localhost ports that are
    /// guaranteed to be closed, so tool-handler tests exercise the error path
    /// without requiring a real backend.
    fn unreachable_state() -> AppState {
        AppState {
            // Using high ephemeral-range ports that are never bound in CI.
            secret_engine_url: "http://127.0.0.1:19981".into(),
            transit_engine_url: "http://127.0.0.1:19982".into(),
            audit_engine_url: "http://127.0.0.1:19983".into(),
            auth_required: false,
        }
    }

    // -----------------------------------------------------------------------
    // parse_request
    // -----------------------------------------------------------------------

    #[test]
    fn parse_request_accepts_valid_envelope() {
        let raw = br#"{"jsonrpc":"2.0","id":1,"method":"ping","params":{}}"#;
        let result = parse_request(raw);
        assert!(
            result.is_ok(),
            "well-formed JSON-RPC should parse without error"
        );
        let req = result.unwrap();
        assert_eq!(req.method, "ping");
        assert_eq!(req.id, json!(1));
    }

    #[test]
    fn parse_request_accepts_notification_without_id() {
        let raw = br#"{"jsonrpc":"2.0","method":"notifications/initialized"}"#;
        let result = parse_request(raw);
        assert!(result.is_ok(), "notification without id field should parse");
        let req = result.unwrap();
        // `id` defaults to `Value::Null` when absent.
        assert!(req.id.is_null(), "absent id must deserialise as null");
    }

    #[test]
    fn parse_request_returns_parse_error_for_invalid_json() {
        let raw = b"not json {{{";
        let result = parse_request(raw);
        assert!(result.is_err(), "invalid JSON must produce an Err");
        let err_resp = result.unwrap_err();
        assert_eq!(
            err_resp.error.as_ref().unwrap().code,
            PARSE_ERROR,
            "error code must be PARSE_ERROR (-32700)"
        );
        // The id must be null because we could not extract it from malformed input.
        assert!(err_resp.id.is_null());
    }

    // -----------------------------------------------------------------------
    // validate_request
    // -----------------------------------------------------------------------

    #[test]
    fn validate_request_rejects_wrong_jsonrpc_version() {
        let req = JsonRpcRequest {
            jsonrpc: "1.0".into(),
            id: json!(1),
            method: "ping".into(),
            params: json!({}),
        };
        let err = validate_request(&req);
        assert!(err.is_some(), "validation must fail for jsonrpc != '2.0'");
        assert_eq!(
            err.unwrap().error.unwrap().code,
            INVALID_REQUEST,
            "wrong jsonrpc version must produce INVALID_REQUEST (-32600)"
        );
    }

    #[test]
    fn validate_request_accepts_correct_version() {
        let req = JsonRpcRequest {
            jsonrpc: "2.0".into(),
            id: json!(99),
            method: "tools/list".into(),
            params: json!({}),
        };
        assert!(
            validate_request(&req).is_none(),
            "valid request must pass validation"
        );
    }

    // -----------------------------------------------------------------------
    // initialize
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn initialize_returns_protocol_version_and_capabilities() {
        let req = JsonRpcRequest {
            jsonrpc: "2.0".into(),
            id: json!(1),
            method: "initialize".into(),
            params: json!({}),
        };
        let state = unreachable_state();
        let resp = dispatch(req, &state, CallerContext::default())
            .await
            .expect("initialize must return a response (not a notification)");

        assert!(
            resp.error.is_none(),
            "initialize must succeed: {:?}",
            resp.error
        );
        let result = resp.result.unwrap();

        assert_eq!(
            result["protocolVersion"], "2024-11-05",
            "protocolVersion must match the chosen MCP spec revision"
        );
        assert!(
            result["capabilities"]["tools"].is_object(),
            "capabilities.tools must be an object"
        );
        assert_eq!(
            result["serverInfo"]["name"], "wslvault-mcp-server",
            "serverInfo.name must identify this server"
        );
        // `version` is injected at compile time from Cargo.toml.
        assert!(
            result["serverInfo"]["version"].is_string(),
            "serverInfo.version must be a string"
        );
    }

    // -----------------------------------------------------------------------
    // notifications/initialized
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn notifications_initialized_produces_no_response() {
        // MCP spec: server must not send a response to a notification.
        let req = JsonRpcRequest {
            jsonrpc: "2.0".into(),
            id: Value::Null, // notifications carry no id
            method: "notifications/initialized".into(),
            params: json!({}),
        };
        let state = unreachable_state();
        let resp = dispatch(req, &state, CallerContext::default()).await;
        assert!(
            resp.is_none(),
            "notifications/initialized must not produce a JSON-RPC response"
        );
    }

    // -----------------------------------------------------------------------
    // ping
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn ping_returns_empty_result_object() {
        let req = JsonRpcRequest {
            jsonrpc: "2.0".into(),
            id: json!(42),
            method: "ping".into(),
            params: json!({}),
        };
        let state = unreachable_state();
        let resp = dispatch(req, &state, CallerContext::default())
            .await
            .expect("ping must return a response");
        assert!(resp.error.is_none(), "ping must not return an error");
        assert!(resp.result.is_some(), "ping must carry a result field");
    }

    // -----------------------------------------------------------------------
    // tools/list
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn tools_list_returns_all_ten_tools_with_correct_shape() {
        let req = JsonRpcRequest {
            jsonrpc: "2.0".into(),
            id: json!(2),
            method: "tools/list".into(),
            params: json!({}),
        };
        let state = unreachable_state();
        let resp = dispatch(req, &state, CallerContext::default())
            .await
            .expect("tools/list must return a response");

        assert!(resp.error.is_none(), "tools/list must succeed");
        let result = resp.result.unwrap();
        let tool_array = result["tools"]
            .as_array()
            .expect("result.tools must be a JSON array");

        // The codebase defines exactly 10 WSLVault tools.
        assert_eq!(
            tool_array.len(),
            10,
            "expected exactly 10 tools, got {}",
            tool_array.len()
        );

        // Every tool must satisfy the MCP tool schema shape (spec §4.2.1).
        for tool in tool_array {
            let name = tool["name"].as_str().expect("tool.name must be a string");
            assert!(
                tool["description"].is_string(),
                "tool '{name}'.description must be a string"
            );
            assert!(
                tool["inputSchema"].is_object(),
                "tool '{name}'.inputSchema must be an object (camelCase per MCP spec)"
            );
            // Verify the camelCase field — `input_schema` (snake_case) must not appear.
            assert!(
                tool.get("input_schema").is_none(),
                "tool '{name}' must not expose snake_case 'input_schema' key"
            );
        }
    }

    // -----------------------------------------------------------------------
    // tools/call — routing and error handling
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn tools_call_unknown_tool_name_returns_is_error_true() {
        // When the tool name is unrecognised, dispatch_tool returns isError=true
        // in the MCP result — not a JSON-RPC protocol error.
        let req = JsonRpcRequest {
            jsonrpc: "2.0".into(),
            id: json!(3),
            method: "tools/call".into(),
            params: json!({ "name": "completely_unknown_tool", "arguments": {} }),
        };
        let state = unreachable_state();
        let resp = dispatch(req, &state, CallerContext::default())
            .await
            .expect("tools/call must always return a JSON-RPC response");

        // The JSON-RPC envelope must be a success (error is a tool-level concern).
        assert!(
            resp.error.is_none(),
            "JSON-RPC envelope must not carry an error for tool failures"
        );
        let result = resp.result.unwrap();
        assert_eq!(
            result["isError"],
            json!(true),
            "unknown tool must set isError=true in the MCP result"
        );
        // The content array must carry an error message.
        let content = result["content"]
            .as_array()
            .expect("content must be an array");
        assert!(!content.is_empty(), "error content must not be empty");
    }

    #[tokio::test]
    async fn tools_call_unreachable_backend_returns_is_error_true() {
        // read_secret against a closed port produces a connection-refused error.
        // The MCP contract: tool errors → isError=true, not a JSON-RPC -32xxx error.
        let req = JsonRpcRequest {
            jsonrpc: "2.0".into(),
            id: json!(4),
            method: "tools/call".into(),
            params: json!({
                "name": "read_secret",
                "arguments": {
                    "path": "prod/database",
                    "tenant_id": "tenant-test"
                }
            }),
        };
        let state = unreachable_state();
        let resp = dispatch(req, &state, CallerContext::default())
            .await
            .expect("tools/call must return a response even when the backend is unreachable");

        assert!(
            resp.error.is_none(),
            "JSON-RPC envelope must not carry a protocol error for backend failures"
        );
        let result = resp.result.unwrap();
        assert_eq!(
            result["isError"],
            json!(true),
            "backend connection failure must produce isError=true"
        );

        // Verify the error message hints at the network failure.
        let content = result["content"]
            .as_array()
            .expect("content must be an array");
        let error_text = content[0]["text"]
            .as_str()
            .expect("content[0].text must be a string");
        assert!(
            error_text.contains("request failed"),
            "error text must describe the network failure; got: {error_text}"
        );
    }

    #[tokio::test]
    async fn tools_call_missing_name_field_returns_invalid_params() {
        // When `params.name` is absent, the handler must return -32602.
        let req = JsonRpcRequest {
            jsonrpc: "2.0".into(),
            id: json!(5),
            method: "tools/call".into(),
            params: json!({ "arguments": { "path": "x", "tenant_id": "t" } }),
        };
        let state = unreachable_state();
        let resp = dispatch(req, &state, CallerContext::default())
            .await
            .expect("tools/call must return a response");
        let err = resp
            .error
            .expect("missing params.name must produce a JSON-RPC error");
        assert_eq!(
            err.code, INVALID_PARAMS,
            "missing params.name must use INVALID_PARAMS (-32602), got {}",
            err.code
        );
    }

    // -----------------------------------------------------------------------
    // Method not found
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn unknown_method_with_id_returns_method_not_found() {
        let req = JsonRpcRequest {
            jsonrpc: "2.0".into(),
            id: json!(6),
            method: "vault/nonexistent".into(),
            params: json!({}),
        };
        let state = unreachable_state();
        let resp = dispatch(req, &state, CallerContext::default())
            .await
            .expect("unknown method must produce a response when id is present");
        let err = resp
            .error
            .expect("unknown method must produce a JSON-RPC error");
        assert_eq!(
            err.code, METHOD_NOT_FOUND,
            "unknown method must use METHOD_NOT_FOUND (-32601), got {}",
            err.code
        );
    }

    #[tokio::test]
    async fn unknown_notification_produces_no_response() {
        // Unknown notifications (id=null) must be silently dropped.
        let req = JsonRpcRequest {
            jsonrpc: "2.0".into(),
            id: Value::Null,
            method: "notifications/unknown_future_event".into(),
            params: json!({}),
        };
        let state = unreachable_state();
        let resp = dispatch(req, &state, CallerContext::default()).await;
        assert!(
            resp.is_none(),
            "unknown notification must produce no response"
        );
    }

    // -----------------------------------------------------------------------
    // CallerContext — header extraction
    // -----------------------------------------------------------------------

    #[test]
    fn caller_context_from_headers_extracts_policies_and_principal_id() {
        use crate::tools::caller_context_from_headers;
        use axum::http::HeaderMap;

        let mut headers = HeaderMap::new();
        headers.insert("x-policies", "read_secrets,write_secrets".parse().unwrap());
        headers.insert("x-principal-id", "user-abc-123".parse().unwrap());

        let ctx = caller_context_from_headers(&headers);

        assert_eq!(
            ctx.policies.as_deref(),
            Some("read_secrets,write_secrets"),
            "X-Policies header must be captured in CallerContext.policies"
        );
        assert_eq!(
            ctx.principal_id.as_deref(),
            Some("user-abc-123"),
            "X-Principal-Id header must be captured in CallerContext.principal_id"
        );
    }

    #[test]
    fn caller_context_from_headers_yields_none_for_absent_headers() {
        use crate::tools::caller_context_from_headers;
        use axum::http::HeaderMap;

        let headers = HeaderMap::new();
        let ctx = caller_context_from_headers(&headers);

        assert!(
            ctx.policies.is_none(),
            "absent X-Policies must produce None in CallerContext.policies"
        );
        assert!(
            ctx.principal_id.is_none(),
            "absent X-Principal-Id must produce None in CallerContext.principal_id"
        );
    }

    #[test]
    fn caller_context_from_headers_treats_empty_value_as_none() {
        use crate::tools::caller_context_from_headers;
        use axum::http::HeaderMap;

        let mut headers = HeaderMap::new();
        headers.insert("x-policies", "".parse().unwrap());
        headers.insert("x-principal-id", "".parse().unwrap());

        let ctx = caller_context_from_headers(&headers);

        assert!(
            ctx.policies.is_none(),
            "empty X-Policies must produce None (not an empty string)"
        );
        assert!(
            ctx.principal_id.is_none(),
            "empty X-Principal-Id must produce None (not an empty string)"
        );
    }

    #[tokio::test]
    async fn tools_call_with_caller_context_reaches_dispatch_tool() {
        // Verify that a non-default CallerContext is accepted end-to-end by the
        // dispatch pipeline.  The backend is unreachable, so we expect isError=true,
        // but the call must not panic or return a protocol error.
        let req = JsonRpcRequest {
            jsonrpc: "2.0".into(),
            id: json!(99),
            method: "tools/call".into(),
            params: json!({
                "name": "read_secret",
                "arguments": {
                    "path": "prod/api-key",
                    "tenant_id": "tenant-xyz"
                }
            }),
        };
        let state = unreachable_state();
        let ctx = CallerContext {
            policies: Some("read_secrets".into()),
            principal_id: Some("svc-account-1".into()),
            token: Some("test-token".into()),
        };
        let resp = dispatch(req, &state, ctx)
            .await
            .expect("tools/call must return a response");

        // Backend is unreachable — tool error, not protocol error.
        assert!(
            resp.error.is_none(),
            "JSON-RPC envelope must not carry a protocol error when caller context is present"
        );
        let result = resp.result.unwrap();
        assert_eq!(
            result["isError"],
            json!(true),
            "unreachable backend must produce isError=true even with caller context"
        );
    }
}
