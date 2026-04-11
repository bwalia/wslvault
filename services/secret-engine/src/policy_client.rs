//! Policy enforcement client for the secret-engine.
//!
//! This module provides a thin async client that delegates authorization
//! decisions to the policy-engine via gRPC.  The policy check MUST happen
//! before any store or crypto operation so that data is never read or written
//! without a successful authorization decision.
//!
//! # Fail-closed behaviour
//! If the policy-engine is unreachable or returns an error the request is
//! denied immediately.  This ensures that a network partition between the
//! secret-engine and the policy-engine never silently grants access.

use tracing::{info, warn};

use wslvault_core::VaultError;

// Include only the generated policy proto types here.  The secret and crypto
// protos remain in grpc.rs to keep each module self-contained.
pub mod policy_proto {
    tonic::include_proto!("wslvault.policy.v1");
}

use policy_proto::policy_service_client::PolicyServiceClient;

/// Thin gRPC client for the policy-engine `Authorize` RPC.
///
/// The struct stores only the endpoint URL so that each call can open a fresh
/// connection.  In a production deployment this should be replaced by a
/// connection pool (e.g. via `tonic::transport::Channel::balance_list`), but a
/// per-call connect is sufficient for the initial implementation and avoids
/// lifetime and clone complexity.
#[derive(Debug, Clone)]
pub struct PolicyClient {
    /// Base URL of the policy-engine gRPC server, e.g. `http://policy-engine:50053`.
    endpoint: String,
}

impl PolicyClient {
    /// Create a new `PolicyClient` pointing at the given gRPC endpoint.
    pub fn new(endpoint: String) -> Self {
        Self { endpoint }
    }

    /// Check whether `principal_id` is permitted to perform `action` on `resource`.
    ///
    /// The function returns `Ok(())` when the policy-engine responds with
    /// `allowed = true`, and a `VaultError::PermissionDenied` otherwise.
    ///
    /// Any transport error or gRPC-level failure is mapped to
    /// `VaultError::ServiceUnavailable` so that the caller can surface a
    /// `503 Service Unavailable` response rather than silently allowing access.
    ///
    /// # Arguments
    /// * `tenant_id`    — The tenant scope for policy evaluation.
    /// * `principal_id` — The identity making the request (e.g. a token UUID or
    ///                    service account name).
    /// * `policies`     — The policy names attached to the principal, parsed
    ///                    from the `X-Policies` request header.
    /// * `action`       — The operation being attempted (`"read"`, `"write"`,
    ///                    `"delete"`, or `"list"`).
    /// * `resource`     — The resource path being accessed, e.g.
    ///                    `"secret/data/my/path"`.
    pub async fn authorize(
        &self,
        tenant_id: &str,
        principal_id: &str,
        policies: &[String],
        action: &str,
        resource: &str,
    ) -> Result<(), VaultError> {
        let mut client = PolicyServiceClient::connect(self.endpoint.clone())
            .await
            .map_err(|connect_err| {
                warn!(
                    error = %connect_err,
                    endpoint = %self.endpoint,
                    "policy-engine unavailable, denying request (fail-closed)"
                );
                VaultError::ServiceUnavailable {
                    service: "policy-engine".into(),
                }
            })?;

        let response = client
            .authorize(policy_proto::AuthorizeRequest {
                tenant_id: tenant_id.to_string(),
                principal_id: principal_id.to_string(),
                policies: policies.to_vec(),
                action: action.to_string(),
                resource: resource.to_string(),
            })
            .await
            .map_err(|rpc_err| {
                warn!(
                    error = %rpc_err,
                    principal_id = %principal_id,
                    action = %action,
                    resource = %resource,
                    "policy-engine authorize RPC failed, denying request (fail-closed)"
                );
                VaultError::ServiceUnavailable {
                    service: "policy-engine".into(),
                }
            })?
            .into_inner();

        if response.allowed {
            info!(
                principal_id = %principal_id,
                action = %action,
                resource = %resource,
                matched_policy = %response.matched_policy,
                "policy-engine authorized request"
            );
            Ok(())
        } else {
            // Build a human-readable denial reason, falling back to a generic
            // message when the policy-engine does not supply one.
            let reason = if response.reason.is_empty() {
                "policy denied".to_string()
            } else {
                response.reason.clone()
            };

            warn!(
                principal_id = %principal_id,
                action = %action,
                resource = %resource,
                reason = %reason,
                "policy-engine denied request"
            );

            Err(VaultError::PermissionDenied {
                resource: resource.to_string(),
                reason,
            })
        }
    }
}

// ---------------------------------------------------------------------------
// Header extraction helpers
// ---------------------------------------------------------------------------

/// Extract the `X-Principal-Id` header value from an HTTP `HeaderMap`.
///
/// Defaults to `"anonymous"` when the header is absent or contains a
/// non-UTF-8 value, matching the fail-open convention for identity — the
/// policy-engine is still consulted and will deny the anonymous principal
/// unless an explicit allow policy exists.
pub fn extract_principal_id(headers: &axum::http::HeaderMap) -> String {
    headers
        .get("x-principal-id")
        .and_then(|v| v.to_str().ok())
        .filter(|s| !s.is_empty())
        .unwrap_or("anonymous")
        .to_string()
}

/// Extract the `X-Policies` header value and split it into individual policy
/// names.
///
/// The header value is expected to be a comma-separated list of policy names,
/// e.g. `"default,readonly-secrets"`.  Whitespace around each name is trimmed.
/// Returns an empty `Vec` when the header is absent.
pub fn extract_policies(headers: &axum::http::HeaderMap) -> Vec<String> {
    headers
        .get("x-policies")
        .and_then(|v| v.to_str().ok())
        .map(|raw| {
            raw.split(',')
                .map(|p| p.trim().to_string())
                .filter(|p| !p.is_empty())
                .collect()
        })
        .unwrap_or_default()
}

/// Extract the `X-Principal-Id` header from a tonic request metadata map.
///
/// Mirrors `extract_principal_id` for the gRPC surface. Returns `"anonymous"`
/// when the metadata key is missing or not valid ASCII.
pub fn extract_grpc_principal_id(metadata: &tonic::metadata::MetadataMap) -> String {
    metadata
        .get("x-principal-id")
        .and_then(|v| v.to_str().ok())
        .filter(|s| !s.is_empty())
        .unwrap_or("anonymous")
        .to_string()
}

/// Extract comma-separated policy names from the `x-policies` gRPC metadata key.
///
/// Returns an empty `Vec` when the key is absent.
pub fn extract_grpc_policies(metadata: &tonic::metadata::MetadataMap) -> Vec<String> {
    metadata
        .get("x-policies")
        .and_then(|v| v.to_str().ok())
        .map(|raw| {
            raw.split(',')
                .map(|p| p.trim().to_string())
                .filter(|p| !p.is_empty())
                .collect()
        })
        .unwrap_or_default()
}
