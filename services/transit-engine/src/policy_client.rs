//! Policy enforcement client for the transit-engine.
//!
//! This module provides a thin async client that delegates authorization
//! decisions to the policy-engine via gRPC.  The policy check MUST happen
//! before any key-store or cryptographic operation so that data is never
//! processed without a successful authorization decision.
//!
//! # Fail-closed behaviour
//! If the policy-engine is unreachable or returns an error the request is
//! denied immediately.  This ensures that a network partition between the
//! transit-engine and the policy-engine never silently grants access.

use tracing::{info, warn};

use wslvault_core::VaultError;

// Include the generated policy proto types.  The transit-engine has its own
// build.rs that compiles only the policy proto, keeping each service
// self-contained.
pub mod policy_proto {
    tonic::include_proto!("wslvault.policy.v1");
}

use policy_proto::policy_service_client::PolicyServiceClient;

/// Thin gRPC client for the policy-engine `Authorize` RPC.
///
/// The struct stores only the endpoint URL so that each call can open a fresh
/// connection.  In a production deployment this should be replaced by a
/// connection pool, but a per-call connect is sufficient for the initial
/// implementation and avoids lifetime complexity.
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
    /// Returns `Ok(())` when the policy-engine responds with `allowed = true`,
    /// and a `VaultError::PermissionDenied` otherwise.
    ///
    /// Any transport error or gRPC-level failure is mapped to
    /// `VaultError::ServiceUnavailable` (fail-closed).
    ///
    /// # Arguments
    /// * `tenant_id`    — The tenant scope for policy evaluation.
    /// * `principal_id` — The identity making the request.
    /// * `policies`     — Policy names attached to the principal, parsed from
    ///                    the `X-Policies` request header.
    /// * `action`       — The operation being attempted (`"read"` or `"write"`).
    /// * `resource`     — The resource path being accessed, e.g.
    ///                    `"transit/encrypt/my-key"`.
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
