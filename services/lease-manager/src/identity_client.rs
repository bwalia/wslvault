//! gRPC client for identity-service token revocation callbacks.

use tracing::{error, warn};

pub mod identity_proto {
    tonic::include_proto!("wslvault.identity.v1");
}

use identity_proto::identity_service_client::IdentityServiceClient;
use identity_proto::RevokeTokenByHashRequest;

/// Thin client over a lazily-connected channel to identity-service.
#[derive(Debug, Clone)]
pub struct IdentityClient {
    channel: tonic::transport::Channel,
}

impl IdentityClient {
    /// # Panics
    /// If `endpoint` is not a valid URI — a startup-time configuration error.
    pub fn new(endpoint: &str) -> Self {
        let channel = wslvault_core::grpc_channel::lazy_channel(endpoint)
            .unwrap_or_else(|e| panic!("identity-service endpoint is unusable: {e}"));
        Self { channel }
    }

    /// Insert `token_hash` into identity's durable revocation list.
    ///
    /// Returns `Err` when identity is unreachable so callers can fail closed.
    pub async fn revoke_token_by_hash(
        &self,
        token_hash: &str,
        tenant_id: &str,
        principal_id: &str,
        expires_at: i64,
    ) -> Result<(), String> {
        let mut client = IdentityServiceClient::new(self.channel.clone());
        client
            .revoke_token_by_hash(RevokeTokenByHashRequest {
                token_hash: token_hash.to_string(),
                tenant_id: tenant_id.to_string(),
                principal_id: principal_id.to_string(),
                expires_at,
            })
            .await
            .map(|_| ())
            .map_err(|e| {
                error!(error = %e, "identity RevokeTokenByHash failed");
                format!("identity-service unreachable: {e}")
            })
    }
}

/// Build from `IDENTITY_SERVICE_GRPC` when set.
pub fn from_env() -> Option<IdentityClient> {
    match std::env::var("IDENTITY_SERVICE_GRPC") {
        Ok(ep) if !ep.trim().is_empty() => Some(IdentityClient::new(ep.trim())),
        _ => {
            warn!(
                "IDENTITY_SERVICE_GRPC is unset — token lease revoke/expire \
                 will not hit the identity revocation list"
            );
            None
        }
    }
}
