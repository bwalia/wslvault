//! Best-effort CreateLease against lease-manager.
//!
//! Login still returns a JWT if this fails (degraded mode). Only tokens that
//! got a row can be killed by lease revoke/expire.

use std::sync::OnceLock;

use tracing::warn;
use wslvault_storage::revocation_store::token_hash;

pub mod lease_proto {
    tonic::include_proto!("wslvault.lease.v1");
}

use lease_proto::lease_service_client::LeaseServiceClient;
use lease_proto::CreateLeaseRequest;

/// Default token TTL used across identity issue paths (seconds).
pub const TOKEN_LEASE_TTL_SECONDS: i64 = 3600;
/// Hard cap on token lease bookkeeping (v1 renew does not extend JWT `exp`).
pub const TOKEN_LEASE_MAX_TTL_SECONDS: i64 = 86_400;

#[derive(Clone)]
struct LeaseClient {
    channel: tonic::transport::Channel,
}

static CLIENT: OnceLock<LeaseClient> = OnceLock::new();

/// Call once at startup when `LEASE_MANAGER_ENDPOINT` is set.
pub fn init(endpoint: String) {
    let channel = wslvault_core::grpc_channel::lazy_channel(&endpoint)
        .unwrap_or_else(|e| panic!("lease-manager endpoint is unusable: {e}"));
    if CLIENT.set(LeaseClient { channel }).is_err() {
        warn!("lease-manager client already initialised");
    }
}

/// Create a token lease. Returns `None` when lease-manager is down or unconfigured.
pub async fn try_create_token_lease(
    tenant_id: &str,
    principal_id: &str,
    token: &str,
    ttl_seconds: i64,
) -> Option<String> {
    let Some(client) = CLIENT.get() else {
        return None;
    };

    let ttl = if ttl_seconds > 0 {
        ttl_seconds
    } else {
        TOKEN_LEASE_TTL_SECONDS
    };
    let hash = token_hash(token);
    let target = wslvault_core::types::lease::LeaseTarget::Token {
        token_id: hash,
        principal_id: principal_id.to_string(),
    };
    let target_data = match serde_json::to_string(&target) {
        Ok(s) => s,
        Err(e) => {
            warn!(error = %e, "failed to serialise token lease target");
            return None;
        }
    };

    let mut grpc = LeaseServiceClient::new(client.channel.clone());
    match grpc
        .create_lease(CreateLeaseRequest {
            tenant_id: tenant_id.to_string(),
            target_type: "token".into(),
            target_data,
            ttl_seconds: ttl,
            max_ttl_seconds: TOKEN_LEASE_MAX_TTL_SECONDS,
            renewable: true,
        })
        .await
    {
        Ok(resp) => {
            let id = resp.into_inner().lease_id;
            if id.is_empty() {
                None
            } else {
                Some(id)
            }
        }
        Err(e) => {
            warn!(
                error = %e,
                tenant_id,
                principal_id,
                "lease-manager CreateLease failed; issuing token without lease_id"
            );
            None
        }
    }
}
