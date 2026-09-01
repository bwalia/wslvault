//! Lease management client for the secret-engine.
//!
//! Provides a thin async wrapper around the lease-manager gRPC service.
//! Lease creation is **optional** — if the lease-manager is unavailable the
//! calling operation still succeeds (degraded mode).  Only lease revocation is
//! offered as a fire-and-forget helper because it must not block responses.

use tracing::warn;

pub mod lease_proto {
    tonic::include_proto!("wslvault.lease.v1");
}

use lease_proto::lease_service_client::LeaseServiceClient;

/// Thin gRPC client for the lease-manager `LeaseService`.
///
/// Holds a lazily-connected, shared `Channel`; revocation used to dial the
/// lease-manager afresh on every call.
#[derive(Debug, Clone)]
pub struct LeaseClient {
    channel: tonic::transport::Channel,
}

/// Simplified lease info returned to the caller after a successful lease
/// creation.  Mirrors the fields that callers typically need to include in a
/// response or store for later renewal/revocation.
#[derive(Debug, Clone)]
pub struct LeaseInfo {
    /// Opaque identifier assigned by the lease-manager.
    pub lease_id: String,
    /// Duration of the lease in seconds as agreed with the lease-manager.
    pub ttl_seconds: i64,
    /// Whether the lease can be renewed before it expires.
    #[allow(dead_code)]
    pub renewable: bool,
}

impl LeaseClient {
    /// Create a new `LeaseClient` targeting `endpoint`.
    ///
    /// # Panics
    /// If `endpoint` is not a valid URI — a startup-time configuration error.
    pub fn new(endpoint: String) -> Self {
        let channel = wslvault_core::grpc_channel::lazy_channel(&endpoint)
            .unwrap_or_else(|e| panic!("lease-manager endpoint is unusable: {e}"));
        Self { channel }
    }

    /// Create a lease. Used by future dynamic engines; KV reads do not call this.
    ///
    /// Returns `Some(LeaseInfo)` on success, or `None` when lease-manager is
    /// down. Callers MUST treat `None` as non-fatal.
    #[allow(dead_code)]
    pub async fn create_lease(
        &self,
        tenant_id: &str,
        target_type: &str,
        target_data: &str,
        ttl_seconds: i64,
        max_ttl_seconds: i64,
        renewable: bool,
    ) -> Option<LeaseInfo> {
        let mut client = LeaseServiceClient::new(self.channel.clone());
        match client
            .create_lease(lease_proto::CreateLeaseRequest {
                tenant_id: tenant_id.to_string(),
                target_type: target_type.to_string(),
                target_data: target_data.to_string(),
                ttl_seconds,
                max_ttl_seconds,
                renewable,
            })
            .await
        {
            Ok(resp) => {
                let inner = resp.into_inner();
                Some(LeaseInfo {
                    lease_id: inner.lease_id,
                    ttl_seconds: inner.ttl_seconds,
                    renewable: inner.renewable,
                })
            }
            Err(e) => {
                warn!(error = %e, tenant_id, "lease-manager CreateLease failed");
                None
            }
        }
    }

    /// KV reads are not leased. HashiCorp Vault does not lease static KV
    /// either, and a row here could not revoke anything. Reserved for a
    /// future dynamic secret engine.
    #[allow(dead_code)]
    pub async fn create_lease_for_read(
        &self,
        _tenant_id: &str,
        _secret_path: &str,
        _ttl_seconds: i64,
    ) -> Option<LeaseInfo> {
        None
    }

    /// Revoke a lease by its opaque identifier.
    ///
    /// The call is spawned as a background tokio task so the caller is never
    /// blocked.  Errors are logged at `WARN` level and silently discarded —
    /// a lease-manager outage must not prevent the secret-engine from
    /// completing an otherwise successful operation.
    ///
    /// # Arguments
    /// * `lease_id` — The opaque lease identifier returned at creation time.
    #[allow(dead_code)]
    pub async fn revoke(&self, lease_id: &str) {
        let channel = self.channel.clone();
        let lease_id = lease_id.to_string();

        // Fire-and-forget: spawn a background task so the caller is not blocked.
        tokio::spawn(async move {
            let mut client = LeaseServiceClient::new(channel);
            if let Err(e) = client
                .revoke_lease(lease_proto::RevokeLeaseRequest { lease_id })
                .await
            {
                warn!(error = %e, "failed to revoke lease via lease-manager");
            }
        });
    }
}
