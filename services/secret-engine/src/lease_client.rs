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
/// The struct stores only the endpoint URL so each call opens a fresh
/// connection.  This avoids lifecycle complexity while the feature is being
/// wired up; a connection pool can be introduced later without changing the
/// public API.
#[derive(Debug, Clone)]
pub struct LeaseClient {
    /// Base URL of the lease-manager gRPC server, e.g. `http://lease-manager:50055`.
    endpoint: String,
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
    pub renewable: bool,
}

impl LeaseClient {
    /// Create a new `LeaseClient` targeting `endpoint`.
    pub fn new(endpoint: String) -> Self {
        Self { endpoint }
    }

    /// Attempt to create a lease for a secret read operation.
    ///
    /// Returns `Some(LeaseInfo)` on success, or `None` when the lease-manager
    /// is unavailable or the proto does not yet expose a `CreateLease` RPC.
    /// Callers MUST treat `None` as a non-fatal degraded result — the read
    /// itself should still succeed.
    ///
    /// # Arguments
    /// * `tenant_id`    — Tenant that owns the secret.
    /// * `secret_path`  — Normalised path of the secret being read.
    /// * `ttl_seconds`  — Requested TTL; the lease-manager may enforce a cap.
    pub async fn create_lease_for_read(
        &self,
        tenant_id: &str,
        secret_path: &str,
        ttl_seconds: i64,
    ) -> Option<LeaseInfo> {
        // The lease proto does not yet include a CreateLease RPC.  Log that
        // the integration point is present but the RPC needs to be added to
        // the proto before end-to-end lease creation can be exercised.
        warn!(
            tenant_id = tenant_id,
            path = secret_path,
            ttl = ttl_seconds,
            "lease creation not yet wired (CreateLease RPC needed in proto)"
        );
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
    pub async fn revoke(&self, lease_id: &str) {
        let endpoint = self.endpoint.clone();
        let lease_id = lease_id.to_string();

        // Fire-and-forget: spawn a background task so the caller is not blocked.
        tokio::spawn(async move {
            match LeaseServiceClient::connect(endpoint).await {
                Ok(mut client) => {
                    if let Err(e) = client
                        .revoke_lease(lease_proto::RevokeLeaseRequest { lease_id })
                        .await
                    {
                        warn!(error = %e, "failed to revoke lease via lease-manager");
                    }
                }
                Err(e) => {
                    warn!(error = %e, "failed to connect to lease-manager for revocation");
                }
            }
        });
    }
}
