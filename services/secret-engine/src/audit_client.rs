//! Audit event emission client for the secret-engine.
//!
//! Wraps the generated `AuditServiceClient` tonic stub and provides a
//! fire-and-forget `emit` method. Audit failures are logged via `tracing`
//! but never propagated to the caller — an audit outage must not block
//! secret-engine operations.

use tracing::warn;

pub mod audit_proto {
    tonic::include_proto!("wslvault.audit.v1");
}

use audit_proto::audit_service_client::AuditServiceClient;

/// Fire-and-forget audit event emitter.
///
/// Audit failures are logged but never block the main operation.
#[derive(Debug, Clone)]
pub struct AuditClient {
    channel: tonic::transport::Channel,
}

impl AuditClient {
    /// Create a new `AuditClient` targeting the given endpoint URL.
    ///
    /// The channel is lazy and shared; emission used to dial the audit-service
    /// afresh for every event.
    ///
    /// # Panics
    /// If `endpoint` is not a valid URI — a startup-time configuration error.
    pub fn new(endpoint: String) -> Self {
        let channel = wslvault_core::grpc_channel::lazy_channel(&endpoint)
            .unwrap_or_else(|e| panic!("audit-service endpoint is unusable: {e}"));
        Self { channel }
    }

    /// Emit an audit event asynchronously.
    ///
    /// The gRPC call is spawned onto a background tokio task so the caller is
    /// not blocked. If the connection or RPC fails, the error is logged at
    /// `WARN` level and silently discarded — audit failures must never cause
    /// the secret-engine to return an error to its own callers.
    pub async fn emit(
        &self,
        tenant_id: &str,
        principal_id: &str,
        action: &str,
        resource: &str,
        outcome: &str,
        outcome_detail: &str,
        details_json: &str,
        client_ip: &str,
    ) {
        let channel = self.channel.clone();
        let req = audit_proto::EmitEventRequest {
            tenant_id: tenant_id.to_string(),
            principal_id: principal_id.to_string(),
            action: action.to_string(),
            resource: resource.to_string(),
            outcome: outcome.to_string(),
            outcome_detail: outcome_detail.to_string(),
            details_json: details_json.to_string(),
            client_ip: client_ip.to_string(),
        };

        // Spawn a background task so audit emission never blocks the response.
        tokio::spawn(async move {
            let mut client = AuditServiceClient::new(channel);
            if let Err(e) = client.emit_event(tonic::Request::new(req)).await {
                warn!(error = %e, "failed to emit audit event to audit-service");
            }
        });
    }
}
