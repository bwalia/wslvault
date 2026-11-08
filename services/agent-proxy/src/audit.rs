//! Fire-and-forget audit emission. One event per brokered request, so every
//! use of a credential is attributable to the agent that caused it, even
//! though the agent never saw the credential.

use tracing::warn;

pub mod audit_proto {
    tonic::include_proto!("wslvault.audit.v1");
}

use audit_proto::audit_service_client::AuditServiceClient;

pub struct AuditEvent<'a> {
    pub tenant_id: &'a str,
    pub principal_id: &'a str,
    pub route: &'a str,
    pub outcome: &'a str,
    pub detail: &'a str,
    pub details_json: serde_json::Value,
}

#[derive(Clone)]
pub struct Audit {
    channel: Option<tonic::transport::Channel>,
}

impl Audit {
    /// `endpoint` of `None` disables emission (tests, local dev); events are
    /// still logged.
    pub fn new(endpoint: Option<String>) -> anyhow::Result<Self> {
        let channel = match endpoint {
            Some(e) => Some(
                wslvault_core::grpc_channel::lazy_channel(&e)
                    .map_err(|e| anyhow::anyhow!("audit-service endpoint is unusable: {e}"))?,
            ),
            None => None,
        };
        Ok(Self { channel })
    }

    pub fn emit(&self, ev: AuditEvent<'_>) {
        tracing::info!(
            tenant_id = ev.tenant_id,
            principal = ev.principal_id,
            route = ev.route,
            outcome = ev.outcome,
            detail = ev.detail,
            details = %ev.details_json,
            "agent_proxy.request"
        );
        let Some(channel) = self.channel.clone() else {
            return;
        };
        let req = audit_proto::EmitEventRequest {
            tenant_id: ev.tenant_id.to_string(),
            principal_id: ev.principal_id.to_string(),
            action: "agent_proxy.request".to_string(),
            resource: format!("broker/{}", ev.route),
            outcome: ev.outcome.to_string(),
            outcome_detail: ev.detail.to_string(),
            details_json: ev.details_json.to_string(),
            client_ip: String::new(),
        };
        tokio::spawn(async move {
            if let Err(e) = AuditServiceClient::new(channel)
                .emit_event(tonic::Request::new(req))
                .await
            {
                warn!(error = %e, "failed to emit audit event");
            }
        });
    }
}
