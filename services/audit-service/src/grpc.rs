//! gRPC service implementation for the audit-service.
//!
//! Implements the `AuditService` trait generated from the
//! `wslvault.audit.v1` proto package. Each handler signs events before
//! storing them and applies filtering for queries.

use std::sync::Arc;

use chrono::DateTime;
use tonic::{Request, Response, Status};
use uuid::Uuid;

use crate::integrity::sign_event;
use crate::store::{AuditRecord, AuditStoreBackend};

use proto::audit_service_server::AuditService;
use proto::{
    AuditEventInfo, EmitEventRequest, EmitEventResponse, QueryEventsRequest, QueryEventsResponse,
};

pub mod proto {
    tonic::include_proto!("wslvault.audit.v1");
}

/// The HMAC signing key used to sign audit records.
///
/// In production this would be fetched from the secrets manager per tenant.
/// For this in-process implementation a static env-provided fallback is used.
const DEFAULT_SIGNING_KEY: &[u8] = b"wslvault-audit-default-hmac-key-256bits!!";

/// Concrete gRPC service handler.
#[derive(Clone)]
pub struct AuditServiceImpl {
    store: Arc<dyn AuditStoreBackend>,
    /// HMAC-SHA256 signing key (shared across all tenants for this implementation).
    signing_key: Vec<u8>,
}

impl AuditServiceImpl {
    pub fn new(store: Arc<dyn AuditStoreBackend>) -> Self {
        // Load the signing key from the environment; fall back to the constant
        // default if not configured so the service starts without crashing.
        let signing_key = std::env::var("AUDIT_SIGNING_KEY")
            .map(|k| k.into_bytes())
            .unwrap_or_else(|_| DEFAULT_SIGNING_KEY.to_vec());

        Self { store, signing_key }
    }
}

#[tonic::async_trait]
impl AuditService for AuditServiceImpl {
    /// Accept an audit event, sign it for integrity, and persist it.
    async fn emit_event(
        &self,
        request: Request<EmitEventRequest>,
    ) -> Result<Response<EmitEventResponse>, Status> {
        let req = request.into_inner();

        if req.tenant_id.is_empty() {
            return Err(Status::invalid_argument("tenant_id is required"));
        }
        if req.action.is_empty() {
            return Err(Status::invalid_argument("action is required"));
        }

        // Parse details_json; treat an empty string as a null JSON value.
        let details: serde_json::Value = if req.details_json.is_empty() {
            serde_json::Value::Null
        } else {
            serde_json::from_str(&req.details_json)
                .map_err(|e| Status::invalid_argument(format!("invalid details_json: {}", e)))?
        };

        // Build the record without the signature so we can compute it.
        let mut record = AuditRecord {
            id: Uuid::now_v7(),
            tenant_id: req.tenant_id,
            principal_id: req.principal_id,
            action: req.action,
            resource: req.resource,
            outcome: req.outcome,
            outcome_detail: req.outcome_detail,
            details,
            client_ip: req.client_ip,
            signature: String::new(),
            timestamp: chrono::Utc::now(),
        };

        // Sign the record over all integrity-protected fields.
        record.signature = sign_event(&record, &self.signing_key);

        let event_id = record.id.to_string();
        self.store.insert_record(record).await;

        Ok(Response::new(EmitEventResponse { event_id }))
    }

    /// Query events with optional filters.
    async fn query_events(
        &self,
        request: Request<QueryEventsRequest>,
    ) -> Result<Response<QueryEventsResponse>, Status> {
        let req = request.into_inner();

        if req.tenant_id.is_empty() {
            return Err(Status::invalid_argument("tenant_id is required"));
        }

        // Parse optional RFC-3339 timestamps.
        let start_time = parse_optional_timestamp(&req.start_time)?;
        let end_time = parse_optional_timestamp(&req.end_time)?;

        let action_filter = if req.action_filter.is_empty() {
            None
        } else {
            Some(req.action_filter.as_str())
        };

        let principal_filter = if req.principal_filter.is_empty() {
            None
        } else {
            Some(req.principal_filter.as_str())
        };

        let limit = req.limit.max(0) as usize;
        let offset = req.offset.max(0) as usize;

        let (records, total_count) = self
            .store
            .query_events(
                &req.tenant_id,
                start_time,
                end_time,
                action_filter,
                principal_filter,
                limit,
                offset,
            )
            .await;

        let events: Vec<AuditEventInfo> = records
            .into_iter()
            .map(|r| AuditEventInfo {
                event_id: r.id.to_string(),
                tenant_id: r.tenant_id,
                principal_id: r.principal_id,
                action: r.action,
                resource: r.resource,
                outcome: r.outcome,
                timestamp: r.timestamp.to_rfc3339(),
                client_ip: r.client_ip,
            })
            .collect();

        Ok(Response::new(QueryEventsResponse {
            events,
            total_count: total_count as i64,
        }))
    }
}

/// Parse an RFC-3339 timestamp string.  Empty strings return `Ok(None)`.
#[allow(clippy::result_large_err)]
fn parse_optional_timestamp(s: &str) -> Result<Option<DateTime<chrono::Utc>>, Status> {
    if s.is_empty() {
        return Ok(None);
    }
    DateTime::parse_from_rfc3339(s)
        .map(|dt| Some(dt.with_timezone(&chrono::Utc)))
        .map_err(|e| Status::invalid_argument(format!("invalid timestamp '{}': {}", s, e)))
}
