//! gRPC service implementation for the audit-service.
//!
//! Implements the `AuditService` trait generated from the
//! `wslvault.audit.v1` proto package. Each handler signs events before
//! storing them and applies filtering for queries.

use std::sync::Arc;

use chrono::DateTime;
use tonic::{Request, Response, Status};
use tracing::error;
use uuid::Uuid;

use crate::integrity::{sign_event, AuditSigner};
use crate::store::{AuditRecord, AuditStoreBackend};
use wslvault_core::metrics::collector::{AUDIT_EVENTS_BY_ACTION, AUDIT_EVENTS_TOTAL};

use proto::audit_service_server::AuditService;
use proto::{
    AuditEventInfo, EmitEventRequest, EmitEventResponse, QueryEventsRequest, QueryEventsResponse,
};

pub mod proto {
    tonic::include_proto!("wslvault.audit.v1");
}

/// Concrete gRPC service handler.
#[derive(Clone)]
pub struct AuditServiceImpl {
    store: Arc<dyn AuditStoreBackend>,
    /// Derives a distinct HMAC key per tenant from one master secret.
    ///
    /// This used to be a single `Vec<u8>` shared across every tenant, with a
    /// hardcoded fallback committed to this repository, so a deployment that
    /// had not set `AUDIT_SIGNING_KEY` produced records anyone could forge.
    signer: AuditSigner,
}

impl AuditServiceImpl {
    pub fn new(store: Arc<dyn AuditStoreBackend>, signer: AuditSigner) -> Self {
        Self { store, signer }
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
            seq: 0,
            prev_hash: String::new(),
            verified: None,
        };

        // Sign over the integrity-protected fields. The Postgres backend
        // re-signs inside its transaction once the chain position is known, so
        // the signature commits to `seq` and `prev_hash` too; this covers the
        // in-memory backend and gives the record a signature either way.
        record.signature = sign_event(&record, &self.signer.key_for(&record.tenant_id));

        let event_id = record.id.to_string();

        // Track metrics for the audit event.
        AUDIT_EVENTS_TOTAL
            .with_label_values(&[&record.outcome])
            .inc();
        AUDIT_EVENTS_BY_ACTION
            .with_label_values(&[&record.action, &record.outcome, &record.tenant_id])
            .inc();

        // Fail the emit if the record cannot be stored. Callers decide what an
        // unrecorded operation means for them; swallowing it here made that
        // decision for everyone, always, in the least safe direction.
        self.store.insert_record(record).await.map_err(|e| {
            error!(error = %e, "audit record could not be persisted");
            Status::internal(format!("audit record was not persisted: {e}"))
        })?;

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
            .await
            .map_err(|e| {
                error!(tenant_id = %req.tenant_id, error = %e, "audit query failed");
                Status::internal(format!("audit query failed: {e}"))
            })?;

        // Check the tenant's chain for structural damage — sequence gaps, or a
        // record whose prev_hash does not match its predecessor — every time
        // the log is read. Per-record signature verification catches edits;
        // this is what catches deletions and reordering.
        //
        // The result is logged rather than returned because the proto response
        // is a HashiCorp-compatible surface with nowhere to put it. An operator
        // reading the audit log gets a loud signal in the service log.
        match self.store.chain_breaks(&req.tenant_id).await {
            Ok(breaks) if !breaks.is_empty() => {
                for (at_seq, reason) in &breaks {
                    error!(
                        tenant_id = %req.tenant_id,
                        at_seq,
                        reason = %reason,
                        "AUDIT CHAIN BROKEN — records have been removed or reordered"
                    );
                }
            }
            Ok(_) => {}
            Err(e) => error!(
                tenant_id = %req.tenant_id,
                error = %e,
                "could not verify the audit chain"
            ),
        }

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
