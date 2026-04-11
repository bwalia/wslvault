//! PostgreSQL-backed implementation of `AuditStoreBackend`.
//!
//! Delegates all storage operations to `wslvault_storage::audit_store`,
//! converting between the service-level `AuditRecord` type and the storage
//! crate's `StoredAuditEvent` type.
//!
//! Any errors returned by the storage layer are logged and swallowed for
//! `insert_record` (to match the infallible in-memory signature), and
//! converted to empty result sets for queries.

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use tracing::error;

use wslvault_storage::audit_store::{self, StoredAuditEvent};
use wslvault_storage::pool::DbPool;

use crate::store::{AuditRecord, AuditStoreBackend};

/// PostgreSQL-backed audit store.
///
/// Uses a shared `DbPool` cloned from the service's connection pool.
pub struct PgAuditBackend {
    pool: DbPool,
}

impl PgAuditBackend {
    /// Construct a new `PgAuditBackend` using the provided connection pool.
    pub fn new(pool: DbPool) -> Self {
        Self { pool }
    }
}

/// Convert an `AuditRecord` (service layer) into a `StoredAuditEvent` (storage layer).
fn record_to_stored(record: AuditRecord) -> StoredAuditEvent {
    StoredAuditEvent {
        id: record.id,
        tenant_id: record.tenant_id,
        principal_id: record.principal_id,
        action: record.action,
        resource: record.resource,
        outcome: record.outcome,
        outcome_detail: record.outcome_detail,
        details: record.details,
        client_ip: record.client_ip,
        signature: record.signature,
        timestamp: record.timestamp,
    }
}

/// Convert a `StoredAuditEvent` (storage layer) back into an `AuditRecord` (service layer).
fn stored_to_record(event: StoredAuditEvent) -> AuditRecord {
    AuditRecord {
        id: event.id,
        tenant_id: event.tenant_id,
        principal_id: event.principal_id,
        action: event.action,
        resource: event.resource,
        outcome: event.outcome,
        outcome_detail: event.outcome_detail,
        details: event.details,
        client_ip: event.client_ip,
        signature: event.signature,
        timestamp: event.timestamp,
    }
}

#[async_trait]
impl AuditStoreBackend for PgAuditBackend {
    /// Persist the record to PostgreSQL.
    ///
    /// Errors are logged rather than propagated because the trait signature is
    /// infallible (mirroring the in-memory backend).  A failed insert should
    /// never crash the server; instead the error surfaces in structured logs.
    async fn insert_record(&self, record: AuditRecord) {
        let event = record_to_stored(record);
        if let Err(err) = audit_store::insert_event(&self.pool, &event).await {
            error!(
                event_id = %event.id,
                error = %err,
                "failed to persist audit event to PostgreSQL"
            );
        }
    }

    /// Query events from PostgreSQL with optional filters.
    ///
    /// On database error the function logs the error and returns an empty
    /// result set so the gRPC caller receives a successful (but empty)
    /// response rather than an internal error for transient failures.
    async fn query_events(
        &self,
        tenant_id: &str,
        start_time: Option<DateTime<Utc>>,
        end_time: Option<DateTime<Utc>>,
        action_filter: Option<&str>,
        principal_filter: Option<&str>,
        limit: usize,
        offset: usize,
    ) -> (Vec<AuditRecord>, usize) {
        // The storage layer uses i32 for limit/offset; clamp to i32::MAX.
        let pg_limit = limit.min(i32::MAX as usize) as i32;
        let pg_offset = offset.min(i32::MAX as usize) as i32;

        match audit_store::query_events(
            &self.pool,
            Some(tenant_id),
            start_time,
            end_time,
            action_filter,
            principal_filter,
            pg_limit,
            pg_offset,
        )
        .await
        {
            Ok((events, total)) => {
                let records = events.into_iter().map(stored_to_record).collect();
                (records, total as usize)
            }
            Err(err) => {
                error!(
                    tenant_id = %tenant_id,
                    error = %err,
                    "failed to query audit events from PostgreSQL"
                );
                (Vec::new(), 0)
            }
        }
    }
}
