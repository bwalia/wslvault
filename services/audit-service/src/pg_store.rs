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
    signer: crate::integrity::AuditSigner,
}

impl PgAuditBackend {
    /// Construct a new `PgAuditBackend` using the provided connection pool.
    pub fn new(pool: DbPool, signer: crate::integrity::AuditSigner) -> Self {
        Self { pool, signer }
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
        seq: record.seq,
        prev_hash: record.prev_hash,
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
        seq: event.seq,
        prev_hash: event.prev_hash,
        verified: None,
    }
}

#[async_trait]
impl AuditStoreBackend for PgAuditBackend {
    /// Persist the record to PostgreSQL, linked into the tenant's hash chain.
    ///
    /// Errors propagate. This used to log and return `()`, so a failed insert
    /// left the audited operation succeeding with no record of it — the exact
    /// inverse of what an audit log is for.
    ///
    /// The signature is computed inside the storage transaction, once the
    /// chain position is known, so it commits to `seq` and `prev_hash` as well
    /// as the record's own fields.
    async fn insert_record(&self, record: AuditRecord) -> Result<(), String> {
        let signing_key = self.signer.key_for(&record.tenant_id);
        let record_for_signing = record.clone();
        let event = record_to_stored(record);

        audit_store::insert_event_chained(&self.pool, &event, move |seq, prev_hash| {
            crate::integrity::sign_event_chained(&record_for_signing, &signing_key, seq, prev_hash)
        })
        .await
        .map(|_| ())
        .map_err(|err| {
            error!(
                event_id = %event.id,
                error = %err,
                "failed to persist audit event to PostgreSQL"
            );
            err.to_string()
        })
    }

    async fn chain_breaks(&self, tenant_id: &str) -> Result<Vec<(i64, String)>, String> {
        audit_store::audit_chain_breaks(&self.pool, tenant_id)
            .await
            .map_err(|e| e.to_string())
    }

    /// Query events from PostgreSQL with optional filters, verifying each
    /// record's signature as it is read.
    ///
    /// A database error now propagates. It used to be logged and turned into an
    /// empty page, so an operator investigating an incident was shown "no
    /// events" — indistinguishable from "nothing happened" — when the truth was
    /// that the query had failed.
    ///
    /// Records whose signature does not verify are returned with
    /// `verified: Some(false)` rather than dropped: silently hiding them would
    /// let an attacker who tampered with a record also make it disappear from
    /// the answer.
    async fn query_events(
        &self,
        tenant_id: &str,
        start_time: Option<DateTime<Utc>>,
        end_time: Option<DateTime<Utc>>,
        action_filter: Option<&str>,
        principal_filter: Option<&str>,
        limit: usize,
        offset: usize,
    ) -> Result<(Vec<AuditRecord>, usize), String> {
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
                let key = self.signer.key_for(tenant_id);
                let mut tampered = 0usize;
                let records: Vec<AuditRecord> = events
                    .into_iter()
                    .map(|e| {
                        let mut r = stored_to_record(e);
                        let sig = r.signature.clone();
                        let ok = crate::integrity::verify_signature(&r, &key, &sig);
                        if !ok {
                            tampered += 1;
                        }
                        r.verified = Some(ok);
                        r
                    })
                    .collect();

                if tampered > 0 {
                    error!(
                        tenant_id = %tenant_id,
                        tampered,
                        "audit records failed signature verification — the log has been modified"
                    );
                }
                Ok((records, total as usize))
            }
            Err(err) => {
                error!(
                    tenant_id = %tenant_id,
                    error = %err,
                    "failed to query audit events from PostgreSQL"
                );
                Err(err.to_string())
            }
        }
    }
}
