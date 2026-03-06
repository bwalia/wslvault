//! In-memory audit event store.
//!
//! Uses an `Arc<RwLock<Vec<AuditRecord>>>` so that multiple gRPC handlers can
//! append and query events concurrently without blocking each other for longer
//! than necessary.

use std::sync::Arc;

use chrono::{DateTime, Utc};
use serde_json::Value as JsonValue;
use tokio::sync::RwLock;
use uuid::Uuid;

/// Type alias used across the crate to pass the shared store around.
pub type SharedAuditStore = Arc<RwLock<Vec<AuditRecord>>>;

/// A single immutable audit record stored in memory.
///
/// The `signature` field is populated by the integrity module before the
/// record is inserted; it covers all other fields so that any post-hoc
/// tampering would be detectable.
#[derive(Debug, Clone)]
pub struct AuditRecord {
    pub id: Uuid,
    pub tenant_id: String,
    pub principal_id: String,
    /// Structured action identifier, e.g. "secret.read", "auth.login".
    pub action: String,
    /// Path or resource the action targeted.
    pub resource: String,
    /// High-level outcome: "success", "failure", "denied".
    pub outcome: String,
    /// Human-readable detail accompanying the outcome.
    pub outcome_detail: String,
    /// Arbitrary structured context supplied by the emitting service.
    pub details: JsonValue,
    /// IP address of the originating client, if known.
    pub client_ip: String,
    /// HMAC-SHA256 signature covering all other fields.
    pub signature: String,
    pub timestamp: DateTime<Utc>,
}

/// Construct a new empty audit store.
pub fn new_store() -> SharedAuditStore {
    Arc::new(RwLock::new(Vec::new()))
}

/// Append a record to the store.
pub async fn insert_record(store: &SharedAuditStore, record: AuditRecord) {
    let mut guard = store.write().await;
    guard.push(record);
}

/// Query events with optional filters applied in-memory.
///
/// Filters are ANDed together; an empty/None filter for a field is treated as
/// "match all".  `limit` 0 means "return all matching records".
#[allow(clippy::too_many_arguments)]
pub async fn query_events(
    store: &SharedAuditStore,
    tenant_id: &str,
    start_time: Option<DateTime<Utc>>,
    end_time: Option<DateTime<Utc>>,
    action_filter: Option<&str>,
    principal_filter: Option<&str>,
    limit: usize,
    offset: usize,
) -> (Vec<AuditRecord>, usize) {
    let guard = store.read().await;

    let matching: Vec<&AuditRecord> = guard
        .iter()
        .filter(|r| r.tenant_id == tenant_id)
        .filter(|r| start_time.is_none_or(|t| r.timestamp >= t))
        .filter(|r| end_time.is_none_or(|t| r.timestamp <= t))
        .filter(|r| {
            action_filter
                .map(|f| f.is_empty() || r.action == f)
                .unwrap_or(true)
        })
        .filter(|r| {
            principal_filter
                .map(|f| f.is_empty() || r.principal_id == f)
                .unwrap_or(true)
        })
        .collect();

    let total = matching.len();

    let page: Vec<AuditRecord> = matching
        .into_iter()
        .skip(offset)
        .take(if limit == 0 { usize::MAX } else { limit })
        .cloned()
        .collect();

    (page, total)
}
