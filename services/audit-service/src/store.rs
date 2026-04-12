//! Audit event store abstraction and in-memory backend.
//!
//! Defines the `AuditStoreBackend` trait so that both the in-memory store
//! (used in tests and when no `DATABASE_URL` is configured) and the
//! PostgreSQL backend can be used interchangeably by the gRPC handlers.

use std::sync::Arc;

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use serde_json::Value as JsonValue;
use tokio::sync::RwLock;
use uuid::Uuid;

/// A single immutable audit record.
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

/// Abstraction over audit storage so that in-memory and PostgreSQL backends
/// can be swapped without modifying the gRPC handlers.
#[async_trait]
pub trait AuditStoreBackend: Send + Sync {
    /// Append a single audit record to the store.
    async fn insert_record(&self, record: AuditRecord);

    /// Query records with optional filters.
    ///
    /// Returns `(page, total_count)` where `total_count` is the number of
    /// matching records before applying `limit`/`offset`.  `limit == 0`
    /// means "return all".
    #[allow(clippy::too_many_arguments)]
    async fn query_events(
        &self,
        tenant_id: &str,
        start_time: Option<DateTime<Utc>>,
        end_time: Option<DateTime<Utc>>,
        action_filter: Option<&str>,
        principal_filter: Option<&str>,
        limit: usize,
        offset: usize,
    ) -> (Vec<AuditRecord>, usize);
}

// ---------------------------------------------------------------------------
// In-memory backend
// ---------------------------------------------------------------------------

/// Type alias kept for internal use by `InMemoryAuditStore`.
type SharedAuditStore = Arc<RwLock<Vec<AuditRecord>>>;

/// In-memory implementation of `AuditStoreBackend`.
///
/// All records live in a heap-allocated `Vec` protected by a `tokio::RwLock`.
/// This backend is used when `DATABASE_URL` is not set.
pub struct InMemoryAuditStore {
    inner: SharedAuditStore,
}

impl InMemoryAuditStore {
    /// Construct a new, empty in-memory store.
    pub fn new() -> Self {
        Self {
            inner: Arc::new(RwLock::new(Vec::new())),
        }
    }
}

impl Default for InMemoryAuditStore {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl AuditStoreBackend for InMemoryAuditStore {
    async fn insert_record(&self, record: AuditRecord) {
        let mut guard = self.inner.write().await;
        guard.push(record);
    }

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
        let guard = self.inner.read().await;

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
}
