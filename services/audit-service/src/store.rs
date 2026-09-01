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
    /// HMAC-SHA256 signature covering all other fields and the chain position.
    pub signature: String,
    pub timestamp: DateTime<Utc>,
    /// Per-tenant monotonic position in the hash chain. Assigned on append.
    pub seq: i64,
    /// Signature of the preceding record in this tenant's chain; empty for the
    /// genesis record.
    pub prev_hash: String,
    /// Whether this record's signature verified when it was read back.
    ///
    /// `None` on records that have not been through a verifying read — the
    /// append path, and the in-memory backend. Never serialised into the
    /// signature; it is a property of the read, not of the record.
    pub verified: Option<bool>,
}

/// Abstraction over audit storage so that in-memory and PostgreSQL backends
/// can be swapped without modifying the gRPC handlers.
#[async_trait]
pub trait AuditStoreBackend: Send + Sync {
    /// Append a single audit record to the store.
    ///
    /// This returned `()` — the trait was infallible by design — so a failed
    /// insert was logged and the audited operation succeeded anyway. Vault
    /// guarantees the opposite: if the event cannot be recorded, the operation
    /// does not happen. Returning `Result` puts that decision back with the
    /// caller instead of hiding it here.
    async fn insert_record(&self, record: AuditRecord) -> Result<(), String>;

    /// Query records with optional filters.
    ///
    /// Returns `(page, total_count)` where `total_count` is the number of
    /// matching records before applying `limit`/`offset`.  `limit == 0`
    /// means "return all".
    ///
    /// Fallible for the same reason: returning an empty page on a database
    /// error told an operator investigating an incident that nothing had
    /// happened.
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
    ) -> Result<(Vec<AuditRecord>, usize), String>;

    /// Structural breaks in a tenant's chain: sequence gaps, or a record whose
    /// `prev_hash` does not match its predecessor. Empty means intact.
    async fn chain_breaks(&self, _tenant_id: &str) -> Result<Vec<(i64, String)>, String> {
        Ok(Vec::new())
    }
}

// ---------------------------------------------------------------------------
// In-memory backend
// ---------------------------------------------------------------------------

/// Type alias kept for internal use by `InMemoryAuditStore`.
pub type SharedAuditStore = Arc<RwLock<Vec<AuditRecord>>>;

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
    async fn insert_record(&self, mut record: AuditRecord) -> Result<(), String> {
        let mut guard = self.inner.write().await;
        // Keep the in-memory backend chain-shaped so behaviour matches the
        // Postgres one; the signature is still computed by the caller.
        record.seq = guard.len() as i64 + 1;
        record.prev_hash = guard
            .last()
            .map(|r| r.signature.clone())
            .unwrap_or_default();
        guard.push(record);
        Ok(())
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
    ) -> Result<(Vec<AuditRecord>, usize), String> {
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

        Ok((page, total))
    }
}
