//! Lease store abstraction and in-memory backend.
//!
//! Defines the `LeaseStoreBackend` trait so that both the in-memory store
//! (used in tests and when no `DATABASE_URL` is configured) and the
//! PostgreSQL backend can be used interchangeably by the gRPC handlers and
//! the background expiration task.

use std::collections::HashMap;
use std::sync::Arc;

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use tokio::sync::RwLock;
use uuid::Uuid;

/// Newtype wrapper for lease identifiers so they cannot be confused with other
/// UUID fields at compile time.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct LeaseId(pub Uuid);

impl LeaseId {
    pub fn new() -> Self {
        Self(Uuid::now_v7())
    }
}

impl Default for LeaseId {
    fn default() -> Self {
        Self::new()
    }
}

impl std::fmt::Display for LeaseId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl std::str::FromStr for LeaseId {
    type Err = uuid::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(Self(Uuid::parse_str(s)?))
    }
}

/// Current lifecycle state of a lease.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LeaseState {
    Active,
    Expired,
    Revoked,
}

impl LeaseState {
    /// Returns the string representation used in proto responses.
    pub fn as_str(&self) -> &'static str {
        match self {
            LeaseState::Active => "active",
            LeaseState::Expired => "expired",
            LeaseState::Revoked => "revoked",
        }
    }
}

/// Full lease record used by the service layer.
#[derive(Debug, Clone)]
#[allow(dead_code)]
pub struct LeaseRecord {
    pub id: LeaseId,
    pub tenant_id: String,
    /// Human-readable label for what this lease protects (e.g. "dynamic_secret").
    pub target_type: String,
    /// Opaque JSON blob describing the concrete target (path, role, etc.).
    pub target_data: String,
    pub state: LeaseState,
    /// Current TTL at the time of last renewal, in seconds.
    pub ttl_seconds: i64,
    /// Hard upper bound; a renewal that would exceed this is clamped to max_ttl.
    pub max_ttl_seconds: i64,
    pub renewable: bool,
    pub issued_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
    /// Set when state transitions to Revoked.
    pub revoked_at: Option<DateTime<Utc>>,
}

impl LeaseRecord {
    /// Remaining lifetime in seconds; 0 when the lease has already expired.
    pub fn remaining_seconds(&self) -> i64 {
        let delta = self.expires_at.signed_duration_since(Utc::now());
        delta.num_seconds().max(0)
    }
}

// ---------------------------------------------------------------------------
// Trait definition
// ---------------------------------------------------------------------------

/// Abstraction over lease storage so that in-memory and PostgreSQL backends
/// can be swapped without modifying the gRPC handlers or expiration task.
#[async_trait]
pub trait LeaseStoreBackend: Send + Sync {
    /// Insert a new lease, returning its assigned `LeaseId`.
    async fn insert_lease(&self, record: LeaseRecord) -> LeaseId;

    /// Retrieve a lease by ID.  Returns `None` when the lease does not exist.
    async fn get_lease(&self, lease_id: &LeaseId) -> Option<LeaseRecord>;

    /// Renew a lease, extending its expiry by `increment_secs`.
    ///
    /// Returns the updated record on success, or an error string describing
    /// why the renewal was rejected.
    async fn renew_lease(
        &self,
        lease_id: &LeaseId,
        increment_secs: i64,
    ) -> Result<LeaseRecord, String>;

    /// Transition a lease to the Revoked state.
    async fn revoke_lease(&self, lease_id: &LeaseId) -> Result<(), String>;

    /// List all leases for a tenant, optionally filtered by state string.
    async fn list_leases(&self, tenant_id: &str, state_filter: Option<&str>) -> Vec<LeaseRecord>;

    /// Sweep active leases whose wall-clock expiry has passed, transitioning
    /// them to Expired.  Returns the IDs of all leases that were expired.
    async fn expire_stale_leases(&self) -> Vec<LeaseId>;
}

// ---------------------------------------------------------------------------
// In-memory backend
// ---------------------------------------------------------------------------

/// Internal map type used by `InMemoryLeaseStore`.
type InnerMap = Arc<RwLock<HashMap<LeaseId, LeaseRecord>>>;

/// In-memory implementation of `LeaseStoreBackend`.
///
/// All lease records live in a heap-allocated `HashMap` protected by a
/// `tokio::RwLock`.  This backend is used when `DATABASE_URL` is not set.
pub struct InMemoryLeaseStore {
    inner: InnerMap,
}

impl InMemoryLeaseStore {
    /// Construct a new, empty in-memory store.
    pub fn new() -> Self {
        Self {
            inner: Arc::new(RwLock::new(HashMap::new())),
        }
    }
}

impl Default for InMemoryLeaseStore {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl LeaseStoreBackend for InMemoryLeaseStore {
    async fn insert_lease(&self, record: LeaseRecord) -> LeaseId {
        let id = record.id.clone();
        let mut guard = self.inner.write().await;
        guard.insert(id.clone(), record);
        id
    }

    async fn get_lease(&self, lease_id: &LeaseId) -> Option<LeaseRecord> {
        let guard = self.inner.read().await;
        guard.get(lease_id).cloned()
    }

    async fn renew_lease(
        &self,
        lease_id: &LeaseId,
        increment_secs: i64,
    ) -> Result<LeaseRecord, String> {
        let mut guard = self.inner.write().await;
        let record = guard
            .get_mut(lease_id)
            .ok_or_else(|| format!("lease not found: {}", lease_id))?;

        if record.state != LeaseState::Active {
            return Err(format!("lease {} is not active", lease_id));
        }

        if !record.renewable {
            return Err(format!("lease {} is not renewable", lease_id));
        }

        let max_expires_at = record.issued_at + chrono::Duration::seconds(record.max_ttl_seconds);
        let proposed_expires_at = Utc::now() + chrono::Duration::seconds(increment_secs);
        // Clamp proposed expiry to the hard upper bound.
        let new_expires_at = proposed_expires_at.min(max_expires_at);

        record.expires_at = new_expires_at;
        record.ttl_seconds = increment_secs;

        Ok(record.clone())
    }

    async fn revoke_lease(&self, lease_id: &LeaseId) -> Result<(), String> {
        let mut guard = self.inner.write().await;
        let record = guard
            .get_mut(lease_id)
            .ok_or_else(|| format!("lease not found: {}", lease_id))?;

        record.state = LeaseState::Revoked;
        record.revoked_at = Some(Utc::now());
        Ok(())
    }

    async fn list_leases(&self, tenant_id: &str, state_filter: Option<&str>) -> Vec<LeaseRecord> {
        let guard = self.inner.read().await;
        guard
            .values()
            .filter(|r| r.tenant_id == tenant_id)
            .filter(|r| {
                // An empty filter string means "return all".
                state_filter
                    .map(|s| s.is_empty() || r.state.as_str() == s)
                    .unwrap_or(true)
            })
            .cloned()
            .collect()
    }

    async fn expire_stale_leases(&self) -> Vec<LeaseId> {
        let now = Utc::now();
        let mut guard = self.inner.write().await;
        let mut expired_ids = Vec::new();

        for record in guard.values_mut() {
            if record.state == LeaseState::Active && record.expires_at <= now {
                record.state = LeaseState::Expired;
                expired_ids.push(record.id.clone());
            }
        }

        expired_ids
    }
}
