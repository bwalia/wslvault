//! In-memory lease store backed by a RwLock-protected HashMap.
//!
//! All lease state transitions go through this module. Each method acquires
//! the lock for the minimum duration needed, avoiding long-held write locks
//! that would block concurrent readers.

use std::collections::HashMap;
use std::sync::Arc;

use chrono::{DateTime, Utc};
use tokio::sync::RwLock;
use uuid::Uuid;

use wslvault_core::VaultError;

/// Type alias to avoid repeating the long lock type throughout the module.
pub type SharedLeaseStore = Arc<RwLock<HashMap<LeaseId, LeaseRecord>>>;

/// Newtype wrapper for lease identifiers so they cannot be confused with other
/// UUID fields at compile time.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct LeaseId(pub Uuid);

impl LeaseId {
    pub fn new() -> Self {
        Self(Uuid::now_v7())
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

/// Full lease record persisted in the in-memory store.
#[derive(Debug, Clone)]
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

/// Create a new in-memory store.
pub fn new_store() -> SharedLeaseStore {
    Arc::new(RwLock::new(HashMap::new()))
}

/// Insert a new lease into the store.
///
/// The caller is responsible for constructing the `LeaseRecord`; this function
/// only handles the storage operation.
pub async fn insert_lease(store: &SharedLeaseStore, record: LeaseRecord) {
    let mut guard = store.write().await;
    guard.insert(record.id.clone(), record);
}

/// Retrieve a lease by ID. Returns `VaultError::LeaseNotFound` when absent.
pub async fn get_lease(
    store: &SharedLeaseStore,
    lease_id: &LeaseId,
) -> Result<LeaseRecord, VaultError> {
    let guard = store.read().await;
    guard
        .get(lease_id)
        .cloned()
        .ok_or_else(|| VaultError::LeaseNotFound {
            lease_id: lease_id.to_string(),
        })
}

/// Renew a lease, extending `expires_at` by `increment_seconds`.
///
/// Validates:
/// - The lease must be active.
/// - The lease must be marked renewable.
/// - The new expiry must not exceed `issued_at + max_ttl_seconds`.
pub async fn renew_lease(
    store: &SharedLeaseStore,
    lease_id: &LeaseId,
    increment_seconds: i64,
) -> Result<LeaseRecord, VaultError> {
    let mut guard = store.write().await;
    let record = guard
        .get_mut(lease_id)
        .ok_or_else(|| VaultError::LeaseNotFound {
            lease_id: lease_id.to_string(),
        })?;

    if record.state != LeaseState::Active {
        return Err(VaultError::LeaseExpired {
            lease_id: lease_id.to_string(),
        });
    }

    if !record.renewable {
        return Err(VaultError::ValidationError {
            field: "renewable".into(),
            reason: "lease is not renewable".into(),
        });
    }

    let max_expires_at = record.issued_at
        + chrono::Duration::seconds(record.max_ttl_seconds);

    let proposed_expires_at = Utc::now() + chrono::Duration::seconds(increment_seconds);

    // Clamp proposed expiry to the hard upper bound.
    let new_expires_at = proposed_expires_at.min(max_expires_at);

    record.expires_at = new_expires_at;
    record.ttl_seconds = increment_seconds;

    Ok(record.clone())
}

/// Transition a lease to the Revoked state immediately.
pub async fn revoke_lease(
    store: &SharedLeaseStore,
    lease_id: &LeaseId,
) -> Result<(), VaultError> {
    let mut guard = store.write().await;
    let record = guard
        .get_mut(lease_id)
        .ok_or_else(|| VaultError::LeaseNotFound {
            lease_id: lease_id.to_string(),
        })?;

    record.state = LeaseState::Revoked;
    record.revoked_at = Some(Utc::now());
    Ok(())
}

/// List all leases for a tenant, optionally filtered by state string.
pub async fn list_leases(
    store: &SharedLeaseStore,
    tenant_id: &str,
    state_filter: Option<&str>,
) -> Vec<LeaseRecord> {
    let guard = store.read().await;
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

/// Mark all active, wall-clock-expired leases as Expired.
///
/// Called periodically by the background expiration task.
pub async fn expire_stale_leases(store: &SharedLeaseStore) -> usize {
    let now = Utc::now();
    let mut guard = store.write().await;
    let mut count = 0usize;

    for record in guard.values_mut() {
        if record.state == LeaseState::Active && record.expires_at <= now {
            record.state = LeaseState::Expired;
            count += 1;
        }
    }

    count
}
