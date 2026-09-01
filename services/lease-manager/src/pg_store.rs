//! PostgreSQL-backed implementation of `LeaseStoreBackend`.
//!
//! Delegates all storage operations to `wslvault_storage::lease_store`,
//! converting between the service-layer `LeaseRecord` type and the storage
//! crate's `wslvault_core::types::lease::Lease` type.
//!
//! Conversion notes:
//! - `tenant_id` in `LeaseRecord` is a plain `String`; the storage layer
//!   expects a `TenantId` (UUID wrapper).  Parsing errors result in
//!   `Option::None` from `get_lease` or a logged error from mutations.
//! - `target_data` is stored as an opaque JSON blob in `LeaseRecord`.  The
//!   storage layer requires a strongly typed `LeaseTarget`.  We store the
//!   blob as `{"DynamicSecret": {<target_data payload>}}` or fall back to a
//!   generic `Token` variant when the JSON cannot be deserialized.
//! - Errors from the storage layer are surfaced as `Option::None` / `String`
//!   errors to match the `LeaseStoreBackend` trait signatures.

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use tracing::error;
use uuid::Uuid;

use wslvault_core::types::lease::{Lease, LeaseTarget};
use wslvault_core::types::lease::{LeaseId as CoreLeaseId, LeaseState as CoreLeaseState};
use wslvault_core::types::tenant::TenantId;
use wslvault_storage::lease_store;
use wslvault_storage::pool::DbPool;

use crate::store::{LeaseId, LeaseRecord, LeaseState, LeaseStoreBackend};

/// PostgreSQL-backed lease store.
pub struct PgLeaseBackend {
    pool: DbPool,
}

impl PgLeaseBackend {
    /// Construct a new `PgLeaseBackend` using the provided connection pool.
    pub fn new(pool: DbPool) -> Self {
        Self { pool }
    }
}

// ---------------------------------------------------------------------------
// Type conversion helpers
// ---------------------------------------------------------------------------

/// Convert a service-layer `LeaseState` to the core `LeaseState`.
fn to_core_state(state: LeaseState) -> CoreLeaseState {
    match state {
        LeaseState::Active => CoreLeaseState::Active,
        LeaseState::Expired => CoreLeaseState::Expired,
        LeaseState::Revoked => CoreLeaseState::Revoked,
    }
}

/// Convert a core `LeaseState` to the service-layer `LeaseState`.
fn from_core_state(state: CoreLeaseState) -> LeaseState {
    match state {
        CoreLeaseState::Active | CoreLeaseState::Renewing => LeaseState::Active,
        CoreLeaseState::Expired => LeaseState::Expired,
        CoreLeaseState::Revoked => LeaseState::Revoked,
    }
}

/// Convert a `LeaseRecord` to a core `Lease`.
///
/// `tenant_id` must be a valid UUID string.  `target_data` is attempted to be
/// deserialized as a `LeaseTarget`; on failure a synthetic
/// `LeaseTarget::Token` variant carrying the raw data string is used so that
/// the row can still be persisted.
fn record_to_core_lease(record: &LeaseRecord) -> Result<Lease, String> {
    let tenant_uuid = Uuid::parse_str(&record.tenant_id)
        .map_err(|e| format!("invalid tenant_id UUID '{}': {}", record.tenant_id, e))?;

    // Try to deserialize target_data as a LeaseTarget JSON value.
    let target: LeaseTarget = serde_json::from_str(&record.target_data).unwrap_or_else(|_| {
        // Fall back to a Token variant carrying the opaque data string.
        LeaseTarget::Token {
            token_id: record.target_data.clone(),
            principal_id: String::new(),
        }
    });

    Ok(Lease {
        id: CoreLeaseId(record.id.0),
        tenant_id: TenantId(tenant_uuid),
        target,
        state: to_core_state(record.state),
        ttl_seconds: record.ttl_seconds.max(0) as u64,
        max_ttl_seconds: record.max_ttl_seconds.max(0) as u64,
        renewable: record.renewable,
        issued_at: record.issued_at,
        expires_at: record.expires_at,
        revoked_at: record.revoked_at,
    })
}

/// Convert a core `Lease` back to a service-layer `LeaseRecord`.
///
/// `target_data` is serialized from the `LeaseTarget`; `target_type` is
/// derived from the enum variant name.
fn core_lease_to_record(lease: Lease) -> LeaseRecord {
    let tenant_id = lease.tenant_id.to_string();

    let target_type = match &lease.target {
        LeaseTarget::Token { .. } => "token",
        LeaseTarget::DynamicSecret { .. } => "dynamic_secret",
        LeaseTarget::ServiceCredential { .. } => "service_credential",
    }
    .to_string();

    // Serialize target to JSON; fall back to empty object on error.
    let target_data = serde_json::to_string(&lease.target).unwrap_or_else(|_| "{}".to_string());

    LeaseRecord {
        id: LeaseId(lease.id.0),
        tenant_id,
        target_type,
        target_data,
        state: from_core_state(lease.state),
        ttl_seconds: lease.ttl_seconds as i64,
        max_ttl_seconds: lease.max_ttl_seconds as i64,
        renewable: lease.renewable,
        issued_at: lease.issued_at,
        expires_at: lease.expires_at,
        revoked_at: lease.revoked_at,
    }
}

// ---------------------------------------------------------------------------
// LeaseStoreBackend implementation
// ---------------------------------------------------------------------------

#[async_trait]
impl LeaseStoreBackend for PgLeaseBackend {
    async fn insert_lease(&self, record: LeaseRecord) -> Result<LeaseId, String> {
        let id = record.id.clone();

        match record_to_core_lease(&record) {
            Ok(core_lease) => {
                lease_store::create_lease(&self.pool, &core_lease)
                    .await
                    .map_err(|e| {
                        error!(
                            lease_id = %id,
                            error = %e,
                            "failed to persist lease to PostgreSQL"
                        );
                        e.to_string()
                    })?;
            }
            Err(err) => {
                error!(
                    lease_id = %id,
                    error = %err,
                    "failed to convert LeaseRecord to core Lease for storage"
                );
                return Err(err);
            }
        }

        Ok(id)
    }

    async fn get_lease(&self, lease_id: &LeaseId) -> Option<LeaseRecord> {
        let core_id = CoreLeaseId(lease_id.0);

        match lease_store::get_lease(&self.pool, &core_id).await {
            Ok(core_lease) => Some(core_lease_to_record(core_lease)),
            Err(err) => {
                // Log only unexpected errors; not-found is a normal outcome.
                use wslvault_core::VaultError;
                if !matches!(err, VaultError::LeaseNotFound { .. }) {
                    error!(
                        lease_id = %lease_id,
                        error = %err,
                        "unexpected error retrieving lease from PostgreSQL"
                    );
                }
                None
            }
        }
    }

    async fn renew_lease(
        &self,
        lease_id: &LeaseId,
        increment_secs: i64,
    ) -> Result<LeaseRecord, String> {
        // Fetch the current record so we can compute the new expiry against
        // max_ttl_seconds and return the updated LeaseRecord to the caller.
        let record = self
            .get_lease(lease_id)
            .await
            .ok_or_else(|| format!("lease not found: {}", lease_id))?;

        if record.state != LeaseState::Active {
            return Err(format!("lease {} is not active", lease_id));
        }

        if !record.renewable {
            return Err(format!("lease {} is not renewable", lease_id));
        }

        let max_expires_at = record.issued_at + chrono::Duration::seconds(record.max_ttl_seconds);
        let proposed_expires_at = Utc::now() + chrono::Duration::seconds(increment_secs);
        let new_expires_at = proposed_expires_at.min(max_expires_at);

        let core_id = CoreLeaseId(lease_id.0);
        lease_store::renew_lease(
            &self.pool,
            &core_id,
            new_expires_at,
            increment_secs.max(0) as u64,
        )
        .await
        .map_err(|e| e.to_string())?;

        // Re-fetch after update so the returned record reflects the persisted state.
        self.get_lease(lease_id)
            .await
            .ok_or_else(|| format!("lease {} vanished after renewal", lease_id))
    }

    async fn revoke_lease(&self, lease_id: &LeaseId) -> Result<(), String> {
        let core_id = CoreLeaseId(lease_id.0);
        lease_store::revoke_lease(&self.pool, &core_id)
            .await
            .map_err(|e| e.to_string())
    }

    async fn list_leases(&self, tenant_id: &str, state_filter: Option<&str>) -> Vec<LeaseRecord> {
        let tenant = match Uuid::parse_str(tenant_id) {
            Ok(u) => TenantId(u),
            Err(err) => {
                error!(tenant_id, error = %err, "list_leases: invalid tenant_id");
                return Vec::new();
            }
        };

        match lease_store::list_leases(&self.pool, &tenant, state_filter).await {
            Ok(leases) => leases.into_iter().map(core_lease_to_record).collect(),
            Err(err) => {
                error!(error = %err, "failed to list leases from PostgreSQL");
                Vec::new()
            }
        }
    }

    async fn expire_stale_leases(&self) -> Vec<LeaseId> {
        // Use the stored procedure exposed by wslvault_storage.
        const BATCH_SIZE: i32 = 500;

        match lease_store::expire_leases(&self.pool, BATCH_SIZE).await {
            Ok(core_ids) => core_ids.into_iter().map(|cid| LeaseId(cid.0)).collect(),
            Err(err) => {
                error!(
                    error = %err,
                    "failed to run lease expiration sweep in PostgreSQL"
                );
                Vec::new()
            }
        }
    }

    async fn list_stale_active_leases(&self) -> Vec<LeaseRecord> {
        const BATCH_SIZE: i32 = 500;
        match lease_store::list_stale_leases(&self.pool, BATCH_SIZE).await {
            Ok(leases) => leases.into_iter().map(core_lease_to_record).collect(),
            Err(err) => {
                error!(error = %err, "failed to list stale leases from PostgreSQL");
                Vec::new()
            }
        }
    }

    async fn mark_expired(&self, lease_id: &LeaseId) -> Result<(), String> {
        let core_id = CoreLeaseId(lease_id.0);
        lease_store::mark_lease_expired(&self.pool, &core_id)
            .await
            .map_err(|e| e.to_string())
    }
}

// Silence dead-code warnings for conversion helpers that may only be used in
// one direction during normal operation.
#[allow(dead_code)]
fn _ensure_types_used(_dt: DateTime<Utc>) {}
