//! Lease domain types for time-bounded secret access.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::types::tenant::TenantId;

/// Newtype wrapper around UUID for type-safe lease references.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
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

/// What the lease is attached to; drives revocation behavior.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum LeaseTarget {
    Token {
        /// SHA-256 hex of the JWT — never the raw token.
        token_id: String,
        /// Display / revocation callback identity. Empty on rows written
        /// before this field existed.
        #[serde(default)]
        principal_id: String,
    },
    DynamicSecret {
        path: String,
        role: String,
    },
    ServiceCredential {
        service: String,
        account_id: String,
    },
}

impl LeaseTarget {
    /// Operator-facing label for list/get JSON (`target_label`).
    pub fn label(&self) -> String {
        match self {
            LeaseTarget::Token {
                principal_id,
                token_id,
            } => {
                if principal_id.is_empty() {
                    let prefix: String = token_id.chars().take(8).collect();
                    format!("token:{prefix}")
                } else {
                    format!("principal:{principal_id}")
                }
            }
            LeaseTarget::DynamicSecret { path, role } => format!("{path} ({role})"),
            LeaseTarget::ServiceCredential {
                service,
                account_id,
            } => format!("{service}:{account_id}"),
        }
    }
}

/// Current lifecycle state of a lease.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum LeaseState {
    Active,
    Renewing,
    Expired,
    Revoked,
}

/// A time-bounded lease associated with a secret or credential.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Lease {
    pub id: LeaseId,
    pub tenant_id: TenantId,
    pub target: LeaseTarget,
    pub state: LeaseState,
    pub ttl_seconds: u64,
    /// Upper bound; cannot renew beyond this.
    pub max_ttl_seconds: u64,
    pub renewable: bool,
    pub issued_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
    pub revoked_at: Option<DateTime<Utc>>,
}

impl Lease {
    /// Returns true when the lease is currently valid according to the system clock.
    pub fn is_active(&self) -> bool {
        self.state == LeaseState::Active && Utc::now() < self.expires_at
    }

    /// Returns remaining lifetime in seconds; 0 if expired.
    pub fn remaining_seconds(&self) -> u64 {
        let delta = self.expires_at.signed_duration_since(Utc::now());
        delta.num_seconds().max(0) as u64
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Duration;

    #[test]
    fn expired_lease_returns_zero_remaining() {
        let lease = Lease {
            id: LeaseId::new(),
            tenant_id: TenantId::new(),
            target: LeaseTarget::Token {
                token_id: "tok-1".into(),
                principal_id: String::new(),
            },
            state: LeaseState::Active,
            ttl_seconds: 60,
            max_ttl_seconds: 3600,
            renewable: true,
            issued_at: Utc::now() - Duration::seconds(120),
            expires_at: Utc::now() - Duration::seconds(60),
            revoked_at: None,
        };
        assert_eq!(lease.remaining_seconds(), 0);
        assert!(!lease.is_active());
    }

    #[test]
    fn active_lease_has_remaining_time() {
        let lease = Lease {
            id: LeaseId::new(),
            tenant_id: TenantId::new(),
            target: LeaseTarget::Token {
                token_id: "tok-2".into(),
                principal_id: "user-2".into(),
            },
            state: LeaseState::Active,
            ttl_seconds: 3600,
            max_ttl_seconds: 7200,
            renewable: true,
            issued_at: Utc::now(),
            expires_at: Utc::now() + Duration::seconds(3600),
            revoked_at: None,
        };
        assert!(lease.remaining_seconds() > 3500);
        assert!(lease.is_active());
    }
}
