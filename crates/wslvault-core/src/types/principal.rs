//! Principal (authenticated caller) domain types.

use std::collections::{HashMap, HashSet};

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::types::tenant::TenantId;

/// Newtype wrapper around UUID for type-safe principal references.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct PrincipalId(pub Uuid);

impl PrincipalId {
    pub fn new() -> Self {
        Self(Uuid::now_v7())
    }
}

impl Default for PrincipalId {
    fn default() -> Self {
        Self::new()
    }
}

impl std::fmt::Display for PrincipalId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// Authentication method that produced this principal's identity.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum AuthMethod {
    Token,
    Oidc {
        provider: String,
        subject: String,
    },
    MachineIdentity {
        service_account: String,
    },
    Mtls {
        fingerprint: String,
    },
    /// Used only for SCIM provisioning operations.
    Scim,
    /// Used by services calling each other within the cluster.
    Internal,
}

/// A verified, authenticated caller. This is the result of successful authentication.
/// Passed through every service call to enforce policy and audit.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Principal {
    pub id: PrincipalId,
    pub tenant_id: TenantId,
    pub display_name: String,
    pub auth_method: AuthMethod,
    /// Explicit policy names granted to this principal.
    pub policies: HashSet<String>,
    /// Arbitrary metadata propagated from the identity provider.
    pub metadata: HashMap<String, String>,
    pub authenticated_at: DateTime<Utc>,
    pub token_expires_at: Option<DateTime<Utc>>,
}

impl Principal {
    /// Returns true when the token backing this principal is still valid.
    pub fn is_token_valid(&self) -> bool {
        self.token_expires_at
            .map(|exp| Utc::now() < exp)
            // No expiry means a long-lived service identity.
            .unwrap_or(true)
    }

    /// Check whether this principal holds the named policy.
    /// Real enforcement happens in the policy-engine; this is a fast-path guard.
    pub fn has_policy(&self, policy: &str) -> bool {
        self.policies.contains(policy)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Duration;

    fn test_principal(expires_at: Option<DateTime<Utc>>) -> Principal {
        Principal {
            id: PrincipalId::new(),
            tenant_id: TenantId::new(),
            display_name: "test-user".into(),
            auth_method: AuthMethod::Token,
            policies: HashSet::from(["admin".into(), "read-only".into()]),
            metadata: HashMap::new(),
            authenticated_at: Utc::now(),
            token_expires_at: expires_at,
        }
    }

    #[test]
    fn principal_with_no_expiry_is_valid() {
        let p = test_principal(None);
        assert!(p.is_token_valid());
    }

    #[test]
    fn principal_with_future_expiry_is_valid() {
        let p = test_principal(Some(Utc::now() + Duration::hours(1)));
        assert!(p.is_token_valid());
    }

    #[test]
    fn principal_with_past_expiry_is_invalid() {
        let p = test_principal(Some(Utc::now() - Duration::hours(1)));
        assert!(!p.is_token_valid());
    }

    #[test]
    fn has_policy_checks_set() {
        let p = test_principal(None);
        assert!(p.has_policy("admin"));
        assert!(!p.has_policy("super-admin"));
    }
}
