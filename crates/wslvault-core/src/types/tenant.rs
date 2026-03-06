//! Tenant domain types for multi-tenant isolation.

use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// Newtype wrapper around UUID for type-safe tenant references.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct TenantId(pub Uuid);

impl TenantId {
    pub fn new() -> Self {
        Self(Uuid::now_v7())
    }

    pub fn as_uuid(&self) -> &Uuid {
        &self.0
    }
}

impl Default for TenantId {
    fn default() -> Self {
        Self::new()
    }
}

impl std::fmt::Display for TenantId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl std::str::FromStr for TenantId {
    type Err = uuid::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(Self(Uuid::parse_str(s)?))
    }
}

/// Isolation tier controlling which infrastructure resources the tenant uses.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum TenantTier {
    /// Shared PostgreSQL schema — cost-effective for small tenants.
    Shared,
    /// Dedicated PostgreSQL database — stronger isolation.
    Dedicated,
    /// Dedicated database + dedicated crypto-service instance — sovereign data requirements.
    Sovereign,
}

/// Core tenant record stored in the system namespace.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Tenant {
    pub id: TenantId,
    /// URL-safe short name, globally unique (e.g. "acme-corp").
    pub slug: String,
    pub display_name: String,
    pub tier: TenantTier,
    /// ID of the tenant's root KEK in the crypto-service key store.
    pub root_key_id: String,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub updated_at: chrono::DateTime<chrono::Utc>,
    pub deleted_at: Option<chrono::DateTime<chrono::Utc>>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tenant_id_roundtrip() {
        let id = TenantId::new();
        let s = id.to_string();
        let parsed: TenantId = s.parse().expect("should parse");
        assert_eq!(id, parsed);
    }

    #[test]
    fn tenant_id_display() {
        let uuid = Uuid::nil();
        let id = TenantId(uuid);
        assert_eq!(id.to_string(), "00000000-0000-0000-0000-000000000000");
    }
}
