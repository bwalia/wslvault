//! Tenant domain types for multi-tenant isolation.

use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::types::secret::SecretEnvironment;

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

/// Whether this tenant holds lower SDLC environments or production only.
///
/// Product rule: keep PROD secrets in a separate production tenant from the
/// project tenant that holds INT/TEST/ACC (e.g. `project-dta` vs `project-dta-prod`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum TenantKind {
    /// Lower environments (INT / TEST / ACC) in one tenancy.
    #[default]
    Project,
    /// PROD-only tenant — recommended separate from the project tenant.
    Production,
}

impl TenantKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Project => "project",
            Self::Production => "production",
        }
    }

    pub fn default_allowed(self) -> Vec<SecretEnvironment> {
        match self {
            Self::Project => vec![
                SecretEnvironment::Int,
                SecretEnvironment::Test,
                SecretEnvironment::Acc,
            ],
            Self::Production => vec![SecretEnvironment::Prod],
        }
    }

    pub fn default_environment(self) -> SecretEnvironment {
        match self {
            Self::Project => SecretEnvironment::Int,
            Self::Production => SecretEnvironment::Prod,
        }
    }
}

impl std::fmt::Display for TenantKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

impl std::str::FromStr for TenantKind {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.trim().to_lowercase().as_str() {
            "project" => Ok(Self::Project),
            "production" | "prod" => Ok(Self::Production),
            other => Err(format!(
                "unknown tenant_kind '{other}'; must be one of: project, production"
            )),
        }
    }
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
    /// SDLC environments this tenant may store secrets for.
    #[serde(default = "default_allowed_environments")]
    pub allowed_environments: Vec<SecretEnvironment>,
    /// Default environment applied when a secret write omits one.
    #[serde(default)]
    pub default_environment: SecretEnvironment,
    /// Optional tenant-level category labels (e.g. `project:dta`).
    #[serde(default)]
    pub tags: Vec<String>,
    /// Project (lower envs) vs production (PROD-only) tenancy.
    #[serde(default)]
    pub tenant_kind: TenantKind,
}

fn default_allowed_environments() -> Vec<SecretEnvironment> {
    Tenant::project_defaults().1
}

impl Tenant {
    /// Defaults for a project tenant: kind=project, allowed=INT/TEST/ACC, default=INT.
    pub fn project_defaults() -> (TenantKind, Vec<SecretEnvironment>, SecretEnvironment) {
        let kind = TenantKind::Project;
        (kind, kind.default_allowed(), kind.default_environment())
    }

    /// Defaults for a production tenant: kind=production, allowed=PROD, default=PROD.
    pub fn production_defaults() -> (TenantKind, Vec<SecretEnvironment>, SecretEnvironment) {
        let kind = TenantKind::Production;
        (kind, kind.default_allowed(), kind.default_environment())
    }

    /// Whether this tenant may store secrets labelled with `env`.
    pub fn allows(&self, env: &SecretEnvironment) -> bool {
        self.allowed_environments.contains(env)
    }

    /// Alias used by some call sites — same as [`Self::allows`].
    pub fn allows_environment(&self, env: SecretEnvironment) -> bool {
        self.allows(&env)
    }
}

/// Runtime tenant context extracted from request headers or JWT claims.
///
/// This struct is threaded through axum middleware extractors and gRPC
/// interceptors so that every handler receives a fully-resolved, validated
/// tenant identity without needing to re-parse headers itself.
///
/// The `policies` field carries the policy names that the authenticated
/// principal is currently entitled to; downstream authorization checks
/// compare this slice against the policy requirements of a given operation.
#[derive(Debug, Clone)]
pub struct TenantContext {
    /// Identifies the tenant that owns this request.
    pub tenant_id: TenantId,
    /// Authenticated caller identity — may be "anonymous" when auth is
    /// disabled (e.g. during local development or integration tests).
    pub principal_id: String,
    /// Policy names currently attached to `principal_id` within this tenant.
    pub policies: Vec<String>,
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

    #[test]
    fn project_tenant_rejects_prod() {
        let (kind, allowed, default) = Tenant::project_defaults();
        assert_eq!(kind, TenantKind::Project);
        assert_eq!(default, SecretEnvironment::Int);
        let tenant = Tenant {
            id: TenantId::new(),
            slug: "project-dta".into(),
            display_name: "Project DTA".into(),
            tier: TenantTier::Shared,
            root_key_id: "kek".into(),
            created_at: chrono::Utc::now(),
            updated_at: chrono::Utc::now(),
            deleted_at: None,
            allowed_environments: allowed,
            default_environment: default,
            tags: vec![],
            tenant_kind: kind,
        };
        assert!(tenant.allows(&SecretEnvironment::Int));
        assert!(tenant.allows(&SecretEnvironment::Test));
        assert!(tenant.allows(&SecretEnvironment::Acc));
        assert!(!tenant.allows(&SecretEnvironment::Prod));
    }

    #[test]
    fn production_tenant_allows_only_prod() {
        let (kind, allowed, default) = Tenant::production_defaults();
        let tenant = Tenant {
            id: TenantId::new(),
            slug: "project-dta-prod".into(),
            display_name: "Project DTA Prod".into(),
            tier: TenantTier::Shared,
            root_key_id: "kek".into(),
            created_at: chrono::Utc::now(),
            updated_at: chrono::Utc::now(),
            deleted_at: None,
            allowed_environments: allowed,
            default_environment: default,
            tags: vec![],
            tenant_kind: kind,
        };
        assert!(tenant.allows(&SecretEnvironment::Prod));
        assert!(!tenant.allows(&SecretEnvironment::Int));
    }
}
