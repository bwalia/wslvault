//! Azure Workload / Managed Identity authentication.
//!
//! # Flow
//!
//! 1. The client obtains a JWT from the Azure Instance Metadata Service
//!    (IMDS at `169.254.169.254`) or the workload identity webhook, with
//!    the audience set to the WSLVault resource URI.
//! 2. The JWT is sent to WSLVault in the `AzureWorkloadAuth` message.
//! 3. This module fetches Microsoft's OIDC discovery document and JWKS
//!    for the claimed Azure AD tenant, then validates the JWT signature,
//!    audience, issuer, and expiry.
//! 4. The `oid` (object ID) and `tid` (Azure tenant ID) claims are
//!    extracted and mapped to a wslvault principal and tenant.
//!
//! This is equivalent to HashiCorp Vault's `azure` auth method and
//! Azure Key Vault's managed identity authentication.

use std::collections::HashMap;
use std::sync::Arc;

use chrono::Utc;
use jsonwebtoken::{decode, decode_header, Algorithm, DecodingKey, Validation};
use serde::Deserialize;
use tokio::sync::RwLock;
use tracing::{info, warn};

// ---------------------------------------------------------------------------
// Configuration
// ---------------------------------------------------------------------------

/// Configuration for the Azure Workload Identity auth backend.
#[derive(Debug, Clone)]
pub struct AzureWorkloadConfig {
    /// Expected audience (`aud`) claim in the Azure JWT.
    /// Typically the WSLVault resource URI (e.g. `api://wslvault`).
    pub expected_audience: String,

    /// Mapping from Azure AD tenant ID → wslvault tenant_id.
    /// If empty, the caller must supply `tenant_id` explicitly.
    pub azure_tenant_map: HashMap<String, String>,

    /// Default policies assigned to Azure workload identities.
    pub default_policies: Vec<String>,

    /// Optional: restrict to specific Azure subscription IDs.
    pub bound_subscription_ids: Vec<String>,

    /// JWKS cache TTL in seconds (default: 3600).
    pub jwks_cache_ttl_seconds: u64,
}

impl Default for AzureWorkloadConfig {
    fn default() -> Self {
        Self {
            expected_audience: "api://wslvault".to_string(),
            azure_tenant_map: HashMap::new(),
            default_policies: Vec::new(),
            bound_subscription_ids: Vec::new(),
            jwks_cache_ttl_seconds: 3600,
        }
    }
}

// ---------------------------------------------------------------------------
// Manager
// ---------------------------------------------------------------------------

/// Validates Azure Managed Identity / Workload Identity JWTs.
pub struct AzureWorkloadManager {
    config: AzureWorkloadConfig,
    http_client: reqwest::Client,
    /// Cached JWKS keyed by Azure AD tenant ID.
    jwks_cache: Arc<RwLock<HashMap<String, CachedJwks>>>,
}

struct CachedJwks {
    keys: Vec<JwkKey>,
    fetched_at: chrono::DateTime<Utc>,
}

/// The result of a successful Azure workload identity authentication.
#[derive(Debug, Clone)]
pub struct AzureValidationResult {
    /// Azure AD object ID (the `oid` claim).
    pub object_id: String,
    /// Azure AD tenant ID (the `tid` claim).
    pub azure_tenant_id: String,
    /// The `sub` claim (subject).
    pub subject: String,
    /// Resolved wslvault tenant_id.
    pub tenant_id: String,
    /// Policies assigned to this identity.
    pub policies: Vec<String>,
    /// Display name derived from the token.
    pub display_name: String,
    /// Optional Azure subscription ID from `xms_mirid` claim.
    pub subscription_id: Option<String>,
}

/// Errors from Azure workload identity authentication.
#[derive(Debug, thiserror::Error)]
pub enum AzureWorkloadError {
    #[error("failed to fetch OIDC discovery: {0}")]
    DiscoveryFailed(String),

    #[error("failed to fetch JWKS: {0}")]
    JwksFetchFailed(String),

    #[error("JWT validation failed: {0}")]
    JwtValidation(String),

    #[error("missing required claim: {0}")]
    MissingClaim(String),

    #[error("Azure AD tenant '{azure_tid}' does not match claimed tenant")]
    TenantMismatch { azure_tid: String },

    #[error("subscription '{subscription_id}' is not in the bound list")]
    UnboundSubscription { subscription_id: String },

    #[error("no matching key found in JWKS for kid '{kid}'")]
    NoMatchingKey { kid: String },

    #[error("cannot resolve wslvault tenant for Azure AD tenant '{azure_tid}'")]
    UnmappedTenant { azure_tid: String },
}

impl AzureWorkloadManager {
    pub fn new(config: AzureWorkloadConfig) -> Self {
        let http_client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(10))
            .build()
            .expect("failed to build HTTP client for Azure");

        Self {
            config,
            http_client,
            jwks_cache: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Validates an Azure Managed Identity / Workload Identity JWT.
    pub async fn validate(
        &self,
        jwt: &str,
        claimed_azure_tenant_id: &str,
        claimed_subscription_id: &str,
        claimed_wslvault_tenant_id: &str,
    ) -> Result<AzureValidationResult, AzureWorkloadError> {
        // Decode the header to get the kid.
        let header = decode_header(jwt)
            .map_err(|e| AzureWorkloadError::JwtValidation(format!("decode header: {e}")))?;

        let kid = header
            .kid
            .ok_or_else(|| AzureWorkloadError::JwtValidation("missing kid in JWT header".into()))?;

        // Fetch JWKS for the Azure AD tenant.
        let jwks_keys = self.get_jwks(claimed_azure_tenant_id).await?;

        // Find the matching key.
        let jwk = jwks_keys
            .iter()
            .find(|k| k.kid == kid)
            .ok_or_else(|| AzureWorkloadError::NoMatchingKey { kid: kid.clone() })?;

        // Build the decoding key from RSA modulus and exponent.
        let decoding_key = DecodingKey::from_rsa_components(&jwk.n, &jwk.e)
            .map_err(|e| AzureWorkloadError::JwtValidation(format!("build key: {e}")))?;

        // Configure validation.
        let mut validation = Validation::new(Algorithm::RS256);
        validation.set_audience(&[&self.config.expected_audience]);
        // Azure AD v2.0 issuer format:
        // https://login.microsoftonline.com/{tenant}/v2.0
        let expected_issuer = format!(
            "https://login.microsoftonline.com/{}/v2.0",
            claimed_azure_tenant_id
        );
        validation.set_issuer(&[&expected_issuer]);
        validation.validate_exp = true;

        // Decode and validate the JWT.
        let token_data = decode::<AzureClaims>(jwt, &decoding_key, &validation)
            .map_err(|e| AzureWorkloadError::JwtValidation(format!("{e}")))?;

        let claims = token_data.claims;

        // Extract required claims.
        let object_id = claims
            .oid
            .ok_or_else(|| AzureWorkloadError::MissingClaim("oid".into()))?;
        let azure_tenant_id = claims
            .tid
            .ok_or_else(|| AzureWorkloadError::MissingClaim("tid".into()))?;

        // Cross-check Azure tenant ID.
        if azure_tenant_id != claimed_azure_tenant_id {
            return Err(AzureWorkloadError::TenantMismatch {
                azure_tid: azure_tenant_id,
            });
        }

        // Extract optional subscription from xms_mirid claim.
        // Format: /subscriptions/{sub}/resourcegroups/{rg}/providers/...
        let subscription_id = claims
            .xms_mirid
            .as_deref()
            .and_then(|mirid| {
                mirid
                    .strip_prefix("/subscriptions/")
                    .and_then(|rest| rest.split('/').next())
                    .map(String::from)
            });

        // Check bound subscription if configured.
        if !self.config.bound_subscription_ids.is_empty() {
            let sub_id = subscription_id
                .as_deref()
                .or(if claimed_subscription_id.is_empty() {
                    None
                } else {
                    Some(claimed_subscription_id)
                });

            if let Some(sid) = sub_id {
                if !self.config.bound_subscription_ids.iter().any(|b| b == sid) {
                    return Err(AzureWorkloadError::UnboundSubscription {
                        subscription_id: sid.to_string(),
                    });
                }
            }
        }

        // Resolve wslvault tenant_id.
        let tenant_id = self
            .config
            .azure_tenant_map
            .get(&azure_tenant_id)
            .cloned()
            .unwrap_or_else(|| claimed_wslvault_tenant_id.to_string());

        let display_name = claims
            .preferred_username
            .or(claims.name)
            .unwrap_or_else(|| format!("azure:{}", object_id));

        info!(
            object_id = %object_id,
            azure_tenant = %azure_tenant_id,
            display_name = %display_name,
            "Azure workload identity verified"
        );

        Ok(AzureValidationResult {
            object_id,
            azure_tenant_id,
            subject: claims.sub,
            tenant_id,
            policies: self.config.default_policies.clone(),
            display_name,
            subscription_id,
        })
    }

    /// Fetches (and caches) the JWKS keys for the given Azure AD tenant.
    async fn get_jwks(
        &self,
        azure_tenant_id: &str,
    ) -> Result<Vec<JwkKey>, AzureWorkloadError> {
        // Check cache first.
        {
            let cache = self.jwks_cache.read().await;
            if let Some(cached) = cache.get(azure_tenant_id) {
                let age = (Utc::now() - cached.fetched_at).num_seconds() as u64;
                if age < self.config.jwks_cache_ttl_seconds {
                    return Ok(cached.keys.clone());
                }
            }
        }

        // Fetch OIDC discovery to get jwks_uri.
        let discovery_url = format!(
            "https://login.microsoftonline.com/{}/.well-known/openid-configuration",
            azure_tenant_id
        );

        let discovery: OidcDiscovery = self
            .http_client
            .get(&discovery_url)
            .send()
            .await
            .map_err(|e| AzureWorkloadError::DiscoveryFailed(e.to_string()))?
            .json()
            .await
            .map_err(|e| AzureWorkloadError::DiscoveryFailed(format!("parse: {e}")))?;

        // Fetch JWKS.
        let jwks: JwksResponse = self
            .http_client
            .get(&discovery.jwks_uri)
            .send()
            .await
            .map_err(|e| AzureWorkloadError::JwksFetchFailed(e.to_string()))?
            .json()
            .await
            .map_err(|e| AzureWorkloadError::JwksFetchFailed(format!("parse: {e}")))?;

        // Cache the keys.
        let keys = jwks.keys.clone();
        {
            let mut cache = self.jwks_cache.write().await;
            cache.insert(
                azure_tenant_id.to_string(),
                CachedJwks {
                    keys: jwks.keys,
                    fetched_at: Utc::now(),
                },
            );
        }

        Ok(keys)
    }
}

// ---------------------------------------------------------------------------
// JWT claims and JWKS types
// ---------------------------------------------------------------------------

/// Claims extracted from an Azure AD v2.0 access/ID token.
#[derive(Debug, Deserialize)]
struct AzureClaims {
    /// Subject (unique per application+user).
    sub: String,
    /// Object ID of the managed identity or service principal.
    oid: Option<String>,
    /// Azure AD tenant ID.
    tid: Option<String>,
    /// Audience.
    #[allow(dead_code)]
    aud: Option<String>,
    /// Display name.
    name: Option<String>,
    /// UPN or email.
    preferred_username: Option<String>,
    /// Managed identity resource ID (for extracting subscription info).
    xms_mirid: Option<String>,
}

#[derive(Debug, Deserialize)]
struct OidcDiscovery {
    jwks_uri: String,
}

#[derive(Debug, Deserialize)]
struct JwksResponse {
    keys: Vec<JwkKey>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct JwkKey {
    /// Key ID.
    pub kid: String,
    /// RSA modulus (base64url-encoded).
    pub n: String,
    /// RSA exponent (base64url-encoded).
    pub e: String,
    /// Key type (always "RSA" for Azure AD).
    #[allow(dead_code)]
    pub kty: Option<String>,
}

// ---------------------------------------------------------------------------
// Unit tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extract_subscription_from_xms_mirid() {
        let mirid = "/subscriptions/abc-123/resourcegroups/rg/providers/Microsoft.ManagedIdentity/userAssignedIdentities/my-id";
        let sub = mirid
            .strip_prefix("/subscriptions/")
            .and_then(|rest| rest.split('/').next())
            .map(String::from);
        assert_eq!(sub, Some("abc-123".to_string()));
    }

    #[test]
    fn extract_subscription_from_empty_mirid() {
        let mirid = "";
        let sub = mirid
            .strip_prefix("/subscriptions/")
            .and_then(|rest| rest.split('/').next())
            .map(String::from);
        assert_eq!(sub, None);
    }
}
