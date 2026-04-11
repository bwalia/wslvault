//! OIDC (OpenID Connect) token validation for the identity-service.
//!
//! This module handles discovery of provider metadata, JWKS key fetching with
//! time-bounded caching, ID token signature/claims validation, and mapping of
//! OIDC claims to wslvault-internal concepts (tenant_id, policies).
//!
//! # Provider discovery flow
//!
//! 1. On first use (or after the 1-hour cache TTL), fetch
//!    `{issuer}/.well-known/openid-configuration` to obtain the `jwks_uri`.
//! 2. Fetch the JWKS document from `jwks_uri` and cache the keys.
//! 3. For each incoming ID token, decode the header to find the `kid`, locate
//!    the matching JWK, validate signature + standard claims, then map the
//!    OIDC claims to wslvault concepts.

use std::{collections::HashMap, sync::Arc, time::Instant};

use jsonwebtoken::{
    decode, decode_header,
    jwk::{AlgorithmParameters, JwkSet},
    Algorithm, DecodingKey, Validation,
};
use reqwest::Client;
use serde::Deserialize;
use thiserror::Error;
use tokio::sync::RwLock;
use tracing::{info, warn};

// ─── Error type ──────────────────────────────────────────────────────────────

/// Errors that can occur during OIDC token validation.
#[derive(Debug, Error)]
pub enum OidcError {
    /// The requested provider name was not found in the configured provider map.
    #[error("OIDC provider '{0}' is not configured")]
    ProviderNotFound(String),

    /// Fetching or parsing the OpenID Connect discovery document failed.
    #[error("OIDC discovery failed for issuer '{issuer}': {reason}")]
    DiscoveryFailed { issuer: String, reason: String },

    /// Fetching or parsing the JWKS document failed.
    #[error("JWKS fetch failed for URI '{uri}': {reason}")]
    JwksFetchFailed { uri: String, reason: String },

    /// The ID token failed signature, expiry, issuer, or audience validation.
    #[error("ID token validation failed: {0}")]
    TokenValidation(String),

    /// Required claims were missing or could not be mapped to wslvault concepts.
    #[error("Claims mapping failed: {0}")]
    ClaimsMappingError(String),
}

// ─── Configuration types ─────────────────────────────────────────────────────

/// Configuration for a single OIDC provider.
///
/// Instances are typically loaded from the `VAULT_OIDC_PROVIDERS` environment
/// variable, which holds a JSON object mapping provider names to these configs.
#[derive(Debug, Clone, Deserialize)]
pub struct OidcProviderConfig {
    /// The expected `iss` claim value in ID tokens (e.g.
    /// `"https://keycloak.example.com/realms/wslvault"`).
    pub issuer: String,

    /// The `aud` claim value that tokens must carry to be accepted.
    pub client_id: String,

    /// Optional client secret — reserved for future token-exchange flows;
    /// not required for pure ID token validation.
    pub client_secret: Option<String>,

    /// Override the JWKS URI instead of discovering it via `.well-known`.
    /// Useful when the IdP does not expose a standard discovery document.
    pub jwks_uri: Option<String>,

    /// Rules for mapping OIDC claims to wslvault-internal concepts.
    pub claims_mapping: ClaimsMapping,
}

/// Rules that control how OIDC claims are translated into wslvault concepts.
#[derive(Debug, Clone, Deserialize)]
pub struct ClaimsMapping {
    /// Name of the claim that carries the wslvault tenant ID.
    /// Defaults to `"tenant_id"` when absent.
    pub tenant_id_claim: Option<String>,

    /// Name of the claim whose string-array value is used as policy names.
    /// Defaults to `"groups"` when absent.
    pub policies_claim: Option<String>,

    /// Policies unconditionally assigned to every principal authenticated via
    /// this provider, regardless of the per-user claim values.
    pub default_policies: Option<Vec<String>>,
}

// ─── Internal deserialization helpers ────────────────────────────────────────

/// Subset of the OpenID Connect discovery document that we actually use.
#[derive(Debug, Deserialize)]
struct OpenIdConfiguration {
    /// Must match `OidcProviderConfig::issuer` after discovery.
    issuer: String,
    /// The URI from which to fetch the JWKS key set.
    jwks_uri: String,
}

// ─── ID token claims ──────────────────────────────────────────────────────────

/// Standard + custom claims extracted from a validated OIDC ID token.
#[derive(Debug, serde::Deserialize)]
pub struct IdTokenClaims {
    /// Issuer — must match the configured issuer.
    pub iss: String,
    /// Subject — stable identifier for the end-user at the IdP.
    pub sub: String,
    /// Audience — can be a single string or an array of strings.
    pub aud: serde_json::Value,
    /// Expiry time (Unix timestamp).
    pub exp: i64,
    /// Issued-at time (Unix timestamp).
    pub iat: i64,
    /// Optional email address of the end-user.
    pub email: Option<String>,
    /// Optional display name of the end-user.
    pub name: Option<String>,
    /// Optional group membership list (used as the default policies claim).
    pub groups: Option<Vec<String>>,
    /// All remaining custom claims, including provider-specific ones such as
    /// `tenant_id`, are captured here for flexible mapping.
    #[serde(flatten)]
    pub extra: HashMap<String, serde_json::Value>,
}

// ─── Validation result ────────────────────────────────────────────────────────

/// The wslvault-internal principal information derived from a valid OIDC token.
pub struct OidcValidationResult {
    /// OIDC `sub` claim — stable user identifier at the IdP.
    pub subject: String,
    /// Tenant ID resolved from the configured claims mapping.
    pub tenant_id: String,
    /// Policy names resolved from the configured claims mapping plus any
    /// statically configured default policies for the provider.
    pub policies: Vec<String>,
    /// Best-effort human-readable display name: email > name > sub.
    pub display_name: String,
}

// ─── JWKS cache entry ─────────────────────────────────────────────────────────

/// A cached JWKS key set together with the instant it was fetched.
struct JwksCacheEntry {
    /// Parsed JWK key set from the provider's JWKS endpoint.
    key_set: JwkSet,
    /// Wall-clock time at which this entry was populated.
    fetched_at: Instant,
}

// ─── OidcManager ─────────────────────────────────────────────────────────────

/// Maximum age of a cached JWKS key set before it is re-fetched.
///
/// One hour matches typical IdP key rotation intervals while keeping latency
/// overhead manageable.  A cache miss triggers a single synchronous HTTP
/// request under a write lock.
const JWKS_CACHE_TTL_SECS: u64 = 3600;

/// Manages OIDC token validation across one or more configured providers.
///
/// The manager is cheaply cloneable via `Arc` and safe to share across async
/// tasks.  JWKS keys are fetched lazily and cached with a configurable TTL to
/// avoid hammering the IdP's JWKS endpoint on every authentication request.
pub struct OidcManager {
    /// Map from provider name (as supplied by the caller) to its config.
    providers: HashMap<String, OidcProviderConfig>,
    /// In-memory JWKS cache keyed by provider name.
    /// Value is the parsed `JwkSet` and the instant it was fetched.
    jwks_cache: Arc<RwLock<HashMap<String, JwksCacheEntry>>>,
    /// Shared HTTP client — reuses TCP connections across requests.
    http_client: Client,
}

impl OidcManager {
    /// Creates a new `OidcManager` backed by the supplied provider map.
    ///
    /// The HTTP client is constructed once here and reused for all outbound
    /// requests (discovery + JWKS), benefiting from connection pooling.
    pub fn new(providers: HashMap<String, OidcProviderConfig>) -> Self {
        Self {
            providers,
            jwks_cache: Arc::new(RwLock::new(HashMap::new())),
            // Use rustls so we do not depend on the system's OpenSSL.
            http_client: Client::builder()
                .build()
                .expect("reqwest client construction should not fail"),
        }
    }

    // ── Public API ────────────────────────────────────────────────────────────

    /// Validates an OIDC ID token issued by the named provider.
    ///
    /// Steps performed:
    /// 1. Look up the provider config by `provider_name`.
    /// 2. Obtain JWKS keys (from cache if < 1 h old, otherwise refresh).
    /// 3. Decode the JWT header to find `kid`.
    /// 4. Locate the matching JWK in the key set.
    /// 5. Validate the token (signature, `exp`, `iss`, `aud`).
    /// 6. Map claims → (`tenant_id`, `policies`) using `ClaimsMapping`.
    /// 7. Return `OidcValidationResult`.
    pub async fn validate_id_token(
        &self,
        provider_name: &str,
        id_token: &str,
    ) -> Result<OidcValidationResult, OidcError> {
        // Step 1: resolve provider config.
        let config = self
            .providers
            .get(provider_name)
            .ok_or_else(|| OidcError::ProviderNotFound(provider_name.to_string()))?;

        // Step 2: obtain JWKS keys (cached or freshly fetched).
        let key_set = self.get_jwks(provider_name, config).await?;

        // Step 3: decode the JWT header (without signature verification) to
        //         find the key ID (`kid`) so we can select the right JWK.
        let header = decode_header(id_token)
            .map_err(|e| OidcError::TokenValidation(format!("cannot decode JWT header: {e}")))?;

        // Step 4: find the matching JWK.
        //
        // If the token header carries a `kid`, use it for an exact match.
        // If not (some IdPs omit `kid` when they only have one key), fall back
        // to the first RSA key in the set.
        let jwk = if let Some(kid) = &header.kid {
            key_set
                .find(kid)
                .ok_or_else(|| OidcError::TokenValidation(format!("no JWK found for kid '{kid}'")))?
        } else {
            // No `kid` in header — use first available RSA key.
            key_set
                .keys
                .iter()
                .find(|k| matches!(k.algorithm, AlgorithmParameters::RSA(_)))
                .ok_or_else(|| {
                    OidcError::TokenValidation(
                        "no kid in token header and no RSA key in JWKS".to_string(),
                    )
                })?
        };

        // Step 5: validate token signature and standard claims.
        //
        // Build a `DecodingKey` from the RSA public key in the JWK, configure
        // validation to check `iss` and `aud`, then decode+verify.
        let decoding_key = DecodingKey::from_jwk(jwk).map_err(|e| {
            OidcError::TokenValidation(format!("failed to build decoding key from JWK: {e}"))
        })?;

        // Determine the algorithm to use for validation.  Prefer the `alg`
        // field on the JWK itself; fall back to the header algorithm.
        //
        // `KeyAlgorithm` implements `Display` which produces the same string
        // representation as `Algorithm`'s `FromStr` (e.g. "RS256"), so a
        // round-trip through a formatted string is reliable here.
        let algorithm = jwk
            .common
            .key_algorithm
            .and_then(|a| format!("{a}").parse::<Algorithm>().ok())
            .unwrap_or(header.alg);

        let mut validation = Validation::new(algorithm);
        validation.set_issuer(&[&config.issuer]);
        validation.set_audience(&[&config.client_id]);
        validation.validate_exp = true;
        validation.leeway = 0;

        let token_data =
            decode::<IdTokenClaims>(id_token, &decoding_key, &validation).map_err(|e| {
                OidcError::TokenValidation(format!("token validation failed: {e}"))
            })?;

        let claims = token_data.claims;

        // Step 6: map OIDC claims to wslvault-internal concepts.
        let (tenant_id, policies) = self.map_claims(&claims, config)?;

        // Build a best-effort display name.
        let display_name = claims
            .email
            .clone()
            .or_else(|| claims.name.clone())
            .unwrap_or_else(|| claims.sub.clone());

        info!(
            provider = provider_name,
            subject = %claims.sub,
            tenant_id = %tenant_id,
            "OIDC token validated successfully"
        );

        Ok(OidcValidationResult {
            subject: claims.sub,
            tenant_id,
            policies,
            display_name,
        })
    }

    // ── Private helpers ───────────────────────────────────────────────────────

    /// Returns the JWKS key set for the given provider, refreshing from the
    /// network if the cached entry is absent or older than `JWKS_CACHE_TTL_SECS`.
    async fn get_jwks(
        &self,
        provider_name: &str,
        config: &OidcProviderConfig,
    ) -> Result<JwkSet, OidcError> {
        // Fast path: check the cache under a read lock.
        {
            let cache = self.jwks_cache.read().await;
            if let Some(entry) = cache.get(provider_name) {
                if entry.fetched_at.elapsed().as_secs() < JWKS_CACHE_TTL_SECS {
                    return Ok(entry.key_set.clone());
                }
            }
        }

        // Slow path: refresh the JWKS and update the cache under a write lock.
        // Re-check inside the write lock to avoid a double-fetch race between
        // two concurrent callers that both missed the read-lock check.
        let mut cache = self.jwks_cache.write().await;
        if let Some(entry) = cache.get(provider_name) {
            if entry.fetched_at.elapsed().as_secs() < JWKS_CACHE_TTL_SECS {
                return Ok(entry.key_set.clone());
            }
        }

        // Resolve the JWKS URI: use the override from config if present,
        // otherwise discover it via the OpenID Connect discovery document.
        let jwks_uri = match &config.jwks_uri {
            Some(uri) => {
                info!(
                    provider = provider_name,
                    jwks_uri = uri,
                    "using overridden JWKS URI from provider config"
                );
                uri.clone()
            }
            None => self.discover_jwks_uri(&config.issuer).await?,
        };

        let key_set = self.fetch_jwks(&jwks_uri).await?;

        cache.insert(
            provider_name.to_string(),
            JwksCacheEntry {
                key_set: key_set.clone(),
                fetched_at: Instant::now(),
            },
        );

        Ok(key_set)
    }

    /// Fetches the OpenID Connect discovery document and extracts the `jwks_uri`.
    ///
    /// Validates that the `issuer` field in the discovery document matches the
    /// configured issuer to guard against provider misconfiguration.
    pub async fn discover_jwks_uri(&self, issuer: &str) -> Result<String, OidcError> {
        let discovery_url = format!("{}/.well-known/openid-configuration", issuer.trim_end_matches('/'));

        info!(issuer = issuer, url = %discovery_url, "fetching OIDC discovery document");

        let response = self
            .http_client
            .get(&discovery_url)
            .send()
            .await
            .map_err(|e| OidcError::DiscoveryFailed {
                issuer: issuer.to_string(),
                reason: format!("HTTP request failed: {e}"),
            })?;

        if !response.status().is_success() {
            return Err(OidcError::DiscoveryFailed {
                issuer: issuer.to_string(),
                reason: format!("HTTP {}", response.status()),
            });
        }

        let discovery: OpenIdConfiguration =
            response.json().await.map_err(|e| OidcError::DiscoveryFailed {
                issuer: issuer.to_string(),
                reason: format!("failed to parse discovery document: {e}"),
            })?;

        // Guard against discovery documents that return a mismatched issuer,
        // which could indicate a misconfigured or compromised IdP endpoint.
        if discovery.issuer != issuer {
            warn!(
                configured_issuer = issuer,
                discovered_issuer = %discovery.issuer,
                "issuer mismatch in OIDC discovery document"
            );
            return Err(OidcError::DiscoveryFailed {
                issuer: issuer.to_string(),
                reason: format!(
                    "issuer mismatch: expected '{}', got '{}'",
                    issuer, discovery.issuer
                ),
            });
        }

        info!(issuer = issuer, jwks_uri = %discovery.jwks_uri, "OIDC discovery succeeded");

        Ok(discovery.jwks_uri)
    }

    /// Fetches and parses the JWKS document from the given URI.
    pub async fn fetch_jwks(&self, jwks_uri: &str) -> Result<JwkSet, OidcError> {
        info!(uri = jwks_uri, "fetching JWKS keys");

        let response = self
            .http_client
            .get(jwks_uri)
            .send()
            .await
            .map_err(|e| OidcError::JwksFetchFailed {
                uri: jwks_uri.to_string(),
                reason: format!("HTTP request failed: {e}"),
            })?;

        if !response.status().is_success() {
            return Err(OidcError::JwksFetchFailed {
                uri: jwks_uri.to_string(),
                reason: format!("HTTP {}", response.status()),
            });
        }

        let key_set: JwkSet = response.json().await.map_err(|e| OidcError::JwksFetchFailed {
            uri: jwks_uri.to_string(),
            reason: format!("failed to parse JWKS response: {e}"),
        })?;

        info!(
            uri = jwks_uri,
            key_count = key_set.keys.len(),
            "JWKS keys fetched successfully"
        );

        Ok(key_set)
    }

    /// Maps validated OIDC claims to a `(tenant_id, policies)` pair.
    ///
    /// Lookup order for `tenant_id`:
    /// 1. The claim named by `ClaimsMapping::tenant_id_claim` (default `"tenant_id"`).
    /// 2. Falls back to the OIDC `sub` claim prefixed with `"oidc:"` when the
    ///    custom claim is absent, ensuring every principal has a tenant scope.
    ///
    /// Lookup order for `policies`:
    /// 1. The claim named by `ClaimsMapping::policies_claim` (default `"groups"`).
    /// 2. Any `default_policies` statically configured for this provider are
    ///    appended after the dynamic per-user policies.
    pub fn map_claims(
        &self,
        claims: &IdTokenClaims,
        config: &OidcProviderConfig,
    ) -> Result<(String, Vec<String>), OidcError> {
        let mapping = &config.claims_mapping;

        // ── Resolve tenant_id ──────────────────────────────────────────────
        let tenant_id_claim_name = mapping
            .tenant_id_claim
            .as_deref()
            .unwrap_or("tenant_id");

        // Look for the tenant claim in the flattened `extra` map first; if the
        // claim name happens to be one of the well-known fields (`iss`, `sub`,
        // etc.) we do not shadow those here because they live in named fields.
        let tenant_id = claims
            .extra
            .get(tenant_id_claim_name)
            .and_then(|v| v.as_str())
            .map(str::to_owned)
            .ok_or_else(|| {
                OidcError::ClaimsMappingError(format!(
                    "required tenant claim '{tenant_id_claim_name}' not found in ID token"
                ))
            })?;

        if tenant_id.is_empty() {
            return Err(OidcError::ClaimsMappingError(format!(
                "tenant claim '{tenant_id_claim_name}' is present but empty"
            )));
        }

        // ── Resolve policies ───────────────────────────────────────────────
        let policies_claim_name = mapping
            .policies_claim
            .as_deref()
            .unwrap_or("groups");

        // Collect per-user policies from the named claim.  The claim may live
        // in the well-known `groups` field or in a custom claim in `extra`.
        let mut policies: Vec<String> = if policies_claim_name == "groups" {
            // Use the typed `groups` field to avoid double-lookup in `extra`.
            claims
                .groups
                .clone()
                .unwrap_or_default()
        } else {
            claims
                .extra
                .get(policies_claim_name)
                .and_then(|v| v.as_array())
                .map(|arr| {
                    arr.iter()
                        .filter_map(|item| item.as_str().map(str::to_owned))
                        .collect()
                })
                .unwrap_or_default()
        };

        // Append provider-level default policies (if any).
        if let Some(defaults) = &mapping.default_policies {
            policies.extend(defaults.iter().cloned());
        }

        Ok((tenant_id, policies))
    }
}
