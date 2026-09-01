//! JWT token management for the identity-service.
//!
//! Provides HMAC-SHA256 signed JWTs for principal authentication.
//! Tokens carry tenant_id and policies as claims so downstream services
//! can make authorization decisions without round-tripping to the identity-service.

use chrono::{DateTime, Utc};
use jsonwebtoken::{decode, encode, Algorithm, DecodingKey, EncodingKey, Header, Validation};
use serde::{Deserialize, Serialize};
use wslvault_core::VaultError;

/// JWT claims embedded in every token issued by this service.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TokenClaims {
    /// Subject — the principal_id (UUID string).
    pub sub: String,
    /// Tenant the principal belongs to.
    pub tenant_id: String,
    /// Policy names granted to this principal at issuance time.
    pub policies: Vec<String>,
    /// Cross-tenant authority. Stamped by identity-service only, never taken
    /// from a request, and false on every ordinary token.
    #[serde(default)]
    pub superuser: bool,
    /// Issuer — identifies the WSLVault deployment that minted the token.
    /// Validated on decode to prevent cross-environment token replay.
    pub iss: String,
    /// Audience — the intended recipient of the token. Validated on decode.
    pub aud: String,
    /// Issued-at time as a Unix timestamp.
    pub iat: i64,
    /// Expiry time as a Unix timestamp.
    pub exp: i64,
}

/// Default issuer claim when `VAULT_JWT_ISSUER` is not configured.
pub const DEFAULT_ISSUER: &str = "wslvault";
/// Default audience claim when `VAULT_JWT_AUDIENCE` is not configured.
pub const DEFAULT_AUDIENCE: &str = "wslvault";

/// Manages JWT issuance and validation.
///
/// Two signing modes, and the difference matters:
///
/// * **Per-tenant EdDSA** (preferred). Each tenant has its own Ed25519 keypair;
///   identity-service holds the private half and is the only thing that can
///   sign. Verifiers fetch public keys from JWKS and can only verify.
///
/// * **Shared HS256** (legacy). One `VAULT_JWT_SECRET` for every tenant. Because
///   a MAC key both signs and verifies, every service that could check a token
///   could also mint one — and one key covered all tenants, so there was no
///   cryptographic boundary between them at the token layer. Retained only so
///   tokens issued before the upgrade keep verifying until they expire.
#[derive(Clone)]
pub struct TokenManager {
    encoding_key: EncodingKey,
    decoding_key: DecodingKey,
    /// Validation config cached here to avoid re-constructing on every call.
    validation: Validation,
    /// Issuer stamped into every issued token's `iss` claim.
    issuer: String,
    /// Audience stamped into every issued token's `aud` claim.
    audience: String,
}

impl TokenManager {
    /// Creates a new `TokenManager` from a raw HMAC secret byte slice, using
    /// the default issuer and audience.
    ///
    /// The secret should be at least 32 bytes of high-entropy random data.
    #[allow(dead_code)]
    pub fn new(secret: &[u8]) -> Self {
        Self::with_issuer_audience(secret, DEFAULT_ISSUER, DEFAULT_AUDIENCE)
    }

    /// Creates a `TokenManager` with explicit issuer and audience claims.
    ///
    /// Issued tokens carry `iss`/`aud`, and validation rejects any token whose
    /// claims do not match, preventing replay of tokens minted for a different
    /// WSLVault deployment or audience.
    pub fn with_issuer_audience(secret: &[u8], issuer: &str, audience: &str) -> Self {
        let mut validation = Validation::new(Algorithm::HS256);
        // Enforce expiry check with zero leeway so tokens expire precisely.
        validation.validate_exp = true;
        validation.leeway = 0;
        // Bind tokens to this deployment's issuer and audience.
        validation.set_issuer(&[issuer]);
        validation.set_audience(&[audience]);
        validation.validate_aud = true;

        Self {
            encoding_key: EncodingKey::from_secret(secret),
            decoding_key: DecodingKey::from_secret(secret),
            validation,
            issuer: issuer.to_string(),
            audience: audience.to_string(),
        }
    }

    /// Issue a token signed with a specific key.
    ///
    /// This is the path that gives each tenant its own signature. `signer` is
    /// the tenant's Ed25519 key, resolved by `SigningKeys::signer_for`.
    ///
    /// `superuser` is stamped into the claims by identity-service alone. It is
    /// deliberately not derivable from anything a caller sends: cross-tenant
    /// authority has to be granted, never asserted.
    #[allow(clippy::too_many_arguments)]
    pub fn issue_token_with_key(
        &self,
        principal_id: &str,
        tenant_id: &str,
        policies: Vec<String>,
        ttl_seconds: i64,
        signer: &jsonwebtoken::EncodingKey,
        header: jsonwebtoken::Header,
        superuser: bool,
    ) -> Result<(String, DateTime<Utc>), VaultError> {
        let now = Utc::now();
        let exp = now.timestamp() + ttl_seconds;
        let expires_at = DateTime::from_timestamp(exp, 0).ok_or_else(|| VaultError::Internal {
            reason: "overflow computing token expiry timestamp".to_string(),
        })?;

        let claims = TokenClaims {
            sub: principal_id.to_string(),
            tenant_id: tenant_id.to_string(),
            policies,
            iss: self.issuer.clone(),
            aud: self.audience.clone(),
            iat: now.timestamp(),
            exp,
            superuser,
        };

        let token = encode(&header, &claims, signer).map_err(|e| VaultError::Internal {
            reason: format!("JWT encoding failed: {e}"),
        })?;

        Ok((token, expires_at))
    }

    /// Issues a new signed JWT for the given principal.
    ///
    /// Legacy HS256 path — see the type docs. Kept for callers not yet routed
    /// through per-tenant keys.
    pub fn issue_token(
        &self,
        principal_id: &str,
        tenant_id: &str,
        policies: Vec<String>,
        ttl_seconds: i64,
    ) -> Result<(String, DateTime<Utc>), VaultError> {
        let now = Utc::now();
        let exp = now.timestamp() + ttl_seconds;
        let expires_at = DateTime::from_timestamp(exp, 0).ok_or_else(|| VaultError::Internal {
            reason: "overflow computing token expiry timestamp".to_string(),
        })?;

        let claims = TokenClaims {
            sub: principal_id.to_string(),
            tenant_id: tenant_id.to_string(),
            policies,
            iss: self.issuer.clone(),
            aud: self.audience.clone(),
            iat: now.timestamp(),
            exp,
            superuser: false,
        };

        let token =
            encode(&Header::new(Algorithm::HS256), &claims, &self.encoding_key).map_err(|e| {
                VaultError::Internal {
                    reason: format!("JWT encoding failed: {e}"),
                }
            })?;

        Ok((token, expires_at))
    }

    /// Decodes and validates a JWT, returning its claims on success.
    ///
    /// Returns `VaultError::Unauthenticated` for any invalid, expired, or
    /// malformed token so callers receive a consistent error variant.
    pub fn validate_token(&self, token: &str) -> Result<TokenClaims, VaultError> {
        let token_data = decode::<TokenClaims>(token, &self.decoding_key, &self.validation)
            .map_err(|e| VaultError::Unauthenticated {
                reason: format!("invalid token: {e}"),
            })?;

        Ok(token_data.claims)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_manager() -> TokenManager {
        TokenManager::new(b"test-secret-that-is-at-least-32-bytes-long!!")
    }

    #[test]
    fn round_trip_token() {
        let mgr = make_manager();
        let (token, expires_at) = mgr
            .issue_token(
                "principal-1",
                "tenant-abc",
                vec!["read".into(), "write".into()],
                3600,
            )
            .expect("issue should succeed");

        assert!(!token.is_empty());
        assert!(expires_at > Utc::now());

        let claims = mgr.validate_token(&token).expect("validate should succeed");
        assert_eq!(claims.sub, "principal-1");
        assert_eq!(claims.tenant_id, "tenant-abc");
        assert_eq!(claims.policies, vec!["read", "write"]);
    }

    #[test]
    fn expired_token_is_rejected() {
        let mgr = make_manager();
        // TTL of -1 produces an already-expired token.
        let (token, _) = mgr
            .issue_token("p", "t", vec![], -1)
            .expect("issue should succeed even with negative ttl");

        let result = mgr.validate_token(&token);
        assert!(
            matches!(result, Err(VaultError::Unauthenticated { .. })),
            "expected Unauthenticated, got {:?}",
            result
        );
    }

    #[test]
    fn tampered_token_is_rejected() {
        let mgr = make_manager();
        let (mut token, _) = mgr
            .issue_token("p", "t", vec![], 3600)
            .expect("issue should succeed");

        // Corrupt the signature portion of the JWT.
        token.push_str("INVALID");

        let result = mgr.validate_token(&token);
        assert!(matches!(result, Err(VaultError::Unauthenticated { .. })));
    }

    #[test]
    fn token_from_different_issuer_is_rejected() {
        let secret = b"test-secret-that-is-at-least-32-bytes-long!!";
        let minter = TokenManager::with_issuer_audience(secret, "wslvault-staging", "wslvault");
        let verifier = TokenManager::with_issuer_audience(secret, "wslvault-prod", "wslvault");

        let (token, _) = minter
            .issue_token("p", "t", vec![], 3600)
            .expect("issue should succeed");

        let result = verifier.validate_token(&token);
        assert!(
            matches!(result, Err(VaultError::Unauthenticated { .. })),
            "token minted by a different issuer must be rejected, got {result:?}"
        );
    }

    #[test]
    fn token_for_different_audience_is_rejected() {
        let secret = b"test-secret-that-is-at-least-32-bytes-long!!";
        let minter = TokenManager::with_issuer_audience(secret, "wslvault", "other-service");
        let verifier = TokenManager::with_issuer_audience(secret, "wslvault", "wslvault");

        let (token, _) = minter
            .issue_token("p", "t", vec![], 3600)
            .expect("issue should succeed");

        let result = verifier.validate_token(&token);
        assert!(
            matches!(result, Err(VaultError::Unauthenticated { .. })),
            "token for a different audience must be rejected, got {result:?}"
        );
    }
}
