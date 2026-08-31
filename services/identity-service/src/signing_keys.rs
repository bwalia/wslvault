//! Per-tenant Ed25519 token signing keys.
//!
//! Tokens used to be HS256 under one shared `VAULT_JWT_SECRET`. Because a MAC
//! key both signs and verifies, every service that needed to *check* a token
//! could also *mint* one — secret-engine holds the secret in order to
//! authenticate KV v2 callers, so compromising it yielded the ability to forge
//! a token for any principal in any tenant. And one key covered every tenant,
//! so there was no cryptographic boundary between them at the token layer at
//! all: only a `tenant_id` claim, protected by the key everyone already had.
//!
//! Each tenant now has its own Ed25519 keypair. identity-service holds the
//! private halves and is the only thing that can sign. Everything else fetches
//! public keys from `/v1/identity/.well-known/jwks.json` and can only verify.
//!
//! # Custody
//!
//! Private keys are wrapped by the crypto-service before storage, which puts
//! them under the root KEK and therefore under the seal. A sealed vault cannot
//! unwrap a signing key, so it cannot mint tokens. That falls out of the design
//! rather than being special-cased, and it is the behaviour you want: a sealed
//! vault should not be issuing credentials.
//!
//! Unwrapped keys are cached per process after first use, so the crypto-service
//! is on the path for a tenant's first token rather than every token.

use std::collections::HashMap;
use std::sync::Arc;

use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64URL;
use base64::Engine as _;
use jsonwebtoken::{
    decode, decode_header, Algorithm, DecodingKey, EncodingKey, Header, Validation,
};
use ring::signature::{Ed25519KeyPair, KeyPair};
use serde::Serialize;
use tokio::sync::RwLock;
use tracing::{info, warn};
use uuid::Uuid;
use zeroize::Zeroizing;

use wslvault_storage::pool::DbPool;
use wslvault_storage::signing_key_store::{self, SigningKeyRecord};

use crate::crypto_client::CryptoClient;

/// AAD binding a wrapped signing key to its `kid`, so a wrapped blob cannot be
/// moved onto another key's row.
fn wrap_aad(kid: &str) -> Vec<u8> {
    format!("wslvault:signing-key:{kid}").into_bytes()
}

/// A key ready to sign with.
pub struct LoadedKey {
    pub kid: String,
    pub encoding: EncodingKey,
}

/// One entry of a JWKS document.
///
/// Ed25519 public keys are published as OKP per RFC 8037.
#[derive(Debug, Clone, Serialize)]
pub struct Jwk {
    pub kty: &'static str,
    pub crv: &'static str,
    pub alg: &'static str,
    #[serde(rename = "use")]
    pub use_: &'static str,
    pub kid: String,
    /// base64url-unpadded public key.
    pub x: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct Jwks {
    pub keys: Vec<Jwk>,
}

/// Issues and caches per-tenant signing keys.
#[derive(Clone)]
pub struct SigningKeys {
    pool: DbPool,
    crypto: CryptoClient,
    /// kid → decoded private key, so the crypto-service is consulted once per
    /// key per process rather than once per token.
    cache: Arc<RwLock<HashMap<String, Arc<Vec<u8>>>>>,
    /// kid → public key, for verifying tokens this service issued.
    public_cache: Arc<RwLock<HashMap<String, Vec<u8>>>>,
}

impl SigningKeys {
    pub fn new(pool: DbPool, crypto: CryptoClient) -> Self {
        Self {
            pool,
            crypto,
            cache: Arc::new(RwLock::new(HashMap::new())),
            public_cache: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// The signing key for `tenant_id`, generating one on first use.
    ///
    /// `None` signs superuser tokens with the system key: those authorise
    /// across tenants, so signing them with any one tenant's key would let that
    /// key mint cross-tenant authority.
    pub async fn signer_for(&self, tenant_id: Option<&Uuid>) -> Result<LoadedKey, String> {
        let existing = match tenant_id {
            Some(t) => signing_key_store::active_for_tenant(&self.pool, t).await,
            None => signing_key_store::active_system_key(&self.pool).await,
        }
        .map_err(|e| e.to_string())?;

        let record = match existing {
            Some(r) => r,
            None => self.generate(tenant_id).await?,
        };

        let pkcs8 = self.unwrap_key(&record).await?;
        let encoding = EncodingKey::from_ed_der(&pkcs8);
        Ok(LoadedKey {
            kid: record.kid,
            encoding,
        })
    }

    /// The JWT header for a given key. Carries `kid` so verifiers can select.
    pub fn header(kid: &str) -> Header {
        let mut h = Header::new(Algorithm::EdDSA);
        h.kid = Some(kid.to_string());
        h
    }

    /// Verify a token this service issued, whichever key signed it.
    ///
    /// identity-service is the JWKS *issuer*, so it resolves public keys from
    /// its own database rather than HTTP-calling itself. Needed because
    /// anything here that consumes a token — the admin gate, most importantly —
    /// would otherwise still be verifying HS256 only, and would reject every
    /// token the moment issuance moved to per-tenant EdDSA.
    pub async fn verify(&self, token: &str) -> Result<crate::token::TokenClaims, String> {
        let header = decode_header(token).map_err(|e| format!("malformed token header: {e}"))?;
        if header.alg != Algorithm::EdDSA {
            return Err(format!("not an EdDSA token (alg {:?})", header.alg));
        }
        let kid = header
            .kid
            .ok_or_else(|| "EdDSA token carries no kid".to_string())?;

        let public_key = self.public_key_for(&kid).await?;

        // Issuer and audience are validated by the caller's own TokenManager
        // config where it matters; here the signature and expiry are what
        // establish that this service issued the token and it is still live.
        let mut validation = Validation::new(Algorithm::EdDSA);
        validation.validate_aud = false;

        decode::<crate::token::TokenClaims>(
            token,
            &DecodingKey::from_ed_der(&public_key),
            &validation,
        )
        .map(|d| d.claims)
        .map_err(|e| format!("invalid token: {e}"))
    }

    /// Public key for a `kid`, cached. Keys are immutable per `kid`, so a hit
    /// never needs invalidating.
    async fn public_key_for(&self, kid: &str) -> Result<Vec<u8>, String> {
        if let Some(hit) = self.public_cache.read().await.get(kid) {
            return Ok(hit.clone());
        }

        let record = signing_key_store::by_kid(&self.pool, kid)
            .await
            .map_err(|e| e.to_string())?
            .ok_or_else(|| format!("unknown signing key {kid:?}"))?;

        let raw = B64URL
            .decode(&record.public_key)
            .map_err(|e| format!("stored public key is not base64url: {e}"))?;
        if raw.len() != 32 {
            return Err("stored public key is not an Ed25519 key".to_string());
        }

        self.public_cache
            .write()
            .await
            .insert(kid.to_string(), raw.clone());
        Ok(raw)
    }

    /// Public keys for every signature a live token might carry.
    pub async fn jwks(&self) -> Result<Jwks, String> {
        let records = signing_key_store::publishable(&self.pool)
            .await
            .map_err(|e| e.to_string())?;
        Ok(Jwks {
            keys: records
                .into_iter()
                .map(|r| Jwk {
                    kty: "OKP",
                    crv: "Ed25519",
                    alg: "EdDSA",
                    use_: "sig",
                    kid: r.kid,
                    x: r.public_key,
                })
                .collect(),
        })
    }

    /// Generate, wrap and store a new keypair.
    ///
    /// A losing race on the partial unique index means another process created
    /// the key first; re-read rather than failing the login that triggered it.
    async fn generate(&self, tenant_id: Option<&Uuid>) -> Result<SigningKeyRecord, String> {
        let rng = ring::rand::SystemRandom::new();
        let pkcs8 = Ed25519KeyPair::generate_pkcs8(&rng)
            .map_err(|_| "could not generate an Ed25519 keypair".to_string())?;
        let pkcs8 = Zeroizing::new(pkcs8.as_ref().to_vec());

        let pair = Ed25519KeyPair::from_pkcs8(&pkcs8)
            .map_err(|_| "generated keypair did not parse".to_string())?;
        let public_key = B64URL.encode(pair.public_key().as_ref());

        let kid = format!("wslv-{}", Uuid::now_v7());

        // Wrapped by the crypto-service, so the private half is protected by
        // the root KEK and unavailable while the vault is sealed.
        let wrapped = self
            .crypto
            .wrap(
                tenant_id
                    .map(|t| t.to_string())
                    .unwrap_or_else(|| SYSTEM_WRAP_TENANT.to_string()),
                &pkcs8,
                wrap_aad(&kid),
            )
            .await?;

        let record = SigningKeyRecord {
            kid: kid.clone(),
            tenant_id: tenant_id.copied(),
            public_key,
            wrapped_private_key: wrapped,
            state: "active".to_string(),
        };

        match signing_key_store::insert_active(&self.pool, &record).await {
            Ok(()) => {
                info!(
                    kid = %kid,
                    tenant_id = ?tenant_id,
                    "issued a new Ed25519 token signing key"
                );
                Ok(record)
            }
            Err(e) => {
                // Lost the race: somebody else's key is now the active one.
                warn!(error = %e, "signing key insert lost a race; re-reading");
                let existing = match tenant_id {
                    Some(t) => signing_key_store::active_for_tenant(&self.pool, t).await,
                    None => signing_key_store::active_system_key(&self.pool).await,
                }
                .map_err(|e| e.to_string())?;
                existing.ok_or_else(|| format!("could not store or find a signing key: {e}"))
            }
        }
    }

    async fn unwrap_key(&self, record: &SigningKeyRecord) -> Result<Arc<Vec<u8>>, String> {
        if let Some(hit) = self.cache.read().await.get(&record.kid) {
            return Ok(Arc::clone(hit));
        }

        let pkcs8 = self
            .crypto
            .unwrap(
                record
                    .tenant_id
                    .map(|t| t.to_string())
                    .unwrap_or_else(|| SYSTEM_WRAP_TENANT.to_string()),
                &record.wrapped_private_key,
                wrap_aad(&record.kid),
            )
            .await?;

        let pkcs8 = Arc::new(pkcs8);
        self.cache
            .write()
            .await
            .insert(record.kid.clone(), Arc::clone(&pkcs8));
        Ok(pkcs8)
    }
}

/// Tenant id the crypto-service wraps the SYSTEM signing key under.
///
/// The system key belongs to no tenant, but the crypto-service's envelope API
/// is tenant-scoped by design — that scoping is what stops one tenant reading
/// another's keys. A reserved, well-known id keeps the system key inside that
/// model instead of carving an exception through it.
const SYSTEM_WRAP_TENANT: &str = "00000000-0000-0000-0000-000000000000";

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wrap_aad_binds_to_the_kid() {
        assert_ne!(wrap_aad("kid-a"), wrap_aad("kid-b"));
    }

    #[test]
    fn header_carries_the_kid_and_eddsa() {
        let h = SigningKeys::header("kid-1");
        assert_eq!(h.alg, Algorithm::EdDSA);
        assert_eq!(h.kid.as_deref(), Some("kid-1"));
    }

    /// The published `x` must be the public half and nothing else — publishing
    /// a JWKS is only safe because it reveals no signing capability.
    #[test]
    fn generated_public_key_is_the_public_half() {
        let rng = ring::rand::SystemRandom::new();
        let pkcs8 = Ed25519KeyPair::generate_pkcs8(&rng).unwrap();
        let pair = Ed25519KeyPair::from_pkcs8(pkcs8.as_ref()).unwrap();

        let x = B64URL.encode(pair.public_key().as_ref());
        let decoded = B64URL.decode(&x).unwrap();

        assert_eq!(decoded.len(), 32, "Ed25519 public keys are 32 bytes");
        assert_eq!(decoded, pair.public_key().as_ref());
        assert!(
            !pkcs8.as_ref().windows(32).all(|w| w != decoded.as_slice()),
            "sanity: the public key is derived from this keypair"
        );
    }

    /// A token signed by one tenant's key must not verify under another's.
    /// This is the boundary the shared HS256 secret did not have.
    #[test]
    fn a_key_does_not_verify_another_keys_signature() {
        use jsonwebtoken::{decode, encode, DecodingKey, Validation};

        #[derive(serde::Serialize, serde::Deserialize)]
        struct Claims {
            sub: String,
            exp: i64,
        }

        let rng = ring::rand::SystemRandom::new();
        let a = Ed25519KeyPair::generate_pkcs8(&rng).unwrap();
        let b = Ed25519KeyPair::generate_pkcs8(&rng).unwrap();
        let b_pub = Ed25519KeyPair::from_pkcs8(b.as_ref())
            .unwrap()
            .public_key()
            .as_ref()
            .to_vec();

        let claims = Claims {
            sub: "p".into(),
            exp: chrono::Utc::now().timestamp() + 3600,
        };
        let token = encode(
            &SigningKeys::header("kid-a"),
            &claims,
            &EncodingKey::from_ed_der(a.as_ref()),
        )
        .unwrap();

        let mut validation = Validation::new(Algorithm::EdDSA);
        validation.validate_aud = false;
        let result = decode::<Claims>(&token, &DecodingKey::from_ed_der(&b_pub), &validation);

        assert!(
            result.is_err(),
            "tenant B's key must not verify tenant A's token"
        );
    }
}
