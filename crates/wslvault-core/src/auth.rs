//! Caller authentication, shared by every service that fronts tenant data.
//!
//! This module exists because the logic previously lived inside
//! `secret-engine/src/kv2.rs`, the HashiCorp-compatibility shim. That placement
//! invited the reading that it was "the KV v2 auth" rather than "the auth", so
//! the native `/v1/secret/*` handlers and the whole of policy-engine were left
//! resolving identity straight from unauthenticated request headers: a caller
//! could assert `X-Tenant-Id: <any tenant>` plus `X-Policies: <any policy>` and
//! read or write that tenant's secrets with no credential at all.
//!
//! There is now exactly one way to learn who is calling — [`resolve_identity`]
//! — and every mount in every service routes through it. Anything that needs a
//! tenant, a principal or a policy set MUST obtain it here and MUST NOT read
//! those headers directly.
//!
//! # Precedence
//!
//! 1. `X-Tenant-Id` (+ `X-Principal-Id`, `X-Policies`) — the internal contract
//!    the native handlers were written against.
//! 2. `X-Vault-Tenant-ID` (+ `X-Vault-Principal-ID`, `X-Vault-Policies`) — the
//!    spelling `gateway/lua/auth/token_auth.lua` injects on a token-cache hit.
//! 3. `X-Vault-Token` / `Authorization: Bearer …` — a wslvault JWT, verified
//!    here with HS256 against the shared `VAULT_JWT_SECRET`. This is the path
//!    Vault clients such as the External Secrets Operator take.
//!
//! **Tiers 1 and 2 are unauthenticated** — they take the caller's word for
//! which tenant they are and which policies they hold. They are gated behind
//! `VAULT_TRUST_GATEWAY_HEADERS`, which defaults to *off*, and are only safe
//! when a proxy that authenticates the caller and *overwrites* those headers
//! fronts every listener. Note that the OpenResty gateway in this repository
//! does not currently scrub them (see `gateway/conf.d/main.conf`), so leaving
//! this flag off is the correct posture for every deployment today.
//!
//! Tier 3 **fails closed**: with no `VAULT_JWT_SECRET` configured a token is
//! rejected rather than believed, because accepting unverified claims would
//! let any caller that can reach this service assert an arbitrary tenant.

use axum::http::HeaderMap;
use base64::Engine as _;
use jsonwebtoken::{decode, Algorithm, DecodingKey, Validation};
use serde::Deserialize;

/// Environment variable holding the shared HS256 signing secret. Must match the
/// value identity-service issues tokens with, or token auth cannot be verified.
pub const JWT_SECRET_ENV: &str = "VAULT_JWT_SECRET";

/// Opt-in for the pre-authenticated gateway header contract (tiers 1 and 2).
///
/// Defaults to DISABLED. Set to "true"/"1"/"yes" only when a header-scrubbing
/// proxy is genuinely in front of every listener.
pub const TRUST_GATEWAY_HEADERS_ENV: &str = "VAULT_TRUST_GATEWAY_HEADERS";

/// The caller, resolved from a verified token or from the gateway contract.
///
/// Construction is deliberately confined to this module: a handler cannot
/// fabricate an `Identity` out of raw headers, it has to ask
/// [`resolve_identity`] for one.
#[derive(Debug, Clone)]
pub struct Identity {
    pub tenant_id: String,
    pub principal_id: String,
    pub policies: Vec<String>,
    /// Unix expiry when the caller authenticated with a token. `None` for the
    /// gateway header paths, which carry no token lifetime of their own.
    pub expires_at: Option<i64>,
    /// Cross-tenant authority, from a signed claim only.
    ///
    /// This can never come from the gateway header contract: those headers are
    /// caller-asserted, and an asserted superuser flag would hand anyone every
    /// tenant. It is set from a verified token's `superuser` claim or not at
    /// all.
    pub superuser: bool,
}

/// Why authentication failed. Rendered by the caller in whichever error shape
/// its mount speaks — Vault's `{"errors":[…]}` or the native `{"code","message"}`.
#[derive(Debug, Clone)]
pub struct AuthFailure(pub String);

impl std::fmt::Display for AuthFailure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

/// Claims issued by identity-service (`services/identity-service/src/token.rs`).
/// Unknown fields (`iss`, `iat`, …) are ignored by serde.
#[derive(Debug, Deserialize)]
struct TokenClaims {
    sub: String,
    tenant_id: String,
    #[serde(default)]
    policies: Vec<String>,
    /// Cross-tenant authority. Absent on every legacy token, hence the default.
    #[serde(default)]
    superuser: bool,
    /// Unix expiry. Surfaced by lookup-self as `expire_time`/`ttl`, which
    /// Vault clients require — ESO rejects a store with "no expiration time
    /// found in response" when it is missing.
    exp: i64,
}

/// Whether the unauthenticated tenant headers may be honoured.
fn gateway_headers_trusted() -> bool {
    matches!(
        std::env::var(TRUST_GATEWAY_HEADERS_ENV)
            .unwrap_or_default()
            .trim()
            .to_ascii_lowercase()
            .as_str(),
        "true" | "1" | "yes"
    )
}

fn header_value<'a>(headers: &'a HeaderMap, name: &str) -> Option<&'a str> {
    headers
        .get(name)
        .and_then(|v| v.to_str().ok())
        .filter(|s| !s.is_empty())
}

fn split_csv(raw: Option<&str>) -> Vec<String> {
    raw.map(|s| {
        s.split(',')
            .map(|p| p.trim().to_string())
            .filter(|p| !p.is_empty())
            .collect()
    })
    .unwrap_or_default()
}

/// Extract a token from `X-Vault-Token` (what Vault clients send) or an
/// `Authorization: Bearer` header.
pub fn extract_token(headers: &HeaderMap) -> Option<String> {
    if let Some(t) = header_value(headers, "x-vault-token") {
        return Some(t.to_string());
    }
    header_value(headers, "authorization")
        .and_then(|a| {
            a.strip_prefix("Bearer ")
                .or_else(|| a.strip_prefix("bearer "))
        })
        .map(|t| t.trim().to_string())
        .filter(|t| !t.is_empty())
}

/// Public keys fetched from the identity-service, cached by `kid`.
///
/// Verifiers must not hit the identity-service on every request — that would
/// put it on the hot path of every secret read and make it a single point of
/// failure for the whole system. Keys are immutable for a given `kid`, so a
/// hit is cacheable forever; only a miss costs a fetch.
///
/// A miss re-fetches at most once every [`JWKS_MIN_REFETCH`], so an
/// unrecognised `kid` — which is what a forged token looks like — cannot be
/// used to hammer the identity-service.
struct JwksCache {
    keys: tokio::sync::RwLock<std::collections::HashMap<String, Vec<u8>>>,
    last_fetch: tokio::sync::Mutex<Option<std::time::Instant>>,
}

/// Floor on how often an unknown `kid` may trigger a JWKS fetch.
const JWKS_MIN_REFETCH: std::time::Duration = std::time::Duration::from_secs(10);

static JWKS: once_cell::sync::Lazy<JwksCache> = once_cell::sync::Lazy::new(|| JwksCache {
    keys: tokio::sync::RwLock::new(std::collections::HashMap::new()),
    last_fetch: tokio::sync::Mutex::new(None),
});

fn jwks_cache() -> &'static JwksCache {
    &JWKS
}

#[derive(serde::Deserialize)]
struct JwksDoc {
    keys: Vec<JwkEntry>,
}

#[derive(serde::Deserialize)]
struct JwkEntry {
    kid: String,
    /// base64url-unpadded Ed25519 public key.
    x: String,
}

impl JwksCache {
    async fn public_key_for(&self, kid: &str) -> Result<Vec<u8>, AuthFailure> {
        if let Some(k) = self.keys.read().await.get(kid) {
            return Ok(k.clone());
        }

        self.refresh().await?;

        self.keys
            .read()
            .await
            .get(kid)
            .cloned()
            .ok_or_else(|| AuthFailure(format!("token signed by an unknown key {kid:?}")))
    }

    async fn refresh(&self) -> Result<(), AuthFailure> {
        let url = std::env::var(JWKS_URL_ENV).map_err(|_| {
            AuthFailure(format!(
                "{JWKS_URL_ENV} is not configured; per-tenant token verification is unavailable"
            ))
        })?;

        // Rate-limit: an unknown kid is what a forged token looks like, and it
        // must not become a way to generate load on the identity-service.
        {
            let mut last = self.last_fetch.lock().await;
            if let Some(t) = *last {
                if t.elapsed() < JWKS_MIN_REFETCH {
                    return Ok(());
                }
            }
            *last = Some(std::time::Instant::now());
        }

        let doc: JwksDoc = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(5))
            .build()
            .map_err(|e| AuthFailure(format!("could not build the JWKS client: {e}")))?
            .get(&url)
            .send()
            .await
            .map_err(|e| AuthFailure(format!("could not reach the JWKS endpoint: {e}")))?
            .json()
            .await
            .map_err(|e| AuthFailure(format!("malformed JWKS document: {e}")))?;

        let mut keys = self.keys.write().await;
        for entry in doc.keys {
            match base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(&entry.x) {
                Ok(raw) if raw.len() == 32 => {
                    keys.insert(entry.kid, raw);
                }
                _ => {
                    tracing::warn!(kid = %entry.kid, "skipping malformed JWKS entry");
                }
            }
        }
        Ok(())
    }
}

/// Where to fetch tenant public keys from, e.g.
/// `http://identity-service:8082/v1/identity/.well-known/jwks.json`.
pub const JWKS_URL_ENV: &str = "VAULT_JWKS_URL";

/// Verify a wslvault JWT and return its claims.
///
/// Tries the token's own signature scheme:
///
/// * **EdDSA** — the token carries a `kid`, so it was signed with a tenant's
///   own Ed25519 key. Verified against the public key from JWKS. This is the
///   path that gives each tenant a real cryptographic boundary, and it is
///   verify-only: holding a public key confers no ability to mint.
///
/// * **HS256** — a legacy token under the shared `VAULT_JWT_SECRET`. Accepted
///   so tokens issued before the upgrade keep working until they expire, and
///   only when that secret is configured.
///
/// Fails closed in both cases: an unverifiable token is rejected, never
/// believed.
async fn verify_token_async(token: &str) -> Result<TokenClaims, AuthFailure> {
    let header = jsonwebtoken::decode_header(token)
        .map_err(|e| AuthFailure(format!("malformed token header: {e}")))?;

    match header.alg {
        Algorithm::EdDSA => {
            let kid = header
                .kid
                .ok_or_else(|| AuthFailure("EdDSA token carries no kid".to_string()))?;
            let public_key = jwks_cache().public_key_for(&kid).await?;

            let mut validation = Validation::new(Algorithm::EdDSA);
            validation.validate_aud = false;
            decode::<TokenClaims>(token, &DecodingKey::from_ed_der(&public_key), &validation)
                .map(|d| d.claims)
                .map_err(|e| AuthFailure(format!("invalid token: {e}")))
        }
        Algorithm::HS256 => verify_token(token),
        other => Err(AuthFailure(format!(
            "unsupported token algorithm {other:?}"
        ))),
    }
}

/// Verify a legacy wslvault JWT (HS256, shared `VAULT_JWT_SECRET`).
fn verify_token(token: &str) -> Result<TokenClaims, AuthFailure> {
    let secret = std::env::var(JWT_SECRET_ENV).map_err(|_| {
        AuthFailure(format!(
            "{JWT_SECRET_ENV} is not configured; token authentication is unavailable"
        ))
    })?;
    if secret.is_empty() {
        return Err(AuthFailure(format!(
            "{JWT_SECRET_ENV} is empty; token authentication is unavailable"
        )));
    }
    // Defaults already require and validate `exp`; issuer/audience are not
    // enforced so tokens from any configured identity provider are accepted.
    let validation = Validation::new(Algorithm::HS256);
    decode::<TokenClaims>(
        token,
        &DecodingKey::from_secret(secret.as_bytes()),
        &validation,
    )
    .map(|data| data.claims)
    .map_err(|e| AuthFailure(format!("invalid token: {e}")))
}

/// Optional lookup into the durable token-revocation list.
///
/// Services that have a database install this at startup via
/// [`set_token_revocation`]. Without it, a cryptographically valid JWT is
/// accepted until `exp` — fine for local in-memory mode, not for production.
/// The checker **fails closed**: an error is treated as "do not authenticate".
#[async_trait::async_trait]
pub trait TokenRevocation: Send + Sync {
    async fn is_revoked(&self, token: &str) -> Result<bool, AuthFailure>;
}

static TOKEN_REVOCATION: once_cell::sync::OnceCell<std::sync::Arc<dyn TokenRevocation>> =
    once_cell::sync::OnceCell::new();

/// Install the process-wide revocation checker. Subsequent calls are ignored.
pub fn set_token_revocation(checker: std::sync::Arc<dyn TokenRevocation>) {
    if TOKEN_REVOCATION.set(checker).is_err() {
        tracing::warn!("token revocation checker already installed; ignoring");
    }
}

fn token_revocation() -> Option<&'static std::sync::Arc<dyn TokenRevocation>> {
    TOKEN_REVOCATION.get()
}

/// Header a superuser uses to name the tenant it is acting on.
///
/// Only honoured for an identity whose *signed* token carries `superuser`.
/// For everyone else it is ignored entirely, so it is not a way to change
/// tenants — it is a way for someone already authorised across all of them to
/// say which one they mean.
pub const ACT_AS_TENANT_HEADER: &str = "x-vault-act-tenant";

/// Apply the superuser's choice of acting tenant, if they made one.
///
/// Returns the tenant actually operated on, and whether it differed from the
/// superuser's home tenant — callers use that to audit the crossing rather than
/// letting it pass as an ordinary request.
pub fn act_as_tenant(identity: &Identity, headers: &HeaderMap) -> (String, bool) {
    if !identity.superuser {
        return (identity.tenant_id.clone(), false);
    }
    match header_value(headers, ACT_AS_TENANT_HEADER) {
        Some(t) if t != identity.tenant_id => (t.to_string(), true),
        _ => (identity.tenant_id.clone(), false),
    }
}

/// Resolve the calling identity. See the module docs for the precedence order.
///
/// This is the only sanctioned source of a tenant id, principal id or policy
/// set inside this service.
pub async fn resolve_identity(headers: &HeaderMap) -> Result<Identity, AuthFailure> {
    // Tiers 1 and 2 are UNAUTHENTICATED: they take the caller's word for which
    // tenant they are. Only honour them when an operator has explicitly asserted
    // that a trusted, header-scrubbing proxy fronts every listener.
    let trust_headers = gateway_headers_trusted();

    // 1. Native internal contract.
    if trust_headers {
        if let Some(tenant) = header_value(headers, "x-tenant-id") {
            return Ok(Identity {
                tenant_id: tenant.to_string(),
                principal_id: header_value(headers, "x-principal-id")
                    .unwrap_or("anonymous")
                    .to_string(),
                policies: split_csv(header_value(headers, "x-policies")),
                expires_at: None,
                // Never from a header. See `Identity::superuser`.
                superuser: false,
            });
        }
    }

    // 2. Headers the gateway injects on a token-cache hit. The gateway writes
    //    the `X-Vault-*` spelling while the native handlers read `x-tenant-id`,
    //    so honouring both keeps gateway-authenticated requests working.
    if trust_headers {
        if let Some(tenant) = header_value(headers, "x-vault-tenant-id") {
            return Ok(Identity {
                tenant_id: tenant.to_string(),
                principal_id: header_value(headers, "x-vault-principal-id")
                    .unwrap_or("anonymous")
                    .to_string(),
                policies: split_csv(header_value(headers, "x-vault-policies")),
                expires_at: None,
                superuser: false,
            });
        }
    }

    // 3. A raw token — the path Vault clients (and ESO) take.
    if let Some(token) = extract_token(headers) {
        let claims = verify_token_async(&token).await?;
        if let Some(checker) = token_revocation() {
            match checker.is_revoked(&token).await {
                Ok(true) => {
                    return Err(AuthFailure("token has been revoked".to_string()));
                }
                Ok(false) => {}
                Err(e) => return Err(e),
            }
        }
        return Ok(Identity {
            tenant_id: claims.tenant_id,
            principal_id: claims.sub,
            policies: claims.policies,
            expires_at: Some(claims.exp),
            superuser: claims.superuser,
        });
    }

    Err(AuthFailure(
        "missing authentication: supply X-Vault-Token, or X-Tenant-Id when behind the gateway"
            .to_string(),
    ))
}

#[cfg(test)]
// ENV_LOCK is deliberately held across `.await`: it serialises mutation of the
// process-wide auth env vars for the whole body of each test, which is exactly
// the window the awaited resolver reads them in. An async mutex would not help
// — these tests must exclude each other, not yield. Same allow and reasoning as
// crypto-service/src/root_key.rs.
#[allow(clippy::await_holding_lock)]
mod tests {
    use super::*;
    use axum::http::{HeaderName, HeaderValue};

    /// `VAULT_TRUST_GATEWAY_HEADERS` and `VAULT_JWT_SECRET` are process-global
    /// and the harness runs tests in parallel, so every test that mutates them
    /// holds this lock for its full duration.
    pub(super) static ENV_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    /// Enable the gateway header contract for the duration of a test.
    struct TrustHeaders(#[allow(dead_code)] std::sync::MutexGuard<'static, ()>);

    impl TrustHeaders {
        fn on() -> Self {
            let g = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
            std::env::set_var(TRUST_GATEWAY_HEADERS_ENV, "true");
            Self(g)
        }
    }

    impl Drop for TrustHeaders {
        fn drop(&mut self) {
            std::env::remove_var(TRUST_GATEWAY_HEADERS_ENV);
        }
    }

    fn headers(pairs: &[(&str, &str)]) -> HeaderMap {
        let mut h = HeaderMap::new();
        for (k, v) in pairs {
            h.insert(
                HeaderName::from_bytes(k.as_bytes()).unwrap(),
                HeaderValue::from_str(v).unwrap(),
            );
        }
        h
    }

    fn tenant_headers() -> HeaderMap {
        headers(&[
            ("x-tenant-id", "victim-tenant"),
            ("x-policies", "root,admin"),
        ])
    }

    // ── The gateway header contract is opt-in ────────────────────────────────

    #[tokio::test]
    async fn headers_are_rejected_by_default() {
        let _g = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        std::env::remove_var(TRUST_GATEWAY_HEADERS_ENV);
        assert!(
            resolve_identity(&tenant_headers()).await.is_err(),
            "X-Tenant-Id must NOT authenticate when the flag is unset"
        );
    }

    #[tokio::test]
    async fn vault_spelling_is_rejected_by_default() {
        let _g = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        std::env::remove_var(TRUST_GATEWAY_HEADERS_ENV);
        let h = headers(&[
            ("x-vault-tenant-id", "victim-tenant"),
            ("x-vault-policies", "root"),
        ]);
        assert!(
            resolve_identity(&h).await.is_err(),
            "X-Vault-Tenant-ID must NOT authenticate when the flag is unset"
        );
    }

    #[tokio::test]
    async fn explicitly_disabled_still_rejects() {
        let _g = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        std::env::set_var(TRUST_GATEWAY_HEADERS_ENV, "false");
        let got = resolve_identity(&tenant_headers()).await;
        std::env::remove_var(TRUST_GATEWAY_HEADERS_ENV);
        assert!(got.is_err());
    }

    #[tokio::test]
    async fn honoured_only_when_explicitly_enabled() {
        let _trust = TrustHeaders::on();
        let id = resolve_identity(&tenant_headers())
            .await
            .expect("flag on: the gateway contract should still work");
        assert_eq!(id.tenant_id, "victim-tenant");
        assert_eq!(id.expires_at, None, "header identities carry no expiry");
    }

    #[tokio::test]
    async fn internal_headers_take_precedence() {
        let _trust = TrustHeaders::on();
        let id = resolve_identity(&headers(&[
            ("x-tenant-id", "acme"),
            ("x-principal-id", "svc"),
            ("x-policies", "read-db, write-db"),
        ]))
        .await
        .expect("should resolve");
        assert_eq!(id.tenant_id, "acme");
        assert_eq!(id.principal_id, "svc");
        assert_eq!(id.policies, vec!["read-db", "write-db"]);
    }

    #[tokio::test]
    async fn gateway_injected_headers_are_honoured() {
        let _trust = TrustHeaders::on();
        let id = resolve_identity(&headers(&[
            ("x-vault-tenant-id", "acme"),
            ("x-vault-principal-id", "svc"),
        ]))
        .await
        .expect("should resolve");
        assert_eq!(id.tenant_id, "acme");
        assert_eq!(id.principal_id, "svc");
    }

    // ── Token path ───────────────────────────────────────────────────────────

    #[tokio::test]
    async fn missing_auth_is_rejected() {
        assert!(resolve_identity(&HeaderMap::new()).await.is_err());
    }

    #[test]
    fn token_without_configured_secret_is_rejected_not_trusted() {
        // Fail closed: an unverifiable token must never be believed.
        let _g = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        std::env::remove_var(JWT_SECRET_ENV);
        assert!(verify_token("any.token.here").is_err());
    }

    #[test]
    fn extracts_token_from_either_header() {
        assert_eq!(
            extract_token(&headers(&[("x-vault-token", "abc")])).as_deref(),
            Some("abc")
        );
        assert_eq!(
            extract_token(&headers(&[("authorization", "Bearer xyz")])).as_deref(),
            Some("xyz")
        );
        assert_eq!(extract_token(&HeaderMap::new()), None);
    }

    /// The regression that motivated this module: an unauthenticated caller
    /// asserting another tenant's id and an elevated policy set must not be
    /// able to authenticate on the DEFAULT configuration, which is what the
    /// native `/v1/secret/*` handlers used to permit unconditionally.
    #[tokio::test]
    async fn forged_tenant_and_policy_headers_do_not_authenticate_by_default() {
        let _g = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        std::env::remove_var(TRUST_GATEWAY_HEADERS_ENV);
        for h in [
            headers(&[("x-tenant-id", "victim"), ("x-policies", "admin")]),
            headers(&[
                ("x-vault-tenant-id", "victim"),
                ("x-vault-policies", "admin"),
            ]),
            headers(&[("x-principal-id", "root"), ("x-policies", "admin")]),
        ] {
            assert!(
                resolve_identity(&h).await.is_err(),
                "forged identity headers must never authenticate by default"
            );
        }
    }

    /// A caller holding a genuine low-privilege token must not be able to
    /// escalate by *also* sending an `X-Policies` header: the policy set comes
    /// from the signed claims, never from the request.
    #[tokio::test]
    async fn policies_come_from_the_token_not_the_headers() {
        use jsonwebtoken::{encode, EncodingKey, Header};

        let _g = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        std::env::set_var(JWT_SECRET_ENV, "test-secret-at-least-32-bytes-long!!");
        std::env::remove_var(TRUST_GATEWAY_HEADERS_ENV);

        let claims = serde_json::json!({
            "sub": "user-1",
            "tenant_id": "acme",
            "policies": ["read-only"],
            "exp": chrono::Utc::now().timestamp() + 3600,
        });
        let token = encode(
            &Header::new(Algorithm::HS256),
            &claims,
            &EncodingKey::from_secret(b"test-secret-at-least-32-bytes-long!!"),
        )
        .expect("test token should encode");

        let id = resolve_identity(&headers(&[
            ("authorization", &format!("Bearer {token}")),
            ("x-policies", "admin,root"),
            ("x-tenant-id", "victim"),
        ]))
        .await
        .expect("valid token should authenticate");

        std::env::remove_var(JWT_SECRET_ENV);

        assert_eq!(id.tenant_id, "acme", "tenant must come from the token");
        assert_eq!(
            id.policies,
            vec!["read-only"],
            "policies must come from the token, not the X-Policies header"
        );
    }

    // ── Superuser ────────────────────────────────────────────────────────────

    fn identity(superuser: bool) -> Identity {
        Identity {
            tenant_id: "home-tenant".into(),
            principal_id: "p".into(),
            policies: vec![],
            expires_at: None,
            superuser,
        }
    }

    /// The header is inert for an ordinary caller. If it were not, it would be
    /// a one-header tenant switch — exactly the class of bug the authenticated
    /// identity path exists to close.
    #[test]
    fn act_as_tenant_is_ignored_for_a_non_superuser() {
        let h = headers(&[(ACT_AS_TENANT_HEADER, "victim-tenant")]);
        let (tenant, crossed) = act_as_tenant(&identity(false), &h);
        assert_eq!(tenant, "home-tenant");
        assert!(!crossed);
    }

    #[test]
    fn a_superuser_may_name_another_tenant() {
        let h = headers(&[(ACT_AS_TENANT_HEADER, "other-tenant")]);
        let (tenant, crossed) = act_as_tenant(&identity(true), &h);
        assert_eq!(tenant, "other-tenant");
        assert!(crossed, "crossing tenants must be reported for audit");
    }

    #[test]
    fn a_superuser_without_the_header_stays_home() {
        let (tenant, crossed) = act_as_tenant(&identity(true), &HeaderMap::new());
        assert_eq!(tenant, "home-tenant");
        assert!(!crossed);
    }

    /// Naming your own tenant is not a crossing, and must not be audited as one
    /// — a log that cries wolf on every superuser request is a log nobody reads.
    #[test]
    fn naming_the_home_tenant_is_not_a_crossing() {
        let h = headers(&[(ACT_AS_TENANT_HEADER, "home-tenant")]);
        let (tenant, crossed) = act_as_tenant(&identity(true), &h);
        assert_eq!(tenant, "home-tenant");
        assert!(!crossed);
    }

    /// The superuser flag must never be derivable from a request. This pins
    /// that: the header contract, even when trusted, cannot produce one.
    #[test]
    fn the_gateway_contract_cannot_produce_a_superuser() {
        let _trust = TrustHeaders::on();
        for h in [
            headers(&[("x-tenant-id", "t"), ("x-superuser", "true")]),
            headers(&[("x-vault-tenant-id", "t"), ("x-policies", "root")]),
        ] {
            let id = futures_lite_block_on(resolve_identity(&h));
            if let Ok(id) = id {
                assert!(
                    !id.superuser,
                    "no header combination may confer cross-tenant authority"
                );
            }
        }
    }

    /// Minimal block_on so the test above does not need a runtime attribute
    /// while the surrounding module mixes sync and async tests.
    fn futures_lite_block_on<F: std::future::Future>(f: F) -> F::Output {
        tokio::runtime::Builder::new_current_thread()
            .build()
            .expect("runtime")
            .block_on(f)
    }
}
