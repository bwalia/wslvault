//! The proxy's own vault identity and the brokered-secret cache.
//!
//! The agent's session token is used only to decide *whether* a request may be
//! brokered. The secret itself is read with the proxy's **own** credential, so
//! an agent token never needs (and must never be given) read access to a
//! brokered path. That is the whole point: a leaked agent token can be used to
//! make requests through this proxy for an hour, but it cannot be used to pull
//! the upstream API key out of the vault.
//!
//! The proxy authenticates in one of two ways:
//!
//! * **Kubernetes auth** (recommended): `VAULT_AGENT_PROXY_K8S_ROLE` set. The
//!   pod's projected service-account token is exchanged at
//!   `POST {identity}/v1/auth/kubernetes/login`, and re-exchanged before the
//!   resulting session token expires.
//! * **Static token**: `VAULT_AGENT_PROXY_TOKEN`. Intended for development.

use std::{
    collections::HashMap,
    sync::Arc,
    time::{Duration, Instant},
};

use axum::http::{HeaderMap, HeaderValue};
use base64::Engine as _;
use serde::Deserialize;
use tokio::sync::{Mutex, RwLock};
use tracing::{info, warn};

use crate::config::Route;

/// Re-login when the broker token has less than this left.
const REFRESH_MARGIN: Duration = Duration::from_secs(300);

const DEFAULT_SA_TOKEN_PATH: &str = "/var/run/secrets/kubernetes.io/serviceaccount/token";

#[derive(Debug, thiserror::Error)]
pub enum BrokerError {
    #[error("broker is not authenticated to the vault: {0}")]
    Auth(String),
    #[error("secret-engine request failed: {0}")]
    Upstream(String),
    #[error("brokered secret '{path}' is unusable: {reason}")]
    Secret { path: String, reason: String },
}

#[derive(Clone)]
pub enum CredentialSource {
    Static(String),
    Kubernetes {
        identity_url: String,
        role: String,
        sa_token_path: String,
    },
}

struct BrokerToken {
    token: String,
    tenant_id: String,
    /// `None` for a static token whose expiry we could not learn.
    refresh_at: Option<Instant>,
}

/// A brokered credential: the raw secret and the header value built from it.
#[derive(Clone)]
pub struct Credential {
    pub secret: String,
    pub header_value: String,
}

struct CachedSecret {
    value: Credential,
    fetched: Instant,
}

/// Holds the broker's credential and caches brokered secret values.
pub struct Broker {
    http: reqwest::Client,
    secret_engine_url: String,
    source: CredentialSource,
    token: RwLock<Option<Arc<BrokerToken>>>,
    login_lock: Mutex<()>,
    cache: RwLock<HashMap<String, CachedSecret>>,
    cache_ttl: Duration,
}

#[derive(Deserialize)]
struct LoginResponse {
    token: String,
    tenant_id: String,
    expires_at: chrono::DateTime<chrono::Utc>,
}

#[derive(Deserialize)]
struct SecretBody {
    data: String,
}

impl Broker {
    pub fn new(
        http: reqwest::Client,
        secret_engine_url: String,
        source: CredentialSource,
        cache_ttl: Duration,
    ) -> Self {
        Self {
            http,
            secret_engine_url: secret_engine_url.trim_end_matches('/').to_string(),
            source,
            token: RwLock::new(None),
            login_lock: Mutex::new(()),
            cache: RwLock::new(HashMap::new()),
            cache_ttl,
        }
    }

    pub fn from_env(http: reqwest::Client) -> anyhow::Result<Self> {
        let secret_engine_url = std::env::var("VAULT_SECRET_ENGINE_ADDR")
            .unwrap_or_else(|_| "http://secret-engine:8081".into());
        let source = if let Ok(role) = std::env::var("VAULT_AGENT_PROXY_K8S_ROLE") {
            CredentialSource::Kubernetes {
                identity_url: std::env::var("VAULT_IDENTITY_SERVICE_ADDR")
                    .unwrap_or_else(|_| "http://identity-service:8080".into())
                    .trim_end_matches('/')
                    .to_string(),
                role,
                sa_token_path: std::env::var("VAULT_AGENT_PROXY_SA_TOKEN_PATH")
                    .unwrap_or_else(|_| DEFAULT_SA_TOKEN_PATH.into()),
            }
        } else if let Ok(t) = std::env::var("VAULT_AGENT_PROXY_TOKEN") {
            if t.trim().is_empty() {
                anyhow::bail!("VAULT_AGENT_PROXY_TOKEN is empty");
            }
            CredentialSource::Static(t.trim().to_string())
        } else {
            anyhow::bail!(
                "the proxy needs its own vault identity: set VAULT_AGENT_PROXY_K8S_ROLE \
                 (Kubernetes auth) or VAULT_AGENT_PROXY_TOKEN"
            );
        };
        let cache_ttl = Duration::from_secs(
            std::env::var("VAULT_AGENT_PROXY_SECRET_TTL_SECS")
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(60),
        );
        Ok(Self::new(http, secret_engine_url, source, cache_ttl))
    }

    /// Tenant the broker acts for. Agents must belong to the same tenant.
    pub async fn tenant_id(&self) -> Result<String, BrokerError> {
        Ok(self.current_token().await?.tenant_id.clone())
    }

    async fn current_token(&self) -> Result<Arc<BrokerToken>, BrokerError> {
        if let Some(t) = self.token.read().await.as_ref() {
            if t.refresh_at.is_none_or(|at| Instant::now() < at) {
                return Ok(t.clone());
            }
        }
        // Single-flight: one login at a time; late arrivals reuse its result.
        let _guard = self.login_lock.lock().await;
        if let Some(t) = self.token.read().await.as_ref() {
            if t.refresh_at.is_none_or(|at| Instant::now() < at) {
                return Ok(t.clone());
            }
        }
        let fresh = Arc::new(self.login().await?);
        *self.token.write().await = Some(fresh.clone());
        Ok(fresh)
    }

    async fn login(&self) -> Result<BrokerToken, BrokerError> {
        match &self.source {
            CredentialSource::Static(token) => {
                let mut headers = HeaderMap::new();
                let v = HeaderValue::from_str(token)
                    .map_err(|_| BrokerError::Auth("token is not a valid header value".into()))?;
                headers.insert("x-vault-token", v);
                let id = wslvault_core::auth::resolve_identity(&headers)
                    .await
                    .map_err(|e| BrokerError::Auth(e.0))?;
                let refresh_at = id.expires_at.and_then(|exp| {
                    let left = exp - chrono::Utc::now().timestamp();
                    u64::try_from(left)
                        .ok()
                        .map(|s| Instant::now() + Duration::from_secs(s))
                });
                Ok(BrokerToken {
                    token: token.clone(),
                    tenant_id: id.tenant_id,
                    refresh_at,
                })
            }
            CredentialSource::Kubernetes {
                identity_url,
                role,
                sa_token_path,
            } => {
                // Re-read every time: kubelet rotates projected tokens.
                let jwt = tokio::fs::read_to_string(sa_token_path)
                    .await
                    .map_err(|e| BrokerError::Auth(format!("read {sa_token_path}: {e}")))?;
                let resp = self
                    .http
                    .post(format!("{identity_url}/v1/auth/kubernetes/login"))
                    .json(&serde_json::json!({ "jwt": jwt.trim(), "role": role }))
                    .send()
                    .await
                    .map_err(|e| BrokerError::Auth(format!("kubernetes login: {e}")))?;
                if !resp.status().is_success() {
                    let status = resp.status();
                    let body = resp.text().await.unwrap_or_default();
                    return Err(BrokerError::Auth(format!(
                        "kubernetes login returned {status}: {body}"
                    )));
                }
                let login: LoginResponse = resp
                    .json()
                    .await
                    .map_err(|e| BrokerError::Auth(format!("kubernetes login body: {e}")))?;
                let left = (login.expires_at - chrono::Utc::now())
                    .to_std()
                    .unwrap_or_default();
                info!(tenant_id = %login.tenant_id, ttl_secs = left.as_secs(), "broker authenticated via kubernetes auth");
                Ok(BrokerToken {
                    token: login.token,
                    tenant_id: login.tenant_id,
                    refresh_at: Some(Instant::now() + left.saturating_sub(REFRESH_MARGIN)),
                })
            }
        }
    }

    /// Drop a cached value, e.g. after the upstream rejected it (rotated key).
    pub async fn invalidate(&self, route: &Route) {
        self.cache.write().await.remove(&route.name);
    }

    /// The header value to inject for `route`, e.g. `Bearer ghp_…`.
    pub async fn credential(&self, route: &Route) -> Result<Credential, BrokerError> {
        if let Some(c) = self.cache.read().await.get(&route.name) {
            if c.fetched.elapsed() < self.cache_ttl {
                return Ok(c.value.clone());
            }
        }
        let secret = self.fetch(route).await?;
        let value = Credential {
            header_value: route
                .inject_format
                .replace(crate::config::SECRET_PLACEHOLDER, &secret),
            secret,
        };
        self.cache.write().await.insert(
            route.name.clone(),
            CachedSecret {
                value: value.clone(),
                fetched: Instant::now(),
            },
        );
        Ok(value)
    }

    async fn fetch(&self, route: &Route) -> Result<String, BrokerError> {
        let token = self.current_token().await?;
        let url = format!(
            "{}/v1/secret/data/{}",
            self.secret_engine_url, route.secret_path
        );
        let resp = self
            .http
            .get(&url)
            .header("x-vault-token", &token.token)
            .send()
            .await
            .map_err(|e| BrokerError::Upstream(e.to_string()))?;
        if resp.status() == reqwest::StatusCode::UNAUTHORIZED {
            // Our token was revoked or rotated out from under us; force a re-login next time.
            *self.token.write().await = None;
        }
        if !resp.status().is_success() {
            return Err(BrokerError::Upstream(format!(
                "secret-engine returned {} for {}",
                resp.status(),
                route.secret_path
            )));
        }
        let body: SecretBody = resp
            .json()
            .await
            .map_err(|e| BrokerError::Upstream(format!("secret body: {e}")))?;
        extract_secret(&route.secret_path, &body.data, route.secret_key.as_deref())
    }
}

/// Decode secret-engine's base64 `data` and pick out the credential.
pub fn extract_secret(
    path: &str,
    data_b64: &str,
    key: Option<&str>,
) -> Result<String, BrokerError> {
    let err = |reason: &str| BrokerError::Secret {
        path: path.to_string(),
        reason: reason.to_string(),
    };
    let bytes = base64::engine::general_purpose::STANDARD
        .decode(data_b64)
        .map_err(|_| err("data is not base64"))?;
    let text = String::from_utf8(bytes).map_err(|_| err("data is not UTF-8"))?;
    let value = match key {
        Some(k) => {
            let json: serde_json::Value =
                serde_json::from_str(&text).map_err(|_| err("data is not a JSON object"))?;
            match json.get(k) {
                Some(serde_json::Value::String(s)) => s.clone(),
                Some(_) => return Err(err(&format!("field '{k}' is not a string"))),
                None => return Err(err(&format!("field '{k}' is missing"))),
            }
        }
        None => text.trim().to_string(),
    };
    if value.is_empty() {
        return Err(err("value is empty"));
    }
    if value.contains(['\r', '\n']) {
        warn!(
            path,
            "brokered secret contains a newline; refusing to inject it into a header"
        );
        return Err(err("value contains a newline"));
    }
    Ok(value)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn b64(s: &str) -> String {
        base64::engine::general_purpose::STANDARD.encode(s)
    }

    #[test]
    fn extracts_json_field() {
        let v = extract_secret(
            "p",
            &b64(r#"{"api_key":"sk-123","other":"x"}"#),
            Some("api_key"),
        );
        assert_eq!(v.unwrap(), "sk-123");
    }

    #[test]
    fn extracts_raw_value() {
        assert_eq!(
            extract_secret("p", &b64("  ghp_abc\n"), None).unwrap(),
            "ghp_abc"
        );
    }

    #[test]
    fn rejects_missing_field_and_header_injection() {
        assert!(extract_secret("p", &b64(r#"{"a":"b"}"#), Some("api_key")).is_err());
        assert!(extract_secret("p", &b64(r#"{"k":"a\r\nX-Evil: 1"}"#), Some("k")).is_err());
        assert!(extract_secret("p", &b64(r#"{"k":7}"#), Some("k")).is_err());
        assert!(extract_secret("p", "!!!", None).is_err());
    }
}
