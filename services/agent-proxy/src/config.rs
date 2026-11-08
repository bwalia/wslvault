//! Route configuration: which upstream an agent may reach, with which brokered
//! credential, and who is allowed to use it.
//!
//! Routes are loaded from `VAULT_AGENT_PROXY_ROUTES` (inline JSON) or
//! `VAULT_AGENT_PROXY_ROUTES_FILE` (a path, typically a mounted ConfigMap).
//! The document is a JSON object keyed by route name:
//!
//! ```json
//! {
//!   "anthropic": {
//!     "upstream": "https://api.anthropic.com",
//!     "hosts": ["api.anthropic.com"],
//!     "allowed_policies": ["agent-claude"],
//!     "secret_path": "brokered/anthropic",
//!     "secret_key": "api_key",
//!     "inject_header": "x-api-key",
//!     "inject_format": "{secret}"
//!   }
//! }
//! ```
//!
//! Validation is strict and happens once at startup, so a typo fails the pod
//! instead of quietly opening (or closing) a route at request time.

use std::collections::HashMap;

use axum::http::{HeaderName, Method};
use serde::Deserialize;

/// Placeholder substituted with the secret value in [`Route::inject_format`].
pub const SECRET_PLACEHOLDER: &str = "{secret}";

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawRoute {
    upstream: String,
    #[serde(default)]
    hosts: Vec<String>,
    allowed_policies: Vec<String>,
    #[serde(default)]
    allowed_principals: Vec<String>,
    secret_path: String,
    #[serde(default)]
    secret_key: Option<String>,
    inject_header: String,
    #[serde(default = "default_inject_format")]
    inject_format: String,
    #[serde(default)]
    allowed_methods: Vec<String>,
    #[serde(default)]
    allowed_path_prefixes: Vec<String>,
    #[serde(default)]
    strip_headers: Vec<String>,
}

fn default_inject_format() -> String {
    SECRET_PLACEHOLDER.to_string()
}

/// A validated route.
#[derive(Debug, Clone)]
pub struct Route {
    pub name: String,
    /// Scheme + authority (+ optional base path), no trailing slash.
    pub upstream: String,
    /// Hostnames matched in forward-proxy mode (absolute-form request URIs).
    pub hosts: Vec<String>,
    /// The caller needs at least one of these policies. Never empty.
    pub allowed_policies: Vec<String>,
    /// Optional principal allowlist; a trailing `*` is a prefix match.
    pub allowed_principals: Vec<String>,
    pub secret_path: String,
    /// Field of the JSON secret to inject. `None` injects the whole value.
    pub secret_key: Option<String>,
    pub inject_header: HeaderName,
    pub inject_format: String,
    /// Empty means any method.
    pub allowed_methods: Vec<Method>,
    /// Empty means any path.
    pub allowed_path_prefixes: Vec<String>,
    /// Extra request headers removed before forwarding.
    pub strip_headers: Vec<HeaderName>,
}

impl Route {
    pub fn principal_allowed(&self, principal: &str) -> bool {
        if self.allowed_principals.is_empty() {
            return true;
        }
        self.allowed_principals
            .iter()
            .any(|p| match p.strip_suffix('*') {
                Some(prefix) => principal.starts_with(prefix),
                None => p == principal,
            })
    }

    pub fn policy_allowed(&self, policies: &[String]) -> bool {
        policies.iter().any(|p| self.allowed_policies.contains(p))
    }

    pub fn method_allowed(&self, method: &Method) -> bool {
        self.allowed_methods.is_empty() || self.allowed_methods.contains(method)
    }

    /// `path` always starts with `/`.
    pub fn path_allowed(&self, path: &str) -> bool {
        self.allowed_path_prefixes.is_empty()
            || self
                .allowed_path_prefixes
                .iter()
                .any(|p| path.starts_with(p.as_str()))
    }
}

#[derive(Debug, thiserror::Error)]
pub enum ConfigError {
    #[error("no routes configured: set VAULT_AGENT_PROXY_ROUTES or VAULT_AGENT_PROXY_ROUTES_FILE")]
    Missing,
    #[error("cannot read routes file {0}: {1}")]
    File(String, std::io::Error),
    #[error("routes are not valid JSON: {0}")]
    Json(#[from] serde_json::Error),
    #[error("route '{0}': {1}")]
    Invalid(String, String),
}

#[derive(Debug, Clone, Default)]
pub struct Routes {
    by_name: HashMap<String, Route>,
    by_host: HashMap<String, String>,
}

impl Routes {
    pub fn from_env() -> Result<Self, ConfigError> {
        if let Ok(path) = std::env::var("VAULT_AGENT_PROXY_ROUTES_FILE") {
            let raw = std::fs::read_to_string(&path).map_err(|e| ConfigError::File(path, e))?;
            return Self::parse(&raw, allow_http_upstreams());
        }
        match std::env::var("VAULT_AGENT_PROXY_ROUTES") {
            Ok(raw) if !raw.trim().is_empty() => Self::parse(&raw, allow_http_upstreams()),
            _ => Err(ConfigError::Missing),
        }
    }

    /// `allow_http` permits `http://` upstreams; local development only.
    pub fn parse(raw: &str, allow_http: bool) -> Result<Self, ConfigError> {
        let raw_routes: HashMap<String, RawRoute> = serde_json::from_str(raw)?;
        if raw_routes.is_empty() {
            return Err(ConfigError::Missing);
        }
        let mut routes = Routes::default();
        for (name, r) in raw_routes {
            let route = validate(&name, r, allow_http)?;
            for host in &route.hosts {
                if let Some(other) = routes.by_host.insert(host.clone(), name.clone()) {
                    return Err(ConfigError::Invalid(
                        name,
                        format!("host '{host}' is already claimed by route '{other}'"),
                    ));
                }
            }
            routes.by_name.insert(name, route);
        }
        Ok(routes)
    }

    pub fn get(&self, name: &str) -> Option<&Route> {
        self.by_name.get(name)
    }

    pub fn by_host(&self, host: &str) -> Option<&Route> {
        self.by_host
            .get(&host.to_ascii_lowercase())
            .and_then(|n| self.by_name.get(n))
    }

    pub fn len(&self) -> usize {
        self.by_name.len()
    }

    pub fn names(&self) -> impl Iterator<Item = &String> {
        self.by_name.keys()
    }
}

fn valid_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 64
        && name
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
}

/// `VAULT_AGENT_PROXY_ALLOW_HTTP_UPSTREAMS` — dev-only escape hatch.
pub fn allow_http_upstreams() -> bool {
    std::env::var("VAULT_AGENT_PROXY_ALLOW_HTTP_UPSTREAMS")
        .map(|v| matches!(v.as_str(), "1" | "true" | "yes"))
        .unwrap_or(false)
}

fn validate(name: &str, r: RawRoute, local_dev: bool) -> Result<Route, ConfigError> {
    let bad = |msg: &str| ConfigError::Invalid(name.to_string(), msg.to_string());

    if !valid_name(name) {
        return Err(bad("name must be 1-64 chars of [A-Za-z0-9_-]"));
    }

    let upstream = r.upstream.trim_end_matches('/').to_string();
    let parsed = reqwest::Url::parse(&upstream).map_err(|e| bad(&format!("upstream: {e}")))?;
    match parsed.scheme() {
        "https" => {}
        "http" if local_dev => {}
        "http" => {
            return Err(bad(
                "upstream must be https (a brokered credential must not cross the wire in clear); \
                 set VAULT_AGENT_PROXY_ALLOW_HTTP_UPSTREAMS=true for local development only",
            ))
        }
        other => return Err(bad(&format!("unsupported upstream scheme '{other}'"))),
    }
    if parsed.host_str().is_none() || parsed.query().is_some() || parsed.fragment().is_some() {
        return Err(bad(
            "upstream must be scheme://host[:port][/base-path] with no query",
        ));
    }

    // Fail closed: a route nobody is bound to is a route anybody could use.
    let allowed_policies: Vec<String> = r
        .allowed_policies
        .into_iter()
        .map(|p| p.trim().to_string())
        .filter(|p| !p.is_empty())
        .collect();
    if allowed_policies.is_empty() {
        return Err(bad("allowed_policies must name at least one policy"));
    }

    if r.secret_path.trim().is_empty() || r.secret_path.contains("..") {
        return Err(bad("secret_path must be a non-empty path without '..'"));
    }

    let inject_header = HeaderName::from_bytes(r.inject_header.trim().as_bytes())
        .map_err(|_| bad("inject_header is not a valid header name"))?;
    if !r.inject_format.contains(SECRET_PLACEHOLDER) {
        return Err(bad("inject_format must contain {secret}"));
    }

    let allowed_methods = r
        .allowed_methods
        .iter()
        .map(|m| {
            Method::from_bytes(m.to_ascii_uppercase().as_bytes())
                .map_err(|_| bad(&format!("invalid method '{m}'")))
        })
        .collect::<Result<Vec<_>, _>>()?;

    for p in &r.allowed_path_prefixes {
        if !p.starts_with('/') {
            return Err(bad("allowed_path_prefixes entries must start with '/'"));
        }
    }

    let strip_headers = r
        .strip_headers
        .iter()
        .map(|h| {
            HeaderName::from_bytes(h.trim().as_bytes())
                .map_err(|_| bad(&format!("invalid strip_headers entry '{h}'")))
        })
        .collect::<Result<Vec<_>, _>>()?;

    let hosts = r
        .hosts
        .iter()
        .map(|h| h.trim().to_ascii_lowercase())
        .filter(|h| !h.is_empty())
        .collect();

    Ok(Route {
        name: name.to_string(),
        upstream,
        hosts,
        allowed_policies,
        allowed_principals: r.allowed_principals,
        secret_path: r.secret_path.trim_matches('/').to_string(),
        secret_key: r.secret_key.filter(|k| !k.is_empty()),
        inject_header,
        inject_format: r.inject_format,
        allowed_methods,
        allowed_path_prefixes: r.allowed_path_prefixes,
        strip_headers,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    const GOOD: &str = r#"{
        "anthropic": {
            "upstream": "https://api.anthropic.com/",
            "hosts": ["API.anthropic.com"],
            "allowed_policies": ["agent-claude"],
            "allowed_principals": ["agents:claude-*"],
            "secret_path": "/brokered/anthropic/",
            "secret_key": "api_key",
            "inject_header": "x-api-key",
            "allowed_methods": ["post", "GET"],
            "allowed_path_prefixes": ["/v1/"]
        }
    }"#;

    #[test]
    fn parses_and_normalises() {
        let routes = Routes::parse(GOOD, false).unwrap();
        let r = routes.get("anthropic").unwrap();
        assert_eq!(r.upstream, "https://api.anthropic.com");
        assert_eq!(r.secret_path, "brokered/anthropic");
        assert_eq!(r.inject_format, "{secret}");
        assert!(routes.by_host("api.anthropic.com").is_some());
        assert!(r.method_allowed(&Method::POST));
        assert!(!r.method_allowed(&Method::DELETE));
        assert!(r.path_allowed("/v1/messages"));
        assert!(!r.path_allowed("/admin"));
    }

    #[test]
    fn principal_and_policy_binding() {
        let routes = Routes::parse(GOOD, false).unwrap();
        let r = routes.get("anthropic").unwrap();
        assert!(r.principal_allowed("agents:claude-coder"));
        assert!(!r.principal_allowed("agents:other"));
        assert!(r.policy_allowed(&["x".into(), "agent-claude".into()]));
        assert!(!r.policy_allowed(&["x".into()]));
        assert!(!r.policy_allowed(&[]));
    }

    #[test]
    fn rejects_unbound_route() {
        let raw = r#"{"a":{"upstream":"https://x.example","allowed_policies":[],
            "secret_path":"p","inject_header":"authorization"}}"#;
        assert!(matches!(
            Routes::parse(raw, false),
            Err(ConfigError::Invalid(..))
        ));
    }

    #[test]
    fn rejects_cleartext_upstream() {
        let raw = r#"{"a":{"upstream":"http://x.example","allowed_policies":["p"],
            "secret_path":"p","inject_header":"authorization"}}"#;
        assert!(Routes::parse(raw, false).is_err());
        assert!(Routes::parse(raw, true).is_ok());
    }

    #[test]
    fn rejects_format_without_placeholder() {
        let raw = r#"{"a":{"upstream":"https://x.example","allowed_policies":["p"],
            "secret_path":"p","inject_header":"authorization","inject_format":"Bearer x"}}"#;
        assert!(Routes::parse(raw, false).is_err());
    }

    #[test]
    fn rejects_duplicate_hosts_and_unknown_fields() {
        let dup = r#"{
            "a":{"upstream":"https://x.example","hosts":["x.example"],"allowed_policies":["p"],"secret_path":"p","inject_header":"authorization"},
            "b":{"upstream":"https://x.example","hosts":["x.example"],"allowed_policies":["p"],"secret_path":"p","inject_header":"authorization"}}"#;
        assert!(Routes::parse(dup, false).is_err());
        let unknown = r#"{"a":{"upstream":"https://x.example","allowed_policies":["p"],
            "secret_path":"p","inject_header":"authorization","alowed_methods":["GET"]}}"#;
        assert!(Routes::parse(unknown, false).is_err());
    }
}
