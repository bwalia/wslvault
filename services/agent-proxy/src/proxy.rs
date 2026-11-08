//! The brokering proxy.
//!
//! Two ways in, one pipeline:
//!
//! * **Route mode** — `ANY /r/{route}/{path}`. Point an SDK's base URL here,
//!   e.g. `ANTHROPIC_BASE_URL=http://agent-proxy:8094/r/anthropic`.
//! * **Forward-proxy mode** — `HTTP_PROXY=http://agent-proxy:8094` and a
//!   plain-`http://` absolute-form request to a host claimed by a route. The
//!   proxy upgrades to `https` towards the upstream.
//!
//! `CONNECT` is refused: a TLS tunnel is opaque, so the proxy could neither
//! inject a credential into it nor constrain what it carries. That makes egress
//! deny-by-default — the only traffic that leaves is traffic a route allows.
//!
//! Pipeline: identify the route → verify the agent's session token → check the
//! route's bindings (tenant, policy, principal, method, path) → fetch the
//! brokered credential with the proxy's own identity → strip every credential
//! the agent sent → inject the real one → stream the request and response.

use std::sync::Arc;

use axum::{
    body::Body,
    extract::{Request, State},
    http::{header, HeaderMap, HeaderName, HeaderValue, Method, StatusCode, Uri},
    response::{IntoResponse, Response},
    Json,
};
use futures::TryStreamExt;
use tracing::warn;

use crate::{
    audit::{Audit, AuditEvent},
    broker::Broker,
    config::{Route, Routes},
};

pub struct AppState {
    pub routes: Routes,
    pub broker: Broker,
    /// Client for upstream calls: no redirects, https-only unless dev mode.
    pub upstream: reqwest::Client,
    pub audit: Audit,
}

/// Hop-by-hop headers (RFC 9110 §7.6.1) plus proxy credentials. Never forwarded
/// in either direction.
const HOP_BY_HOP: &[&str] = &[
    "connection",
    "keep-alive",
    "proxy-authenticate",
    "proxy-authorization",
    "proxy-connection",
    "te",
    "trailer",
    "transfer-encoding",
    "upgrade",
];

/// Credential-bearing request headers the agent might send. Always stripped:
/// whatever the agent holds is a session token or a placeholder, never
/// something an upstream should see.
const AGENT_CREDENTIAL_HEADERS: &[&str] = &["authorization", "x-vault-token", "cookie"];

/// wslvault-internal identity headers. Meaningless to a third party, and they
/// would leak tenant and principal names to it.
const INTERNAL_HEADERS: &[&str] = &["x-tenant-id", "x-principal-id", "x-policies"];

#[derive(Debug)]
pub struct ProxyError {
    status: StatusCode,
    code: &'static str,
    message: String,
}

impl ProxyError {
    fn new(status: StatusCode, code: &'static str, message: impl Into<String>) -> Self {
        Self {
            status,
            code,
            message: message.into(),
        }
    }
}

impl IntoResponse for ProxyError {
    fn into_response(self) -> Response {
        let mut resp = (
            self.status,
            Json(serde_json::json!({ "error": self.code, "message": self.message })),
        )
            .into_response();
        if self.status == StatusCode::PROXY_AUTHENTICATION_REQUIRED {
            resp.headers_mut().insert(
                header::PROXY_AUTHENTICATE,
                HeaderValue::from_static("Bearer realm=\"wslvault-agent-proxy\""),
            );
        }
        resp.headers_mut().insert(
            "x-wslvault-proxy-error",
            HeaderValue::from_static(self.code),
        );
        resp
    }
}

/// Which route a request targets and the upstream-relative path.
#[derive(Debug)]
pub struct Target<'a> {
    pub route: &'a Route,
    /// Begins with `/`.
    pub path: String,
    pub forward_mode: bool,
}

pub fn resolve_target<'a>(
    routes: &'a Routes,
    method: &Method,
    uri: &Uri,
) -> Result<Target<'a>, ProxyError> {
    if method == Method::CONNECT {
        return Err(ProxyError::new(
            StatusCode::FORBIDDEN,
            "tunnel_refused",
            "CONNECT is not brokered: egress is limited to configured routes. \
             Use http:// through the proxy, or a /r/{route} base URL.",
        ));
    }

    if let Some(authority) = uri.authority() {
        if uri.scheme_str() != Some("http") {
            return Err(ProxyError::new(
                StatusCode::BAD_REQUEST,
                "bad_scheme",
                "forward-proxy requests must use http://; the proxy upgrades to https",
            ));
        }
        let host = authority.host();
        let route = routes.by_host(host).ok_or_else(|| {
            ProxyError::new(
                StatusCode::FORBIDDEN,
                "egress_denied",
                format!("no route brokers host '{host}'"),
            )
        })?;
        return Ok(Target {
            route,
            path: uri.path().to_string(),
            forward_mode: true,
        });
    }

    let rest = uri.path().strip_prefix("/r/").ok_or_else(|| {
        ProxyError::new(
            StatusCode::NOT_FOUND,
            "not_found",
            "expected /r/{route}/{path}",
        )
    })?;
    let (name, path) = match rest.split_once('/') {
        Some((n, p)) => (n, format!("/{p}")),
        None => (rest, "/".to_string()),
    };
    let route = routes.get(name).ok_or_else(|| {
        ProxyError::new(
            StatusCode::NOT_FOUND,
            "unknown_route",
            format!("no route named '{name}'"),
        )
    })?;
    Ok(Target {
        route,
        path,
        forward_mode: false,
    })
}

/// Reject dot-segments, raw or percent-encoded, so `/r/gh/../../x` cannot climb
/// out of an `allowed_path_prefixes` entry once the upstream normalises it.
pub fn path_is_safe(path: &str) -> bool {
    let lowered = path.to_ascii_lowercase().replace("%2e", ".");
    if lowered.contains("%2f") || lowered.contains("%5c") || lowered.contains('\\') {
        return false;
    }
    !lowered.split('/').any(|seg| seg == "." || seg == "..")
}

/// Find the agent's session token. Precedence: `Proxy-Authorization`,
/// `X-Vault-Token`, `Authorization: Bearer`, then the route's own credential
/// header — which lets an unmodified SDK carry the session token in the slot
/// where it would normally put the API key.
pub fn extract_session_token(headers: &HeaderMap, route: &Route) -> Option<String> {
    let bearer = |v: &str| {
        let v = v.trim();
        v.strip_prefix("Bearer ")
            .or_else(|| v.strip_prefix("bearer "))
            .unwrap_or(v)
            .trim()
            .to_string()
    };
    let get = |name: &str| headers.get(name).and_then(|v| v.to_str().ok());

    [
        get("proxy-authorization"),
        get("x-vault-token"),
        get("authorization"),
        get(route.inject_header.as_str()),
    ]
    .into_iter()
    .flatten()
    .map(bearer)
    .find(|t| looks_like_jwt(t))
}

fn looks_like_jwt(t: &str) -> bool {
    let parts: Vec<&str> = t.split('.').collect();
    parts.len() == 3 && parts.iter().all(|p| !p.is_empty())
}

/// Build the outbound header set: drop hop-by-hop, Host, every agent credential
/// and the route's own credential header, then inject the brokered one.
pub fn outbound_headers(
    inbound: &HeaderMap,
    route: &Route,
    credential: &str,
) -> Result<HeaderMap, ProxyError> {
    // Headers listed in `Connection` are hop-by-hop for this message too.
    let connection_listed: Vec<String> = inbound
        .get_all(header::CONNECTION)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .flat_map(|v| v.split(','))
        .map(|s| s.trim().to_ascii_lowercase())
        .collect();

    let mut out = HeaderMap::new();
    for (name, value) in inbound {
        let n = name.as_str();
        let dropped = HOP_BY_HOP.contains(&n)
            || AGENT_CREDENTIAL_HEADERS.contains(&n)
            || INTERNAL_HEADERS.contains(&n)
            || n == "host"
            || n.starts_with("x-vault-")
            || n.starts_with("x-wslvault-")
            || *name == route.inject_header
            || route.strip_headers.contains(name)
            || connection_listed.iter().any(|c| c == n);
        if !dropped {
            out.append(name.clone(), value.clone());
        }
    }
    let mut v = HeaderValue::from_str(credential).map_err(|_| {
        ProxyError::new(
            StatusCode::INTERNAL_SERVER_ERROR,
            "bad_credential",
            "brokered credential is not a valid header value",
        )
    })?;
    v.set_sensitive(true);
    out.insert(route.inject_header.clone(), v);
    Ok(out)
}

/// Response headers back to the agent: drop hop-by-hop, and drop any header
/// that echoes the brokered secret so it cannot reach the agent that way.
pub fn inbound_response_headers(upstream: &HeaderMap, secret_material: &str) -> HeaderMap {
    let mut out = HeaderMap::new();
    for (name, value) in upstream {
        if HOP_BY_HOP.contains(&name.as_str()) {
            continue;
        }
        if value
            .to_str()
            .map(|v| v.contains(secret_material))
            .unwrap_or(false)
        {
            warn!(header = %name, "upstream echoed the brokered credential; header dropped");
            continue;
        }
        out.append(name.clone(), value.clone());
    }
    out
}

pub async fn handle(State(state): State<Arc<AppState>>, req: Request) -> Response {
    let (parts, body) = req.into_parts();

    let target = match resolve_target(&state.routes, &parts.method, &parts.uri) {
        Ok(t) => t,
        Err(e) => {
            if e.code == "egress_denied" || e.code == "tunnel_refused" {
                warn!(method = %parts.method, uri = %parts.uri, "egress denied");
            }
            return e.into_response();
        }
    };
    let route = target.route;

    let unauth_status = if target.forward_mode {
        StatusCode::PROXY_AUTHENTICATION_REQUIRED
    } else {
        StatusCode::UNAUTHORIZED
    };

    // ── Who is calling? ────────────────────────────────────────────────────
    let Some(session) = extract_session_token(&parts.headers, route) else {
        return ProxyError::new(
            unauth_status,
            "unauthenticated",
            "no wslvault session token: send Proxy-Authorization: Bearer <token>, \
             or put the token where the API key would go",
        )
        .into_response();
    };
    // A fresh header map holding only the token, so none of the agent's other
    // headers (X-Tenant-Id, …) can influence identity resolution.
    let mut id_headers = HeaderMap::new();
    let Ok(tok) = HeaderValue::from_str(&session) else {
        return ProxyError::new(unauth_status, "unauthenticated", "malformed token")
            .into_response();
    };
    id_headers.insert("x-vault-token", tok);
    let identity = match wslvault_core::auth::resolve_identity(&id_headers).await {
        Ok(i) => i,
        Err(e) => {
            return ProxyError::new(unauth_status, "unauthenticated", e.0).into_response();
        }
    };

    let audit = |outcome: &str, detail: &str, status: Option<u16>| {
        state.audit.emit(AuditEvent {
            tenant_id: &identity.tenant_id,
            principal_id: &identity.principal_id,
            route: &route.name,
            outcome,
            detail,
            details_json: serde_json::json!({
                "method": parts.method.as_str(),
                "path": target.path,
                "status": status,
                "upstream": route.upstream,
            }),
        });
    };
    let deny = |code: &'static str, msg: String| {
        audit("failure", code, None);
        ProxyError::new(StatusCode::FORBIDDEN, code, msg).into_response()
    };

    // ── May they use this route? ───────────────────────────────────────────
    let broker_tenant = match state.broker.tenant_id().await {
        Ok(t) => t,
        Err(e) => {
            audit("failure", "broker_unavailable", None);
            return ProxyError::new(
                StatusCode::SERVICE_UNAVAILABLE,
                "broker_unavailable",
                e.to_string(),
            )
            .into_response();
        }
    };
    if identity.tenant_id != broker_tenant {
        return deny(
            "tenant_mismatch",
            "token belongs to a different tenant".into(),
        );
    }
    if !route.policy_allowed(&identity.policies) {
        return deny(
            "policy_denied",
            format!(
                "route '{}' requires one of {:?}",
                route.name, route.allowed_policies
            ),
        );
    }
    if !route.principal_allowed(&identity.principal_id) {
        return deny(
            "principal_denied",
            format!("principal not bound to route '{}'", route.name),
        );
    }
    if !route.method_allowed(&parts.method) {
        return deny(
            "method_denied",
            format!("{} not allowed on route '{}'", parts.method, route.name),
        );
    }
    if !path_is_safe(&target.path) {
        audit("failure", "bad_path", None);
        return ProxyError::new(
            StatusCode::BAD_REQUEST,
            "bad_path",
            "path contains dot-segments",
        )
        .into_response();
    }
    if !route.path_allowed(&target.path) {
        return deny(
            "path_denied",
            format!("path not allowed on route '{}'", route.name),
        );
    }

    // ── Broker the credential ──────────────────────────────────────────────
    let credential = match state.broker.credential(route).await {
        Ok(c) => c,
        Err(e) => {
            warn!(route = %route.name, error = %e, "credential fetch failed");
            audit("failure", "credential_unavailable", None);
            return ProxyError::new(
                StatusCode::BAD_GATEWAY,
                "credential_unavailable",
                "the brokered credential could not be fetched",
            )
            .into_response();
        }
    };
    let headers = match outbound_headers(&parts.headers, route, &credential.header_value) {
        Ok(h) => h,
        Err(e) => {
            audit("failure", "bad_credential", None);
            return e.into_response();
        }
    };

    let mut url = format!("{}{}", route.upstream, target.path);
    if let Some(q) = parts.uri.query() {
        url.push('?');
        url.push_str(q);
    }

    let body_stream = body.into_data_stream();
    let upstream_resp = state
        .upstream
        .request(parts.method.clone(), &url)
        .headers(headers)
        .body(reqwest::Body::wrap_stream(body_stream))
        .send()
        .await;

    let resp = match upstream_resp {
        Ok(r) => r,
        Err(e) => {
            warn!(route = %route.name, error = %e, "upstream request failed");
            audit("failure", "upstream_unreachable", None);
            return ProxyError::new(
                StatusCode::BAD_GATEWAY,
                "upstream_unreachable",
                "upstream request failed",
            )
            .into_response();
        }
    };

    let status = resp.status();
    if status == StatusCode::UNAUTHORIZED {
        // The brokered key was probably rotated; refetch on the next request.
        state.broker.invalidate(route).await;
    }
    audit(
        if status.is_success() {
            "success"
        } else {
            "upstream_error"
        },
        status.as_str(),
        Some(status.as_u16()),
    );

    let resp_headers = inbound_response_headers(resp.headers(), &credential.secret);
    let stream = resp.bytes_stream().map_err(std::io::Error::other);
    let mut out = Response::new(Body::from_stream(stream));
    *out.status_mut() = status;
    *out.headers_mut() = resp_headers;
    out.headers_mut().insert(
        HeaderName::from_static("x-wslvault-brokered-by"),
        HeaderValue::from_static("agent-proxy"),
    );
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn routes() -> Routes {
        Routes::parse(
            r#"{
            "gh": {"upstream":"https://api.github.com","hosts":["api.github.com"],
                   "allowed_policies":["agent"],"secret_path":"brokered/gh",
                   "inject_header":"authorization","inject_format":"Bearer {secret}",
                   "strip_headers":["x-github-placeholder"]},
            "anthropic": {"upstream":"https://api.anthropic.com","allowed_policies":["agent"],
                   "secret_path":"brokered/anthropic","inject_header":"x-api-key"}
        }"#,
            false,
        )
        .unwrap()
    }

    const JWT: &str = "aaa.bbb.ccc";

    #[test]
    fn route_mode_resolves() {
        let r = routes();
        let t = resolve_target(
            &r,
            &Method::POST,
            &"/r/anthropic/v1/messages?x=1".parse().unwrap(),
        )
        .unwrap();
        assert_eq!(t.route.name, "anthropic");
        assert_eq!(t.path, "/v1/messages");
        assert!(!t.forward_mode);
        let t = resolve_target(&r, &Method::GET, &"/r/gh".parse().unwrap()).unwrap();
        assert_eq!(t.path, "/");
    }

    #[test]
    fn forward_mode_resolves_only_brokered_hosts() {
        let r = routes();
        let t = resolve_target(
            &r,
            &Method::GET,
            &"http://api.github.com/user".parse().unwrap(),
        )
        .unwrap();
        assert_eq!(t.route.name, "gh");
        assert!(t.forward_mode);
        let e = resolve_target(&r, &Method::GET, &"http://evil.example/x".parse().unwrap())
            .unwrap_err();
        assert_eq!(e.code, "egress_denied");
        let e = resolve_target(&r, &Method::CONNECT, &"api.github.com:443".parse().unwrap())
            .unwrap_err();
        assert_eq!(e.code, "tunnel_refused");
        let e = resolve_target(&r, &Method::GET, &"/r/nope/x".parse().unwrap()).unwrap_err();
        assert_eq!(e.code, "unknown_route");
    }

    #[test]
    fn rejects_dot_segments() {
        assert!(path_is_safe("/v1/messages"));
        assert!(!path_is_safe("/v1/../admin"));
        assert!(!path_is_safe("/v1/%2E%2e/admin"));
        assert!(!path_is_safe("/v1/a%2fb"));
        assert!(!path_is_safe("/v1/./x"));
    }

    #[test]
    fn session_token_sources() {
        let r = routes();
        let anthropic = r.get("anthropic").unwrap();
        let mut h = HeaderMap::new();
        h.insert("x-api-key", "placeholder".parse().unwrap());
        assert_eq!(
            extract_session_token(&h, anthropic),
            None,
            "placeholder is not a token"
        );
        h.insert("x-api-key", JWT.parse().unwrap());
        assert_eq!(extract_session_token(&h, anthropic).as_deref(), Some(JWT));
        let mut h = HeaderMap::new();
        h.insert(
            "proxy-authorization",
            format!("Bearer {JWT}").parse().unwrap(),
        );
        assert_eq!(extract_session_token(&h, anthropic).as_deref(), Some(JWT));
    }

    #[test]
    fn outbound_strips_agent_credentials_and_injects() {
        let r = routes();
        let gh = r.get("gh").unwrap();
        let mut h = HeaderMap::new();
        h.insert("authorization", format!("Bearer {JWT}").parse().unwrap());
        h.insert("proxy-authorization", "Bearer x".parse().unwrap());
        h.insert("x-vault-token", JWT.parse().unwrap());
        h.insert("x-tenant-id", "other".parse().unwrap());
        h.insert("x-vault-policies", "root".parse().unwrap());
        h.insert("cookie", "s=1".parse().unwrap());
        h.insert("host", "agent-proxy".parse().unwrap());
        h.insert("connection", "keep-alive, x-drop-me".parse().unwrap());
        h.insert("x-drop-me", "1".parse().unwrap());
        h.insert("x-github-placeholder", "1".parse().unwrap());
        h.insert("accept", "application/json".parse().unwrap());
        let out = outbound_headers(&h, gh, "Bearer ghp_real").unwrap();
        assert_eq!(out.get("authorization").unwrap(), "Bearer ghp_real");
        assert!(out.get("authorization").unwrap().is_sensitive());
        assert_eq!(out.get("accept").unwrap(), "application/json");
        for gone in [
            "proxy-authorization",
            "x-vault-token",
            "cookie",
            "host",
            "connection",
            "x-drop-me",
            "x-github-placeholder",
            "x-vault-policies",
        ] {
            assert!(out.get(gone).is_none(), "{gone} should be stripped");
        }
        assert!(out.get("x-tenant-id").is_none());
        assert_eq!(out.len(), 2, "{out:?}");
    }

    #[test]
    fn response_headers_never_echo_secret() {
        let mut h = HeaderMap::new();
        h.insert("x-echo", "key=ghp_real".parse().unwrap());
        h.insert("content-type", "application/json".parse().unwrap());
        h.insert("transfer-encoding", "chunked".parse().unwrap());
        let out = inbound_response_headers(&h, "ghp_real");
        assert!(out.get("x-echo").is_none());
        assert!(out.get("transfer-encoding").is_none());
        assert!(out.get("content-type").is_some());
    }
}
