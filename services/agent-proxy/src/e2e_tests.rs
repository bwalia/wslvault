//! End-to-end: real HS256 session tokens, a stand-in secret-engine, a recording
//! upstream, and the proxy itself, all over real sockets.

use std::{
    sync::{
        atomic::{AtomicUsize, Ordering},
        Arc, Mutex,
    },
    time::Duration,
};

use axum::{
    extract::{Request, State},
    http::{HeaderMap, StatusCode},
    response::IntoResponse,
    routing::get,
    Json, Router,
};
use base64::Engine as _;
use jsonwebtoken::{encode, EncodingKey, Header};

use crate::{
    audit::Audit,
    broker::{Broker, CredentialSource},
    config::Routes,
    proxy::{self, AppState},
};

const JWT_SECRET: &str = "e2e-test-secret-at-least-32-bytes-long!!";
const REAL_KEY: &str = "sk-real-upstream-key-123";
const TENANT: &str = "homelab";

fn mint(sub: &str, tenant: &str, policies: &[&str], ttl: i64) -> String {
    let exp = chrono::Utc::now().timestamp() + ttl;
    encode(
        &Header::default(),
        &serde_json::json!({ "sub": sub, "tenant_id": tenant, "policies": policies, "exp": exp }),
        &EncodingKey::from_secret(JWT_SECRET.as_bytes()),
    )
    .unwrap()
}

async fn serve(app: Router) -> String {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    format!("http://{addr}")
}

#[derive(Clone, Default)]
struct Recorder {
    last_headers: Arc<Mutex<Option<HeaderMap>>>,
    secret_reads: Arc<AtomicUsize>,
}

async fn fake_secret_engine(
    State(rec): State<(Recorder, String)>,
    headers: HeaderMap,
) -> impl IntoResponse {
    let (rec, broker_token) = rec;
    if headers.get("x-vault-token").and_then(|v| v.to_str().ok()) != Some(broker_token.as_str()) {
        return (StatusCode::FORBIDDEN, "wrong token").into_response();
    }
    rec.secret_reads.fetch_add(1, Ordering::SeqCst);
    let data = base64::engine::general_purpose::STANDARD
        .encode(serde_json::json!({ "api_key": REAL_KEY }).to_string());
    Json(serde_json::json!({ "data": data, "version": 1, "created_at": "", "metadata": {} }))
        .into_response()
}

async fn fake_upstream(State(rec): State<Recorder>, req: Request) -> impl IntoResponse {
    let path = req.uri().path().to_string();
    let headers = req.headers().clone();
    *rec.last_headers.lock().unwrap() = Some(headers.clone());
    if path == "/redirect" {
        return (
            StatusCode::FOUND,
            [("location", "http://attacker.example/steal")],
        )
            .into_response();
    }
    let body = axum::body::to_bytes(req.into_body(), 1 << 20)
        .await
        .unwrap();
    let key_seen = headers
        .get("x-api-key")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_string();
    (
        StatusCode::OK,
        [("x-echo-key", format!("you sent {key_seen}"))],
        Json(serde_json::json!({ "path": path, "body": String::from_utf8_lossy(&body) })),
    )
        .into_response()
}

struct Harness {
    proxy: String,
    rec: Recorder,
    client: reqwest::Client,
}

async fn harness() -> Harness {
    std::env::set_var(wslvault_core::auth::JWT_SECRET_ENV, JWT_SECRET);
    let rec = Recorder::default();
    let broker_token = mint("agent-proxy:agent-proxy", TENANT, &["broker-read"], 3600);

    let se = serve(
        Router::new()
            .route("/v1/secret/data/*path", get(fake_secret_engine))
            .with_state((rec.clone(), broker_token.clone())),
    )
    .await;
    let up = serve(
        Router::new()
            .fallback(fake_upstream)
            .with_state(rec.clone()),
    )
    .await;

    let routes = Routes::parse(
        &serde_json::json!({
            "anthropic": {
                "upstream": up,
                "hosts": ["api.anthropic.test"],
                "allowed_policies": ["agent-claude"],
                "allowed_principals": ["agents:claude-*"],
                "secret_path": "brokered/anthropic",
                "secret_key": "api_key",
                "inject_header": "x-api-key",
                "allowed_path_prefixes": ["/v1/", "/redirect"]
            }
        })
        .to_string(),
        true,
    )
    .unwrap();

    let http = reqwest::Client::new();
    let state = Arc::new(AppState {
        routes,
        broker: Broker::new(
            http.clone(),
            se,
            CredentialSource::Static(broker_token),
            Duration::from_secs(60),
        ),
        upstream: reqwest::Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .unwrap(),
        audit: Audit::new(None).unwrap(),
    });
    let proxy = serve(Router::new().fallback(proxy::handle).with_state(state)).await;
    Harness {
        proxy,
        rec,
        client: reqwest::Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .unwrap(),
    }
}

fn agent() -> String {
    mint("agents:claude-coder", TENANT, &["agent-claude"], 3600)
}

#[tokio::test]
async fn brokers_credential_agent_never_sees_it() {
    let h = harness().await;
    for _ in 0..2 {
        let resp = h
            .client
            .post(format!("{}/r/anthropic/v1/messages", h.proxy))
            .header("x-api-key", agent()) // session token in the API-key slot
            .header("x-tenant-id", "someone-else")
            .body("{\"hello\":1}")
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), 200);
        assert!(
            resp.headers().get("x-echo-key").is_none(),
            "echoed key must be dropped"
        );
        let body: serde_json::Value = resp.json().await.unwrap();
        assert_eq!(body["path"], "/v1/messages");
        assert_eq!(body["body"], "{\"hello\":1}");
        assert!(!body.to_string().contains(REAL_KEY));
    }
    let seen = h.rec.last_headers.lock().unwrap().clone().unwrap();
    assert_eq!(seen.get("x-api-key").unwrap(), REAL_KEY);
    assert!(seen.get("x-vault-token").is_none());
    assert!(seen.get("x-tenant-id").is_none());
    assert_eq!(
        h.rec.secret_reads.load(Ordering::SeqCst),
        1,
        "credential is cached"
    );
}

#[tokio::test]
async fn placeholder_key_is_rejected() {
    let h = harness().await;
    let resp = h
        .client
        .post(format!("{}/r/anthropic/v1/messages", h.proxy))
        .header("x-api-key", "sk-placeholder")
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 401);
    assert!(
        h.rec.last_headers.lock().unwrap().is_none(),
        "nothing reached upstream"
    );
}

#[tokio::test]
async fn bindings_are_enforced() {
    let h = harness().await;
    let cases = [
        (
            mint("agents:claude-coder", TENANT, &["other"], 3600),
            403,
            "policy_denied",
        ),
        (
            mint(
                "agents:claude-coder",
                "other-tenant",
                &["agent-claude"],
                3600,
            ),
            403,
            "tenant_mismatch",
        ),
        (
            mint("agents:rogue", TENANT, &["agent-claude"], 3600),
            403,
            "principal_denied",
        ),
        (
            mint("agents:claude-coder", TENANT, &["agent-claude"], -120),
            401,
            "unauthenticated",
        ),
    ];
    for (token, status, code) in cases {
        let resp = h
            .client
            .get(format!("{}/r/anthropic/v1/models", h.proxy))
            .bearer_auth(token)
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status().as_u16(), status, "{code}");
        assert_eq!(resp.headers()["x-wslvault-proxy-error"], code);
    }
    // Path outside the allowlist, and traversal out of it.
    for path in ["/admin", "/v1/%2e%2e/admin"] {
        let resp = h
            .client
            .get(format!("{}/r/anthropic{path}", h.proxy))
            .bearer_auth(agent())
            .send()
            .await
            .unwrap();
        assert!(
            resp.status() == 403 || resp.status() == 400,
            "{path}: {}",
            resp.status()
        );
    }
    assert!(
        h.rec.last_headers.lock().unwrap().is_none(),
        "nothing reached upstream"
    );
}

#[tokio::test]
async fn redirects_are_not_followed() {
    let h = harness().await;
    let resp = h
        .client
        .get(format!("{}/r/anthropic/redirect", h.proxy))
        .bearer_auth(agent())
        .send()
        .await
        .unwrap();
    assert_eq!(
        resp.status(),
        302,
        "3xx returned to the agent, not followed with the key"
    );
}

#[tokio::test]
async fn forward_proxy_mode_and_egress_denial() {
    let h = harness().await;
    let via_proxy = reqwest::Client::builder()
        .proxy(
            reqwest::Proxy::http(&h.proxy)
                .unwrap()
                .custom_http_auth(format!("Bearer {}", agent()).parse().unwrap()),
        )
        .build()
        .unwrap();

    let resp = via_proxy
        .get("http://api.anthropic.test/v1/models")
        .header("x-api-key", "sk-placeholder")
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let seen = h.rec.last_headers.lock().unwrap().clone().unwrap();
    assert_eq!(seen.get("x-api-key").unwrap(), REAL_KEY);
    assert!(seen.get("proxy-authorization").is_none());

    let resp = via_proxy
        .get("http://exfil.example/upload")
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 403);
    assert_eq!(resp.headers()["x-wslvault-proxy-error"], "egress_denied");
}
