//! WSLVault Secret Lifecycle Example — Rust
//!
//! Shows the full flow:
//!   1. Write a secret (base64-encoded payload)
//!   2. Read the secret back and decode it
//!   3. List secrets
//!   4. Read a specific version
//!   5. Soft-delete a version
//!   6. (Optional) Exchange an API key for a JWT via /v1/auth/api-key
//!
//! Usage:
//!   VAULT_ADDR=http://localhost:8081 \
//!   VAULT_TENANT_ID=019d813d-74bc-7660-89a7-f02fd9f2736d \
//!   cargo run
//!
//! Dependencies (see Cargo.toml): reqwest, tokio, serde, serde_json, base64

use base64::{engine::general_purpose::STANDARD as BASE64, Engine as _};
use reqwest::header::{HeaderMap, HeaderValue, CONTENT_TYPE};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

const SECRET_PATH: &str = "demo/rust/credentials";

#[derive(Serialize)]
struct WriteRequest {
    data: String,
}

#[derive(Deserialize)]
struct WriteResponse {
    secret_id: String,
    version: u32,
}

#[derive(Deserialize)]
struct ReadResponse {
    data: String,
    version: u32,
    created_at: String,
    #[serde(default)]
    metadata: HashMap<String, String>,
}

#[derive(Serialize)]
struct DeleteRequest {
    versions: Vec<u32>,
}

// Optional: exchange an API key for a short-lived JWT.
//
// #[derive(Serialize)]
// struct AuthRequest<'a> {
//     api_key: &'a str,
//     tenant_id: &'a str,
// }
//
// #[derive(Deserialize)]
// struct AuthResponse { token: String }
//
// async fn exchange_api_key(
//     client: &reqwest::Client,
//     identity_addr: &str,
//     api_key: &str,
//     tenant_id: &str,
// ) -> anyhow::Result<String> {
//     let resp: AuthResponse = client
//         .post(format!("{}/v1/auth/api-key", identity_addr))
//         .json(&AuthRequest { api_key, tenant_id })
//         .send().await?.error_for_status()?.json().await?;
//     Ok(resp.token) // Use as: Bearer <token> in Authorization header
// }

/// Thin wrapper that injects the standard WSLVault headers on every request.
struct VaultClient {
    inner: reqwest::Client,
    vault_addr: String,
    default_headers: HeaderMap,
}

impl VaultClient {
    fn new(vault_addr: &str, tenant_id: &str, principal_id: &str, policies: &str) -> anyhow::Result<Self> {
        let mut headers = HeaderMap::new();
        headers.insert(CONTENT_TYPE, HeaderValue::from_static("application/json"));
        headers.insert("x-tenant-id", HeaderValue::from_str(tenant_id)?);
        headers.insert("x-principal-id", HeaderValue::from_str(principal_id)?);
        headers.insert("x-policies", HeaderValue::from_str(policies)?);

        // In production the gateway injects X-Principal-Id / X-Policies from the JWT.
        // When calling the secret-engine directly (dev / service mesh), pass them manually.
        let inner = reqwest::Client::builder()
            .default_headers(headers.clone())
            .build()?;

        Ok(Self {
            inner,
            vault_addr: vault_addr.to_string(),
            default_headers: headers,
        })
    }

    fn url(&self, path: &str) -> String {
        format!("{}{}", self.vault_addr, path)
    }
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let vault_addr = std::env::var("VAULT_ADDR")
        .unwrap_or_else(|_| "http://localhost:8081".to_string());
    let tenant_id = std::env::var("VAULT_TENANT_ID")
        .unwrap_or_else(|_| "019d813d-74bc-7660-89a7-f02fd9f2736d".to_string());
    let principal_id = std::env::var("VAULT_PRINCIPAL_ID")
        .unwrap_or_else(|_| "rust-example".to_string());
    let policies = std::env::var("VAULT_POLICIES")
        .unwrap_or_else(|_| "admin".to_string());

    let client = VaultClient::new(&vault_addr, &tenant_id, &principal_id, &policies)?;

    // ── 1. Write a secret ──────────────────────────────────────────────────────
    println!("==> 1. Writing secret to '{}'...", SECRET_PATH);
    let payload = serde_json::json!({
        "db_host": "postgres.internal",
        "db_user": "app_user",
        "db_pass": "correct-horse-battery-staple",
    });
    let data = BASE64.encode(serde_json::to_vec(&payload)?);

    let write_resp: WriteResponse = client.inner
        .post(client.url(&format!("/v1/secret/data/{}", SECRET_PATH)))
        .json(&WriteRequest { data })
        .send()
        .await?
        .error_for_status()?
        .json()
        .await?;
    println!("    secret_id={}  version={}", write_resp.secret_id, write_resp.version);

    // ── 2. Read the secret back ────────────────────────────────────────────────
    println!("\n==> 2. Reading secret from '{}'...", SECRET_PATH);
    let read_resp: ReadResponse = client.inner
        .get(client.url(&format!("/v1/secret/data/{}", SECRET_PATH)))
        .send()
        .await?
        .error_for_status()?
        .json()
        .await?;

    let decoded_bytes = BASE64.decode(&read_resp.data)?;
    let decoded: serde_json::Value = serde_json::from_slice(&decoded_bytes)?;
    println!("    Decoded: {}", decoded);

    // ── 3. List secrets ────────────────────────────────────────────────────────
    println!("\n==> 3. Listing secrets...");
    let list_resp: serde_json::Value = client.inner
        .get(client.url("/v1/secret/list"))
        .send()
        .await?
        .error_for_status()?
        .json()
        .await?;
    println!("    Secrets: {}", serde_json::to_string_pretty(&list_resp)?);

    // ── 4. Read a specific version ─────────────────────────────────────────────
    println!("\n==> 4. Reading version {} explicitly...", write_resp.version);
    let ver_resp: ReadResponse = client.inner
        .get(client.url(&format!(
            "/v1/secret/data/{}?version={}",
            SECRET_PATH, write_resp.version
        )))
        .send()
        .await?
        .error_for_status()?
        .json()
        .await?;
    println!("    version={}  created_at={}", ver_resp.version, ver_resp.created_at);
    if !ver_resp.metadata.is_empty() {
        println!("    metadata={:?}", ver_resp.metadata);
    }

    // ── 5. Soft-delete the version ─────────────────────────────────────────────
    println!("\n==> 5. Soft-deleting version {}...", write_resp.version);
    client.inner
        .post(client.url(&format!("/v1/secret/delete/{}", SECRET_PATH)))
        .json(&DeleteRequest { versions: vec![write_resp.version] })
        .send()
        .await?
        .error_for_status()?;
    println!("    Deleted (soft — data retained for undelete).");

    println!("\nDone! All WSLVault operations completed successfully.");
    Ok(())
}
