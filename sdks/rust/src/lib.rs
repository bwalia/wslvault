//! WSLVault Rust SDK — client library for the WSLVault secrets platform.
//!
//! Provides a high-level async client for interacting with WSLVault services
//! including secret read/write, transit encryption, policy management, audit
//! event queries, lease lifecycle, tenant management, and API key management.
//!
//! # Quick Start
//!
//! ```rust,no_run
//! use wslvault_sdk::VaultClient;
//! use wslvault_sdk::client::{ApiKeyCreateRequest, TenantCreateRequest};
//!
//! #[tokio::main]
//! async fn main() -> Result<(), Box<dyn std::error::Error>> {
//!     let client = VaultClient::builder()
//!         .endpoint("https://vault.example.com")
//!         .token("s.my-vault-token")
//!         .tenant_id("my-tenant-uuid")
//!         .build()?;
//!
//!     // Read a secret
//!     let secret = client.read_secret("prod/database/password").await?;
//!     println!("password: {}", secret.data["password"]);
//!
//!     // Write a secret
//!     client.write_secret("prod/app/config", serde_json::json!({
//!         "api_key": "abc123"
//!     })).await?;
//!
//!     // Encrypt with the transit engine
//!     let enc = client.transit_encrypt("my-key", "dGVzdA==").await?;
//!     println!("ciphertext: {}", enc.ciphertext);
//!
//!     // Create an API key
//!     let key = client.create_api_key(ApiKeyCreateRequest {
//!         name: "ci-bot".into(),
//!         tenant_id: "my-tenant-uuid".into(),
//!         policies: Some(vec!["read-only".into()]),
//!         path_prefixes: None,
//!         expires_in_seconds: Some(86400),
//!         rate_limit_per_minute: Some(60),
//!     }).await?;
//!     println!("raw key (store securely!): {}", key.key);
//!
//!     Ok(())
//! }
//! ```

pub mod client;
pub mod config;
pub mod error;

pub use client::VaultClient;
pub use client::{
    // API key types
    ApiKeyAuthResponse,
    ApiKeyCreateRequest,
    ApiKeyCreateResponse,
    ApiKeyMetadata,
    // Audit types
    AuditEvent,
    AuditQueryFilters,
    AuditQueryResponse,
    // Lease types
    LeaseRecord,
    LeaseRenewResponse,
    // Secret types
    ListResponse,
    // Policy types
    PolicyCreateRequest,
    PolicyListResponse,
    PolicyResponse,
    PolicyRule,
    SecretData,
    // Tenant types
    TenantCreateRequest,
    TenantResponse,
    // Transit types
    TransitDecryptResponse,
    TransitEncryptResponse,
    TransitHashResponse,
    TransitHmacResponse,
    TransitKeyResponse,
    TransitKeyRotateResponse,
    TransitSignResponse,
    TransitVerifyResponse,
    WriteResponse,
};
pub use config::ClientConfig;
pub use error::VaultClientError;
