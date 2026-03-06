//! WSLVault Rust SDK — client library for the WSLVault secrets platform.
//!
//! Provides a high-level async client for interacting with WSLVault services
//! including secret read/write, transit encryption, and token management.
//!
//! # Quick Start
//!
//! ```rust,no_run
//! use wslvault_sdk::VaultClient;
//!
//! #[tokio::main]
//! async fn main() -> Result<(), Box<dyn std::error::Error>> {
//!     let client = VaultClient::builder()
//!         .endpoint("https://vault.example.com")
//!         .token("s.my-vault-token")
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
//!     Ok(())
//! }
//! ```

pub mod client;
pub mod config;
pub mod error;

pub use client::VaultClient;
pub use config::ClientConfig;
pub use error::VaultClientError;
