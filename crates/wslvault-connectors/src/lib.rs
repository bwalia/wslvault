//! wslvault-connectors: external secret management connectors for WSLVault.
//!
//! This crate provides the [`traits::SecretConnector`] trait and connector
//! implementations for syncing secrets to and from external secret management
//! services.
//!
//! # Feature flags
//!
//! Each connector backend is gated behind a Cargo feature so that applications
//! only pull in the dependencies they actually use.
//!
//! | Feature              | Connector                             |
//! |----------------------|---------------------------------------|
//! | `aws`                | AWS Secrets Manager                   |
//! | `azure`              | Azure Key Vault (reqwest REST client) |
//! | `gcp`                | GCP Secret Manager (reqwest REST)     |
//! | `postgres-rotation`  | PostgreSQL dynamic credential rotation|
//! | `all`                | All of the above                      |
//!
//! # Quick start
//!
//! ```toml
//! # Cargo.toml
//! [dependencies]
//! wslvault-connectors = { path = "...", features = ["aws"] }
//! ```
//!
//! ```rust,no_run
//! # #[cfg(feature = "aws")]
//! # async fn example() -> Result<(), Box<dyn std::error::Error>> {
//! use wslvault_connectors::aws::AwsSecretsManagerConnector;
//! use wslvault_connectors::traits::{SecretConnector, SyncDirection};
//!
//! let connector = AwsSecretsManagerConnector::new(
//!     Some("us-east-1".to_string()),
//!     "prod/myapp/".to_string(),
//! ).await?;
//!
//! connector.health_check().await?;
//! # Ok(())
//! # }
//! ```

pub mod error;
pub mod traits;

/// AWS Secrets Manager connector.
///
/// Enabled by the `aws` Cargo feature.
pub mod aws;

/// Azure Key Vault connector.
///
/// Enabled by the `azure` Cargo feature.
pub mod azure;

/// GCP Secret Manager connector.
///
/// Enabled by the `gcp` Cargo feature.
pub mod gcp;

/// PostgreSQL dynamic credential rotation.
///
/// Enabled by the `postgres-rotation` Cargo feature.
pub mod postgres_rotation;

/// HashiCorp Vault KV v2 connector.
///
/// Enabled by the `hashicorp-vault` Cargo feature.
pub mod hashicorp_vault;

/// Kubernetes Secrets API connector.
///
/// Enabled by the `k8s` Cargo feature.
pub mod kubernetes;

/// Path and field mapping utilities for external integrations.
pub mod mapping;

// Re-export the most commonly used types at crate root for convenience.
pub use error::ConnectorError;
pub use traits::{SecretConnector, SecretData, SyncDirection, SyncResult};
