//! Client configuration.

use crate::error::VaultClientError;

/// Configuration for the WSLVault client.
#[derive(Debug, Clone)]
pub struct ClientConfig {
    /// Base URL of the WSLVault gateway (e.g. "https://vault.example.com").
    pub endpoint: String,
    /// Authentication token.
    pub token: Option<String>,
    /// Tenant ID for multi-tenant deployments.
    pub tenant_id: Option<String>,
    /// Request timeout in seconds.
    pub timeout_secs: u64,
    /// Maximum number of retries for transient failures.
    pub max_retries: u32,
}

impl Default for ClientConfig {
    fn default() -> Self {
        Self {
            endpoint: "http://localhost:8443".into(),
            token: None,
            tenant_id: None,
            timeout_secs: 30,
            max_retries: 3,
        }
    }
}

impl ClientConfig {
    pub fn validate(&self) -> Result<(), VaultClientError> {
        if self.endpoint.is_empty() {
            return Err(VaultClientError::Config(
                "endpoint must not be empty".into(),
            ));
        }
        Ok(())
    }
}
