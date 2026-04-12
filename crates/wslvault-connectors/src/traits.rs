//! Core connector trait and supporting types.
//!
//! All connector implementations (AWS, Azure, GCP, …) implement the
//! [`SecretConnector`] trait.  Callers interact exclusively through this
//! trait, making it straightforward to swap backends in tests or add new
//! providers without touching call-sites.

use std::collections::HashMap;

use async_trait::async_trait;
use serde_json::Value;

use crate::error::ConnectorError;

// =============================================================================
// Data structures
// =============================================================================

/// Opaque secret payload retrieved from or destined for an external service.
///
/// The `value` field holds the raw JSON representation of the secret.  For
/// simple string secrets this is typically `Value::String(…)`; for structured
/// secrets it is a `Value::Object(…)`.
///
/// SECURITY NOTE: `value` may contain plaintext credentials.  Avoid logging
/// or cloning this struct beyond the minimum required scope.
#[derive(Debug, Clone)]
pub struct SecretData {
    /// The canonical key / name of the secret as understood by the connector.
    pub key: String,
    /// The secret payload as a JSON value.  Never log this field.
    pub value: Value,
    /// Provider-specific version identifier (ARN version ID, Azure version, etc.).
    pub version: Option<String>,
    /// Arbitrary key/value metadata returned by the provider (labels, tags, …).
    pub metadata: HashMap<String, String>,
}

/// Summary produced after a batch sync operation.
#[derive(Debug, Clone, Default, serde::Serialize)]
pub struct SyncResult {
    /// Number of secrets that were successfully synced.
    pub synced: usize,
    /// Number of secrets that could not be synced due to an error.
    pub failed: usize,
    /// Human-readable error messages — one per failed secret, in order.
    ///
    /// These messages MUST NOT contain plaintext secret material.
    pub errors: Vec<String>,
}

/// Direction of a sync operation between WSLVault and an external service.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SyncDirection {
    /// Read secrets from the external service into WSLVault.
    Pull,
    /// Write secrets from WSLVault to the external service.
    Push,
    /// Reconcile both directions; external service wins on conflict.
    Bidirectional,
}

// =============================================================================
// Core trait
// =============================================================================

/// Abstraction over an external secret management service.
///
/// Implementations must be `Send + Sync` so they can be stored behind an
/// `Arc<dyn SecretConnector>` and shared across async tasks.
#[async_trait]
pub trait SecretConnector: Send + Sync {
    /// Pull a single secret from the external service at `external_path`.
    ///
    /// `external_path` is interpreted according to the connector's own naming
    /// conventions (e.g. an ARN, a Key Vault secret name, or a GCP resource
    /// path).
    async fn pull(&self, external_path: &str) -> Result<SecretData, ConnectorError>;

    /// Push `data` to the external service at `external_path`.
    ///
    /// Implementations SHOULD perform an upsert (create-or-update) rather than
    /// failing if the secret already exists, unless the connector's API does not
    /// support upsert semantics.
    async fn push(
        &self,
        external_path: &str,
        data: &SecretData,
    ) -> Result<(), ConnectorError>;

    /// List the names / paths of secrets available under `prefix`.
    ///
    /// Returns an empty `Vec` if no secrets are found — never returns
    /// `ConnectorError::SecretNotFound` for a missing prefix.
    async fn list(&self, prefix: &str) -> Result<Vec<String>, ConnectorError>;

    /// Sync all secrets whose paths start with `prefix` in the given direction.
    ///
    /// This is a best-effort batch operation.  Individual failures are
    /// accumulated in [`SyncResult::errors`] rather than short-circuiting the
    /// entire batch, so callers can inspect partial success.
    async fn sync(
        &self,
        prefix: &str,
        direction: SyncDirection,
    ) -> Result<SyncResult, ConnectorError>;

    /// Verify that the connector can reach and authenticate to the external
    /// service.
    ///
    /// Implementations SHOULD perform the lightest-weight read operation the
    /// API exposes (e.g. listing with `max_results=1`).
    async fn health_check(&self) -> Result<(), ConnectorError>;
}
