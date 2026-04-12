//! Error types for the wslvault-connectors crate.
//!
//! `ConnectorError` covers every failure mode a connector implementation can
//! encounter: authentication, network, serialisation, configuration, and
//! service-level errors.  Each variant carries enough context to produce a
//! useful log line without leaking secret material.

use thiserror::Error;

/// Top-level error type returned by all connector operations.
#[derive(Debug, Error)]
pub enum ConnectorError {
    // -------------------------------------------------------------------------
    // Configuration errors — caught at construction time
    // -------------------------------------------------------------------------
    /// A required configuration value is absent or malformed.
    #[error("connector misconfiguration: {reason}")]
    Configuration { reason: String },

    // -------------------------------------------------------------------------
    // Authentication / authorisation errors
    // -------------------------------------------------------------------------
    /// The connector could not obtain valid credentials to reach the remote service.
    #[error("authentication failed for connector '{connector}': {reason}")]
    Authentication { connector: String, reason: String },

    /// The identity used by the connector lacks permission for the requested operation.
    #[error("permission denied on '{resource}' (connector '{connector}'): {reason}")]
    PermissionDenied {
        connector: String,
        resource: String,
        reason: String,
    },

    // -------------------------------------------------------------------------
    // Remote resource errors
    // -------------------------------------------------------------------------
    /// The requested secret path does not exist in the external service.
    #[error("secret not found at external path '{path}' (connector '{connector}')")]
    SecretNotFound { connector: String, path: String },

    /// The external service reports that the secret already exists and the
    /// requested operation (e.g. create) cannot be performed as an upsert.
    #[error("secret already exists at external path '{path}' (connector '{connector}')")]
    SecretAlreadyExists { connector: String, path: String },

    // -------------------------------------------------------------------------
    // Network / transport errors
    // -------------------------------------------------------------------------
    /// A transient HTTP or TCP failure when contacting the external service.
    #[error("network error contacting '{endpoint}': {source}")]
    Network {
        endpoint: String,
        #[source]
        source: reqwest::Error,
    },

    /// The external service returned an unexpected HTTP status code.
    #[error("unexpected HTTP {status} from '{endpoint}': {body}")]
    HttpStatus {
        endpoint: String,
        status: u16,
        body: String,
    },

    // -------------------------------------------------------------------------
    // Serialisation errors
    // -------------------------------------------------------------------------
    /// A response payload from the external service could not be deserialised.
    #[error("failed to deserialise response from '{connector}': {reason}")]
    Deserialise { connector: String, reason: String },

    /// A request payload could not be serialised before sending.
    #[error("failed to serialise request for '{connector}': {reason}")]
    Serialise { connector: String, reason: String },

    // -------------------------------------------------------------------------
    // Database errors (postgres-rotation feature)
    // -------------------------------------------------------------------------
    /// A database operation during credential rotation failed.
    #[cfg(feature = "postgres-rotation")]
    #[error("database error during rotation for user '{username}': {source}")]
    Database {
        username: String,
        #[source]
        source: sqlx::Error,
    },

    // -------------------------------------------------------------------------
    // Sync errors
    // -------------------------------------------------------------------------
    /// One or more secrets failed during a bulk sync operation.
    /// The `errors` field lists individual failure messages.
    #[error("sync partially failed: {succeeded} succeeded, {failed} failed")]
    SyncPartialFailure {
        succeeded: usize,
        failed: usize,
        errors: Vec<String>,
    },

    // -------------------------------------------------------------------------
    // Internal / catch-all
    // -------------------------------------------------------------------------
    /// An unexpected internal error that does not fit another variant.
    #[error("internal connector error: {reason}")]
    Internal { reason: String },
}

impl ConnectorError {
    /// Returns a short machine-readable code suitable for metrics labels.
    pub fn code(&self) -> &'static str {
        match self {
            ConnectorError::Configuration { .. } => "configuration",
            ConnectorError::Authentication { .. } => "authentication",
            ConnectorError::PermissionDenied { .. } => "permission_denied",
            ConnectorError::SecretNotFound { .. } => "not_found",
            ConnectorError::SecretAlreadyExists { .. } => "already_exists",
            ConnectorError::Network { .. } => "network",
            ConnectorError::HttpStatus { .. } => "http_status",
            ConnectorError::Deserialise { .. } => "deserialise",
            ConnectorError::Serialise { .. } => "serialise",
            #[cfg(feature = "postgres-rotation")]
            ConnectorError::Database { .. } => "database",
            ConnectorError::SyncPartialFailure { .. } => "sync_partial_failure",
            ConnectorError::Internal { .. } => "internal",
        }
    }

    /// Returns true if this error is likely transient and a retry may succeed.
    pub fn is_retryable(&self) -> bool {
        match self {
            // Transient network errors are always retryable.
            ConnectorError::Network { .. } => true,
            // Rate-limiting (429) and server errors (5xx) are retryable.
            ConnectorError::HttpStatus { status, .. } => *status == 429 || *status >= 500,
            _ => false,
        }
    }
}
