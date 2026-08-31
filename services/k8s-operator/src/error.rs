//! Error types for the k8s-operator.
//!
//! All operator errors are represented as variants of [`OperatorError`], which
//! implements both [`std::error::Error`] via [`thiserror`] and the kube-rs
//! `ReconcileError` contract (it is returned from the reconcile function).
//!
//! Each variant carries enough context for the caller to decide whether to
//! requeue the resource or surface a terminal failure.

use thiserror::Error;

#[allow(dead_code)] // wire/DTO type: fields exist for serde and validation, not direct reads
/// Top-level error type returned by the operator's reconcile loop and helpers.
#[derive(Debug, Error)]
pub enum OperatorError {
    /// A Kubernetes API call failed.
    #[error("Kubernetes API error: {0}")]
    KubeApi(#[from] kube::Error),

    /// JSON serialization or deserialization failed.
    #[error("JSON (de)serialization error: {0}")]
    Json(#[from] serde_json::Error),

    /// The wslvault secret-engine returned an HTTP error response.
    #[error("wslvault HTTP error (status {status}): {message}")]
    VaultHttp {
        /// HTTP status code returned by the secret-engine.
        status: u16,
        /// Human-readable error message from the response body, if available.
        message: String,
    },

    /// The reqwest client encountered a transport-level error.
    #[error("HTTP transport error: {0}")]
    HttpTransport(#[from] reqwest::Error),

    /// The secret-engine response body could not be parsed.
    #[error("unexpected secret-engine response format: {0}")]
    UnexpectedResponseFormat(String),

    /// A required field was missing on the VaultSecret spec or status.
    #[error("missing required field: {0}")]
    MissingField(String),

    /// Base64 decoding of secret data failed.
    #[error("base64 decode error: {0}")]
    Base64Decode(#[from] base64::DecodeError),

    /// A target Kubernetes Secret could not be created or patched.
    #[error("failed to apply target secret '{name}' in namespace '{namespace}': {source}")]
    ApplyTargetSecret {
        name: String,
        namespace: String,
        #[source]
        source: kube::Error,
    },

    /// The CRD installation check or application failed.
    #[error("CRD installation error: {0}")]
    /// Constructed by the CRD bootstrap path, which is currently disabled.
    #[allow(dead_code)]
    CrdInstall(String),

    /// A generic, unclassified error. Used as a catch-all when no more
    /// specific variant applies.
    #[error("operator error: {0}")]
    #[allow(dead_code)]
    Generic(String),
}

/// Allow `OperatorError` to be used directly as the error type for
/// `kube::runtime::controller::Action` re-queue decisions.
impl OperatorError {
    /// Returns `true` when the error is transient and the resource should be
    /// requeued for another reconcile attempt.
    ///
    /// Permanent errors (e.g. invalid spec) return `false` to avoid an
    /// infinite requeue loop.
    pub fn is_transient(&self) -> bool {
        match self {
            // Network and API errors are typically transient.
            OperatorError::KubeApi(_) => true,
            OperatorError::HttpTransport(_) => true,
            OperatorError::VaultHttp { status, .. } => {
                // 5xx errors are transient; 4xx are permanent (bad config).
                *status >= 500
            }
            // Structural / config errors are permanent.
            OperatorError::MissingField(_) => false,
            OperatorError::UnexpectedResponseFormat(_) => false,
            OperatorError::Base64Decode(_) => false,
            // Serialization failures are usually permanent.
            OperatorError::Json(_) => false,
            OperatorError::ApplyTargetSecret { .. } => true,
            OperatorError::CrdInstall(_) => false,
            OperatorError::Generic(_) => true,
        }
    }
}
