//! Client error types.

use thiserror::Error;

#[derive(Debug, Error)]
pub enum VaultClientError {
    #[error("vault API error ({status}): {message}")]
    Api { status: u16, message: String },

    #[error("authentication required")]
    Unauthenticated,

    #[error("permission denied: {0}")]
    PermissionDenied(String),

    #[error("secret not found: {0}")]
    NotFound(String),

    #[error("connection error: {0}")]
    Connection(String),

    #[error("invalid configuration: {0}")]
    Config(String),

    #[error("serialization error: {0}")]
    Serialization(String),

    #[error(transparent)]
    Http(#[from] reqwest::Error),
}
