//! Cluster-specific error types.

use thiserror::Error;

#[derive(Debug, Error)]
pub enum ClusterError {
    #[error("failed to acquire leadership lock: {reason}")]
    LockAcquisitionFailed { reason: String },

    #[error("heartbeat failed: {reason}")]
    HeartbeatFailed { reason: String },

    #[error("node registration failed: {reason}")]
    RegistrationFailed { reason: String },

    #[error("database error: {reason}")]
    Database { reason: String },
}

impl From<sqlx::Error> for ClusterError {
    fn from(e: sqlx::Error) -> Self {
        ClusterError::Database {
            reason: e.to_string(),
        }
    }
}
