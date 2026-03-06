//! Secret domain types for the KV secret engine.

use std::collections::HashMap;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::types::tenant::TenantId;

/// Newtype wrapper around UUID for type-safe secret references.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct SecretId(pub Uuid);

impl SecretId {
    pub fn new() -> Self {
        Self(Uuid::now_v7())
    }
}

impl Default for SecretId {
    fn default() -> Self {
        Self::new()
    }
}

impl std::fmt::Display for SecretId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// Classification of which engine manages this secret.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum SecretEngine {
    KvV2,
    Transit,
    DynamicDatabase,
    Ssh,
    Pki,
    CloudAws,
    CloudGcp,
    CloudAzure,
}

/// A single version of a KV secret. The `ciphertext` field holds the
/// AES-256-GCM encrypted blob of the secret data. Raw plaintext is NEVER
/// stored in this struct beyond the duration of a single request.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecretVersion {
    pub version: u32,
    pub created_at: DateTime<Utc>,
    pub deleted_at: Option<DateTime<Utc>>,
    pub destroyed: bool,
    pub custom_metadata: HashMap<String, String>,
    /// Opaque ciphertext: base64(nonce || ciphertext || GCM tag) encrypted under the secret's DEK.
    pub ciphertext: String,
    /// ID of the DEK used to encrypt this version, for key rotation tracking.
    pub dek_id: String,
}

/// Top-level secret metadata; no plaintext data stored here.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecretMetadata {
    pub id: SecretId,
    pub tenant_id: TenantId,
    /// Normalized path, e.g. "prod/database/password".
    pub path: String,
    pub engine: SecretEngine,
    pub current_version: u32,
    /// Maximum versions retained; older versions are pruned automatically.
    pub max_versions: u32,
    /// If true, write operations must include a check-and-set version.
    pub cas_required: bool,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub custom_metadata: HashMap<String, String>,
}

/// Transient plaintext value; dropped and zeroed as soon as the request handler returns.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct PlaintextSecret {
    #[zeroize(skip)]
    pub path: String,
    #[zeroize(skip)]
    pub version: u32,
    /// Raw JSON bytes of the secret data map.
    pub data: Vec<u8>,
    #[zeroize(skip)]
    pub metadata: HashMap<String, String>,
}

// Custom Debug to avoid leaking plaintext in logs.
impl std::fmt::Debug for PlaintextSecret {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PlaintextSecret")
            .field("path", &self.path)
            .field("version", &self.version)
            .field("data", &format!("[{} bytes REDACTED]", self.data.len()))
            .finish()
    }
}

/// Wrapper returned by read operations — metadata is safe to log;
/// data is a ZeroizeOnDrop plaintext that must be consumed immediately.
pub struct SecretReadResult {
    pub metadata: SecretMetadata,
    pub plaintext: PlaintextSecret,
}
