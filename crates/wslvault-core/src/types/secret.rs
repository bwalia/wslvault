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

/// Lifecycle type controlling how a secret expires and rotates.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum SecretType {
    /// Short-lived, TTL-enforced credential. Auto-expires; renewable.
    Ephemeral,
    /// Has a TTL but not strictly enforced. Soft-rotation with warnings.
    #[default]
    StaleTtl,
    /// Must be rotated periodically. Rotation is coordinated with the target
    /// application via two-phase confirmation before the new version activates.
    RotationRequired,
}

impl SecretType {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Ephemeral => "EPHEMERAL",
            Self::StaleTtl => "STALE_TTL",
            Self::RotationRequired => "ROTATION_REQUIRED",
        }
    }
}

impl std::str::FromStr for SecretType {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_uppercase().as_str() {
            "EPHEMERAL" => Ok(Self::Ephemeral),
            "STALE_TTL" => Ok(Self::StaleTtl),
            "ROTATION_REQUIRED" => Ok(Self::RotationRequired),
            other => Err(format!("unknown secret type: {other}")),
        }
    }
}

impl std::fmt::Display for SecretType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Lifecycle status of a single secret version.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum VersionStatus {
    /// The current readable version.
    #[default]
    Active,
    /// Awaiting rotation confirmation (two-phase rotation).
    Pending,
    /// Superseded by a newer version; readable by power_admin only.
    Deprecated,
    /// Grace period expired; ciphertext destroyed.
    Revoked,
}

impl VersionStatus {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Active => "active",
            Self::Pending => "pending",
            Self::Deprecated => "deprecated",
            Self::Revoked => "revoked",
        }
    }
}

impl std::str::FromStr for VersionStatus {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "active" => Ok(Self::Active),
            "pending" => Ok(Self::Pending),
            "deprecated" => Ok(Self::Deprecated),
            "revoked" => Ok(Self::Revoked),
            other => Err(format!("unknown version status: {other}")),
        }
    }
}

/// Lifecycle policy attached to a secret.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct RotationPolicy {
    /// Seconds until the secret expires (EPHEMERAL / STALE_TTL).
    pub ttl_seconds: Option<i64>,
    /// Seconds before expiry to emit a soft-warning (STALE_TTL).
    pub soft_warn_seconds: Option<i64>,
    /// How often the secret must be rotated (ROTATION_REQUIRED), in seconds.
    pub rotation_interval_seconds: Option<i64>,
    /// Grace period (seconds) before the old version is revoked after confirmation.
    pub grace_period_seconds: Option<i64>,
    /// Webhook URL to notify during two-phase rotation.
    pub webhook_url: Option<String>,
}

/// In-progress rotation record returned by the rotation API.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RotationRecord {
    pub rotation_id: String,
    pub secret_id: String,
    pub path: String,
    pub old_version: u32,
    pub new_version: u32,
    pub status: String,
    pub initiated_by: String,
    pub confirmed_by: Option<String>,
    pub created_at: DateTime<Utc>,
    pub confirmed_at: Option<DateTime<Utc>>,
    pub grace_ends_at: Option<DateTime<Utc>>,
    pub expires_at: DateTime<Utc>,
}

/// Version metadata entry without ciphertext — safe to return to admins.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VersionMeta {
    pub version: u32,
    pub status: VersionStatus,
    pub created_by: Option<String>,
    pub created_at: DateTime<Utc>,
    pub deleted_at: Option<DateTime<Utc>>,
    pub deprecated_at: Option<DateTime<Utc>>,
    pub revoked_at: Option<DateTime<Utc>>,
    pub destroyed: bool,
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
    /// Lifecycle status of this version.
    #[serde(default)]
    pub status: VersionStatus,
    /// Principal ID that created this version (if recorded).
    #[serde(default)]
    pub created_by: Option<String>,
    /// When this version was deprecated (superseded).
    #[serde(default)]
    pub deprecated_at: Option<DateTime<Utc>>,
    /// When this version was revoked (ciphertext destroyed after grace period).
    #[serde(default)]
    pub revoked_at: Option<DateTime<Utc>>,
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
    /// Lifecycle type governing expiry and rotation behaviour.
    #[serde(default)]
    pub secret_type: SecretType,
    /// Attached rotation / TTL policy.
    #[serde(default)]
    pub rotation_policy: RotationPolicy,
    /// When this secret expires (derived from TTL at write time).
    #[serde(default)]
    pub expires_at: Option<DateTime<Utc>>,
    /// When the last rotation was completed.
    #[serde(default)]
    pub last_rotated_at: Option<DateTime<Utc>>,
    /// When the next rotation is due (ROTATION_REQUIRED).
    #[serde(default)]
    pub next_rotation_at: Option<DateTime<Utc>>,
    /// Current rotation workflow state ('none' | 'pending' | 'confirmed').
    #[serde(default)]
    pub rotation_status: String,
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
