//! CRD type definitions for the wslvault Kubernetes operator.
//!
//! The [`VaultSecret`] custom resource drives the operator. Each instance
//! describes a single path in the wslvault secret-engine that should be
//! materialised as a native Kubernetes [`Secret`].
//!
//! # Schema overview
//!
//! ```text
//! apiVersion: wslvault.io/v1alpha1
//! kind: VaultSecret
//! metadata:
//!   name: my-app-db
//!   namespace: production
//! spec:
//!   path: myapp/database/credentials
//!   target:
//!     name: my-app-db-secret   # defaults to VaultSecret name
//!     type: Opaque
//!   refresh_interval: 300       # re-sync every 5 minutes
//!   vault_endpoint: http://secret-engine:8081
//!   data_mappings:
//!     - vaultKey: DB_PASSWORD
//!       secretKey: password
//! ```

use kube::CustomResource;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

// ─── Main CRD ─────────────────────────────────────────────────────────────────

/// Specification for the `VaultSecret` custom resource.
///
/// Drives the operator to watch the referenced wslvault path and sync its
/// contents into a Kubernetes [`Secret`].
#[derive(CustomResource, Deserialize, Serialize, Clone, Debug, JsonSchema)]
#[kube(
    group = "wslvault.io",
    version = "v1alpha1",
    kind = "VaultSecret",
    namespaced
)]
#[kube(status = "VaultSecretStatus")]
#[kube(
    printcolumn = r#"{"name":"Path","type":"string","jsonPath":".spec.path"}"#
)]
#[kube(
    printcolumn = r#"{"name":"Synced","type":"string","jsonPath":".status.conditions[0].status"}"#
)]
#[kube(
    printcolumn = r#"{"name":"Age","type":"date","jsonPath":".metadata.creationTimestamp"}"#
)]
pub struct VaultSecretSpec {
    /// Path in wslvault secret engine (e.g. `"myapp/database/credentials"`).
    ///
    /// This is passed verbatim to the `GET /v1/secrets/<path>` endpoint of the
    /// secret-engine. The operator does not perform any path normalisation.
    pub path: String,

    /// Specification of the Kubernetes `Secret` that will be created or updated
    /// to hold the synced data.
    ///
    /// When omitted the operator creates a secret with the same name and
    /// namespace as the `VaultSecret` resource.
    pub target: Option<TargetSpec>,

    /// How often (in seconds) the operator should re-sync this secret.
    ///
    /// Defaults to `60` seconds when not set.
    pub refresh_interval: Option<u64>,

    /// Override the wslvault secret-engine HTTP endpoint.
    ///
    /// When omitted the operator uses the `VAULT_ENDPOINT` environment variable
    /// (default: `http://secret-engine:8081`).
    pub vault_endpoint: Option<String>,

    /// Authentication configuration for reaching the secret-engine.
    ///
    /// When omitted the operator uses its own pod service account or the
    /// `VAULT_TOKEN` environment variable.
    pub auth: Option<AuthSpec>,

    /// Optional key remapping between secret-engine response keys and the
    /// resulting Kubernetes Secret data keys.
    ///
    /// When omitted all keys returned by the secret-engine are copied verbatim.
    pub data_mappings: Option<Vec<DataMapping>>,
}

// ─── TargetSpec ───────────────────────────────────────────────────────────────

/// Describes the Kubernetes `Secret` that the operator will create or patch.
#[derive(Deserialize, Serialize, Clone, Debug, Default, JsonSchema)]
pub struct TargetSpec {
    /// Name of the Kubernetes `Secret` to create.
    ///
    /// Defaults to the name of the parent `VaultSecret` when not set.
    pub name: Option<String>,

    /// Namespace in which the target `Secret` will be created.
    ///
    /// Defaults to the namespace of the parent `VaultSecret` when not set.
    pub namespace: Option<String>,

    /// The `type` field written to the Kubernetes `Secret`.
    ///
    /// One of: `Opaque`, `kubernetes.io/tls`, `kubernetes.io/dockerconfigjson`.
    /// Defaults to `Opaque`.
    #[serde(default)]
    pub secret_type: SecretType,
}

/// Strongly-typed enumeration of supported Kubernetes Secret types.
#[derive(Deserialize, Serialize, Clone, Debug, Default, JsonSchema, PartialEq, Eq)]
pub enum SecretType {
    /// Generic key-value secret (the Kubernetes default).
    #[default]
    #[serde(rename = "Opaque")]
    Opaque,

    /// Secret intended for TLS certificates and private keys.
    #[serde(rename = "kubernetes.io/tls")]
    Tls,

    /// Secret intended for Docker registry credentials.
    #[serde(rename = "kubernetes.io/dockerconfigjson")]
    DockerConfigJson,
}

impl SecretType {
    /// Returns the raw string value written to the Kubernetes Secret manifest.
    pub fn as_str(&self) -> &'static str {
        match self {
            SecretType::Opaque => "Opaque",
            SecretType::Tls => "kubernetes.io/tls",
            SecretType::DockerConfigJson => "kubernetes.io/dockerconfigjson",
        }
    }
}

// ─── AuthSpec ─────────────────────────────────────────────────────────────────

/// Authentication configuration for the wslvault secret-engine.
///
/// The operator supports two authentication mechanisms:
///
/// 1. **Service account token** — the operator exchanges the bound
///    Kubernetes service account JWT for a vault token via the Kubernetes
///    auth method.
/// 2. **Static token secret** — a pre-created Kubernetes `Secret` that holds
///    a `token` key whose value is a valid vault token.
#[derive(Deserialize, Serialize, Clone, Debug, Default, JsonSchema)]
pub struct AuthSpec {
    /// Reference to a Kubernetes service account whose projected token should
    /// be used to authenticate with the secret-engine.
    pub service_account_ref: Option<ServiceAccountRef>,

    /// Reference to a Kubernetes `Secret` that holds a `token` key.
    pub token_secret_ref: Option<SecretKeyRef>,
}

/// Reference to a Kubernetes service account.
#[derive(Deserialize, Serialize, Clone, Debug, JsonSchema)]
pub struct ServiceAccountRef {
    /// Name of the service account.
    pub name: String,

    /// Namespace of the service account.
    ///
    /// Defaults to the `VaultSecret` namespace when omitted.
    pub namespace: Option<String>,
}

/// A reference to a specific key inside a Kubernetes `Secret`.
#[derive(Deserialize, Serialize, Clone, Debug, JsonSchema)]
pub struct SecretKeyRef {
    /// Name of the Kubernetes `Secret`.
    pub name: String,

    /// Key within the `Secret`'s `data` map.
    ///
    /// Defaults to `"token"` when not set.
    pub key: Option<String>,
}

// ─── DataMapping ──────────────────────────────────────────────────────────────

/// A single key remapping rule applied to the secret-engine response.
///
/// The operator looks up `vault_key` in the decrypted JSON returned by the
/// secret-engine and writes it under `secret_key` in the Kubernetes Secret.
#[derive(Deserialize, Serialize, Clone, Debug, JsonSchema)]
pub struct DataMapping {
    /// The key name as it appears in the wslvault secret-engine response.
    pub vault_key: String,

    /// The key name to use in the resulting Kubernetes Secret data map.
    pub secret_key: String,
}

// ─── VaultSecretStatus ────────────────────────────────────────────────────────

/// Observed state of a `VaultSecret` resource, written by the operator.
#[derive(Deserialize, Serialize, Clone, Debug, Default, JsonSchema)]
pub struct VaultSecretStatus {
    /// Standard Kubernetes status conditions.
    ///
    /// The operator sets a `Synced` condition with `status: "True"` on
    /// success and `status: "False"` on failure.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub conditions: Vec<Condition>,

    /// RFC 3339 timestamp of the most recent successful sync.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_sync_time: Option<String>,

    /// The `metadata.generation` value that was last reconciled.
    ///
    /// Used by clients to determine whether the status reflects the current
    /// spec.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub observed_generation: Option<i64>,

    /// Opaque version identifier returned by the secret-engine on the last
    /// successful sync. Used to detect out-of-band changes.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub secret_version: Option<u32>,
}

// ─── Condition ────────────────────────────────────────────────────────────────

/// A standard Kubernetes-style status condition.
///
/// Mirrors the `meta.k8s.io/v1` `Condition` type so that tooling that
/// understands standard conditions (e.g. `kubectl wait`) can be used directly.
#[derive(Deserialize, Serialize, Clone, Debug, JsonSchema)]
pub struct Condition {
    /// Type of condition (e.g. `"Synced"`, `"Ready"`).
    #[serde(rename = "type")]
    pub condition_type: String,

    /// `"True"`, `"False"`, or `"Unknown"`.
    pub status: ConditionStatus,

    /// A brief machine-readable string that describes the reason for the
    /// condition (e.g. `"SyncFailed"`, `"SecretApplied"`).
    pub reason: String,

    /// A human-readable description of the condition, including actionable
    /// troubleshooting guidance where possible.
    pub message: String,

    /// RFC 3339 timestamp when the condition last transitioned.
    pub last_transition_time: String,

    /// `metadata.generation` of the resource when the condition was set.
    pub observed_generation: Option<i64>,
}

/// Strongly-typed condition status values.
#[derive(Deserialize, Serialize, Clone, Debug, JsonSchema, PartialEq, Eq)]
pub enum ConditionStatus {
    /// The condition is asserted to be true.
    #[serde(rename = "True")]
    True,

    /// The condition is asserted to be false.
    #[serde(rename = "False")]
    False,

    /// The condition state is not yet known.
    #[serde(rename = "Unknown")]
    Unknown,
}

// ─── Helpers ──────────────────────────────────────────────────────────────────

impl VaultSecretStatus {
    /// Build a status with a single `Synced=True` condition at the given
    /// `generation` and RFC 3339 `now` timestamp.
    pub fn synced(
        generation: i64,
        version: u32,
        now: &str,
    ) -> Self {
        VaultSecretStatus {
            conditions: vec![Condition {
                condition_type: "Synced".to_string(),
                status: ConditionStatus::True,
                reason: "SecretApplied".to_string(),
                message: "Secret successfully synced from wslvault.".to_string(),
                last_transition_time: now.to_string(),
                observed_generation: Some(generation),
            }],
            last_sync_time: Some(now.to_string()),
            observed_generation: Some(generation),
            secret_version: Some(version),
        }
    }

    /// Build a status with a single `Synced=False` condition describing the
    /// given error.
    pub fn failed(generation: i64, reason: &str, message: &str, now: &str) -> Self {
        VaultSecretStatus {
            conditions: vec![Condition {
                condition_type: "Synced".to_string(),
                status: ConditionStatus::False,
                reason: reason.to_string(),
                message: message.to_string(),
                last_transition_time: now.to_string(),
                observed_generation: Some(generation),
            }],
            last_sync_time: None,
            observed_generation: Some(generation),
            secret_version: None,
        }
    }
}
