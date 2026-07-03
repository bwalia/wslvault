//! CRD type definitions for the wslvault Kubernetes operator.
//!
//! This module defines two custom resources:
//!
//! - [`VaultSecret`] — syncs a single path from the wslvault secret-engine
//!   into a native Kubernetes [`Secret`].
//! - [`VaultPolicy`] — declares a wslvault policy document in Kubernetes so
//!   teams can manage access-control rules via GitOps.
//!
//! # VaultSecret schema overview
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
//!
//! # VaultPolicy schema overview
//!
//! ```text
//! apiVersion: wslvault.io/v1alpha1
//! kind: VaultPolicy
//! metadata:
//!   name: my-app-policy
//!   namespace: production
//! spec:
//!   policyName: my-app-policy
//!   tenantId: my-tenant
//!   rules:
//!     - name: allow-app-secrets
//!       paths:
//!         - "myapp/*"
//!         - "shared/**"
//!       capabilities:
//!         - read
//!         - list
//! ```

use kube::CustomResource;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

// ─── VaultPolicy CRD ─────────────────────────────────────────────────────────

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

// ─── VaultPolicy CRD ─────────────────────────────────────────────────────────

/// Set of capabilities that a policy rule can grant or deny.
///
/// Maps 1-to-1 with the `Capability` enum in the policy-engine model.
/// The string representation (lowercase) is what the policy-engine REST API
/// accepts; validation is performed by [`PolicyCapability::from_str`] before
/// any HTTP call is made.
#[derive(Deserialize, Serialize, Clone, Debug, JsonSchema, PartialEq, Eq, Hash)]
#[serde(rename_all = "lowercase")]
pub enum PolicyCapability {
    /// Permits reading a secret at the matched path.
    Read,
    /// Permits writing (creating or replacing) a secret.
    Write,
    /// Permits soft-deletion of a secret version.
    Delete,
    /// Permits listing children under the matched prefix.
    List,
    /// Permits creating a new resource at the matched path.
    Create,
    /// Permits updating metadata or data on an existing resource.
    Update,
    /// Explicitly denies all access, overriding any other matching rules.
    Deny,
}

impl PolicyCapability {
    /// Return the lowercase string form expected by the policy-engine HTTP API.
    pub fn as_str(&self) -> &'static str {
        match self {
            PolicyCapability::Read => "read",
            PolicyCapability::Write => "write",
            PolicyCapability::Delete => "delete",
            PolicyCapability::List => "list",
            PolicyCapability::Create => "create",
            PolicyCapability::Update => "update",
            PolicyCapability::Deny => "deny",
        }
    }

    /// Parse from a case-insensitive string.
    ///
    /// Returns `None` when the string does not match any known capability.
    /// This is used to validate raw string values supplied via the CRD spec
    /// before forwarding them to the policy-engine.
    pub fn from_str(s: &str) -> Option<Self> {
        match s.to_lowercase().as_str() {
            "read" => Some(PolicyCapability::Read),
            "write" => Some(PolicyCapability::Write),
            "delete" => Some(PolicyCapability::Delete),
            "list" => Some(PolicyCapability::List),
            "create" => Some(PolicyCapability::Create),
            "update" => Some(PolicyCapability::Update),
            "deny" => Some(PolicyCapability::Deny),
            _ => None,
        }
    }
}

/// A single access-control rule within a [`VaultPolicySpec`].
///
/// Each rule pairs a list of glob-style path patterns with the capabilities
/// that are granted (or denied) for any path that matches.
#[derive(Deserialize, Serialize, Clone, Debug, JsonSchema)]
pub struct PolicyRuleSpec {
    /// Human-readable name for this rule (e.g. `"allow-app-secrets"`).
    ///
    /// Used only for documentation; not transmitted to the policy-engine.
    pub name: String,

    /// Glob-style path patterns matched against the resource path in an
    /// authorization request.
    ///
    /// Supports:
    /// - `*` — matches a single path segment (no slashes)
    /// - `**` — recursively matches zero or more segments
    ///
    /// Example: `["myapp/*", "shared/**"]`
    pub paths: Vec<String>,

    /// Capabilities granted (or denied) when this rule's path matches.
    ///
    /// Must contain at least one entry.  Valid values are:
    /// `read`, `write`, `delete`, `list`, `create`, `update`, `deny`.
    pub capabilities: Vec<PolicyCapability>,
}

/// Specification for the `VaultPolicy` custom resource.
///
/// The operator reconciles this into a `PolicyDocument` on the policy-engine
/// via `PUT /v1/policies/<policyName>` with the tenant supplied by `tenantId`.
#[derive(CustomResource, Deserialize, Serialize, Clone, Debug, JsonSchema)]
#[kube(
    group = "wslvault.io",
    version = "v1alpha1",
    kind = "VaultPolicy",
    namespaced
)]
#[kube(status = "VaultPolicyStatus")]
#[kube(
    printcolumn = r#"{"name":"PolicyName","type":"string","jsonPath":".spec.policyName"}"#
)]
#[kube(
    printcolumn = r#"{"name":"Tenant","type":"string","jsonPath":".spec.tenantId"}"#
)]
#[kube(
    printcolumn = r#"{"name":"Synced","type":"string","jsonPath":".status.synced"}"#
)]
#[kube(
    printcolumn = r#"{"name":"Age","type":"date","jsonPath":".metadata.creationTimestamp"}"#
)]
pub struct VaultPolicySpec {
    /// Name of the policy document inside wslvault.
    ///
    /// This becomes the `name` field of the `PolicyDocument` and is also used
    /// as the URL path segment in `PUT /v1/policies/<policyName>`.
    ///
    /// Must be unique within the tenant.
    pub policy_name: String,

    /// Tenant identifier to associate this policy with.
    ///
    /// Sent as the `X-Tenant-Id` header on all policy-engine API calls.
    pub tenant_id: String,

    /// Override for the wslvault policy-engine HTTP endpoint.
    ///
    /// When omitted the operator uses the `POLICY_ENGINE_ENDPOINT` environment
    /// variable (default: `http://policy-engine:8082`).
    pub policy_engine_endpoint: Option<String>,

    /// Authentication token for the policy-engine.
    ///
    /// References a Kubernetes `Secret` that holds the token under a specified
    /// key.  When omitted the operator falls back to the `VAULT_TOKEN`
    /// environment variable.
    pub auth: Option<AuthSpec>,

    /// Ordered list of access-control rules that make up this policy.
    ///
    /// At least one rule is required.
    pub rules: Vec<PolicyRuleSpec>,
}

// ─── VaultPolicyStatus ───────────────────────────────────────────────────────

/// Observed state of a `VaultPolicy` resource, written by the operator.
#[derive(Deserialize, Serialize, Clone, Debug, Default, JsonSchema)]
pub struct VaultPolicyStatus {
    /// Whether the policy is currently in sync with the policy-engine.
    ///
    /// `true` after a successful upsert; `false` when the last reconcile
    /// attempt failed.
    #[serde(default)]
    pub synced: bool,

    /// RFC 3339 timestamp of the most recent successful sync.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_sync_time: Option<String>,

    /// The `metadata.generation` value that was last reconciled successfully.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub observed_generation: Option<i64>,

    /// Human-readable status message.
    ///
    /// Contains a success confirmation on sync or a detailed error description
    /// when `synced` is `false`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
}

impl VaultPolicyStatus {
    /// Build a status reflecting a successful policy upsert.
    pub fn synced(generation: i64, policy_name: &str, now: &str) -> Self {
        VaultPolicyStatus {
            synced: true,
            last_sync_time: Some(now.to_string()),
            observed_generation: Some(generation),
            message: Some(format!(
                "Policy '{policy_name}' successfully synced to the policy-engine."
            )),
        }
    }

    /// Build a status reflecting a failed reconcile attempt.
    pub fn failed(generation: i64, message: &str) -> Self {
        VaultPolicyStatus {
            synced: false,
            last_sync_time: None,
            observed_generation: Some(generation),
            message: Some(message.to_string()),
        }
    }
}
