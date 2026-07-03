//! Reconciler for `VaultPolicy` custom resources.
//!
//! # Reconcile flow
//!
//! For each `VaultPolicy` event the reconciler performs the following steps:
//!
//! 1. Detect deletion via a finalizer (`wslvault.io/policy-protection`). On
//!    deletion, remove the policy from the policy-engine and strip the
//!    finalizer.
//! 2. Ensure the finalizer is present on the resource (add it if missing).
//! 3. Validate the `spec.rules` capabilities against the allowed set.  Surface
//!    validation errors in `status.message` and stop reconciling the resource
//!    until it is corrected.
//! 4. Build a [`PolicyDocumentDto`] from the CRD spec and send it to the
//!    policy-engine via `PUT /v1/policies/<policyName>`.
//! 5. Patch `VaultPolicyStatus` with the outcome.
//!
//! All transient errors cause an exponential-backoff requeue.  Permanent
//! errors (invalid spec, unexpected 4xx) are recorded in status and the
//! resource is not requeued until it changes.

use std::{sync::Arc, time::Duration};

use chrono::Utc;
use kube::{
    api::{Api, Patch, PatchParams},
    runtime::controller::Action,
    Client, ResourceExt,
};
use serde_json::json;
use tracing::{debug, error, info, instrument, warn};

use crate::{
    crd::{PolicyCapability, VaultPolicy, VaultPolicySpec, VaultPolicyStatus},
    error::OperatorError,
};

// ─── Constants ────────────────────────────────────────────────────────────────

/// Field manager name used for all server-side apply operations.
const FIELD_MANAGER: &str = "k8s-operator.wslvault.io";

/// Finalizer that protects a `VaultPolicy` from deletion until the policy has
/// been removed from the policy-engine.
const POLICY_FINALIZER: &str = "wslvault.io/policy-protection";

/// Default policy-engine endpoint used when neither the spec nor the
/// environment variable override is set.
const DEFAULT_POLICY_ENGINE_ENDPOINT: &str = "http://policy-engine:8082";

/// Environment variable name for the default policy-engine endpoint.
const POLICY_ENGINE_ENDPOINT_ENV: &str = "POLICY_ENGINE_ENDPOINT";

/// Backoff applied after transient errors.
const DEFAULT_ERROR_BACKOFF_SECS: u64 = 30;

/// Backoff applied after permanent errors (long, to avoid tight loops while
/// still recovering if the external system self-heals).
const PERMANENT_ERROR_BACKOFF_SECS: u64 = 300;

/// Interval at which a successfully-synced policy is re-confirmed with the
/// policy-engine.  This catches out-of-band deletions.
const RESYNC_INTERVAL_SECS: u64 = 300;

// ─── Context ──────────────────────────────────────────────────────────────────

/// Shared context passed to every reconcile invocation for `VaultPolicy`.
///
/// Reuses the same reqwest and Kubernetes clients as the `VaultSecret`
/// controller to avoid creating redundant connection pools.
pub struct PolicyOperatorContext {
    /// Authenticated Kubernetes client.
    pub kube_client: Client,

    /// Pre-built reqwest HTTP client.
    pub http_client: reqwest::Client,

    /// Fallback policy-engine endpoint read from `POLICY_ENGINE_ENDPOINT` (or
    /// the compile-time default) at startup.
    pub default_policy_engine_endpoint: String,

    /// Optional static vault token used to authenticate with the policy-engine.
    pub default_vault_token: Option<String>,
}

// ─── DTO types (mirror of policy-engine HTTP API) ─────────────────────────────

/// Wire format for a single rule sent to the policy-engine.
#[derive(serde::Serialize)]
struct PolicyRuleDto {
    pub paths: Vec<String>,
    pub capabilities: Vec<String>,
}

/// Wire format for the full policy document sent to the policy-engine.
#[derive(serde::Serialize)]
struct PolicyDocumentDto {
    pub name: String,
    pub rules: Vec<PolicyRuleDto>,
}

// ─── Reconciler ───────────────────────────────────────────────────────────────

/// Entry point for the kube-rs controller runtime for `VaultPolicy` resources.
///
/// The runtime calls this function for every `VaultPolicy` event.
#[instrument(
    skip(vault_policy, ctx),
    fields(
        name = %vault_policy.name_any(),
        namespace = %vault_policy.namespace().unwrap_or_default(),
    )
)]
pub async fn reconcile(
    vault_policy: Arc<VaultPolicy>,
    ctx: Arc<PolicyOperatorContext>,
) -> Result<Action, OperatorError> {
    let namespace = vault_policy
        .namespace()
        .unwrap_or_else(|| "default".to_string());
    let generation = vault_policy.metadata.generation.unwrap_or(0);

    info!(
        policy_name = %vault_policy.spec.policy_name,
        tenant_id = %vault_policy.spec.tenant_id,
        "reconciling VaultPolicy"
    );

    // ── 1. Handle deletion ───────────────────────────────────────────────────
    if vault_policy
        .metadata
        .deletion_timestamp
        .is_some()
    {
        return handle_delete(&vault_policy, &ctx, &namespace, generation).await;
    }

    // ── 2. Ensure the finalizer is present ───────────────────────────────────
    if !has_finalizer(&vault_policy) {
        add_finalizer(&ctx.kube_client, &vault_policy, &namespace).await?;
        // After patching the finalizer the resource version changes and the
        // controller will be called again; no need to continue this iteration.
        return Ok(Action::requeue(Duration::from_secs(1)));
    }

    // ── 3. Validate capabilities ─────────────────────────────────────────────
    if let Err(validation_message) = validate_capabilities(&vault_policy.spec) {
        warn!(
            error = %validation_message,
            "VaultPolicy has invalid capabilities; halting until corrected"
        );

        patch_policy_status(
            &ctx.kube_client,
            &vault_policy,
            VaultPolicyStatus::failed(generation, &validation_message),
            &namespace,
        )
        .await;

        // Permanent failure — requeue with a long backoff to avoid a tight
        // loop while still picking up spec corrections.
        return Ok(Action::requeue(Duration::from_secs(
            PERMANENT_ERROR_BACKOFF_SECS,
        )));
    }

    // ── 4. Resolve policy-engine endpoint and auth ───────────────────────────
    let policy_engine_endpoint = resolve_policy_engine_endpoint(&vault_policy.spec, &ctx);
    let vault_token = resolve_auth_token(&vault_policy.spec, &ctx, &namespace).await;

    // ── 5. Upsert the policy into the policy-engine ──────────────────────────
    let dto = build_policy_document_dto(&vault_policy.spec);

    match upsert_policy(
        &ctx.http_client,
        &policy_engine_endpoint,
        &vault_policy.spec.tenant_id,
        &vault_policy.spec.policy_name,
        &dto,
        vault_token.as_deref(),
    )
    .await
    {
        Ok(()) => {
            let now = Utc::now().to_rfc3339();

            info!(
                policy_name = %vault_policy.spec.policy_name,
                tenant_id = %vault_policy.spec.tenant_id,
                "VaultPolicy synced successfully"
            );

            patch_policy_status(
                &ctx.kube_client,
                &vault_policy,
                VaultPolicyStatus::synced(generation, &vault_policy.spec.policy_name, &now),
                &namespace,
            )
            .await;

            Ok(Action::requeue(Duration::from_secs(RESYNC_INTERVAL_SECS)))
        }
        Err(err) => {
            let message = err.to_string();
            let is_transient = err.is_transient();

            error!(
                error = %err,
                transient = is_transient,
                "failed to upsert policy into policy-engine"
            );

            patch_policy_status(
                &ctx.kube_client,
                &vault_policy,
                VaultPolicyStatus::failed(generation, &message),
                &namespace,
            )
            .await;

            let backoff = if is_transient {
                DEFAULT_ERROR_BACKOFF_SECS
            } else {
                PERMANENT_ERROR_BACKOFF_SECS
            };

            Ok(Action::requeue(Duration::from_secs(backoff)))
        }
    }
}

/// Error handler called by the controller runtime when `reconcile` returns an
/// `Err`.  We do not return `Err` from `reconcile` intentionally, but this
/// handler is required by the kube-rs runtime API.
pub fn error_policy(
    _vault_policy: Arc<VaultPolicy>,
    err: &OperatorError,
    _ctx: Arc<PolicyOperatorContext>,
) -> Action {
    warn!(error = %err, "VaultPolicy reconcile returned an error; scheduling retry");
    Action::requeue(Duration::from_secs(DEFAULT_ERROR_BACKOFF_SECS))
}

// ─── Deletion handler ─────────────────────────────────────────────────────────

/// Handle a deletion event: remove the policy from the policy-engine and then
/// strip the finalizer so Kubernetes can garbage-collect the resource.
async fn handle_delete(
    vault_policy: &VaultPolicy,
    ctx: &PolicyOperatorContext,
    namespace: &str,
    generation: i64,
) -> Result<Action, OperatorError> {
    let policy_engine_endpoint = resolve_policy_engine_endpoint(&vault_policy.spec, ctx);
    let vault_token = resolve_auth_token(&vault_policy.spec, ctx, namespace).await;

    debug!(
        policy_name = %vault_policy.spec.policy_name,
        "deleting policy from policy-engine"
    );

    match delete_policy(
        &ctx.http_client,
        &policy_engine_endpoint,
        &vault_policy.spec.tenant_id,
        &vault_policy.spec.policy_name,
        vault_token.as_deref(),
    )
    .await
    {
        Ok(()) => {
            info!(
                policy_name = %vault_policy.spec.policy_name,
                "policy deleted from policy-engine; removing finalizer"
            );
        }
        Err(OperatorError::VaultHttp { status: 404, .. }) => {
            // Policy already absent from the engine — safe to proceed.
            info!(
                policy_name = %vault_policy.spec.policy_name,
                "policy not found in policy-engine (already deleted); removing finalizer"
            );
        }
        Err(err) => {
            let message = err.to_string();
            error!(error = %err, "failed to delete policy from policy-engine");

            // Record the failure in status so the user can see why deletion is
            // blocked.  We do not strip the finalizer — the delete will be
            // retried on the next reconcile.
            patch_policy_status(
                &ctx.kube_client,
                vault_policy,
                VaultPolicyStatus::failed(generation, &message),
                namespace,
            )
            .await;

            return Ok(Action::requeue(Duration::from_secs(DEFAULT_ERROR_BACKOFF_SECS)));
        }
    }

    // Strip the finalizer so Kubernetes can complete the deletion.
    remove_finalizer(&ctx.kube_client, vault_policy, namespace).await?;

    Ok(Action::await_change())
}

// ─── Helpers ──────────────────────────────────────────────────────────────────

/// Validate that every capability string in every rule maps to a known
/// [`PolicyCapability`].
///
/// Returns `Ok(())` when all capabilities are valid, or an `Err` containing a
/// human-readable description of the first invalid value encountered.
///
/// Even though the CRD schema enforces the enum at admission time, this check
/// provides a defence-in-depth guard against API-server version skew or
/// dry-run bypass.
pub fn validate_capabilities(spec: &VaultPolicySpec) -> Result<(), String> {
    for rule in &spec.rules {
        if rule.paths.is_empty() {
            return Err(format!(
                "rule '{}' must have at least one path",
                rule.name
            ));
        }

        if rule.capabilities.is_empty() {
            return Err(format!(
                "rule '{}' must have at least one capability",
                rule.name
            ));
        }

        // Validate that each capability is serializable to a known string.
        // We do a round-trip through the string representation to surface any
        // future schema drift early.
        for cap in &rule.capabilities {
            let cap_str = cap.as_str();
            if PolicyCapability::from_str(cap_str).is_none() {
                return Err(format!(
                    "rule '{}' contains unknown capability '{}'",
                    rule.name, cap_str
                ));
            }
        }
    }

    Ok(())
}

/// Build the [`PolicyDocumentDto`] wire payload from the CRD spec.
fn build_policy_document_dto(spec: &VaultPolicySpec) -> PolicyDocumentDto {
    let rules = spec
        .rules
        .iter()
        .map(|rule| PolicyRuleDto {
            paths: rule.paths.clone(),
            capabilities: rule
                .capabilities
                .iter()
                .map(|cap| cap.as_str().to_string())
                .collect(),
        })
        .collect();

    PolicyDocumentDto {
        name: spec.policy_name.clone(),
        rules,
    }
}

/// Send `PUT /v1/policies/<policy_name>` to the policy-engine.
async fn upsert_policy(
    http_client: &reqwest::Client,
    policy_engine_endpoint: &str,
    tenant_id: &str,
    policy_name: &str,
    dto: &PolicyDocumentDto,
    vault_token: Option<&str>,
) -> Result<(), OperatorError> {
    let url = format!("{}/v1/policies/{}", policy_engine_endpoint, policy_name);

    debug!(url = %url, tenant_id = %tenant_id, "upserting policy");

    let mut request = http_client
        .put(&url)
        .header("X-Tenant-Id", tenant_id)
        .json(dto);

    if let Some(token) = vault_token {
        request = request.bearer_auth(token);
    }

    let response = request.send().await?;
    let status = response.status();

    if !status.is_success() {
        let message = response
            .text()
            .await
            .unwrap_or_else(|_| format!("HTTP {}", status));

        return Err(OperatorError::VaultHttp {
            status: status.as_u16(),
            message,
        });
    }

    Ok(())
}

/// Send `DELETE /v1/policies/<policy_name>` to the policy-engine.
async fn delete_policy(
    http_client: &reqwest::Client,
    policy_engine_endpoint: &str,
    tenant_id: &str,
    policy_name: &str,
    vault_token: Option<&str>,
) -> Result<(), OperatorError> {
    let url = format!("{}/v1/policies/{}", policy_engine_endpoint, policy_name);

    debug!(url = %url, tenant_id = %tenant_id, "deleting policy");

    let mut request = http_client
        .delete(&url)
        .header("X-Tenant-Id", tenant_id);

    if let Some(token) = vault_token {
        request = request.bearer_auth(token);
    }

    let response = request.send().await?;
    let status = response.status();

    if !status.is_success() {
        let message = response
            .text()
            .await
            .unwrap_or_else(|_| format!("HTTP {}", status));

        return Err(OperatorError::VaultHttp {
            status: status.as_u16(),
            message,
        });
    }

    Ok(())
}

/// Determine the policy-engine endpoint to use for this resource.
///
/// Resolution order:
/// 1. `spec.policy_engine_endpoint`
/// 2. `ctx.default_policy_engine_endpoint` (from `POLICY_ENGINE_ENDPOINT` env var)
fn resolve_policy_engine_endpoint(
    spec: &VaultPolicySpec,
    ctx: &PolicyOperatorContext,
) -> String {
    spec.policy_engine_endpoint
        .as_deref()
        .unwrap_or(&ctx.default_policy_engine_endpoint)
        .trim_end_matches('/')
        .to_string()
}

/// Resolve the vault token to use for authenticating with the policy-engine.
///
/// Resolution order:
/// 1. `spec.auth.token_secret_ref` — reads the token from a Kubernetes Secret.
/// 2. `ctx.default_vault_token` — the `VAULT_TOKEN` env var captured at startup.
/// 3. `None` — unauthenticated.
async fn resolve_auth_token(
    spec: &VaultPolicySpec,
    ctx: &PolicyOperatorContext,
    namespace: &str,
) -> Option<String> {
    if let Some(auth) = &spec.auth {
        if let Some(token_ref) = &auth.token_secret_ref {
            let secrets_api: Api<k8s_openapi::api::core::v1::Secret> =
                Api::namespaced(ctx.kube_client.clone(), namespace);

            match secrets_api.get(&token_ref.name).await {
                Ok(secret) => {
                    let key = token_ref.key.as_deref().unwrap_or("token");
                    let token_bytes = secret
                        .data
                        .as_ref()
                        .and_then(|d| d.get(key))
                        .map(|bs| bs.0.clone());

                    if let Some(bytes) = token_bytes {
                        match String::from_utf8(bytes) {
                            Ok(token) => return Some(token.trim().to_string()),
                            Err(err) => {
                                warn!(
                                    secret = %token_ref.name,
                                    key = %key,
                                    error = %err,
                                    "policy token secret value is not valid UTF-8"
                                );
                            }
                        }
                    } else {
                        warn!(
                            secret = %token_ref.name,
                            key = %key,
                            "policy token key not found in referenced secret"
                        );
                    }
                }
                Err(err) => {
                    warn!(
                        secret = %token_ref.name,
                        error = %err,
                        "failed to read policy token from referenced Kubernetes Secret"
                    );
                }
            }
        }
    }

    ctx.default_vault_token.clone()
}

/// Patch the `VaultPolicy` status subresource.
///
/// Status writes are fire-and-forget; failures are logged but do not cause the
/// reconcile to fail or requeue.
async fn patch_policy_status(
    kube_client: &Client,
    vault_policy: &VaultPolicy,
    status: VaultPolicyStatus,
    namespace: &str,
) {
    let api: Api<VaultPolicy> = Api::namespaced(kube_client.clone(), namespace);

    let patch_body = json!({
        "apiVersion": "wslvault.io/v1alpha1",
        "kind": "VaultPolicy",
        "status": status,
    });

    let patch_params = PatchParams::apply(FIELD_MANAGER).force();

    if let Err(err) = api
        .patch_status(
            &vault_policy.name_any(),
            &patch_params,
            &Patch::Apply(patch_body),
        )
        .await
    {
        warn!(
            name = %vault_policy.name_any(),
            error = %err,
            "failed to patch VaultPolicy status"
        );
    }
}

/// Returns `true` if the `VaultPolicy` resource already has the protection
/// finalizer.
fn has_finalizer(vault_policy: &VaultPolicy) -> bool {
    vault_policy
        .metadata
        .finalizers
        .as_deref()
        .unwrap_or_default()
        .contains(&POLICY_FINALIZER.to_string())
}

/// Add the protection finalizer to the `VaultPolicy` resource via a JSON merge
/// patch.
async fn add_finalizer(
    kube_client: &Client,
    vault_policy: &VaultPolicy,
    namespace: &str,
) -> Result<(), OperatorError> {
    let api: Api<VaultPolicy> = Api::namespaced(kube_client.clone(), namespace);

    let mut finalizers = vault_policy
        .metadata
        .finalizers
        .clone()
        .unwrap_or_default();

    if !finalizers.contains(&POLICY_FINALIZER.to_string()) {
        finalizers.push(POLICY_FINALIZER.to_string());
    }

    let patch_body = json!({
        "metadata": {
            "finalizers": finalizers
        }
    });

    api.patch(
        &vault_policy.name_any(),
        &PatchParams::apply(FIELD_MANAGER),
        &Patch::Merge(patch_body),
    )
    .await
    .map_err(|err| OperatorError::KubeApi(err))?;

    debug!(name = %vault_policy.name_any(), "added policy finalizer");
    Ok(())
}

/// Remove the protection finalizer from the `VaultPolicy` resource via a JSON
/// merge patch, allowing Kubernetes to garbage-collect it.
async fn remove_finalizer(
    kube_client: &Client,
    vault_policy: &VaultPolicy,
    namespace: &str,
) -> Result<(), OperatorError> {
    let api: Api<VaultPolicy> = Api::namespaced(kube_client.clone(), namespace);

    let remaining_finalizers: Vec<String> = vault_policy
        .metadata
        .finalizers
        .as_deref()
        .unwrap_or_default()
        .iter()
        .filter(|f| f.as_str() != POLICY_FINALIZER)
        .cloned()
        .collect();

    let patch_body = json!({
        "metadata": {
            "finalizers": remaining_finalizers
        }
    });

    api.patch(
        &vault_policy.name_any(),
        &PatchParams::apply(FIELD_MANAGER),
        &Patch::Merge(patch_body),
    )
    .await
    .map_err(|err| OperatorError::KubeApi(err))?;

    debug!(name = %vault_policy.name_any(), "removed policy finalizer");
    Ok(())
}

// ─── Configuration helper ─────────────────────────────────────────────────────

/// Read the default policy-engine endpoint from the environment.
///
/// Falls back to [`DEFAULT_POLICY_ENGINE_ENDPOINT`] when the variable is
/// absent or empty.
pub fn default_policy_engine_endpoint() -> String {
    std::env::var(POLICY_ENGINE_ENDPOINT_ENV)
        .ok()
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| DEFAULT_POLICY_ENGINE_ENDPOINT.to_string())
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crd::{PolicyCapability, PolicyRuleSpec, VaultPolicySpec};

    /// Build a minimal [`VaultPolicySpec`] for testing.
    fn make_spec(rules: Vec<PolicyRuleSpec>) -> VaultPolicySpec {
        VaultPolicySpec {
            policy_name: "test-policy".to_string(),
            tenant_id: "tenant-a".to_string(),
            policy_engine_endpoint: None,
            auth: None,
            rules,
        }
    }

    /// Build a single rule with the given capabilities.
    fn make_rule(name: &str, caps: Vec<PolicyCapability>) -> PolicyRuleSpec {
        PolicyRuleSpec {
            name: name.to_string(),
            paths: vec!["app/*".to_string()],
            capabilities: caps,
        }
    }

    // ── validate_capabilities ────────────────────────────────────────────────

    #[test]
    fn validate_capabilities_accepts_all_valid_values() {
        let spec = make_spec(vec![
            make_rule(
                "all-caps",
                vec![
                    PolicyCapability::Read,
                    PolicyCapability::Write,
                    PolicyCapability::Delete,
                    PolicyCapability::List,
                    PolicyCapability::Create,
                    PolicyCapability::Update,
                    PolicyCapability::Deny,
                ],
            ),
        ]);

        assert!(validate_capabilities(&spec).is_ok());
    }

    #[test]
    fn validate_capabilities_rejects_empty_paths() {
        let spec = VaultPolicySpec {
            policy_name: "p".to_string(),
            tenant_id: "t".to_string(),
            policy_engine_endpoint: None,
            auth: None,
            rules: vec![PolicyRuleSpec {
                name: "empty-paths".to_string(),
                paths: vec![], // intentionally empty
                capabilities: vec![PolicyCapability::Read],
            }],
        };

        let result = validate_capabilities(&spec);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("at least one path"));
    }

    #[test]
    fn validate_capabilities_rejects_empty_capabilities() {
        let spec = VaultPolicySpec {
            policy_name: "p".to_string(),
            tenant_id: "t".to_string(),
            policy_engine_endpoint: None,
            auth: None,
            rules: vec![PolicyRuleSpec {
                name: "empty-caps".to_string(),
                paths: vec!["app/*".to_string()],
                capabilities: vec![], // intentionally empty
            }],
        };

        let result = validate_capabilities(&spec);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("at least one capability"));
    }

    #[test]
    fn validate_capabilities_accepts_empty_rules() {
        // A spec with zero rules is technically valid at the validation layer;
        // the CRD schema may add a minItems constraint separately.
        let spec = make_spec(vec![]);
        assert!(validate_capabilities(&spec).is_ok());
    }

    // ── build_policy_document_dto ────────────────────────────────────────────

    #[test]
    fn build_dto_maps_rules_and_capabilities_correctly() {
        let spec = make_spec(vec![
            make_rule("r1", vec![PolicyCapability::Read, PolicyCapability::List]),
            make_rule("r2", vec![PolicyCapability::Write, PolicyCapability::Delete]),
        ]);

        let dto = build_policy_document_dto(&spec);

        assert_eq!(dto.name, "test-policy");
        assert_eq!(dto.rules.len(), 2);

        let r1 = &dto.rules[0];
        assert_eq!(r1.paths, vec!["app/*"]);
        assert!(r1.capabilities.contains(&"read".to_string()));
        assert!(r1.capabilities.contains(&"list".to_string()));
        assert!(!r1.capabilities.contains(&"write".to_string()));

        let r2 = &dto.rules[1];
        assert!(r2.capabilities.contains(&"write".to_string()));
        assert!(r2.capabilities.contains(&"delete".to_string()));
    }

    #[test]
    fn build_dto_preserves_multi_segment_paths() {
        let spec = make_spec(vec![PolicyRuleSpec {
            name: "deep-paths".to_string(),
            paths: vec!["secrets/**".to_string(), "shared/db/*".to_string()],
            capabilities: vec![PolicyCapability::Read],
        }]);

        let dto = build_policy_document_dto(&spec);

        assert_eq!(dto.rules[0].paths.len(), 2);
        assert_eq!(dto.rules[0].paths[0], "secrets/**");
        assert_eq!(dto.rules[0].paths[1], "shared/db/*");
    }

    #[test]
    fn build_dto_deny_capability_is_forwarded() {
        let spec = make_spec(vec![make_rule("deny-all", vec![PolicyCapability::Deny])]);

        let dto = build_policy_document_dto(&spec);

        assert_eq!(dto.rules[0].capabilities, vec!["deny".to_string()]);
    }

    // ── PolicyCapability round-trip ──────────────────────────────────────────

    #[test]
    fn capability_as_str_and_from_str_round_trip() {
        let all_caps = [
            PolicyCapability::Read,
            PolicyCapability::Write,
            PolicyCapability::Delete,
            PolicyCapability::List,
            PolicyCapability::Create,
            PolicyCapability::Update,
            PolicyCapability::Deny,
        ];

        for cap in &all_caps {
            let s = cap.as_str();
            let parsed = PolicyCapability::from_str(s)
                .unwrap_or_else(|| panic!("from_str failed for '{}'", s));
            assert_eq!(parsed.as_str(), s);
        }
    }

    #[test]
    fn capability_from_str_is_case_insensitive() {
        assert!(PolicyCapability::from_str("READ").is_some());
        assert!(PolicyCapability::from_str("Write").is_some());
        assert!(PolicyCapability::from_str("DENY").is_some());
    }

    #[test]
    fn capability_from_str_returns_none_for_unknown() {
        assert!(PolicyCapability::from_str("superadmin").is_none());
        assert!(PolicyCapability::from_str("").is_none());
        assert!(PolicyCapability::from_str("exec").is_none());
    }

    // ── resolve_policy_engine_endpoint ───────────────────────────────────────
    //
    // `resolve_policy_engine_endpoint` only reads `spec.policy_engine_endpoint`
    // and `ctx.default_policy_engine_endpoint`.  We test it via the thin
    // `resolve_endpoint_raw` helper below so we don't need to construct a live
    // `kube::Client` (which requires a running cluster or a mock server).

    /// Test-only wrapper that exercises the endpoint resolution logic without
    /// requiring a live `kube::Client`.
    fn resolve_endpoint_raw(spec_override: Option<&str>, ctx_default: &str) -> String {
        let spec = VaultPolicySpec {
            policy_name: "p".to_string(),
            tenant_id: "t".to_string(),
            policy_engine_endpoint: spec_override.map(str::to_string),
            auth: None,
            rules: vec![],
        };

        // Resolution is purely a string operation — inline it here so we avoid
        // constructing a `PolicyOperatorContext` (which embeds `kube::Client`).
        spec.policy_engine_endpoint
            .as_deref()
            .unwrap_or(ctx_default)
            .trim_end_matches('/')
            .to_string()
    }

    #[test]
    fn resolve_endpoint_uses_spec_override_when_present() {
        let endpoint = resolve_endpoint_raw(
            Some("http://custom-engine:9999"),
            "http://default:8082",
        );
        assert_eq!(endpoint, "http://custom-engine:9999");
    }

    #[test]
    fn resolve_endpoint_falls_back_to_context_default() {
        let endpoint = resolve_endpoint_raw(None, "http://policy-engine:8082");
        assert_eq!(endpoint, "http://policy-engine:8082");
    }

    #[test]
    fn resolve_endpoint_strips_trailing_slash() {
        let endpoint = resolve_endpoint_raw(
            Some("http://engine:8082/"),
            "http://default:8082",
        );
        assert_eq!(endpoint, "http://engine:8082");
    }
}
