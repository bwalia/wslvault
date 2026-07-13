//! Reconciler for `VaultSecret` custom resources.
//!
//! # Reconcile flow
//!
//! For each `VaultSecret` event the reconciler performs the following steps:
//!
//! 1. Resolve the wslvault endpoint and authentication token.
//! 2. Fetch the secret at `spec.path` from the secret-engine via HTTP.
//! 3. Decode and optionally remap the key/value data.
//! 4. Apply (`ServerSideApply`) a Kubernetes `Secret` with the data,
//!    setting an owner reference so the secret is garbage-collected when
//!    the `VaultSecret` is deleted.
//! 5. Patch `VaultSecretStatus` with a `Synced` condition.
//! 6. Return an [`Action::requeue`] with the configured `refresh_interval`
//!    so the secret is periodically re-synced.
//!
//! Transient errors (network, 5xx from vault) cause an exponential-backoff
//! requeue. Permanent errors (bad spec, 4xx) are recorded in the status and
//! the resource is not requeued until it is modified.

use std::{collections::BTreeMap, sync::Arc, time::Duration};

use base64::Engine as _;
use chrono::Utc;
use k8s_openapi::{api::core::v1::Secret, apimachinery::pkg::apis::meta::v1::OwnerReference};
use kube::{
    api::{Api, ObjectMeta, Patch, PatchParams},
    runtime::controller::Action,
    Client, Resource, ResourceExt,
};
use serde_json::Value;
use tracing::{debug, error, info, instrument, warn};

use crate::{
    crd::{VaultSecret, VaultSecretStatus},
    error::OperatorError,
};

// ─── Constants ────────────────────────────────────────────────────────────────

/// Field manager name used for server-side apply operations.
const FIELD_MANAGER: &str = "k8s-operator.wslvault.io";

/// Default re-sync interval when `spec.refresh_interval` is not set.
const DEFAULT_REFRESH_INTERVAL_SECS: u64 = 60;

/// Default backoff duration when a transient error occurs.
const DEFAULT_ERROR_BACKOFF_SECS: u64 = 30;

/// Maximum exponential backoff cap (5 minutes).
const MAX_ERROR_BACKOFF_SECS: u64 = 300;

/// JSON key in the `GetSecret` HTTP response body that holds the base64-encoded
/// secret data returned by the secret-engine.
const VAULT_RESPONSE_DATA_KEY: &str = "data";

/// JSON key in the `GetSecret` HTTP response body that holds the version number.
const VAULT_RESPONSE_VERSION_KEY: &str = "version";

// ─── Context ──────────────────────────────────────────────────────────────────

/// Shared context passed to every reconcile invocation.
///
/// `reqwest::Client` is kept here so that connection pools are reused across
/// reconcile iterations rather than being rebuilt on every call.
pub struct OperatorContext {
    /// Authenticated Kubernetes client.
    pub kube_client: Client,

    /// Pre-built reqwest client for reaching the wslvault secret-engine.
    pub http_client: reqwest::Client,

    /// Fallback wslvault endpoint read from `VAULT_ENDPOINT` at startup.
    ///
    /// A per-resource `spec.vault_endpoint` always takes precedence over this
    /// value.
    pub default_vault_endpoint: String,

    /// Optional static vault token read from `VAULT_TOKEN` at startup.
    ///
    /// Per-resource `spec.auth` configuration takes precedence.
    pub default_vault_token: Option<String>,
}

// ─── Response shapes ──────────────────────────────────────────────────────────

/// The JSON body returned by `GET /v1/secrets/<path>` on the secret-engine.
///
/// The `data` field holds the base64-encoded JSON map of key→value pairs that
/// was stored by the caller.
#[derive(Debug, serde::Deserialize)]
struct VaultGetSecretResponse {
    /// Base64-encoded JSON object whose keys become Secret data entries.
    pub data: String,

    /// Monotonically increasing version counter for the secret path.
    pub version: u32,
}

// ─── Reconciler ───────────────────────────────────────────────────────────────

/// Entry point for the kube-rs controller runtime.
///
/// The runtime calls this function for every `VaultSecret` event.  The
/// function is responsible for updating the in-cluster `Secret` and writing
/// status conditions back to the `VaultSecret` object.
///
/// # Error handling strategy
///
/// - Returns `Ok(Action::requeue(...))` for transient errors so the runtime
///   schedules a retry with backoff.
/// - Returns `Ok(Action::requeue(...))` with a long interval for permanent
///   errors (after recording the failure in status), preventing tight loops
///   while still allowing recovery if the user corrects the spec.
#[instrument(
    skip(vault_secret, ctx),
    fields(
        name = %vault_secret.name_any(),
        namespace = %vault_secret.namespace().unwrap_or_default(),
    )
)]
pub async fn reconcile(
    vault_secret: Arc<VaultSecret>,
    ctx: Arc<OperatorContext>,
) -> Result<Action, OperatorError> {
    let name = vault_secret.name_any();
    let namespace = vault_secret
        .namespace()
        .unwrap_or_else(|| "default".to_string());
    let generation = vault_secret.metadata.generation.unwrap_or(0);

    info!(
        path = %vault_secret.spec.path,
        "reconciling VaultSecret"
    );

    // ── 1. Resolve vault endpoint ────────────────────────────────────────────
    let vault_endpoint = vault_secret
        .spec
        .vault_endpoint
        .as_deref()
        .unwrap_or(&ctx.default_vault_endpoint)
        .trim_end_matches('/')
        .to_string();

    // ── 2. Resolve authentication token ──────────────────────────────────────
    // For v1 we support a static token from the environment or spec.auth
    // tokenSecretRef. ServiceAccount-based auth is left as a future extension.
    let vault_token = resolve_auth_token(&vault_secret, &ctx, &namespace).await;

    // ── 3. Fetch secret from wslvault ─────────────────────────────────────────
    let fetch_result = fetch_secret_from_vault(
        &ctx.http_client,
        &vault_endpoint,
        &vault_secret.spec.path,
        vault_token.as_deref(),
    )
    .await;

    let (raw_data_b64, secret_version) = match fetch_result {
        Ok(response) => (response.data, response.version),
        Err(err) => {
            let now = Utc::now().to_rfc3339();
            let is_transient = err.is_transient();
            let (reason, message) = error_to_condition_parts(&err);

            error!(
                error = %err,
                transient = is_transient,
                "failed to fetch secret from wslvault"
            );

            // Record the failure in status regardless of transience.
            patch_status(
                &ctx.kube_client,
                &vault_secret,
                VaultSecretStatus::failed(generation, &reason, &message, &now),
                &namespace,
            )
            .await;

            let backoff = if is_transient {
                DEFAULT_ERROR_BACKOFF_SECS
            } else {
                // Permanent errors: requeue after a long interval so that if
                // the spec is corrected externally the operator picks it up.
                MAX_ERROR_BACKOFF_SECS
            };

            return Ok(Action::requeue(Duration::from_secs(backoff)));
        }
    };

    // ── 4. Decode and build the Secret data map ───────────────────────────────
    let secret_data =
        match build_secret_data(&raw_data_b64, vault_secret.spec.data_mappings.as_deref()) {
            Ok(d) => d,
            Err(err) => {
                let now = Utc::now().to_rfc3339();
                let (reason, message) = error_to_condition_parts(&err);
                warn!(error = %err, "failed to decode secret data");

                patch_status(
                    &ctx.kube_client,
                    &vault_secret,
                    VaultSecretStatus::failed(generation, &reason, &message, &now),
                    &namespace,
                )
                .await;

                // This is a permanent error — do not tightly requeue.
                return Ok(Action::requeue(Duration::from_secs(MAX_ERROR_BACKOFF_SECS)));
            }
        };

    // ── 5. Determine target secret name and namespace ─────────────────────────
    let (target_name, target_namespace, secret_type_str) =
        resolve_target(&name, &namespace, vault_secret.spec.target.as_ref());

    // ── 6. Apply the Kubernetes Secret ───────────────────────────────────────
    let owner_ref = build_owner_reference(&vault_secret)?;

    if let Err(err) = apply_kubernetes_secret(
        &ctx.kube_client,
        &target_name,
        &target_namespace,
        secret_type_str,
        secret_data,
        owner_ref,
    )
    .await
    {
        let now = Utc::now().to_rfc3339();
        let (reason, message) = error_to_condition_parts(&err);
        error!(error = %err, "failed to apply target Kubernetes Secret");

        patch_status(
            &ctx.kube_client,
            &vault_secret,
            VaultSecretStatus::failed(generation, &reason, &message, &now),
            &namespace,
        )
        .await;

        return Ok(Action::requeue(Duration::from_secs(
            DEFAULT_ERROR_BACKOFF_SECS,
        )));
    }

    // ── 7. Update status to reflect successful sync ───────────────────────────
    let now = Utc::now().to_rfc3339();
    patch_status(
        &ctx.kube_client,
        &vault_secret,
        VaultSecretStatus::synced(generation, secret_version, &now),
        &namespace,
    )
    .await;

    info!(
        target_secret = %target_name,
        target_namespace = %target_namespace,
        version = secret_version,
        "VaultSecret reconciled successfully"
    );

    // ── 8. Schedule next reconcile ────────────────────────────────────────────
    let refresh_interval = vault_secret
        .spec
        .refresh_interval
        .unwrap_or(DEFAULT_REFRESH_INTERVAL_SECS);

    Ok(Action::requeue(Duration::from_secs(refresh_interval)))
}

/// Error handler called by the controller runtime when `reconcile` returns
/// an `Err`.  We do not return `Err` from `reconcile` intentionally (all
/// errors are turned into `Action::requeue`), but this handler is required
/// by the runtime API.
pub fn error_policy(
    _vault_secret: Arc<VaultSecret>,
    err: &OperatorError,
    _ctx: Arc<OperatorContext>,
) -> Action {
    warn!(error = %err, "reconcile returned an error; scheduling retry");
    Action::requeue(Duration::from_secs(DEFAULT_ERROR_BACKOFF_SECS))
}

// ─── Helpers ──────────────────────────────────────────────────────────────────

/// Fetch the secret at `path` from the wslvault secret-engine.
///
/// The secret-engine exposes:
/// ```
/// GET /v1/secrets/<path>
/// ```
/// The response body is `{ "data": "<base64>", "version": <u32>, ... }`.
async fn fetch_secret_from_vault(
    http_client: &reqwest::Client,
    vault_endpoint: &str,
    path: &str,
    vault_token: Option<&str>,
) -> Result<VaultGetSecretResponse, OperatorError> {
    let url = format!("{}/v1/secrets/{}", vault_endpoint, path);
    debug!(url = %url, "fetching secret from wslvault");

    let mut request = http_client.get(&url);

    // Attach the vault token as a bearer token when available.
    if let Some(token) = vault_token {
        request = request.bearer_auth(token);
    }

    let response = request.send().await?;

    let status = response.status();

    if !status.is_success() {
        // Attempt to extract an error message from the response body.
        let message = response
            .text()
            .await
            .unwrap_or_else(|_| format!("HTTP {}", status));

        return Err(OperatorError::VaultHttp {
            status: status.as_u16(),
            message,
        });
    }

    // Parse the JSON response body.
    let body: serde_json::Value = response.json().await.map_err(|err| {
        OperatorError::UnexpectedResponseFormat(format!("could not parse JSON: {}", err))
    })?;

    // Extract the `data` field (base64-encoded secret payload).
    let data_b64 = body
        .get(VAULT_RESPONSE_DATA_KEY)
        .and_then(Value::as_str)
        .ok_or_else(|| {
            OperatorError::UnexpectedResponseFormat(format!(
                "response missing '{}' field",
                VAULT_RESPONSE_DATA_KEY
            ))
        })?
        .to_string();

    // Extract the `version` field.
    let version = body
        .get(VAULT_RESPONSE_VERSION_KEY)
        .and_then(Value::as_u64)
        .unwrap_or(0) as u32;

    Ok(VaultGetSecretResponse {
        data: data_b64,
        version,
    })
}

/// Decode the base64-encoded secret data from the vault response and apply
/// any configured key remappings.
///
/// The `raw_data_b64` field from the vault response is expected to contain a
/// base64-encoded JSON object (`{ "KEY": "VALUE", ... }`).  Each value in the
/// object is expected to be a UTF-8 string; non-string values are serialised
/// to their JSON representation.
///
/// When `data_mappings` is provided only the listed keys are included in the
/// output.  When `data_mappings` is `None` all keys are copied verbatim.
fn build_secret_data(
    raw_data_b64: &str,
    data_mappings: Option<&[crate::crd::DataMapping]>,
) -> Result<BTreeMap<String, k8s_openapi::ByteString>, OperatorError> {
    // Step 1: base64-decode the raw payload.
    let decoded_bytes = base64::engine::general_purpose::STANDARD.decode(raw_data_b64)?;

    // Step 2: parse as a JSON object.
    let json_map: serde_json::Map<String, Value> =
        serde_json::from_slice(&decoded_bytes).map_err(|err| {
            OperatorError::UnexpectedResponseFormat(format!(
                "decoded secret data is not a JSON object: {}",
                err
            ))
        })?;

    let mut secret_data: BTreeMap<String, k8s_openapi::ByteString> = BTreeMap::new();

    match data_mappings {
        Some(mappings) if !mappings.is_empty() => {
            // Apply explicit key remappings. Keys not listed in mappings are
            // dropped — this allows the operator to expose only a subset of the
            // secret to a particular workload.
            for mapping in mappings {
                let value = json_map.get(&mapping.vault_key).ok_or_else(|| {
                    OperatorError::MissingField(format!(
                        "data_mapping vault_key '{}' not found in secret response",
                        mapping.vault_key
                    ))
                })?;

                let bytes = value_to_bytes(value);
                secret_data.insert(mapping.secret_key.clone(), k8s_openapi::ByteString(bytes));
            }
        }
        _ => {
            // No mappings configured — copy all keys verbatim.
            for (key, value) in &json_map {
                let bytes = value_to_bytes(value);
                secret_data.insert(key.clone(), k8s_openapi::ByteString(bytes));
            }
        }
    }

    Ok(secret_data)
}

/// Convert a JSON value to its raw byte representation for storage in a
/// Kubernetes Secret.
///
/// String values are UTF-8 encoded without quotes.  All other values (numbers,
/// booleans, arrays, objects) are serialised to their compact JSON form.
fn value_to_bytes(value: &Value) -> Vec<u8> {
    match value {
        Value::String(s) => s.as_bytes().to_vec(),
        other => serde_json::to_vec(other).unwrap_or_default(),
    }
}

/// Determine the name, namespace, and type string for the target Kubernetes
/// Secret based on the `spec.target` field.
fn resolve_target<'a>(
    vs_name: &'a str,
    vs_namespace: &'a str,
    target: Option<&'a crate::crd::TargetSpec>,
) -> (String, String, &'a str) {
    match target {
        Some(t) => {
            let name = t.name.as_deref().unwrap_or(vs_name).to_string();
            let ns = t.namespace.as_deref().unwrap_or(vs_namespace).to_string();
            let type_str = t.secret_type.as_str();
            (name, ns, type_str)
        }
        None => (vs_name.to_string(), vs_namespace.to_string(), "Opaque"),
    }
}

/// Build an `OwnerReference` pointing at the `VaultSecret` so that the
/// Kubernetes garbage collector deletes the `Secret` when the `VaultSecret`
/// is deleted.
fn build_owner_reference(vs: &VaultSecret) -> Result<OwnerReference, OperatorError> {
    let uid = vs
        .metadata
        .uid
        .clone()
        .ok_or_else(|| OperatorError::MissingField("metadata.uid".to_string()))?;

    Ok(OwnerReference {
        api_version: VaultSecret::api_version(&()).to_string(),
        kind: VaultSecret::kind(&()).to_string(),
        name: vs.name_any(),
        uid,
        // The secret is a dependent object; block deletion of the VaultSecret
        // until the target Secret has been removed (cascade protection).
        block_owner_deletion: Some(true),
        controller: Some(true),
    })
}

/// Apply (create or patch) the target Kubernetes `Secret` using server-side
/// apply.  The entire object is replaced on every reconcile so that stale keys
/// are pruned when the secret-engine data changes.
async fn apply_kubernetes_secret(
    kube_client: &Client,
    name: &str,
    namespace: &str,
    secret_type: &str,
    data: BTreeMap<String, k8s_openapi::ByteString>,
    owner_ref: OwnerReference,
) -> Result<(), OperatorError> {
    let secrets_api: Api<Secret> = Api::namespaced(kube_client.clone(), namespace);

    // Build the desired Secret manifest.
    let desired = Secret {
        metadata: ObjectMeta {
            name: Some(name.to_string()),
            namespace: Some(namespace.to_string()),
            // Labels allow operators and tools to discover synced secrets.
            labels: Some(BTreeMap::from([
                (
                    "app.kubernetes.io/managed-by".to_string(),
                    "k8s-operator.wslvault.io".to_string(),
                ),
                ("wslvault.io/synced".to_string(), "true".to_string()),
            ])),
            owner_references: Some(vec![owner_ref]),
            ..Default::default()
        },
        type_: Some(secret_type.to_string()),
        data: Some(data),
        ..Default::default()
    };

    let patch_params = PatchParams::apply(FIELD_MANAGER).force();

    secrets_api
        .patch(name, &patch_params, &Patch::Apply(&desired))
        .await
        .map_err(|err| OperatorError::ApplyTargetSecret {
            name: name.to_string(),
            namespace: namespace.to_string(),
            source: err,
        })?;

    debug!(
        secret = %name,
        namespace = %namespace,
        "Kubernetes Secret applied"
    );

    Ok(())
}

/// Patch the `VaultSecret` status subresource.
///
/// Status writes are fire-and-forget from the reconcile logic's perspective;
/// failures are logged but do not cause the reconcile to error out or requeue.
async fn patch_status(
    kube_client: &Client,
    vault_secret: &VaultSecret,
    status: VaultSecretStatus,
    namespace: &str,
) {
    let vs_api: Api<VaultSecret> = Api::namespaced(kube_client.clone(), namespace);

    let patch_body = serde_json::json!({
        "apiVersion": "wslvault.io/v1alpha1",
        "kind": "VaultSecret",
        "status": status,
    });

    let patch_params = PatchParams::apply(FIELD_MANAGER).force();

    if let Err(err) = vs_api
        .patch_status(
            &vault_secret.name_any(),
            &patch_params,
            &Patch::Apply(patch_body),
        )
        .await
    {
        warn!(
            name = %vault_secret.name_any(),
            error = %err,
            "failed to patch VaultSecret status"
        );
    }
}

/// Resolve the vault token to use for authenticating with the secret-engine.
///
/// Resolution order:
/// 1. `spec.auth.token_secret_ref` — reads the token from a Kubernetes Secret.
/// 2. `ctx.default_vault_token` — the `VAULT_TOKEN` env var captured at
///    startup.
/// 3. `None` — unauthenticated (valid for permissive vault configurations).
///
/// Service account JWT exchange (for production use) is a future extension.
async fn resolve_auth_token(
    vault_secret: &VaultSecret,
    ctx: &OperatorContext,
    namespace: &str,
) -> Option<String> {
    // Check for explicit token secret reference in the spec.
    if let Some(auth) = &vault_secret.spec.auth {
        if let Some(token_ref) = &auth.token_secret_ref {
            let ref_namespace = namespace.to_string();
            let secrets_api: Api<Secret> = Api::namespaced(ctx.kube_client.clone(), &ref_namespace);

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
                                    "vault token secret value is not valid UTF-8"
                                );
                            }
                        }
                    } else {
                        warn!(
                            secret = %token_ref.name,
                            key = %key,
                            "vault token key not found in referenced secret"
                        );
                    }
                }
                Err(err) => {
                    warn!(
                        secret = %token_ref.name,
                        error = %err,
                        "failed to read vault token from referenced Kubernetes Secret"
                    );
                }
            }
        }
    }

    // Fall back to the operator-level default token.
    ctx.default_vault_token.clone()
}

/// Convert an [`OperatorError`] into a `(reason, message)` pair suitable for
/// writing into a Kubernetes status condition.
fn error_to_condition_parts(err: &OperatorError) -> (String, String) {
    let reason = match err {
        OperatorError::VaultHttp { status, .. } if *status == 404 => "SecretNotFound",
        OperatorError::VaultHttp { status, .. } if *status >= 500 => "VaultServerError",
        OperatorError::VaultHttp { .. } => "VaultClientError",
        OperatorError::HttpTransport(_) => "NetworkError",
        OperatorError::MissingField(_) => "InvalidSpec",
        OperatorError::UnexpectedResponseFormat(_) => "UnexpectedResponse",
        OperatorError::Base64Decode(_) => "DecodeError",
        OperatorError::ApplyTargetSecret { .. } => "KubeApplyFailed",
        OperatorError::KubeApi(_) => "KubeApiError",
        OperatorError::Json(_) => "SerializationError",
        OperatorError::CrdInstall(_) => "CrdInstallError",
        OperatorError::Generic(_) => "ReconcileError",
    };

    (reason.to_string(), err.to_string())
}
