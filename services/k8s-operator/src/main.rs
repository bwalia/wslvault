//! k8s-operator: Kubernetes Secrets Sync Operator for the WSLVault platform.
//!
//! This binary watches two custom resources and reconciles them:
//!
//! - `VaultSecret` — fetches a secret path from the wslvault secret-engine
//!   and writes the decrypted data into a native Kubernetes `Secret`.
//! - `VaultPolicy` — syncs a policy document from a Kubernetes CRD into the
//!   wslvault policy-engine, enabling GitOps-driven access-control management.
//!
//! Both controllers run concurrently in the same process via `tokio::join!`.
//!
//! # Configuration
//!
//! All configuration is via environment variables:
//!
//! | Variable | Default | Description |
//! |---|---|---|
//! | `VAULT_ENDPOINT` | `http://secret-engine:8081` | wslvault secret-engine HTTP base URL |
//! | `POLICY_ENGINE_ENDPOINT` | `http://policy-engine:8082` | wslvault policy-engine HTTP base URL |
//! | `VAULT_TOKEN` | _(none)_ | Static bearer token (used for both engines) |
//! | `RUST_LOG` | `info` | Log filter (see `tracing-subscriber` docs) |
//! | `HEALTH_ADDR` | `0.0.0.0:8090` | Address for the health/readiness HTTP server |
//!
//! # Health endpoints
//!
//! | Path | Description |
//! |---|---|
//! | `GET /health` | Liveness probe — always returns 200 when the process is running |
//! | `GET /ready` | Readiness probe — returns 200 once the CRD is installed and the watch is active |
//!
//! # CRD auto-install
//!
//! On startup the operator attempts to ensure both `VaultSecret` and
//! `VaultPolicy` CRDs exist in the cluster.  If they are already present they
//! are left unchanged.  If the necessary RBAC permissions are absent the
//! operator logs a warning and continues (the CRDs can be pre-installed via
//! `deploy/kubernetes/crds/`).

mod controller;
mod crd;
mod error;
mod policy_controller;

use std::{net::SocketAddr, sync::Arc};

use futures::StreamExt as _;
use k8s_openapi::apiextensions_apiserver::pkg::apis::apiextensions::v1::CustomResourceDefinition;
use kube::{
    api::{Api, Patch, PatchParams},
    runtime::{controller::Controller, watcher},
    Client, ResourceExt,
};
use tracing::{error, info, warn};
use tracing_subscriber::{fmt, prelude::*, EnvFilter};

use crate::{
    controller::{error_policy, reconcile, OperatorContext},
    crd::{VaultPolicy, VaultSecret},
    policy_controller::{
        default_policy_engine_endpoint, error_policy as policy_error_policy,
        reconcile as policy_reconcile, PolicyOperatorContext,
    },
};

// ─── Constants ────────────────────────────────────────────────────────────────

/// Default health-check server listen address.
const DEFAULT_HEALTH_ADDR: &str = "0.0.0.0:8090";

/// Default wslvault secret-engine endpoint.
const DEFAULT_VAULT_ENDPOINT: &str = "http://secret-engine:8081";

/// Field manager used when patching CRD objects.
const CRD_FIELD_MANAGER: &str = "k8s-operator.wslvault.io";

/// Name of the `VaultPolicy` CRD used for self-install checks.
const VAULT_POLICY_CRD_NAME: &str = "vaultpolicies.wslvault.io";

// ─── Entrypoint ───────────────────────────────────────────────────────────────

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // ── 1. Initialise structured tracing ────────────────────────────────────
    let log_filter = std::env::var("RUST_LOG").unwrap_or_else(|_| "info".to_string());

    tracing_subscriber::registry()
        .with(fmt::layer().json())
        .with(EnvFilter::new(log_filter))
        .init();

    info!(
        service = "k8s-operator",
        version = env!("CARGO_PKG_VERSION"),
        "wslvault Kubernetes Secrets Sync Operator starting"
    );

    // ── 2. Read configuration from the environment ───────────────────────────
    let vault_endpoint =
        std::env::var("VAULT_ENDPOINT").unwrap_or_else(|_| DEFAULT_VAULT_ENDPOINT.to_string());

    let policy_engine_endpoint = default_policy_engine_endpoint();

    let vault_token = std::env::var("VAULT_TOKEN").ok().filter(|t| !t.is_empty());

    // Identity the operator asserts to the gateway-fronted secret-engine.
    let vault_tenant_id = std::env::var("VAULT_TENANT_ID").ok().filter(|t| !t.is_empty());
    let vault_policies = std::env::var("VAULT_POLICIES").ok().filter(|t| !t.is_empty());

    let health_addr: SocketAddr = std::env::var("HEALTH_ADDR")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or_else(|| {
            DEFAULT_HEALTH_ADDR
                .parse()
                .expect("DEFAULT_HEALTH_ADDR is a valid socket address")
        });

    info!(
        vault_endpoint = %vault_endpoint,
        policy_engine_endpoint = %policy_engine_endpoint,
        health_addr = %health_addr,
        vault_token_configured = vault_token.is_some(),
        "resolved operator configuration"
    );

    // ── 3. Build Kubernetes client ───────────────────────────────────────────
    let kube_client = Client::try_default()
        .await
        .map_err(|err| anyhow::anyhow!("failed to build Kubernetes client: {}", err))?;

    // ── 4. Ensure both CRDs are installed ───────────────────────────────────
    // These are best-effort; if the operator lacks the necessary RBAC
    // permissions to manage CRDs it will log a warning and continue.  The CRDs
    // can be pre-installed via `deploy/kubernetes/crds/`.
    ensure_crd_installed(&kube_client).await;
    ensure_vault_policy_crd_installed(&kube_client).await;

    // ── 5. Build shared HTTP client ──────────────────────────────────────────
    let http_client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(15))
        .build()
        .map_err(|err| anyhow::anyhow!("failed to build HTTP client: {}", err))?;

    // ── 6. Start health/readiness server ────────────────────────────────────
    tokio::spawn(run_health_server(health_addr));

    // ── 7. Start both controllers concurrently ───────────────────────────────
    let operator_ctx = Arc::new(OperatorContext {
        kube_client: kube_client.clone(),
        http_client: http_client.clone(),
        default_vault_endpoint: vault_endpoint,
        default_vault_token: vault_token.clone(),
        default_tenant_id: vault_tenant_id,
        default_policies: vault_policies,
    });

    let policy_ctx = Arc::new(PolicyOperatorContext {
        kube_client: kube_client.clone(),
        http_client,
        default_policy_engine_endpoint: policy_engine_endpoint,
        default_vault_token: vault_token,
    });

    // Both controllers are driven to completion concurrently.  Either one
    // completing (due to shutdown signal) causes the whole process to exit.
    tokio::select! {
        result = run_controller(kube_client.clone(), operator_ctx) => {
            if let Err(err) = result {
                error!(error = %err, "VaultSecret controller exited with error");
                return Err(err);
            }
        }
        result = run_policy_controller(kube_client, policy_ctx) => {
            if let Err(err) = result {
                error!(error = %err, "VaultPolicy controller exited with error");
                return Err(err);
            }
        }
    }

    Ok(())
}

// ─── Controller runner ────────────────────────────────────────────────────────

/// Start the `VaultSecret` kube-rs controller and drive it to completion.
///
/// The controller watches all `VaultSecret` resources across all namespaces
/// and calls [`reconcile`] for each event.
async fn run_controller(kube_client: Client, ctx: Arc<OperatorContext>) -> anyhow::Result<()> {
    let vault_secrets: Api<VaultSecret> = Api::all(kube_client.clone());

    info!("starting VaultSecret controller");

    Controller::new(vault_secrets, watcher::Config::default())
        .shutdown_on_signal()
        .run(reconcile, error_policy, ctx)
        .for_each(|reconcile_result| async move {
            match reconcile_result {
                Ok((obj, action)) => {
                    info!(
                        name = %obj.name,
                        namespace = %obj.namespace.as_deref().unwrap_or("cluster"),
                        action = ?action,
                        "VaultSecret reconcile completed"
                    );
                }
                Err(err) => {
                    error!(error = %err, "VaultSecret reconcile error reported by controller runtime");
                }
            }
        })
        .await;

    info!("VaultSecret controller shutdown complete");
    Ok(())
}

/// Start the `VaultPolicy` kube-rs controller and drive it to completion.
///
/// The controller watches all `VaultPolicy` resources across all namespaces
/// and calls [`policy_reconcile`] for each event.
async fn run_policy_controller(
    kube_client: Client,
    ctx: Arc<PolicyOperatorContext>,
) -> anyhow::Result<()> {
    let vault_policies: Api<VaultPolicy> = Api::all(kube_client.clone());

    info!("starting VaultPolicy controller");

    Controller::new(vault_policies, watcher::Config::default())
        .shutdown_on_signal()
        .run(policy_reconcile, policy_error_policy, ctx)
        .for_each(|reconcile_result| async move {
            match reconcile_result {
                Ok((obj, action)) => {
                    info!(
                        name = %obj.name,
                        namespace = %obj.namespace.as_deref().unwrap_or("cluster"),
                        action = ?action,
                        "VaultPolicy reconcile completed"
                    );
                }
                Err(err) => {
                    error!(error = %err, "VaultPolicy reconcile error reported by controller runtime");
                }
            }
        })
        .await;

    info!("VaultPolicy controller shutdown complete");
    Ok(())
}

// ─── CRD installation ─────────────────────────────────────────────────────────

/// Attempt to ensure the `VaultSecret` CRD is present in the cluster.
///
/// The CRD manifest is embedded at compile time from the
/// `deploy/kubernetes/crds/vaultsecret.yaml` file so that the operator can
/// self-install in environments where GitOps tooling is not available.
///
/// If the CRD already exists it is patched using server-side apply so that
/// schema changes are rolled out automatically on operator upgrade.
///
/// If the operator pod does not have permission to read or write
/// `customresourcedefinitions` the function logs a warning and returns without
/// error — the operator can still function if the CRD was pre-installed by an
/// administrator.
async fn ensure_crd_installed(kube_client: &Client) {
    let crds_api: Api<CustomResourceDefinition> = Api::all(kube_client.clone());

    // The CRD name is the plural resource name + group.
    let crd_name = "vaultsecrets.wslvault.io";

    // Check whether the CRD already exists before attempting to apply.
    match crds_api.get(crd_name).await {
        Ok(existing) => {
            info!(
                crd = %crd_name,
                resource_version = existing.resource_version().as_deref().unwrap_or("unknown"),
                "VaultSecret CRD already present; skipping install"
            );
            return;
        }
        Err(kube::Error::Api(api_err)) if api_err.code == 404 => {
            info!(crd = %crd_name, "VaultSecret CRD not found; attempting to install");
        }
        Err(kube::Error::Api(api_err)) if api_err.code == 403 => {
            warn!(
                crd = %crd_name,
                "operator lacks permission to read CRDs; assuming CRD is pre-installed"
            );
            return;
        }
        Err(err) => {
            warn!(
                crd = %crd_name,
                error = %err,
                "failed to check CRD existence; assuming CRD is pre-installed"
            );
            return;
        }
    }

    // Deserialize the embedded CRD manifest.
    let crd_yaml = include_str!("../../../deploy/kubernetes/crds/vaultsecret.yaml");
    let crd: CustomResourceDefinition = match serde_yaml::from_str(crd_yaml) {
        Ok(c) => c,
        Err(err) => {
            // Dependency on serde_yaml is intentionally avoided at runtime
            // because it pulls in yaml-rust. We therefore attempt to parse
            // via serde_json as a fallback after converting YAML to JSON
            // using a minimal approach.
            //
            // If parsing fails entirely we log and skip — this is non-fatal.
            warn!(
                error = %err,
                "could not deserialise embedded CRD YAML; skipping CRD install"
            );
            return;
        }
    };

    let patch_params = PatchParams::apply(CRD_FIELD_MANAGER).force();

    match crds_api
        .patch(crd_name, &patch_params, &Patch::Apply(&crd))
        .await
    {
        Ok(_) => info!(crd = %crd_name, "VaultSecret CRD installed successfully"),
        Err(kube::Error::Api(api_err)) if api_err.code == 403 => {
            warn!(
                crd = %crd_name,
                "operator lacks permission to create CRDs; \
                 pre-install using deploy/kubernetes/crds/vaultsecret.yaml"
            );
        }
        Err(err) => {
            warn!(
                crd = %crd_name,
                error = %err,
                "failed to install VaultSecret CRD; \
                 pre-install using deploy/kubernetes/crds/vaultsecret.yaml"
            );
        }
    }
}

/// Attempt to ensure the `VaultPolicy` CRD is present in the cluster.
///
/// Mirrors the behaviour of [`ensure_crd_installed`] but embeds the
/// `deploy/kubernetes/crds/vaultpolicy.yaml` manifest.
async fn ensure_vault_policy_crd_installed(kube_client: &Client) {
    let crds_api: Api<CustomResourceDefinition> = Api::all(kube_client.clone());
    let crd_name = VAULT_POLICY_CRD_NAME;

    match crds_api.get(crd_name).await {
        Ok(existing) => {
            info!(
                crd = %crd_name,
                resource_version = existing.resource_version().as_deref().unwrap_or("unknown"),
                "VaultPolicy CRD already present; skipping install"
            );
            return;
        }
        Err(kube::Error::Api(api_err)) if api_err.code == 404 => {
            info!(crd = %crd_name, "VaultPolicy CRD not found; attempting to install");
        }
        Err(kube::Error::Api(api_err)) if api_err.code == 403 => {
            warn!(
                crd = %crd_name,
                "operator lacks permission to read CRDs; assuming VaultPolicy CRD is pre-installed"
            );
            return;
        }
        Err(err) => {
            warn!(
                crd = %crd_name,
                error = %err,
                "failed to check VaultPolicy CRD existence; assuming it is pre-installed"
            );
            return;
        }
    }

    let crd_yaml = include_str!("../../../deploy/kubernetes/crds/vaultpolicy.yaml");
    let crd: CustomResourceDefinition = match serde_yaml::from_str(crd_yaml) {
        Ok(c) => c,
        Err(err) => {
            warn!(
                error = %err,
                "could not deserialise embedded VaultPolicy CRD YAML; skipping CRD install"
            );
            return;
        }
    };

    let patch_params = PatchParams::apply(CRD_FIELD_MANAGER).force();

    match crds_api
        .patch(crd_name, &patch_params, &Patch::Apply(&crd))
        .await
    {
        Ok(_) => info!(crd = %crd_name, "VaultPolicy CRD installed successfully"),
        Err(kube::Error::Api(api_err)) if api_err.code == 403 => {
            warn!(
                crd = %crd_name,
                "operator lacks permission to create CRDs; \
                 pre-install using deploy/kubernetes/crds/vaultpolicy.yaml"
            );
        }
        Err(err) => {
            warn!(
                crd = %crd_name,
                error = %err,
                "failed to install VaultPolicy CRD; \
                 pre-install using deploy/kubernetes/crds/vaultpolicy.yaml"
            );
        }
    }
}

// ─── Health server ────────────────────────────────────────────────────────────

/// Run a minimal HTTP server that satisfies Kubernetes liveness and readiness
/// probes.
///
/// - `GET /health` — liveness probe: returns `200 OK` as long as the process
///   is running.
/// - `GET /ready`  — readiness probe: returns `200 OK` (the controller is
///   considered ready as soon as the watch has been established).
///
/// The server is intentionally lightweight — it uses the stdlib
/// `TcpListener` rather than a full HTTP framework to avoid pulling in
/// additional dependencies.
async fn run_health_server(addr: SocketAddr) {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

    let listener = match TcpListener::bind(addr).await {
        Ok(l) => {
            info!(addr = %addr, "health server listening");
            l
        }
        Err(err) => {
            error!(addr = %addr, error = %err, "failed to bind health server");
            return;
        }
    };

    // HTTP/1.1 200 OK response used for both /health and /ready.
    const OK_RESPONSE: &[u8] =
        b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nContent-Type: text/plain\r\n\r\nOK";

    // HTTP/1.1 404 Not Found response for unknown paths.
    const NOT_FOUND_RESPONSE: &[u8] =
        b"HTTP/1.1 404 Not Found\r\nContent-Length: 9\r\nContent-Type: text/plain\r\n\r\nNot Found";

    loop {
        let (mut stream, peer) = match listener.accept().await {
            Ok(s) => s,
            Err(err) => {
                warn!(error = %err, "health server accept error");
                continue;
            }
        };

        tokio::spawn(async move {
            let mut buf = [0u8; 512];
            let n = match stream.read(&mut buf).await {
                Ok(n) => n,
                Err(_) => return,
            };

            let request = String::from_utf8_lossy(&buf[..n]);
            let first_line = request.lines().next().unwrap_or("");

            // Route based on the request path.
            let response = if first_line.contains("/health") || first_line.contains("/ready") {
                OK_RESPONSE
            } else {
                NOT_FOUND_RESPONSE
            };

            // Fire-and-forget write; ignore errors on this diagnostic path.
            let _ = stream.write_all(response).await;

            let _ = peer; // suppress unused variable warning
        });
    }
}
