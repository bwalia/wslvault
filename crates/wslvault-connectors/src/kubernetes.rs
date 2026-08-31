//! Kubernetes Secrets API connector.
//!
//! Implements the [`SecretConnector`] trait against the Kubernetes API to
//! enable bidirectional sync between WSLVault secrets and native Kubernetes
//! `Secret` objects.
//!
//! Enabled by the `k8s` Cargo feature.

use std::collections::HashMap;

use async_trait::async_trait;
use base64::Engine;
use tracing::debug;

use crate::error::ConnectorError;
use crate::traits::{SecretConnector, SecretData, SyncDirection, SyncResult};

/// Kubernetes Secrets API connector.
pub struct KubernetesConnector {
    client: reqwest::Client,
    api_server: String,
    namespace: String,
    token: String,
    label_selector: Option<String>,
}

impl KubernetesConnector {
    /// Create a new connector.
    ///
    /// * `api_server` — Kubernetes API server URL (e.g. `https://kubernetes.default.svc`)
    /// * `namespace` — target namespace for Secret objects
    /// * `token` — bearer token (service account JWT)
    /// * `label_selector` — optional label selector to filter Secrets
    pub fn new(
        api_server: String,
        namespace: String,
        token: String,
        label_selector: Option<String>,
    ) -> Result<Self, ConnectorError> {
        Self::with_ca(api_server, namespace, token, label_selector, None)
    }

    /// Create a connector that trusts `ca_pem` in addition to the system roots.
    ///
    /// Certificate verification used to be switched off outright, with
    /// `danger_accept_invalid_certs(true)` and a comment saying the in-cluster
    /// CA was "handled separately". It was not handled separately — nothing anywhere loaded the cluster CA —
    /// so every secret this connector synchronised was exposed to a trivial
    /// man-in-the-middle, which is a poor trade for a connector whose entire
    /// job is moving secrets.
    ///
    /// In-cluster callers get the CA from the service account mount via
    /// [`from_in_cluster`]. Out-of-cluster callers may supply one with
    /// `K8S_CA_CERT_PATH`.
    pub fn with_ca(
        api_server: String,
        namespace: String,
        token: String,
        label_selector: Option<String>,
        ca_pem: Option<Vec<u8>>,
    ) -> Result<Self, ConnectorError> {
        let mut builder = reqwest::Client::builder().timeout(std::time::Duration::from_secs(10));

        if let Some(pem) = ca_pem {
            let cert = reqwest::Certificate::from_pem(&pem).map_err(|e| {
                ConnectorError::Configuration {
                    reason: format!("Kubernetes CA certificate is not valid PEM: {e}"),
                }
            })?;
            builder = builder.add_root_certificate(cert);
        }

        let client = builder.build().map_err(|e| ConnectorError::Configuration {
            reason: format!("failed to build HTTP client: {e}"),
        })?;

        Ok(Self {
            client,
            api_server,
            namespace,
            token,
            label_selector,
        })
    }

    /// Create from in-cluster service account environment.
    ///
    /// Reads the standard Kubernetes env vars and mounted service account token.
    pub fn from_in_cluster() -> Result<Self, ConnectorError> {
        let api_server = std::env::var("KUBERNETES_SERVICE_HOST")
            .map(|host| {
                let port =
                    std::env::var("KUBERNETES_SERVICE_PORT").unwrap_or_else(|_| "443".into());
                format!("https://{}:{}", host, port)
            })
            .map_err(|_| ConnectorError::Configuration {
                reason: "KUBERNETES_SERVICE_HOST not set; not running in-cluster?".into(),
            })?;

        let token = std::fs::read_to_string("/var/run/secrets/kubernetes.io/serviceaccount/token")
            .map_err(|e| ConnectorError::Configuration {
                reason: format!("failed to read SA token: {}", e),
            })?;

        let namespace =
            std::fs::read_to_string("/var/run/secrets/kubernetes.io/serviceaccount/namespace")
                .unwrap_or_else(|_| "default".to_string());

        let label_selector = std::env::var("K8S_LABEL_SELECTOR").ok();

        // The API server's CA is mounted into every pod alongside the token.
        // This is the "handled separately" the old comment promised and never
        // delivered.
        const IN_CLUSTER_CA: &str = "/var/run/secrets/kubernetes.io/serviceaccount/ca.crt";
        let ca_path =
            std::env::var("K8S_CA_CERT_PATH").unwrap_or_else(|_| IN_CLUSTER_CA.to_string());
        let ca_pem = std::fs::read(&ca_path).map_err(|e| ConnectorError::Configuration {
            reason: format!(
                "could not read the Kubernetes CA at {ca_path}: {e}. \
                 Set K8S_CA_CERT_PATH when running out-of-cluster; \
                 refusing to fall back to unverified TLS"
            ),
        })?;

        Self::with_ca(
            api_server,
            namespace,
            token.trim().to_string(),
            label_selector,
            Some(ca_pem),
        )
    }

    fn secrets_url(&self) -> String {
        format!(
            "{}/api/v1/namespaces/{}/secrets",
            self.api_server, self.namespace
        )
    }

    fn secret_url(&self, name: &str) -> String {
        format!(
            "{}/api/v1/namespaces/{}/secrets/{}",
            self.api_server, self.namespace, name
        )
    }
}

#[async_trait]
impl SecretConnector for KubernetesConnector {
    async fn pull(&self, external_path: &str) -> Result<SecretData, ConnectorError> {
        let url = self.secret_url(external_path);

        let resp = self
            .client
            .get(&url)
            .bearer_auth(&self.token)
            .send()
            .await
            .map_err(|e| ConnectorError::Network {
                endpoint: url.clone(),
                source: e,
            })?;

        if resp.status() == reqwest::StatusCode::NOT_FOUND {
            return Err(ConnectorError::SecretNotFound {
                connector: "kubernetes".into(),
                path: external_path.to_string(),
            });
        }

        if !resp.status().is_success() {
            return Err(ConnectorError::HttpStatus {
                endpoint: url,
                status: resp.status().as_u16(),
                body: resp.text().await.unwrap_or_default(),
            });
        }

        let k8s_secret: K8sSecret = resp.json().await.map_err(|_| ConnectorError::Deserialise {
            connector: "kubernetes".into(),
            reason: "failed to parse K8s Secret".into(),
        })?;

        // Base64-decode each data field.
        let mut data_map = serde_json::Map::new();
        if let Some(data) = k8s_secret.data {
            for (key, b64_val) in data {
                let decoded = base64::engine::general_purpose::STANDARD
                    .decode(&b64_val)
                    .unwrap_or_default();
                let val_str = String::from_utf8_lossy(&decoded).to_string();
                data_map.insert(key, serde_json::Value::String(val_str));
            }
        }

        let mut metadata = HashMap::new();
        if let Some(annotations) = k8s_secret.metadata.annotations {
            metadata = annotations;
        }
        let version = k8s_secret.metadata.resource_version;

        Ok(SecretData {
            key: external_path.to_string(),
            value: serde_json::Value::Object(data_map),
            version,
            metadata,
        })
    }

    async fn push(&self, external_path: &str, data: &SecretData) -> Result<(), ConnectorError> {
        use base64::Engine;

        // Base64-encode each field value for Kubernetes.
        let mut encoded_data = HashMap::new();
        if let serde_json::Value::Object(ref map) = data.value {
            for (key, val) in map {
                let val_str = match val {
                    serde_json::Value::String(s) => s.clone(),
                    other => other.to_string(),
                };
                encoded_data.insert(
                    key.clone(),
                    base64::engine::general_purpose::STANDARD.encode(val_str.as_bytes()),
                );
            }
        }

        let k8s_body = serde_json::json!({
            "apiVersion": "v1",
            "kind": "Secret",
            "metadata": {
                "name": external_path,
                "namespace": self.namespace,
                "annotations": {
                    "vault.io/path": data.key,
                    "vault.io/managed-by": "wslvault",
                },
            },
            "type": "Opaque",
            "data": encoded_data,
        });

        // Try PUT (update); if 404, fallback to POST (create).
        let url = self.secret_url(external_path);
        let resp = self
            .client
            .put(&url)
            .bearer_auth(&self.token)
            .json(&k8s_body)
            .send()
            .await
            .map_err(|e| ConnectorError::Network {
                endpoint: url.clone(),
                source: e,
            })?;

        if resp.status() == reqwest::StatusCode::NOT_FOUND {
            // Create the secret.
            let create_url = self.secrets_url();
            let create_resp = self
                .client
                .post(&create_url)
                .bearer_auth(&self.token)
                .json(&k8s_body)
                .send()
                .await
                .map_err(|e| ConnectorError::Network {
                    endpoint: create_url.clone(),
                    source: e,
                })?;

            if !create_resp.status().is_success() {
                return Err(ConnectorError::HttpStatus {
                    endpoint: create_url,
                    status: create_resp.status().as_u16(),
                    body: create_resp.text().await.unwrap_or_default(),
                });
            }
        } else if !resp.status().is_success() {
            return Err(ConnectorError::HttpStatus {
                endpoint: url,
                status: resp.status().as_u16(),
                body: resp.text().await.unwrap_or_default(),
            });
        }

        debug!(name = external_path, "pushed secret to Kubernetes");
        Ok(())
    }

    async fn list(&self, prefix: &str) -> Result<Vec<String>, ConnectorError> {
        let mut url = self.secrets_url();
        let mut params = Vec::new();
        if let Some(ref selector) = self.label_selector {
            params.push(format!("labelSelector={}", selector));
        }
        if !params.is_empty() {
            url = format!("{}?{}", url, params.join("&"));
        }

        let resp = self
            .client
            .get(&url)
            .bearer_auth(&self.token)
            .send()
            .await
            .map_err(|e| ConnectorError::Network {
                endpoint: url.clone(),
                source: e,
            })?;

        if !resp.status().is_success() {
            return Err(ConnectorError::HttpStatus {
                endpoint: url,
                status: resp.status().as_u16(),
                body: resp.text().await.unwrap_or_default(),
            });
        }

        let list: K8sSecretList = resp.json().await.map_err(|_| ConnectorError::Deserialise {
            connector: "kubernetes".into(),
            reason: "failed to parse K8s SecretList".into(),
        })?;

        let names: Vec<String> = list
            .items
            .into_iter()
            .map(|s| s.metadata.name)
            .filter(|name| prefix.is_empty() || name.starts_with(prefix))
            .collect();

        Ok(names)
    }

    async fn sync(
        &self,
        prefix: &str,
        direction: SyncDirection,
    ) -> Result<SyncResult, ConnectorError> {
        let mut synced = 0;
        let mut failed = 0;
        let mut errors = Vec::new();

        let names = self.list(prefix).await?;

        for name in names {
            match direction {
                SyncDirection::Pull | SyncDirection::Bidirectional => {
                    match self.pull(&name).await {
                        Ok(_) => synced += 1,
                        Err(e) => {
                            errors.push(format!("pull {}: {}", name, e));
                            failed += 1;
                        }
                    }
                }
                SyncDirection::Push => {
                    synced += 1;
                }
            }
        }

        Ok(SyncResult {
            synced,
            failed,
            errors,
        })
    }

    async fn health_check(&self) -> Result<(), ConnectorError> {
        let url = format!("{}/healthz", self.api_server);
        let resp = self
            .client
            .get(&url)
            .bearer_auth(&self.token)
            .send()
            .await
            .map_err(|e| ConnectorError::Network {
                endpoint: url.clone(),
                source: e,
            })?;

        if resp.status().is_success() {
            Ok(())
        } else {
            Err(ConnectorError::HttpStatus {
                endpoint: url,
                status: resp.status().as_u16(),
                body: resp.text().await.unwrap_or_default(),
            })
        }
    }
}

// --- Internal K8s types ---

#[derive(serde::Deserialize)]
struct K8sSecret {
    metadata: K8sObjectMeta,
    data: Option<HashMap<String, String>>,
}

#[derive(serde::Deserialize)]
struct K8sObjectMeta {
    name: String,
    #[serde(default)]
    annotations: Option<HashMap<String, String>>,
    #[serde(rename = "resourceVersion")]
    resource_version: Option<String>,
}

#[derive(serde::Deserialize)]
struct K8sSecretList {
    items: Vec<K8sSecret>,
}
