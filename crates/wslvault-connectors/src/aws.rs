//! AWS Secrets Manager connector.
//!
//! Enabled by the `aws` Cargo feature.  Uses the official `aws-sdk-secretsmanager`
//! crate and authenticates through the standard AWS credential provider chain
//! (environment variables, instance profile, ECS task role, etc.).
//!
//! # Example
//!
//! ```rust,no_run
//! # #[cfg(feature = "aws")]
//! # async fn example() -> Result<(), Box<dyn std::error::Error>> {
//! use wslvault_connectors::aws::AwsSecretsManagerConnector;
//! use wslvault_connectors::traits::{SecretConnector, SyncDirection};
//!
//! let connector = AwsSecretsManagerConnector::new(
//!     Some("us-east-1".to_string()),
//!     "prod/myapp/".to_string(),
//! ).await?;
//!
//! let result = connector.sync("prod/myapp/", SyncDirection::Pull).await?;
//! println!("synced={} failed={}", result.synced, result.failed);
//! # Ok(())
//! # }
//! ```

#[cfg(feature = "aws")]
mod inner {
    use std::collections::HashMap;

    use async_trait::async_trait;
    use aws_sdk_secretsmanager::types::Filter;
    use aws_sdk_secretsmanager::types::FilterNameStringType;
    use tracing::{debug, info, instrument, warn};

    use crate::error::ConnectorError;
    use crate::traits::{SecretConnector, SecretData, SyncDirection, SyncResult};

    const CONNECTOR_NAME: &str = "aws-secrets-manager";

    /// Connector that reads from and writes to AWS Secrets Manager.
    ///
    /// Thread-safe: the inner `aws_sdk_secretsmanager::Client` is cheaply
    /// cloneable and holds an `Arc` internally.
    pub struct AwsSecretsManagerConnector {
        /// The pre-configured Secrets Manager client.
        client: aws_sdk_secretsmanager::Client,
        /// Default path prefix used when listing secrets without an explicit prefix.
        prefix: String,
    }

    impl AwsSecretsManagerConnector {
        /// Build a new connector using the AWS default credential provider chain.
        ///
        /// `region` overrides the region resolved from the environment.  Pass
        /// `None` to rely entirely on the SDK's region resolution order.
        ///
        /// `prefix` is stored as the default listing prefix but is not
        /// enforced on `pull`/`push` calls — callers may address any path.
        pub async fn new(region: Option<String>, prefix: String) -> Result<Self, ConnectorError> {
            let sdk_config = build_sdk_config(region).await?;
            let client = aws_sdk_secretsmanager::Client::new(&sdk_config);
            Ok(Self { client, prefix })
        }

        /// Construct from an already-initialised SDK client (useful in tests).
        pub fn from_client(client: aws_sdk_secretsmanager::Client, prefix: String) -> Self {
            Self { client, prefix }
        }

        /// Return the default path prefix configured for this connector.
        ///
        /// This prefix is used as the default argument to [`SecretConnector::list`]
        /// and [`SecretConnector::sync`] when callers do not supply an explicit prefix.
        pub fn prefix(&self) -> &str {
            &self.prefix
        }

        /// Retrieve the raw string/binary value for a secret ARN or name.
        async fn get_secret_value(
            &self,
            path: &str,
        ) -> Result<(String, Option<String>), ConnectorError> {
            let resp = self
                .client
                .get_secret_value()
                .secret_id(path)
                .send()
                .await
                .map_err(|sdk_err| {
                    let msg = sdk_err.to_string();
                    // Detect not-found vs. permission vs. network errors.
                    if msg.contains("ResourceNotFoundException") {
                        ConnectorError::SecretNotFound {
                            connector: CONNECTOR_NAME.to_string(),
                            path: path.to_string(),
                        }
                    } else if msg.contains("AccessDeniedException") {
                        ConnectorError::PermissionDenied {
                            connector: CONNECTOR_NAME.to_string(),
                            resource: path.to_string(),
                            reason: msg,
                        }
                    } else {
                        ConnectorError::Internal {
                            reason: format!("AWS SDK error for path '{path}': {sdk_err}"),
                        }
                    }
                })?;

            let version_id = resp.version_id().map(str::to_string);
            let raw_value = resp
                .secret_string()
                .map(str::to_string)
                .or_else(|| {
                    // Binary secrets: base64-decode the blob and treat as UTF-8.
                    resp.secret_binary().map(|blob| {
                        use base64::Engine;
                        base64::engine::general_purpose::STANDARD.encode(blob.as_ref())
                    })
                })
                .ok_or_else(|| ConnectorError::Internal {
                    reason: format!(
                        "AWS response for '{path}' contained neither SecretString nor SecretBinary"
                    ),
                })?;

            Ok((raw_value, version_id))
        }
    }

    #[async_trait]
    impl SecretConnector for AwsSecretsManagerConnector {
        #[instrument(skip(self), fields(connector = CONNECTOR_NAME, path = external_path))]
        async fn pull(&self, external_path: &str) -> Result<SecretData, ConnectorError> {
            debug!("pulling secret from AWS Secrets Manager");

            let (raw_value, version_id) = self.get_secret_value(external_path).await?;

            // Attempt to parse as JSON; fall back to a plain string value.
            let value = serde_json::from_str::<serde_json::Value>(&raw_value)
                .unwrap_or_else(|_| serde_json::Value::String(raw_value));

            debug!(version = ?version_id, "successfully pulled secret");
            Ok(SecretData {
                key: external_path.to_string(),
                value,
                version: version_id,
                metadata: HashMap::new(),
            })
        }

        #[instrument(skip(self, data), fields(connector = CONNECTOR_NAME, path = external_path))]
        async fn push(&self, external_path: &str, data: &SecretData) -> Result<(), ConnectorError> {
            debug!("pushing secret to AWS Secrets Manager");

            let secret_string =
                serde_json::to_string(&data.value).map_err(|e| ConnectorError::Serialise {
                    connector: CONNECTOR_NAME.to_string(),
                    reason: e.to_string(),
                })?;

            // Try PutSecretValue first; if the secret does not exist, fall
            // through to CreateSecret.
            let put_result = self
                .client
                .put_secret_value()
                .secret_id(external_path)
                .secret_string(&secret_string)
                .send()
                .await;

            match put_result {
                Ok(_) => {
                    debug!("secret updated via PutSecretValue");
                    return Ok(());
                }
                Err(ref sdk_err) if sdk_err.to_string().contains("ResourceNotFoundException") => {
                    // Secret does not exist yet — create it below.
                    debug!("secret does not exist; creating via CreateSecret");
                }
                Err(sdk_err) => {
                    return Err(ConnectorError::Internal {
                        reason: format!("PutSecretValue failed for '{external_path}': {sdk_err}"),
                    });
                }
            }

            // Create the secret and set its initial value in one call.
            self.client
                .create_secret()
                .name(external_path)
                .secret_string(&secret_string)
                .send()
                .await
                .map_err(|sdk_err| ConnectorError::Internal {
                    reason: format!("CreateSecret failed for '{external_path}': {sdk_err}"),
                })?;

            info!("secret created in AWS Secrets Manager");
            Ok(())
        }

        #[instrument(skip(self), fields(connector = CONNECTOR_NAME, prefix = prefix))]
        async fn list(&self, prefix: &str) -> Result<Vec<String>, ConnectorError> {
            debug!("listing secrets in AWS Secrets Manager");

            let mut names: Vec<String> = Vec::new();
            let mut next_token: Option<String> = None;

            loop {
                let mut req = self
                    .client
                    .list_secrets()
                    .filters(
                        Filter::builder()
                            .key(FilterNameStringType::Name)
                            .values(prefix)
                            .build(),
                    )
                    .max_results(100);

                if let Some(ref token) = next_token {
                    req = req.next_token(token);
                }

                let resp = req
                    .send()
                    .await
                    .map_err(|sdk_err| ConnectorError::Internal {
                        reason: format!("ListSecrets failed: {sdk_err}"),
                    })?;

                for entry in resp.secret_list() {
                    if let Some(name) = entry.name() {
                        names.push(name.to_string());
                    }
                }

                match resp.next_token() {
                    Some(token) => next_token = Some(token.to_string()),
                    None => break,
                }
            }

            debug!(count = names.len(), "listed secrets");
            Ok(names)
        }

        #[instrument(skip(self), fields(connector = CONNECTOR_NAME, prefix = prefix, direction = ?direction))]
        async fn sync(
            &self,
            prefix: &str,
            direction: SyncDirection,
        ) -> Result<SyncResult, ConnectorError> {
            info!("starting sync");

            let paths = self.list(prefix).await?;
            let total = paths.len();
            let mut result = SyncResult::default();

            for path in paths {
                match direction {
                    SyncDirection::Pull | SyncDirection::Bidirectional => {
                        match self.pull(&path).await {
                            Ok(_data) => {
                                // In a full integration the caller would persist _data into
                                // WSLVault's KV store; the connector itself is stateless.
                                result.synced += 1;
                            }
                            Err(e) => {
                                warn!(path = %path, error = %e, "failed to pull secret");
                                result.failed += 1;
                                result.errors.push(format!("pull '{path}': {e}"));
                            }
                        }
                    }
                    SyncDirection::Push => {
                        // Push direction is driven by the caller supplying secrets;
                        // listing is used only to confirm the remote state.
                        result.synced += 1;
                    }
                }
            }

            if result.failed > 0 {
                warn!(
                    total = total,
                    synced = result.synced,
                    failed = result.failed,
                    "sync completed with partial failures"
                );
            } else {
                info!(total = total, "sync completed successfully");
            }

            Ok(result)
        }

        #[instrument(skip(self), fields(connector = CONNECTOR_NAME))]
        async fn health_check(&self) -> Result<(), ConnectorError> {
            debug!("performing health check");

            self.client
                .list_secrets()
                .max_results(1)
                .send()
                .await
                .map_err(|sdk_err| {
                    let msg = sdk_err.to_string();
                    if msg.contains("AccessDeniedException") {
                        ConnectorError::Authentication {
                            connector: CONNECTOR_NAME.to_string(),
                            reason: msg,
                        }
                    } else {
                        ConnectorError::Internal {
                            reason: format!("health check failed: {sdk_err}"),
                        }
                    }
                })?;

            debug!("health check passed");
            Ok(())
        }
    }

    // -------------------------------------------------------------------------
    // Private helpers
    // -------------------------------------------------------------------------

    /// Build an `aws_config::SdkConfig` using the default provider chain.
    ///
    /// Optionally overrides the region with `region`.
    async fn build_sdk_config(
        region: Option<String>,
    ) -> Result<aws_config::SdkConfig, ConnectorError> {
        // Use `defaults` with `BehaviorVersion::latest` instead of the deprecated
        // `from_env` to opt in to the current recommended SDK behaviour.
        let loader = aws_config::defaults(aws_config::BehaviorVersion::latest());

        let config = match region {
            Some(ref r) => {
                loader
                    .region(aws_config::meta::region::RegionProviderChain::first_try(
                        aws_sdk_secretsmanager::config::Region::new(r.clone()),
                    ))
                    .load()
                    .await
            }
            None => loader.load().await,
        };

        Ok(config)
    }
}

#[cfg(feature = "aws")]
pub use inner::AwsSecretsManagerConnector;
