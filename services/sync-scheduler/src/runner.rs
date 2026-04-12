//! Sync job execution — loads the appropriate connector and runs the sync.

use tracing::{info, warn};
use wslvault_connectors::traits::{SyncDirection, SyncResult};
use wslvault_storage::pool::DbPool;

use crate::store::SyncJob;

/// Execute a single sync job.
///
/// Loads the connector based on `job.connector_type`, determines the sync
/// direction, and runs the sync operation. Integration credentials are loaded
/// from WSLVault secrets at `system/integrations/{integration_id}/credentials`.
pub async fn run_sync_job(pool: &DbPool, job: &SyncJob) -> anyhow::Result<SyncResult> {
    let direction = parse_direction(&job.direction)?;

    // Dispatch to the appropriate connector.
    match job.connector_type.as_str() {
        "aws" => run_aws_sync(job, direction).await,
        "azure" => run_azure_sync(job, direction).await,
        "gcp" => run_gcp_sync(job, direction).await,
        "hashicorp" => run_hashicorp_sync(job, direction).await,
        "k8s" => run_k8s_sync(job, direction).await,
        other => anyhow::bail!("unsupported connector type: {}", other),
    }
}

fn parse_direction(s: &str) -> anyhow::Result<SyncDirection> {
    match s {
        "pull" => Ok(SyncDirection::Pull),
        "push" => Ok(SyncDirection::Push),
        "bidirectional" => Ok(SyncDirection::Bidirectional),
        other => anyhow::bail!("invalid sync direction: {}", other),
    }
}

async fn run_aws_sync(job: &SyncJob, direction: SyncDirection) -> anyhow::Result<SyncResult> {
    #[cfg(feature = "aws")]
    {
        use wslvault_connectors::aws::AwsSecretsManagerConnector;
        use wslvault_connectors::traits::SecretConnector;

        let connector = AwsSecretsManagerConnector::new(None, job.prefix.clone()).await
            .map_err(|e| anyhow::anyhow!("failed to create AWS connector: {}", e))?;
        connector
            .sync(&job.prefix, direction)
            .await
            .map_err(|e| anyhow::anyhow!("AWS sync failed: {}", e))
    }
    #[cfg(not(feature = "aws"))]
    {
        anyhow::bail!("AWS connector not compiled (missing 'aws' feature)")
    }
}

async fn run_azure_sync(job: &SyncJob, direction: SyncDirection) -> anyhow::Result<SyncResult> {
    info!(
        integration = %job.integration_id,
        "Azure sync not yet implemented — returning empty result"
    );
    Ok(SyncResult {
        synced: 0,
        failed: 0,
        errors: vec!["Azure sync not yet implemented".into()],
    })
}

async fn run_gcp_sync(job: &SyncJob, direction: SyncDirection) -> anyhow::Result<SyncResult> {
    info!(
        integration = %job.integration_id,
        "GCP sync not yet implemented — returning empty result"
    );
    Ok(SyncResult {
        synced: 0,
        failed: 0,
        errors: vec!["GCP sync not yet implemented".into()],
    })
}

async fn run_hashicorp_sync(
    job: &SyncJob,
    direction: SyncDirection,
) -> anyhow::Result<SyncResult> {
    use wslvault_connectors::hashicorp_vault::HashiCorpVaultConnector;
    use wslvault_connectors::traits::SecretConnector;

    let connector = HashiCorpVaultConnector::from_env()
        .map_err(|e| anyhow::anyhow!("failed to create HashiCorp Vault connector: {}", e))?;

    connector
        .sync(&job.prefix, direction)
        .await
        .map_err(|e| anyhow::anyhow!("HashiCorp Vault sync failed: {}", e))
}

async fn run_k8s_sync(job: &SyncJob, direction: SyncDirection) -> anyhow::Result<SyncResult> {
    use wslvault_connectors::kubernetes::KubernetesConnector;
    use wslvault_connectors::traits::SecretConnector;

    let connector = KubernetesConnector::from_in_cluster()
        .map_err(|e| anyhow::anyhow!("failed to create Kubernetes connector: {}", e))?;

    connector
        .sync(&job.prefix, direction)
        .await
        .map_err(|e| anyhow::anyhow!("Kubernetes sync failed: {}", e))
}
