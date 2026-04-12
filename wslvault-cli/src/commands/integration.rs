//! `wslvault integration` subcommands — manage external secret manager integrations.

use clap::{Args, Subcommand};

use super::CommandContext;

#[derive(Args)]
pub struct IntegrationArgs {
    #[command(subcommand)]
    pub command: IntegrationCommands,
}

#[derive(Subcommand)]
pub enum IntegrationCommands {
    /// Register a new external integration
    Add {
        /// Unique name for this integration (e.g. "prod-aws")
        #[arg(long)]
        name: String,
        /// Connector type: aws, azure, gcp, hashicorp, k8s
        #[arg(long)]
        connector: String,
        /// Sync direction: pull, push, bidirectional
        #[arg(long, default_value = "bidirectional")]
        direction: String,
        /// Cron schedule (e.g. "0 */6 * * *"); omit for event-driven only
        #[arg(long)]
        schedule: Option<String>,
        /// Prefix filter for secrets to sync
        #[arg(long, default_value = "")]
        prefix: String,
    },
    /// List all integrations and their sync status
    List,
    /// Trigger an immediate sync for an integration
    Sync {
        /// Integration name
        name: String,
    },
    /// Show detailed sync history for an integration
    Status {
        /// Integration name
        name: String,
    },
    /// Remove an integration
    Remove {
        /// Integration name
        name: String,
    },
}

pub async fn execute(args: IntegrationArgs, ctx: &CommandContext) -> anyhow::Result<()> {
    let client = reqwest::Client::new();
    let base = &ctx.endpoint;

    match args.command {
        IntegrationCommands::Add {
            name,
            connector,
            direction,
            schedule,
            prefix,
        } => {
            let url = format!("{}/v1/sys/integrations", base);
            let body = serde_json::json!({
                "name": name,
                "connector_type": connector,
                "direction": direction,
                "schedule": schedule,
                "prefix": prefix,
            });
            let mut req = client.post(&url).json(&body);
            if let Some(ref t) = ctx.token {
                req = req.bearer_auth(t);
            }
            if let Some(ref tid) = ctx.tenant_id {
                req = req.header("X-Tenant-Id", tid);
            }
            let resp = req.send().await?;
            let result: serde_json::Value = resp.json().await?;
            println!("{}", serde_json::to_string_pretty(&result)?);
        }
        IntegrationCommands::List => {
            let url = format!("{}/v1/sys/integrations", base);
            let mut req = client.get(&url);
            if let Some(ref t) = ctx.token {
                req = req.bearer_auth(t);
            }
            let resp = req.send().await?;
            let body: serde_json::Value = resp.json().await?;
            println!("{}", serde_json::to_string_pretty(&body)?);
        }
        IntegrationCommands::Sync { name } => {
            let url = format!("{}/v1/sys/integrations/{}/sync", base, name);
            let mut req = client.post(&url);
            if let Some(ref t) = ctx.token {
                req = req.bearer_auth(t);
            }
            let resp = req.send().await?;
            let status = resp.status();
            let body: serde_json::Value = resp.json().await?;
            if status.is_success() {
                println!("Sync triggered for integration '{}'", name);
                println!("{}", serde_json::to_string_pretty(&body)?);
            } else {
                println!("Sync failed: {}", serde_json::to_string_pretty(&body)?);
            }
        }
        IntegrationCommands::Status { name } => {
            let url = format!("{}/v1/sys/integrations/{}/status", base, name);
            let mut req = client.get(&url);
            if let Some(ref t) = ctx.token {
                req = req.bearer_auth(t);
            }
            let resp = req.send().await?;
            let body: serde_json::Value = resp.json().await?;
            println!("{}", serde_json::to_string_pretty(&body)?);
        }
        IntegrationCommands::Remove { name } => {
            let url = format!("{}/v1/sys/integrations/{}", base, name);
            let mut req = client.delete(&url);
            if let Some(ref t) = ctx.token {
                req = req.bearer_auth(t);
            }
            let resp = req.send().await?;
            if resp.status().is_success() {
                println!("Integration '{}' removed", name);
            } else {
                let body: serde_json::Value = resp.json().await?;
                println!("Remove failed: {}", serde_json::to_string_pretty(&body)?);
            }
        }
    }

    Ok(())
}
