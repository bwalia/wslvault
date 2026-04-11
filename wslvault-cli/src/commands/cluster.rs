//! `wslvault cluster` subcommands — inspect HA cluster state.

use clap::{Args, Subcommand};

use super::CommandContext;

#[derive(Args)]
pub struct ClusterArgs {
    #[command(subcommand)]
    pub command: ClusterCommands,
}

#[derive(Subcommand)]
pub enum ClusterCommands {
    /// Show all cluster nodes, their leader status, and heartbeat age
    Status,
    /// List nodes for a specific service
    Nodes {
        /// Service name to filter (e.g. "lease-manager", "policy-engine")
        service: String,
    },
}

pub async fn execute(args: ClusterArgs, ctx: &CommandContext) -> anyhow::Result<()> {
    let client = reqwest::Client::new();
    let base = &ctx.endpoint;

    match args.command {
        ClusterCommands::Status => {
            let url = format!("{}/v1/sys/cluster/status", base);
            let mut req = client.get(&url);
            if let Some(ref t) = ctx.token {
                req = req.bearer_auth(t);
            }
            let resp = req.send().await?;
            let body: serde_json::Value = resp.json().await?;
            println!("{}", serde_json::to_string_pretty(&body)?);
        }
        ClusterCommands::Nodes { service } => {
            let url = format!("{}/v1/sys/cluster/nodes?service={}", base, service);
            let mut req = client.get(&url);
            if let Some(ref t) = ctx.token {
                req = req.bearer_auth(t);
            }
            let resp = req.send().await?;
            let body: serde_json::Value = resp.json().await?;
            println!("{}", serde_json::to_string_pretty(&body)?);
        }
    }

    Ok(())
}
