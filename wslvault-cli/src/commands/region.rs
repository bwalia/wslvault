//! `wslvault region` subcommands — inspect and manage multi-region state.

use clap::{Args, Subcommand};

use super::CommandContext;

#[derive(Args)]
pub struct RegionArgs {
    #[command(subcommand)]
    pub command: RegionCommands,
}

#[derive(Subcommand)]
pub enum RegionCommands {
    /// List all regions and their health status
    List,
    /// Show detailed status of a specific region
    Status {
        /// Region identifier (e.g. "us-east-1")
        region: String,
    },
    /// Trigger a manual failover to the specified region
    Failover {
        /// Target region to promote
        target: String,
    },
}

pub async fn execute(args: RegionArgs, ctx: &CommandContext) -> anyhow::Result<()> {
    let client = reqwest::Client::new();
    let base = &ctx.endpoint;

    match args.command {
        RegionCommands::List => {
            let url = format!("{}/v1/sys/regions", base);
            let mut req = client.get(&url);
            if let Some(ref t) = ctx.token {
                req = req.bearer_auth(t);
            }
            let resp = req.send().await?;
            let body: serde_json::Value = resp.json().await?;
            println!("{}", serde_json::to_string_pretty(&body)?);
        }
        RegionCommands::Status { region } => {
            let url = format!("{}/v1/sys/regions/{}", base, region);
            let mut req = client.get(&url);
            if let Some(ref t) = ctx.token {
                req = req.bearer_auth(t);
            }
            let resp = req.send().await?;
            let body: serde_json::Value = resp.json().await?;
            println!("{}", serde_json::to_string_pretty(&body)?);
        }
        RegionCommands::Failover { target } => {
            let url = format!("{}/v1/sys/regions/{}/promote", base, target);
            let mut req = client.post(&url);
            if let Some(ref t) = ctx.token {
                req = req.bearer_auth(t);
            }
            let resp = req.send().await?;
            let status = resp.status();
            let body: serde_json::Value = resp.json().await?;
            if status.is_success() {
                println!("Failover to {} initiated successfully", target);
            } else {
                println!("Failover failed: {}", serde_json::to_string_pretty(&body)?);
            }
        }
    }

    Ok(())
}
