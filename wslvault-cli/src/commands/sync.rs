//! `wslvault sync` subcommands — monitor replication and sync job status.

use clap::{Args, Subcommand};

use super::CommandContext;

#[derive(Args)]
pub struct SyncArgs {
    #[command(subcommand)]
    pub command: SyncCommands,
}

#[derive(Subcommand)]
pub enum SyncCommands {
    /// Show status of cross-region replication and sync jobs
    Status,
    /// Show detailed logs for a specific sync job
    Logs {
        /// Sync job ID
        job_id: String,
    },
}

pub async fn execute(args: SyncArgs, ctx: &CommandContext) -> anyhow::Result<()> {
    let client = reqwest::Client::new();
    let base = &ctx.endpoint;

    match args.command {
        SyncCommands::Status => {
            let url = format!("{}/v1/sys/sync/status", base);
            let mut req = client.get(&url);
            if let Some(ref t) = ctx.token {
                req = req.bearer_auth(t);
            }
            let resp = req.send().await?;
            let body: serde_json::Value = resp.json().await?;
            println!("{}", serde_json::to_string_pretty(&body)?);
        }
        SyncCommands::Logs { job_id } => {
            let url = format!("{}/v1/sys/sync/jobs/{}/logs", base, job_id);
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
