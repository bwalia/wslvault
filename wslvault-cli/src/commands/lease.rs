//! Lease command handler — list, renew, and revoke leases via the REST API.

use crate::commands::CommandContext;
use crate::output;
use clap::{Args, Subcommand};

#[derive(Args)]
pub struct LeaseArgs {
    #[command(subcommand)]
    pub command: LeaseCommands,
}

#[derive(Subcommand)]
pub enum LeaseCommands {
    /// List active leases
    List,
    /// Renew a lease
    Renew {
        /// Lease ID
        lease_id: String,
        /// TTL increment in seconds
        #[arg(short, long, default_value = "3600")]
        increment: u64,
    },
    /// Revoke a lease
    Revoke {
        /// Lease ID
        lease_id: String,
    },
}

pub async fn execute(args: LeaseArgs, ctx: &CommandContext) -> anyhow::Result<()> {
    let client = reqwest::Client::new();
    let base = &ctx.endpoint;

    match args.command {
        LeaseCommands::List => {
            let mut req = client.get(format!("{}/v1/leases/", base));
            if let Some(ref t) = ctx.token {
                req = req.bearer_auth(t);
            }
            if let Some(ref tid) = ctx.tenant_id {
                req = req.header("X-Vault-Tenant-ID", tid);
            }
            let resp: serde_json::Value = req.send().await?.json().await?;
            output::print_value(&resp, &ctx.format)?;
        }
        LeaseCommands::Renew {
            lease_id,
            increment,
        } => {
            let mut req = client
                .post(format!("{}/v1/leases/{}/renew", base, lease_id))
                .json(&serde_json::json!({ "increment_seconds": increment }));
            if let Some(ref t) = ctx.token {
                req = req.bearer_auth(t);
            }
            if let Some(ref tid) = ctx.tenant_id {
                req = req.header("X-Vault-Tenant-ID", tid);
            }
            let resp: serde_json::Value = req.send().await?.json().await?;
            output::success(&format!("lease '{}' renewed", lease_id));
            output::print_value(&resp, &ctx.format)?;
        }
        LeaseCommands::Revoke { lease_id } => {
            let mut req = client.post(format!("{}/v1/leases/{}/revoke", base, lease_id));
            if let Some(ref t) = ctx.token {
                req = req.bearer_auth(t);
            }
            if let Some(ref tid) = ctx.tenant_id {
                req = req.header("X-Vault-Tenant-ID", tid);
            }
            let resp: serde_json::Value = req.send().await?.json().await?;
            output::success(&format!("lease '{}' revoked", lease_id));
            output::print_value(&resp, &ctx.format)?;
        }
    }
    Ok(())
}
