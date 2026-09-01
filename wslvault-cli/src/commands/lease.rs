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
    /// List leases for the authenticated tenant
    List {
        /// Optional state filter: active | expired | revoked
        #[arg(long)]
        state: Option<String>,
    },
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
        LeaseCommands::List { state } => {
            let mut url = format!("{}/v1/leases", base);
            if let Some(s) = state {
                url.push_str(&format!("?state={}", s));
            }
            let mut req = client.get(url);
            if let Some(ref t) = ctx.token {
                req = req.bearer_auth(t);
            }
            let resp = req.send().await?;
            let status = resp.status();
            let body = resp.text().await?;
            if !status.is_success() {
                anyhow::bail!("list leases failed: {} {}", status, body);
            }
            let value: serde_json::Value = serde_json::from_str(&body)?;
            output::print_value(&value, &ctx.format)?;
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
            let resp = req.send().await?;
            let status = resp.status();
            let body = resp.text().await?;
            if !status.is_success() {
                anyhow::bail!("renew failed: {} {}", status, body);
            }
            output::success(&format!("lease '{}' renewed", lease_id));
            if !body.is_empty() {
                let value: serde_json::Value = serde_json::from_str(&body)?;
                output::print_value(&value, &ctx.format)?;
            }
        }
        LeaseCommands::Revoke { lease_id } => {
            let mut req = client.post(format!("{}/v1/leases/{}/revoke", base, lease_id));
            if let Some(ref t) = ctx.token {
                req = req.bearer_auth(t);
            }
            let resp = req.send().await?;
            let status = resp.status();
            let body = resp.text().await.unwrap_or_default();
            if status.as_u16() == 204 || status.is_success() {
                output::success(&format!("lease '{}' revoked", lease_id));
                if !body.is_empty() {
                    if let Ok(value) = serde_json::from_str::<serde_json::Value>(&body) {
                        output::print_value(&value, &ctx.format)?;
                    }
                }
            } else {
                anyhow::bail!("revoke failed: {} {}", status, body);
            }
        }
    }
    Ok(())
}
