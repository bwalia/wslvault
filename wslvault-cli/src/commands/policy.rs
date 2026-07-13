//! Policy command handler — create, list, get, and delete policies via the policy-engine HTTP API.

use crate::commands::CommandContext;
use crate::output;
use clap::{Args, Subcommand};

#[derive(Args)]
pub struct PolicyArgs {
    #[command(subcommand)]
    pub command: PolicyCommands,
}

#[derive(Subcommand)]
pub enum PolicyCommands {
    /// Create a new policy
    Create {
        /// Policy name (e.g. admin)
        #[arg(long)]
        name: String,
        /// Secret path pattern the policy applies to (e.g. secret/*)
        #[arg(long)]
        path: String,
        /// Comma-separated list of capabilities (read,write,delete,list,create,update)
        #[arg(long, value_delimiter = ',', num_args = 1..)]
        capabilities: Vec<String>,
    },
    /// List all policies
    List,
    /// Get a policy by name
    Get {
        /// Policy name
        name: String,
    },
    /// Delete a policy by name
    Delete {
        /// Policy name
        name: String,
    },
}

pub async fn execute(args: PolicyArgs, ctx: &CommandContext) -> anyhow::Result<()> {
    let client = reqwest::Client::new();
    let base = &ctx.endpoint;

    match args.command {
        PolicyCommands::Create {
            name,
            path,
            capabilities,
        } => {
            if capabilities.is_empty() {
                anyhow::bail!(
                    "at least one capability must be specified (e.g. --capabilities read,write)"
                );
            }
            let body = serde_json::json!({
                "name": name,
                "path": path,
                "capabilities": capabilities,
            });
            let mut req = client.post(format!("{}/v1/policies", base)).json(&body);
            if let Some(ref t) = ctx.token {
                req = req.bearer_auth(t);
            }
            if let Some(ref tid) = ctx.tenant_id {
                req = req.header("X-Vault-Tenant-ID", tid);
            }
            let resp = req.send().await?;
            if !resp.status().is_success() {
                let status = resp.status();
                let body_text = resp.text().await.unwrap_or_default();
                anyhow::bail!("policy create failed ({}): {}", status, body_text);
            }
            let resp_body: serde_json::Value = resp.json().await?;
            output::success(&format!("policy '{}' created", name));
            output::print_value(&resp_body, &ctx.format)?;
        }
        PolicyCommands::List => {
            let mut req = client.get(format!("{}/v1/policies", base));
            if let Some(ref t) = ctx.token {
                req = req.bearer_auth(t);
            }
            if let Some(ref tid) = ctx.tenant_id {
                req = req.header("X-Vault-Tenant-ID", tid);
            }
            let resp = req.send().await?;
            if !resp.status().is_success() {
                let status = resp.status();
                let body_text = resp.text().await.unwrap_or_default();
                anyhow::bail!("policy list failed ({}): {}", status, body_text);
            }
            let resp_body: serde_json::Value = resp.json().await?;
            output::print_value(&resp_body, &ctx.format)?;
        }
        PolicyCommands::Get { name } => {
            let mut req = client.get(format!("{}/v1/policies/{}", base, name));
            if let Some(ref t) = ctx.token {
                req = req.bearer_auth(t);
            }
            if let Some(ref tid) = ctx.tenant_id {
                req = req.header("X-Vault-Tenant-ID", tid);
            }
            let resp = req.send().await?;
            if !resp.status().is_success() {
                let status = resp.status();
                let body_text = resp.text().await.unwrap_or_default();
                anyhow::bail!("policy get failed ({}): {}", status, body_text);
            }
            let resp_body: serde_json::Value = resp.json().await?;
            output::print_value(&resp_body, &ctx.format)?;
        }
        PolicyCommands::Delete { name } => {
            let mut req = client.delete(format!("{}/v1/policies/{}", base, name));
            if let Some(ref t) = ctx.token {
                req = req.bearer_auth(t);
            }
            if let Some(ref tid) = ctx.tenant_id {
                req = req.header("X-Vault-Tenant-ID", tid);
            }
            let resp = req.send().await?;
            if !resp.status().is_success() {
                let status = resp.status();
                let body_text = resp.text().await.unwrap_or_default();
                anyhow::bail!("policy delete failed ({}): {}", status, body_text);
            }
            output::success(&format!("policy '{}' deleted", name));
        }
    }
    Ok(())
}
