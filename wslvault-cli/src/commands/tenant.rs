//! Tenant command handler — create, list, get, and delete tenants via the identity-service REST API.

use crate::commands::CommandContext;
use crate::output;
use clap::{Args, Subcommand};

#[derive(Args)]
pub struct TenantArgs {
    #[command(subcommand)]
    pub command: TenantCommands,
}

#[derive(Subcommand)]
pub enum TenantCommands {
    /// Create a new tenant
    Create {
        /// URL-safe slug identifier for the tenant (e.g. myapp)
        #[arg(long)]
        slug: String,
        /// Human-readable display name
        #[arg(long)]
        display_name: String,
        /// Tier for the tenant (shared, dedicated)
        #[arg(long, default_value = "shared")]
        tier: String,
    },
    /// List all tenants
    List,
    /// Get a single tenant by ID
    Get {
        /// Tenant ID (UUID)
        id: String,
    },
    /// Delete a tenant by ID
    Delete {
        /// Tenant ID (UUID)
        id: String,
    },
}

pub async fn execute(args: TenantArgs, ctx: &CommandContext) -> anyhow::Result<()> {
    let client = reqwest::Client::new();
    let base = &ctx.endpoint;

    match args.command {
        TenantCommands::Create {
            slug,
            display_name,
            tier,
        } => {
            let body = serde_json::json!({
                "slug": slug,
                "display_name": display_name,
                "tier": tier,
            });
            let mut req = client.post(format!("{}/v1/tenants", base)).json(&body);
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
                anyhow::bail!("tenant create failed ({}): {}", status, body_text);
            }
            let resp_body: serde_json::Value = resp.json().await?;
            output::success(&format!("tenant '{}' created", slug));
            output::print_value(&resp_body, &ctx.format)?;
        }
        TenantCommands::List => {
            let mut req = client.get(format!("{}/v1/tenants", base));
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
                anyhow::bail!("tenant list failed ({}): {}", status, body_text);
            }
            let resp_body: serde_json::Value = resp.json().await?;
            output::print_value(&resp_body, &ctx.format)?;
        }
        TenantCommands::Get { id } => {
            let mut req = client.get(format!("{}/v1/tenants/{}", base, id));
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
                anyhow::bail!("tenant get failed ({}): {}", status, body_text);
            }
            let resp_body: serde_json::Value = resp.json().await?;
            output::print_value(&resp_body, &ctx.format)?;
        }
        TenantCommands::Delete { id } => {
            let mut req = client.delete(format!("{}/v1/tenants/{}", base, id));
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
                anyhow::bail!("tenant delete failed ({}): {}", status, body_text);
            }
            output::success(&format!("tenant '{}' deleted", id));
        }
    }
    Ok(())
}
