//! API key command handler — create, list, revoke, and rotate API keys via the identity-service REST API.

use crate::commands::CommandContext;
use crate::output;
use clap::{Args, Subcommand};

#[derive(Args)]
pub struct ApiKeyArgs {
    #[command(subcommand)]
    pub command: ApiKeyCommands,
}

#[derive(Subcommand)]
pub enum ApiKeyCommands {
    /// Create a new API key for a tenant
    Create {
        /// Human-readable name for the API key (e.g. ci-deploy)
        #[arg(long)]
        name: String,
        /// Tenant ID the key belongs to
        #[arg(long)]
        tenant_id: String,
        /// Comma-separated list of policy names to attach
        #[arg(long, value_delimiter = ',', num_args = 1..)]
        policies: Vec<String>,
    },
    /// List API keys for a tenant
    List {
        /// Tenant ID to list keys for
        #[arg(long)]
        tenant_id: String,
    },
    /// Revoke an API key
    Revoke {
        /// API key ID
        id: String,
        /// Tenant ID the key belongs to
        #[arg(long)]
        tenant_id: String,
    },
    /// Rotate an API key, issuing a new secret while preserving the key ID
    Rotate {
        /// API key ID
        id: String,
        /// Tenant ID the key belongs to
        #[arg(long)]
        tenant_id: String,
    },
}

pub async fn execute(args: ApiKeyArgs, ctx: &CommandContext) -> anyhow::Result<()> {
    let client = reqwest::Client::new();
    let base = &ctx.endpoint;

    match args.command {
        ApiKeyCommands::Create {
            name,
            tenant_id,
            policies,
        } => {
            let body = serde_json::json!({
                "name": name,
                "tenant_id": tenant_id,
                "policies": policies,
            });
            let mut req = client.post(format!("{}/v1/api-keys", base)).json(&body);
            if let Some(ref t) = ctx.token {
                req = req.bearer_auth(t);
            }
            // Forward the per-command tenant_id as the tenant header so the
            // identity-service can authorise the request against the correct tenant.
            req = req.header("X-Vault-Tenant-ID", &tenant_id);
            let resp = req.send().await?;
            if !resp.status().is_success() {
                let status = resp.status();
                let body_text = resp.text().await.unwrap_or_default();
                anyhow::bail!("api-key create failed ({}): {}", status, body_text);
            }
            let resp_body: serde_json::Value = resp.json().await?;
            output::success(&format!("api-key '{}' created", name));
            // Surface the generated secret immediately — it is only shown once.
            output::print_value(&resp_body, &ctx.format)?;
        }
        ApiKeyCommands::List { tenant_id } => {
            let mut req = client
                .get(format!("{}/v1/api-keys", base))
                .header("X-Vault-Tenant-ID", &tenant_id);
            if let Some(ref t) = ctx.token {
                req = req.bearer_auth(t);
            }
            let resp = req.send().await?;
            if !resp.status().is_success() {
                let status = resp.status();
                let body_text = resp.text().await.unwrap_or_default();
                anyhow::bail!("api-key list failed ({}): {}", status, body_text);
            }
            let resp_body: serde_json::Value = resp.json().await?;
            output::print_value(&resp_body, &ctx.format)?;
        }
        ApiKeyCommands::Revoke { id, tenant_id } => {
            let mut req = client
                .delete(format!("{}/v1/api-keys/{}", base, id))
                .header("X-Vault-Tenant-ID", &tenant_id);
            if let Some(ref t) = ctx.token {
                req = req.bearer_auth(t);
            }
            let resp = req.send().await?;
            if !resp.status().is_success() {
                let status = resp.status();
                let body_text = resp.text().await.unwrap_or_default();
                anyhow::bail!("api-key revoke failed ({}): {}", status, body_text);
            }
            output::success(&format!("api-key '{}' revoked", id));
        }
        ApiKeyCommands::Rotate { id, tenant_id } => {
            let mut req = client
                .post(format!("{}/v1/api-keys/{}/rotate", base, id))
                .header("X-Vault-Tenant-ID", &tenant_id);
            if let Some(ref t) = ctx.token {
                req = req.bearer_auth(t);
            }
            let resp = req.send().await?;
            if !resp.status().is_success() {
                let status = resp.status();
                let body_text = resp.text().await.unwrap_or_default();
                anyhow::bail!("api-key rotate failed ({}): {}", status, body_text);
            }
            let resp_body: serde_json::Value = resp.json().await?;
            output::success(&format!(
                "api-key '{}' rotated — store the new secret immediately",
                id
            ));
            output::print_value(&resp_body, &ctx.format)?;
        }
    }
    Ok(())
}
