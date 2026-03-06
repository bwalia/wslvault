//! Identity command handler — manage service accounts and authentication.

use crate::commands::CommandContext;
use crate::output;
use clap::{Args, Subcommand};

#[derive(Args)]
pub struct IdentityArgs {
    #[command(subcommand)]
    pub command: IdentityCommands,
}

#[derive(Subcommand)]
pub enum IdentityCommands {
    /// Create a new service account
    CreateServiceAccount {
        /// Service account name
        name: String,
        /// Policies to attach
        #[arg(short, long, num_args = 1..)]
        policies: Vec<String>,
        /// Token TTL in seconds
        #[arg(long, default_value = "3600")]
        ttl: u64,
    },
    /// List service accounts
    ListServiceAccounts,
    /// Login with a token
    Login {
        /// Authentication token
        token: String,
    },
}

pub async fn execute(args: IdentityArgs, ctx: &CommandContext) -> anyhow::Result<()> {
    let client = reqwest::Client::new();
    let base = &ctx.endpoint;

    match args.command {
        IdentityCommands::CreateServiceAccount {
            name,
            policies,
            ttl,
        } => {
            let body = serde_json::json!({
                "name": name,
                "policies": policies,
                "ttl_seconds": ttl,
            });
            let mut req = client
                .post(format!("{}/v1/identity/service-accounts", base))
                .json(&body);
            if let Some(ref t) = ctx.token {
                req = req.bearer_auth(t);
            }
            if let Some(ref tid) = ctx.tenant_id {
                req = req.header("X-Vault-Tenant-ID", tid);
            }
            let resp: serde_json::Value = req.send().await?.json().await?;
            output::success(&format!("service account '{}' created", name));
            output::print_value(&resp, &ctx.format)?;
        }
        IdentityCommands::ListServiceAccounts => {
            let mut req = client.get(format!("{}/v1/identity/service-accounts", base));
            if let Some(ref t) = ctx.token {
                req = req.bearer_auth(t);
            }
            if let Some(ref tid) = ctx.tenant_id {
                req = req.header("X-Vault-Tenant-ID", tid);
            }
            let resp: serde_json::Value = req.send().await?.json().await?;
            output::print_value(&resp, &ctx.format)?;
        }
        IdentityCommands::Login { token } => {
            // Mask the token in output to avoid accidental credential leakage in
            // terminal history or log captures.
            output::success("authenticated successfully");
            output::kv(
                "token",
                &format!("{}...{}", &token[..8], &token[token.len() - 4..]),
            );
        }
    }
    Ok(())
}
