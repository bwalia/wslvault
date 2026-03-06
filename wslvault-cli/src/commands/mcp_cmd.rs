//! MCP client command handler — interact with WSLVault via the MCP protocol.

use crate::commands::CommandContext;
use crate::mcp::McpClient;
use crate::output;
use clap::{Args, Subcommand};

#[derive(Args)]
pub struct McpArgs {
    #[command(subcommand)]
    pub command: McpCommands,
}

#[derive(Subcommand)]
pub enum McpCommands {
    /// List available MCP tools
    ListTools,
    /// Read a secret via MCP
    GetSecret {
        /// Secret path
        path: String,
    },
    /// List secrets via MCP
    ListSecrets {
        /// Path prefix
        #[arg(default_value = "")]
        prefix: String,
    },
    /// Encrypt data via MCP
    Encrypt {
        /// Transit key name
        key_name: String,
        /// Plaintext to encrypt
        plaintext: String,
    },
    /// Decrypt data via MCP
    Decrypt {
        /// Transit key name
        key_name: String,
        /// Ciphertext to decrypt
        ciphertext: String,
    },
    /// Call a raw MCP tool by name
    Call {
        /// Tool name
        tool: String,
        /// Arguments as JSON string
        #[arg(short, long)]
        args: String,
    },
}

pub async fn execute(args: McpArgs, ctx: &CommandContext) -> anyhow::Result<()> {
    let client = McpClient::new(
        &ctx.endpoint,
        ctx.token.as_deref(),
        ctx.tenant_id.as_deref(),
    )?;

    match args.command {
        McpCommands::ListTools => {
            let tools = client.list_tools().await?;
            output::print_value(&tools, &ctx.format)?;
        }
        McpCommands::GetSecret { path } => {
            let result = client
                .call_tool(
                    "read_secret",
                    serde_json::json!({
                        "path": path,
                        "tenant_id": ctx.tenant_id.as_deref().unwrap_or("default"),
                    }),
                )
                .await?;
            output::print_value(&result, &ctx.format)?;
        }
        McpCommands::ListSecrets { prefix } => {
            let result = client
                .call_tool(
                    "list_secrets",
                    serde_json::json!({
                        "prefix": prefix,
                        "tenant_id": ctx.tenant_id.as_deref().unwrap_or("default"),
                    }),
                )
                .await?;
            output::print_value(&result, &ctx.format)?;
        }
        McpCommands::Encrypt {
            key_name,
            plaintext,
        } => {
            let result = client
                .call_tool(
                    "encrypt_data",
                    serde_json::json!({
                        "key_name": key_name,
                        "plaintext": plaintext,
                        "tenant_id": ctx.tenant_id.as_deref().unwrap_or("default"),
                    }),
                )
                .await?;
            output::print_value(&result, &ctx.format)?;
        }
        McpCommands::Decrypt {
            key_name,
            ciphertext,
        } => {
            let result = client
                .call_tool(
                    "decrypt_data",
                    serde_json::json!({
                        "key_name": key_name,
                        "ciphertext": ciphertext,
                        "tenant_id": ctx.tenant_id.as_deref().unwrap_or("default"),
                    }),
                )
                .await?;
            output::print_value(&result, &ctx.format)?;
        }
        McpCommands::Call {
            tool,
            args: arguments,
        } => {
            // Parse the caller-supplied JSON arguments before forwarding to MCP,
            // surfacing malformed JSON with a clear error rather than a server-side failure.
            let args_val: serde_json::Value = serde_json::from_str(&arguments)
                .map_err(|e| anyhow::anyhow!("invalid JSON arguments: {}", e))?;
            let result = client.call_tool(&tool, args_val).await?;
            output::print_value(&result, &ctx.format)?;
        }
    }
    Ok(())
}
