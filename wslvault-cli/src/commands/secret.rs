//! Secret command handler — read, write, delete, destroy, and list secrets.

use crate::commands::CommandContext;
use crate::mcp::McpClient;
use crate::output;
use clap::{Args, Subcommand};
use colored::Colorize;

#[derive(Args)]
pub struct SecretArgs {
    #[command(subcommand)]
    pub command: SecretCommands,
}

#[derive(Subcommand)]
pub enum SecretCommands {
    /// Read a secret at the given path
    Get {
        /// Secret path (e.g. prod/database/password)
        path: String,
        /// Specific version to read
        #[arg(long = "secret-version", id = "secret_version")]
        version: Option<u32>,
        /// Output only the raw value of a specific field (for piping)
        #[arg(short, long)]
        field: Option<String>,
    },
    /// Write a secret at the given path
    Put {
        /// Secret path
        path: String,
        /// Key=value pairs to store
        #[arg(short, long, num_args = 1..)]
        data: Vec<String>,
        /// Check-and-set version (only write if current version matches)
        #[arg(long)]
        cas: Option<u32>,
    },
    /// Delete secret versions (soft delete)
    Delete {
        /// Secret path
        path: String,
        /// Versions to delete
        #[arg(short, long, num_args = 1..)]
        versions: Vec<u32>,
    },
    /// Permanently destroy secret versions
    Destroy {
        /// Secret path
        path: String,
        /// Versions to destroy
        #[arg(short, long, num_args = 1..)]
        versions: Vec<u32>,
    },
    /// List secrets under a prefix
    List {
        /// Path prefix
        #[arg(default_value = "")]
        prefix: String,
    },
}

pub async fn execute(args: SecretArgs, ctx: &CommandContext) -> anyhow::Result<()> {
    let client = McpClient::new(
        &ctx.endpoint,
        ctx.token.as_deref(),
        ctx.tenant_id.as_deref(),
    )?;

    match args.command {
        SecretCommands::Get {
            path,
            version,
            field,
        } => {
            let resp = client.get_secret(&path, version).await?;
            if let Some(field_name) = field {
                // Raw field output for piping — omit trailing newline so the caller
                // can compose the value directly in a shell pipeline.
                if let Some(val) = resp.get("data").and_then(|d| d.get(&field_name)) {
                    match val {
                        serde_json::Value::String(s) => print!("{}", s),
                        other => print!("{}", other),
                    }
                } else {
                    anyhow::bail!("field '{}' not found in secret", field_name);
                }
            } else {
                output::print_value(&resp, &ctx.format)?;
            }
        }
        SecretCommands::Put { path, data, cas } => {
            let mut map = serde_json::Map::new();
            for kv in &data {
                let (k, v) = kv
                    .split_once('=')
                    .ok_or_else(|| anyhow::anyhow!("invalid key=value pair: '{}'", kv))?;
                map.insert(k.to_string(), serde_json::Value::String(v.to_string()));
            }
            let resp = client
                .put_secret(&path, serde_json::Value::Object(map), cas)
                .await?;
            output::success(&format!(
                "secret written at '{}' (version {})",
                path,
                resp.get("version").and_then(|v| v.as_u64()).unwrap_or(0)
            ));
            output::print_value(&resp, &ctx.format)?;
        }
        SecretCommands::Delete { path, versions } => {
            let resp = client.delete_secret(&path, &versions).await?;
            output::success(&format!(
                "deleted {} version(s) at '{}'",
                versions.len(),
                path
            ));
            output::print_value(&resp, &ctx.format)?;
        }
        SecretCommands::Destroy { path, versions } => {
            // Warn the operator before permanently destroying secret data.
            eprintln!(
                "{}",
                "WARNING: This permanently destroys secret data and cannot be undone!"
                    .red()
                    .bold()
            );
            let resp = client.destroy_secret(&path, &versions).await?;
            output::success(&format!(
                "destroyed {} version(s) at '{}'",
                versions.len(),
                path
            ));
            output::print_value(&resp, &ctx.format)?;
        }
        SecretCommands::List { prefix } => {
            let resp = client.list_secrets(&prefix).await?;
            output::print_value(&resp, &ctx.format)?;
        }
    }
    Ok(())
}
