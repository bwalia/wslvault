use clap::{Parser, Subcommand};

mod completion;
mod identity;
mod lease;
mod mcp_cmd;
mod secret;
mod status;
mod transit;

use crate::config::AppConfig;

#[derive(Parser)]
#[command(
    name = "wslvault",
    about = "WSLVault CLI — Next-generation secrets management",
    version,
    propagate_version = true,
    arg_required_else_help = true
)]
pub struct Cli {
    /// Configuration profile to use (dev, staging, prod)
    #[arg(long, global = true, env = "WSLVAULT_PROFILE")]
    pub profile: Option<String>,

    /// WSLVault server endpoint (overrides config)
    #[arg(long, global = true, env = "WSLVAULT_ADDR")]
    pub addr: Option<String>,

    /// Authentication token (overrides config)
    #[arg(long, global = true, env = "WSLVAULT_TOKEN", hide_env_values = true)]
    pub token: Option<String>,

    /// Tenant ID for multi-tenant operations
    #[arg(long, global = true, env = "WSLVAULT_TENANT_ID")]
    pub tenant_id: Option<String>,

    /// Output format
    #[arg(long, global = true, default_value = "text")]
    pub format: OutputFormat,

    #[command(subcommand)]
    pub command: Commands,
}

#[derive(Clone, clap::ValueEnum)]
pub enum OutputFormat {
    Text,
    Json,
    Yaml,
}

#[derive(Subcommand)]
pub enum Commands {
    /// Read, write, delete, and list secrets
    Secret(secret::SecretArgs),
    /// Transit encryption operations (encrypt, decrypt, sign, verify)
    Transit(transit::TransitArgs),
    /// Manage leases (list, renew, revoke)
    Lease(lease::LeaseArgs),
    /// Manage identities and service accounts
    Identity(identity::IdentityArgs),
    /// MCP client operations for AI agent integration
    Mcp(mcp_cmd::McpArgs),
    /// Check server status and connectivity
    Status,
    /// Generate shell completions
    Completion(completion::CompletionArgs),
}

pub async fn execute(cli: Cli, config: AppConfig) -> anyhow::Result<()> {
    // Resolve effective endpoint and token from CLI flags > config
    let endpoint = cli.addr.as_deref().unwrap_or(&config.endpoint).to_string();
    let token = cli
        .token
        .as_deref()
        .or(config.token.as_deref())
        .map(|s| s.to_string());
    let tenant_id = cli
        .tenant_id
        .as_deref()
        .or(config.tenant_id.as_deref())
        .map(|s| s.to_string());

    let ctx = CommandContext {
        endpoint,
        token,
        tenant_id,
        format: cli.format,
    };

    match cli.command {
        Commands::Secret(args) => secret::execute(args, &ctx).await,
        Commands::Transit(args) => transit::execute(args, &ctx).await,
        Commands::Lease(args) => lease::execute(args, &ctx).await,
        Commands::Identity(args) => identity::execute(args, &ctx).await,
        Commands::Mcp(args) => mcp_cmd::execute(args, &ctx).await,
        Commands::Status => status::execute(&ctx).await,
        Commands::Completion(args) => completion::execute(args),
    }
}

/// Shared context passed to all command handlers.
pub struct CommandContext {
    pub endpoint: String,
    pub token: Option<String>,
    pub tenant_id: Option<String>,
    pub format: OutputFormat,
}
