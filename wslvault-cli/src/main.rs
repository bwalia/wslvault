//! WSLVault CLI — production-ready command-line tool for the WSLVault secrets platform.

mod commands;
mod config;
mod mcp;
mod output;
#[allow(dead_code)]
mod secrets;

use clap::Parser;
use colored::Colorize;
use tracing_subscriber::EnvFilter;

use crate::commands::Cli;
use crate::config::AppConfig;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // Initialize tracing (respects RUST_LOG env var, defaults to warn)
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("warn")),
        )
        .with_target(false)
        .init();

    let cli = Cli::parse();

    // Load configuration
    let config = AppConfig::load(cli.profile.as_deref())?;

    // Execute the command
    if let Err(e) = commands::execute(cli, config).await {
        eprintln!("{} {}", "error:".red().bold(), e);
        std::process::exit(1);
    }

    Ok(())
}
