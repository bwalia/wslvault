//! Status command handler — check server health and authentication configuration.

use crate::commands::CommandContext;
use colored::Colorize;

pub async fn execute(ctx: &CommandContext) -> anyhow::Result<()> {
    eprintln!("Checking WSLVault server at {}...", ctx.endpoint.bold());

    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(5))
        .build()?;

    let health_url = format!("{}/health", ctx.endpoint);
    match client.get(&health_url).send().await {
        Ok(resp) => {
            if resp.status().is_success() {
                let body: serde_json::Value = resp.json().await.unwrap_or_default();
                eprintln!("{} Server is {}", "✓".green().bold(), "healthy".green());
                if let Some(status) = body.get("status") {
                    eprintln!("  status: {}", status);
                }
            } else {
                eprintln!("{} Server returned {}", "✗".red().bold(), resp.status());
            }
        }
        Err(e) => {
            eprintln!("{} Cannot reach server: {}", "✗".red().bold(), e);
            anyhow::bail!("server unreachable at {}", ctx.endpoint);
        }
    }

    // Report authentication and tenant configuration so operators can diagnose
    // missing credentials without inspecting config files manually.
    if ctx.token.is_some() {
        eprintln!("{} Authentication token configured", "✓".green().bold());
    } else {
        eprintln!("{} No authentication token configured", "⚠".yellow().bold());
    }

    if let Some(ref tid) = ctx.tenant_id {
        eprintln!("{} Tenant: {}", "✓".green().bold(), tid);
    }

    Ok(())
}
