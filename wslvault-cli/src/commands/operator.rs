//! Operator command handler — display the health status of all WSLVault services.

use crate::commands::CommandContext;
use colored::Colorize;

/// Well-known WSLVault service names and the relative health endpoint paths they expose.
/// Each entry is (display_name, health_path).
const SERVICES: &[(&str, &str)] = &[
    ("vault-core", "/health"),
    ("identity-service", "/health"),
    ("policy-engine", "/health"),
    ("transit-engine", "/health"),
    ("audit-log", "/health"),
];

pub async fn execute(ctx: &CommandContext) -> anyhow::Result<()> {
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(5))
        .build()?;

    eprintln!(
        "Querying WSLVault service health at {}...\n",
        ctx.endpoint.bold()
    );

    // Column widths for a clean fixed-width table
    let col_service = 20usize;
    let col_status = 12usize;
    let col_version = 15usize;

    // Print table header
    eprintln!(
        "{:<col_service$}  {:<col_status$}  {:<col_version$}",
        "SERVICE".bold(),
        "STATUS".bold(),
        "VERSION".bold(),
        col_service = col_service,
        col_status = col_status,
        col_version = col_version,
    );
    eprintln!("{}", "-".repeat(col_service + col_status + col_version + 4));

    let mut any_unhealthy = false;

    for (service_name, health_path) in SERVICES {
        let url = format!("{}{}", ctx.endpoint, health_path);
        let (status_str, version_str) = match client.get(&url).send().await {
            Ok(resp) if resp.status().is_success() => {
                let body: serde_json::Value = resp.json().await.unwrap_or_default();
                let version = body
                    .get("version")
                    .and_then(|v| v.as_str())
                    .unwrap_or("unknown")
                    .to_string();
                ("healthy".green().bold().to_string(), version)
            }
            Ok(resp) => {
                any_unhealthy = true;
                (
                    format!("degraded ({})", resp.status())
                        .red()
                        .bold()
                        .to_string(),
                    "unknown".to_string(),
                )
            }
            Err(_) => {
                any_unhealthy = true;
                (
                    "unreachable".red().bold().to_string(),
                    "unknown".to_string(),
                )
            }
        };

        eprintln!(
            "{:<col_service$}  {:<col_status$}  {:<col_version$}",
            service_name,
            status_str,
            version_str,
            col_service = col_service,
            col_status = col_status,
            col_version = col_version,
        );
    }

    eprintln!();
    if any_unhealthy {
        eprintln!(
            "{} One or more services are unhealthy or unreachable.",
            "!".red().bold()
        );
    } else {
        eprintln!("{} All services are healthy.", "✓".green().bold());
    }

    Ok(())
}
