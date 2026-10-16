//! Init command handler — interactive guided setup that writes ~/.wslvault/config.toml.

use crate::commands::identity::{lookup_tenant, mask};
use crate::config::{AppConfig, ProfileConfig};
use colored::Colorize;
use dialoguer::{theme::ColorfulTheme, Input};

pub async fn execute() -> anyhow::Result<()> {
    let config_path = AppConfig::config_path();

    eprintln!("{} WSLVault interactive setup", "»".cyan().bold());
    eprintln!(
        "  Config will be written to: {}\n",
        config_path.display().to_string().bold()
    );

    // Guard against accidentally overwriting an existing config.  Ask the user
    // explicitly rather than silently clobbering it.
    if config_path.exists() {
        eprintln!(
            "{} A config file already exists at {}.",
            "!".yellow().bold(),
            config_path.display()
        );
        let overwrite: String = Input::with_theme(&ColorfulTheme::default())
            .with_prompt("Overwrite it? [y/N]")
            .default("N".into())
            .interact_text()?;
        if !overwrite.trim().eq_ignore_ascii_case("y") {
            eprintln!("Aborted — existing config left unchanged.");
            return Ok(());
        }
    }

    let theme = ColorfulTheme::default();

    // Prompt for the vault endpoint URL
    let endpoint: String = Input::with_theme(&theme)
        .with_prompt("WSLVault endpoint URL")
        .default("http://localhost:8443".into())
        .interact_text()?;

    // Test connectivity before committing the config so the user gets immediate
    // feedback if the URL is wrong or the service is not running.
    eprint!("  Testing connectivity to {}... ", endpoint.bold());
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(5))
        .build()?;
    match client.get(format!("{}/health", endpoint)).send().await {
        Ok(resp) if resp.status().is_success() => {
            eprintln!("{}", "ok".green().bold());
        }
        Ok(resp) => {
            eprintln!("{} (status {})", "warning".yellow().bold(), resp.status());
            eprintln!(
                "  {} The server responded with a non-success status. Proceeding anyway.",
                "⚠".yellow()
            );
        }
        Err(e) => {
            eprintln!("{}", "failed".red().bold());
            eprintln!("  {} Could not reach server: {}", "⚠".yellow(), e);
            let proceed: String = Input::with_theme(&theme)
                .with_prompt("Save config anyway? [y/N]")
                .default("N".into())
                .interact_text()?;
            if !proceed.trim().eq_ignore_ascii_case("y") {
                eprintln!("Aborted — no config written.");
                return Ok(());
            }
        }
    }

    // Optional token. The server derives the tenant from it, so this is what
    // decides which tenant `wslvault secret ...` reads and writes.
    let token: String = dialoguer::Password::with_theme(&theme)
        .with_prompt("Token (leave blank to add later with `wslvault identity login`)")
        .allow_empty_password(true)
        .interact()?;
    let token = token.trim().to_string();

    let mut config = AppConfig {
        endpoint: endpoint.clone(),
        profiles: std::collections::HashMap::from([(
            "dev".into(),
            ProfileConfig {
                endpoint: Some("http://localhost:8443".into()),
                ..Default::default()
            },
        )]),
        ..Default::default()
    };

    if !token.is_empty() {
        eprint!("  Verifying token... ");
        match lookup_tenant(&endpoint, &token).await {
            Ok(tenant) => {
                eprintln!(
                    "{} (tenant {})",
                    "ok".green().bold(),
                    tenant.as_deref().unwrap_or("unknown").bold()
                );
                config.set_credentials(None, &endpoint, token, tenant);
            }
            Err(e) => {
                eprintln!("{}", "failed".red().bold());
                eprintln!("  {} {}", "⚠".yellow(), e);
                let keep: String = Input::with_theme(&theme)
                    .with_prompt("Save the unverified token anyway? [y/N]")
                    .default("N".into())
                    .interact_text()?;
                if keep.trim().eq_ignore_ascii_case("y") {
                    eprintln!("  saving token {}", mask(&token));
                    config.set_credentials(None, &endpoint, token, None);
                }
            }
        }
    }

    config.save()?;

    eprintln!(
        "\n{} Config written to {}",
        "✓".green().bold(),
        config_path.display().to_string().bold()
    );
    eprintln!(
        "  Run {} to verify connectivity at any time.",
        "wslvault status".bold()
    );

    Ok(())
}
