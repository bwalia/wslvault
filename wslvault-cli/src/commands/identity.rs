//! Identity command handler — manage service accounts and authentication.

use crate::commands::CommandContext;
use crate::config::AppConfig;
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
    /// Verify a token and save it to ~/.wslvault/config.toml (in the
    /// `--profile` section when one is given). The tenant it acts on comes
    /// from the token itself.
    Login {
        /// Authentication token (prompted for when omitted, which keeps it
        /// out of shell history)
        token: Option<String>,
        /// Save the token without checking it against the server
        #[arg(long)]
        no_verify: bool,
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
        IdentityCommands::Login { token, no_verify } => {
            let token = match token {
                Some(t) => t,
                None => dialoguer::Password::new().with_prompt("Token").interact()?,
            };
            let token = token.trim().to_string();
            if token.is_empty() {
                anyhow::bail!("token is empty");
            }

            let tenant_id = if no_verify {
                output::warn("token not verified; tenant unknown until first use");
                None
            } else {
                lookup_tenant(base, &token).await?
            };

            let mut config = AppConfig::load_raw()?;
            config.set_credentials(
                ctx.profile.as_deref(),
                base,
                token.clone(),
                tenant_id.clone(),
            );
            let path = config.save()?;

            if tenant_id.is_some() || !no_verify {
                output::success("authenticated successfully");
            } else {
                output::success("token saved");
            }
            output::kv("token", &mask(&token));
            output::kv("tenant", tenant_id.as_deref().unwrap_or("(unverified)"));
            output::kv("profile", ctx.profile.as_deref().unwrap_or("(default)"));
            output::kv("saved to", &path.display().to_string());
        }
    }
    Ok(())
}

/// Ask the server which tenant `token` belongs to, via the Vault-compatible
/// `GET /v1/auth/token/lookup-self` (served by secret-engine).
pub async fn lookup_tenant(endpoint: &str, token: &str) -> anyhow::Result<Option<String>> {
    let resp = reqwest::Client::new()
        .get(format!("{}/v1/auth/token/lookup-self", endpoint))
        .bearer_auth(token)
        .timeout(std::time::Duration::from_secs(10))
        .send()
        .await
        .map_err(|e| {
            anyhow::anyhow!(
                "could not reach {}: {} (use --no-verify to save anyway)",
                endpoint,
                e
            )
        })?;
    let status = resp.status();
    if status == reqwest::StatusCode::UNAUTHORIZED || status == reqwest::StatusCode::FORBIDDEN {
        anyhow::bail!("token rejected by {} ({})", endpoint, status);
    }
    if !status.is_success() {
        // An HTML page here usually means the endpoint is the web console
        // rather than the API host.
        let body = resp.text().await.unwrap_or_default();
        let detail = if body.trim_start().starts_with('<') {
            "endpoint returned an HTML page — is it the API host rather than the web console?"
                .to_string()
        } else {
            body.chars().take(200).collect()
        };
        anyhow::bail!(
            "token lookup failed ({}): {} (use --no-verify to save anyway)",
            status,
            detail
        );
    }
    let body: serde_json::Value = resp.json().await?;
    Ok(body["data"]["meta"]["tenant_id"]
        .as_str()
        .filter(|t| !t.is_empty())
        .map(str::to_string))
}

/// Show only the ends of a token, and nothing at all of a short one.
pub fn mask(token: &str) -> String {
    let chars: Vec<char> = token.chars().collect();
    if chars.len() < 16 {
        return "****".into();
    }
    let head: String = chars[..8].iter().collect();
    let tail: String = chars[chars.len() - 4..].iter().collect();
    format!("{}...{}", head, tail)
}

#[cfg(test)]
mod tests {
    use super::mask;

    #[test]
    fn mask_hides_short_tokens_entirely() {
        assert_eq!(mask("abc"), "****");
        assert_eq!(mask("0123456789abcdef"), "01234567...cdef");
    }
}
