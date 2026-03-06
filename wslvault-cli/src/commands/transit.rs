//! Transit command handler — encrypt, decrypt, sign, verify, and manage transit keys.

use crate::commands::CommandContext;
use crate::mcp::McpClient;
use crate::output;
use clap::{Args, Subcommand};

#[derive(Args)]
pub struct TransitArgs {
    #[command(subcommand)]
    pub command: TransitCommands,
}

#[derive(Subcommand)]
pub enum TransitCommands {
    /// Encrypt data with a named transit key
    Encrypt {
        /// Transit key name
        key_name: String,
        /// Plaintext to encrypt (base64-encoded)
        plaintext: String,
    },
    /// Decrypt ciphertext with a named transit key
    Decrypt {
        /// Transit key name
        key_name: String,
        /// Ciphertext to decrypt
        ciphertext: String,
    },
    /// Sign data with a named transit key
    Sign {
        /// Transit key name
        key_name: String,
        /// Data to sign (base64-encoded)
        data: String,
    },
    /// Verify a signature
    Verify {
        /// Transit key name
        key_name: String,
        /// Data that was signed
        data: String,
        /// Signature to verify
        signature: String,
    },
    /// Create a new transit encryption key
    CreateKey {
        /// Key name
        key_name: String,
    },
    /// Rotate a transit key to a new version
    RotateKey {
        /// Key name
        key_name: String,
    },
}

pub async fn execute(args: TransitArgs, ctx: &CommandContext) -> anyhow::Result<()> {
    let client = McpClient::new(
        &ctx.endpoint,
        ctx.token.as_deref(),
        ctx.tenant_id.as_deref(),
    )?;

    match args.command {
        TransitCommands::Encrypt {
            key_name,
            plaintext,
        } => {
            let resp = client.transit_encrypt(&key_name, &plaintext).await?;
            output::print_value(&resp, &ctx.format)?;
        }
        TransitCommands::Decrypt {
            key_name,
            ciphertext,
        } => {
            let resp = client.transit_decrypt(&key_name, &ciphertext).await?;
            output::print_value(&resp, &ctx.format)?;
        }
        TransitCommands::Sign { key_name, data } => {
            let resp = client.transit_sign(&key_name, &data).await?;
            output::print_value(&resp, &ctx.format)?;
        }
        TransitCommands::Verify {
            key_name,
            data,
            signature,
        } => {
            let resp = client.transit_verify(&key_name, &data, &signature).await?;
            output::print_value(&resp, &ctx.format)?;
        }
        TransitCommands::CreateKey { key_name } => {
            let resp = client.transit_create_key(&key_name).await?;
            output::success(&format!("transit key '{}' created", key_name));
            output::print_value(&resp, &ctx.format)?;
        }
        TransitCommands::RotateKey { key_name } => {
            let resp = client.transit_rotate_key(&key_name).await?;
            output::success(&format!("transit key '{}' rotated", key_name));
            output::print_value(&resp, &ctx.format)?;
        }
    }
    Ok(())
}
