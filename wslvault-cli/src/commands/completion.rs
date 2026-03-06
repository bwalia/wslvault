//! Shell completion generation command handler.

use crate::commands::Cli;
use clap::{Args, CommandFactory};
use clap_complete::{generate, Shell};

#[derive(Args)]
pub struct CompletionArgs {
    /// Shell type
    #[arg(value_enum)]
    pub shell: Shell,
}

pub fn execute(args: CompletionArgs) -> anyhow::Result<()> {
    let mut cmd = Cli::command();
    generate(args.shell, &mut cmd, "wslvault", &mut std::io::stdout());
    Ok(())
}
