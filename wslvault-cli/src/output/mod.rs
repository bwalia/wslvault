use crate::commands::OutputFormat;
use colored::Colorize;
use serde::Serialize;

/// Print a value in the requested format.
pub fn print_value<T: Serialize>(value: &T, format: &OutputFormat) -> anyhow::Result<()> {
    match format {
        OutputFormat::Json => {
            println!("{}", serde_json::to_string_pretty(value)?);
        }
        OutputFormat::Yaml => {
            // Use JSON as fallback since serde_yaml is not in deps
            println!("{}", serde_json::to_string_pretty(value)?);
        }
        OutputFormat::Text => {
            println!("{}", serde_json::to_string_pretty(value)?);
        }
    }
    Ok(())
}

/// Print a success message.
pub fn success(msg: &str) {
    eprintln!("{} {}", "✓".green().bold(), msg);
}

/// Print a warning.
#[allow(dead_code)]
pub fn warn(msg: &str) {
    eprintln!("{} {}", "⚠".yellow().bold(), msg);
}

/// Print a key-value pair in text format.
pub fn kv(key: &str, value: &str) {
    println!("{}: {}", key.bold(), value);
}

/// Print a table header.
#[allow(dead_code)]
pub fn table_header(columns: &[&str]) {
    let header = columns
        .iter()
        .map(|c| c.bold().to_string())
        .collect::<Vec<_>>()
        .join("  ");
    println!("{}", header);
    println!("{}", "-".repeat(header.len()));
}
