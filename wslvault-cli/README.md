# wslvault-cli

Production-ready CLI for the [WSLVault](https://github.com/bwalia/wslvault) secrets management platform.

## Installation

```bash
# From source
cargo install --path .

# Or build locally
cargo build --release
```

## Configuration

Create `~/.wslvault/config.toml`:

```toml
endpoint = "https://vault.example.com"
token = "s.my-vault-token"
tenant_id = "my-tenant"

[profiles.dev]
endpoint = "http://localhost:8443"

[profiles.prod]
endpoint = "https://vault.prod.example.com"
```

Or use environment variables:

```bash
export WSLVAULT_ADDR="https://vault.example.com"
export WSLVAULT_TOKEN="s.my-token"
export WSLVAULT_TENANT_ID="my-tenant"
```

## Usage

### Secrets

```bash
# Write a secret
wslvault secret put prod/database/creds --data username=admin --data password=s3cret

# Read a secret
wslvault secret get prod/database/creds

# Read a single field (for piping)
wslvault secret get prod/database/creds --field password | pbcopy

# List secrets
wslvault secret list prod/

# Delete a version
wslvault secret delete prod/database/creds --versions 1 2

# Output as JSON
wslvault --format json secret get prod/database/creds
```

### Transit Encryption

```bash
# Create a transit key
wslvault transit create-key my-app-key

# Encrypt data
wslvault transit encrypt my-app-key "sensitive data"

# Decrypt data
wslvault transit decrypt my-app-key "vault:v1:..."

# Rotate key
wslvault transit rotate-key my-app-key
```

### MCP (AI Agent Integration)

```bash
# List available MCP tools
wslvault mcp list-tools

# Read a secret via MCP protocol
wslvault mcp get-secret prod/database/password

# Encrypt via MCP
wslvault mcp encrypt my-key "plaintext"

# Call any MCP tool directly
wslvault mcp call read_secret --args '{"path":"prod/db","tenant_id":"t1"}'
```

### Identity & Leases

```bash
# Create a service account
wslvault identity create-service-account my-app --policies read-only admin

# List leases
wslvault lease list

# Renew a lease
wslvault lease renew <lease-id> --increment 7200

# Check server status
wslvault status
```

### Profiles

```bash
# Use a specific profile
wslvault --profile prod secret get prod/database/creds

# Override endpoint on the fly
wslvault --addr https://other-vault.com secret list
```

### Shell Completions

```bash
# Bash
wslvault completion bash >> ~/.bashrc

# Zsh
wslvault completion zsh >> ~/.zshrc

# Fish
wslvault completion fish > ~/.config/fish/completions/wslvault.fish

# PowerShell
wslvault completion powershell >> $PROFILE
```

## Security

- Secrets are held in memory using `zeroize` — automatically wiped on drop
- Authentication tokens are never logged (hidden from `--help` and tracing)
- TLS certificate validation is enforced by default
- Destructive operations (destroy) show warnings before proceeding

## License

Apache-2.0
