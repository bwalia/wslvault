use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::PathBuf;

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct AppConfig {
    /// WSLVault server endpoint
    #[serde(default = "default_endpoint")]
    pub endpoint: String,
    /// Authentication token
    pub token: Option<String>,
    /// Default tenant ID
    pub tenant_id: Option<String>,
    /// TLS CA certificate path
    pub ca_cert: Option<String>,
    /// Named profiles (dev, staging, prod)
    #[serde(default, skip_serializing_if = "HashMap::is_empty")]
    pub profiles: HashMap<String, ProfileConfig>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ProfileConfig {
    pub endpoint: Option<String>,
    pub token: Option<String>,
    pub tenant_id: Option<String>,
    pub ca_cert: Option<String>,
}

fn default_endpoint() -> String {
    "http://localhost:8443".into()
}

impl AppConfig {
    /// Load configuration from `~/.wslvault/config.toml`, merging the named profile if specified.
    /// A missing profile is an error unless `allow_missing_profile` is set.
    pub fn load(profile: Option<&str>, allow_missing_profile: bool) -> anyhow::Result<Self> {
        let config_path = Self::config_path();

        let mut config = if config_path.exists() {
            let content = std::fs::read_to_string(&config_path)?;
            toml::from_str::<AppConfig>(&content)?
        } else {
            AppConfig::default()
        };

        // Merge profile overrides
        if let Some(profile_name) = profile {
            if let Some(profile) = config.profiles.get(profile_name) {
                if let Some(ref ep) = profile.endpoint.clone() {
                    config.endpoint = ep.clone();
                }
                if profile.token.is_some() {
                    config.token = profile.token.clone();
                }
                if profile.tenant_id.is_some() {
                    config.tenant_id = profile.tenant_id.clone();
                }
                if profile.ca_cert.is_some() {
                    config.ca_cert = profile.ca_cert.clone();
                }
            } else if !allow_missing_profile {
                anyhow::bail!("profile '{}' not found in config", profile_name);
            }
        }

        Ok(config)
    }

    /// Load the config file exactly as written, without merging any profile.
    pub fn load_raw() -> anyhow::Result<Self> {
        let path = Self::config_path();
        if !path.exists() {
            return Ok(AppConfig {
                endpoint: default_endpoint(),
                ..Default::default()
            });
        }
        Ok(toml::from_str(&std::fs::read_to_string(&path)?)?)
    }

    /// Store a token, the endpoint that issued it and its tenant, at the top
    /// level or in `profile` (created if missing). The tenant is informational:
    /// the server takes the tenant from the token itself.
    pub fn set_credentials(
        &mut self,
        profile: Option<&str>,
        endpoint: &str,
        token: String,
        tenant_id: Option<String>,
    ) {
        match profile {
            Some(name) => {
                let p = self.profiles.entry(name.to_string()).or_default();
                p.endpoint = Some(endpoint.to_string());
                p.token = Some(token);
                p.tenant_id = tenant_id;
            }
            None => {
                self.endpoint = endpoint.to_string();
                self.token = Some(token);
                self.tenant_id = tenant_id;
            }
        }
    }

    /// Write the config to `~/.wslvault/config.toml`, owner-only on Unix
    /// because it may hold a token.
    pub fn save(&self) -> anyhow::Result<PathBuf> {
        let path = Self::config_path();
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).map_err(|e| {
                anyhow::anyhow!(
                    "failed to create config directory {}: {}",
                    parent.display(),
                    e
                )
            })?;
        }
        let content = format!(
            "# WSLVault configuration — managed by `wslvault init` / `wslvault identity login`\n{}",
            toml::to_string_pretty(self)?
        );
        std::fs::write(&path, content)
            .map_err(|e| anyhow::anyhow!("failed to write config to {}: {}", path.display(), e))?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))?;
        }
        Ok(path)
    }

    /// Returns the path to the config file: `~/.wslvault/config.toml`
    pub fn config_path() -> PathBuf {
        dirs::home_dir()
            .unwrap_or_else(|| PathBuf::from("."))
            .join(".wslvault")
            .join("config.toml")
    }

    /// Initialize a default config file if none exists.
    /// Used by `wslvault init`; retained for the config-scaffolding path.
    #[allow(dead_code)]
    pub fn init_default() -> anyhow::Result<PathBuf> {
        let path = Self::config_path();
        if path.exists() {
            anyhow::bail!("config already exists at {}", path.display());
        }
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let default = AppConfig {
            endpoint: default_endpoint(),
            token: None,
            tenant_id: None,
            ca_cert: None,
            profiles: HashMap::from([
                (
                    "dev".into(),
                    ProfileConfig {
                        endpoint: Some("http://localhost:8443".into()),
                        ..Default::default()
                    },
                ),
                (
                    "prod".into(),
                    ProfileConfig {
                        endpoint: Some("https://vault.example.com".into()),
                        ..Default::default()
                    },
                ),
            ]),
        };
        let content = toml::to_string_pretty(&default)?;
        std::fs::write(&path, content)?;
        Ok(path)
    }
}
