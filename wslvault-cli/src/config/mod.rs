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
    #[serde(default)]
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
    pub fn load(profile: Option<&str>) -> anyhow::Result<Self> {
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
            } else {
                anyhow::bail!("profile '{}' not found in config", profile_name);
            }
        }

        Ok(config)
    }

    /// Returns the path to the config file: `~/.wslvault/config.toml`
    pub fn config_path() -> PathBuf {
        dirs::home_dir()
            .unwrap_or_else(|| PathBuf::from("."))
            .join(".wslvault")
            .join("config.toml")
    }

    /// Initialize a default config file if none exists.
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
