use std::collections::HashMap;
use zeroize::{Zeroize, ZeroizeOnDrop};

/// A secret value that is automatically zeroed from memory on drop.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct SecretValue {
    data: Vec<u8>,
}

impl SecretValue {
    pub fn new(data: Vec<u8>) -> Self {
        Self { data }
    }

    pub fn from_string(s: String) -> Self {
        Self {
            data: s.into_bytes(),
        }
    }

    /// Access the raw bytes. Caller must not store this reference beyond the current scope.
    pub fn as_bytes(&self) -> &[u8] {
        &self.data
    }

    /// Convert to a string, consuming the secret. The returned String is NOT zeroized.
    pub fn to_string_lossy(&self) -> String {
        String::from_utf8_lossy(&self.data).to_string()
    }
}

// Custom Debug to prevent leaking in logs
impl std::fmt::Debug for SecretValue {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("[REDACTED]")
    }
}

/// Parsed secret data from a WSLVault response.
#[derive(Debug, serde::Deserialize, serde::Serialize)]
pub struct SecretData {
    pub data: HashMap<String, serde_json::Value>,
    #[serde(default)]
    pub version: u32,
    #[serde(default)]
    pub created_at: Option<String>,
    #[serde(default)]
    pub metadata: Option<HashMap<String, String>>,
}
