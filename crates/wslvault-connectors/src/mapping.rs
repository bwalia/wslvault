//! Path and field mapping for external integrations.
//!
//! When syncing between WSLVault and external secret managers, paths and field
//! names may differ. This module provides a `PathMapper` trait and a default
//! implementation that handles prefix-based translation and field renaming.

use std::collections::HashMap;

use crate::traits::SecretData;

/// Maps between WSLVault paths and external system paths.
pub trait PathMapper: Send + Sync {
    /// Convert a WSLVault internal path to an external system path.
    fn to_external(&self, wslvault_path: &str) -> String;

    /// Convert an external system path to a WSLVault internal path.
    fn to_internal(&self, external_path: &str) -> String;

    /// Remap fields in a SecretData according to configured field mappings.
    fn map_fields(&self, data: &SecretData) -> SecretData;
}

/// Default path mapper with prefix substitution and field renaming.
#[derive(Debug, Clone)]
pub struct PrefixPathMapper {
    /// WSLVault path prefix (e.g. "prod/myapp/")
    pub internal_prefix: String,
    /// External system path prefix (e.g. "production-myapp-")
    pub external_prefix: String,
    /// Field name mappings: WSLVault field name → external field name.
    pub field_mappings: HashMap<String, String>,
}

impl PrefixPathMapper {
    pub fn new(
        internal_prefix: String,
        external_prefix: String,
        field_mappings: HashMap<String, String>,
    ) -> Self {
        Self {
            internal_prefix,
            external_prefix,
            field_mappings,
        }
    }

    /// Identity mapper — no transformation.
    pub fn identity() -> Self {
        Self {
            internal_prefix: String::new(),
            external_prefix: String::new(),
            field_mappings: HashMap::new(),
        }
    }
}

impl PathMapper for PrefixPathMapper {
    fn to_external(&self, wslvault_path: &str) -> String {
        if let Some(suffix) = wslvault_path.strip_prefix(&self.internal_prefix) {
            format!("{}{}", self.external_prefix, suffix)
        } else {
            format!("{}{}", self.external_prefix, wslvault_path)
        }
    }

    fn to_internal(&self, external_path: &str) -> String {
        if let Some(suffix) = external_path.strip_prefix(&self.external_prefix) {
            format!("{}{}", self.internal_prefix, suffix)
        } else {
            format!("{}{}", self.internal_prefix, external_path)
        }
    }

    fn map_fields(&self, data: &SecretData) -> SecretData {
        if self.field_mappings.is_empty() {
            return data.clone();
        }

        let mapped_value = match &data.value {
            serde_json::Value::Object(map) => {
                let mut new_map = serde_json::Map::new();
                for (key, val) in map {
                    let mapped_key = self
                        .field_mappings
                        .get(key)
                        .cloned()
                        .unwrap_or_else(|| key.clone());
                    new_map.insert(mapped_key, val.clone());
                }
                serde_json::Value::Object(new_map)
            }
            other => other.clone(),
        };

        SecretData {
            key: data.key.clone(),
            value: mapped_value,
            version: data.version.clone(),
            metadata: data.metadata.clone(),
        }
    }
}
