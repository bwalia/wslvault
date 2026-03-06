//! Path normalization and validation for KV secret paths.
//!
//! All paths stored in the secret engine are normalized to a canonical form:
//! - No leading or trailing slashes
//! - No empty segments ("//")
//! - No ".." traversal segments
//! - Only alphanumeric characters, hyphens, underscores, and forward slashes

use wslvault_core::VaultError;

/// Normalize a raw path string to a canonical form.
///
/// Strips leading and trailing slashes, then validates that no segment is
/// empty or equals "..". Returns the normalized path on success.
pub fn normalize_path(raw: &str) -> Result<String, VaultError> {
    let trimmed = raw.trim_matches('/');

    if trimmed.is_empty() {
        return Err(VaultError::InvalidPath {
            path: raw.to_string(),
            reason: "path must not be empty".into(),
        });
    }

    // Reject any ".." traversal segments before further processing.
    for segment in trimmed.split('/') {
        if segment.is_empty() {
            return Err(VaultError::InvalidPath {
                path: raw.to_string(),
                reason: "path must not contain empty segments (//)".into(),
            });
        }
        if segment == ".." {
            return Err(VaultError::InvalidPath {
                path: raw.to_string(),
                reason: "path must not contain '..' traversal segments".into(),
            });
        }
    }

    Ok(trimmed.to_string())
}

/// Validate that all characters in the path are permitted.
///
/// Permitted: alphanumeric ASCII (`a-z`, `A-Z`, `0-9`), hyphen (`-`),
/// underscore (`_`), dot (`.`), and forward slash (`/`).
///
/// This function must be called *after* `normalize_path` so that the path
/// is already free of leading/trailing slashes and empty segments.
pub fn validate_path(path: &str) -> Result<(), VaultError> {
    for ch in path.chars() {
        if !ch.is_ascii_alphanumeric() && ch != '-' && ch != '_' && ch != '.' && ch != '/' {
            return Err(VaultError::InvalidPath {
                path: path.to_string(),
                reason: format!(
                    "character '{}' is not allowed; only alphanumeric, '-', '_', '.', and '/' are permitted",
                    ch
                ),
            });
        }
    }
    Ok(())
}

/// Convenience function that normalizes then validates a path.
///
/// Returns the normalized path string if both checks pass.
pub fn normalize_and_validate(raw: &str) -> Result<String, VaultError> {
    let normalized = normalize_path(raw)?;
    validate_path(&normalized)?;
    Ok(normalized)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn strips_leading_and_trailing_slashes() {
        assert_eq!(normalize_path("/foo/bar/").unwrap(), "foo/bar");
    }

    #[test]
    fn rejects_empty_path() {
        assert!(normalize_path("").is_err());
        assert!(normalize_path("///").is_err());
    }

    #[test]
    fn rejects_dotdot_traversal() {
        assert!(normalize_path("foo/../bar").is_err());
        assert!(normalize_path("../secret").is_err());
    }

    #[test]
    fn rejects_empty_segments() {
        assert!(normalize_path("foo//bar").is_err());
    }

    #[test]
    fn rejects_invalid_characters() {
        assert!(validate_path("foo/bar$baz").is_err());
        assert!(validate_path("foo/bar baz").is_err());
    }

    #[test]
    fn accepts_valid_paths() {
        assert!(normalize_and_validate("prod/database/password").is_ok());
        assert!(normalize_and_validate("team-a/service_b/key.v1").is_ok());
    }
}
