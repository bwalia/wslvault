//! Policy domain types for the WSLVault policy engine.
//!
//! These types represent the in-memory policy model that the engine evaluates
//! against incoming authorization requests. They are intentionally decoupled
//! from the gRPC proto types to allow independent evolution.

use std::collections::HashSet;

use serde::{Deserialize, Serialize};

/// A named collection of rules that together define access permissions.
///
/// Policies are stored per-tenant and evaluated as a set: any matching
/// allow rule grants access, but a Deny capability in any rule always wins.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyDocument {
    /// Human-readable identifier, unique within a tenant (e.g. "admin-policy").
    pub name: String,
    /// Ordered list of rules applied during evaluation.
    pub rules: Vec<PolicyRule>,
}

/// A single rule within a policy: a set of path patterns paired with the
/// capabilities that are granted (or explicitly denied) for those paths.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyRule {
    /// Glob-style path patterns. Supports:
    ///   - `*`  — matches a single path segment (no slashes)
    ///   - `**` — recursively matches zero or more segments
    pub paths: Vec<String>,
    /// The set of capabilities that apply when this rule's paths match.
    pub capabilities: HashSet<Capability>,
}

/// The set of operations a policy can grant or deny on a resource path.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Capability {
    /// Permits reading a secret at the matched path.
    Read,
    /// Permits writing (creating or replacing) a secret.
    Write,
    /// Permits soft-deletion of a secret version.
    Delete,
    /// Permits listing children under the matched prefix.
    List,
    /// Permits creating a new resource at the matched path.
    Create,
    /// Permits updating metadata or data on an existing resource.
    Update,
    /// Explicitly denies all access, overriding any other matching rules.
    Deny,
}

impl Capability {
    /// Convert a string action token (as received over gRPC) to the
    /// corresponding capability. Returns `None` for unrecognised actions.
    ///
    /// Convention: `"<namespace>:<verb>"`, e.g. `"secret:read"`.
    pub fn from_action(action: &str) -> Option<Self> {
        // Strip an optional namespace prefix so callers can pass either
        // "read" or "secret:read" and get the same result.
        let verb = action.split(':').last().unwrap_or(action);
        match verb {
            "read" => Some(Capability::Read),
            "write" => Some(Capability::Write),
            "delete" => Some(Capability::Delete),
            "list" => Some(Capability::List),
            "create" => Some(Capability::Create),
            "update" => Some(Capability::Update),
            "deny" => Some(Capability::Deny),
            _ => None,
        }
    }
}

/// The outcome of evaluating a set of policies against a single request.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum PolicyDecision {
    /// The request is permitted by at least one matching rule and no deny
    /// rule was triggered.
    Allow,
    /// The request is forbidden. The `reason` field explains why (e.g.
    /// "explicit deny", "no matching policy", "unknown action").
    Deny { reason: String },
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn capability_from_namespaced_action() {
        assert_eq!(
            Capability::from_action("secret:read"),
            Some(Capability::Read)
        );
        assert_eq!(
            Capability::from_action("secret:write"),
            Some(Capability::Write)
        );
        assert_eq!(Capability::from_action("read"), Some(Capability::Read));
        assert_eq!(Capability::from_action("unknown"), None);
    }

    #[test]
    fn policy_document_round_trips_via_json() {
        let doc = PolicyDocument {
            name: "test-policy".to_string(),
            rules: vec![PolicyRule {
                paths: vec!["secret/*".to_string()],
                capabilities: [Capability::Read, Capability::List].into(),
            }],
        };
        let serialized = serde_json::to_string(&doc).expect("serialize");
        let deserialized: PolicyDocument = serde_json::from_str(&serialized).expect("deserialize");
        assert_eq!(deserialized.name, doc.name);
        assert_eq!(deserialized.rules.len(), 1);
    }
}
